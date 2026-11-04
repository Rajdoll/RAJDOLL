"""httpx and nuclei adapters: argv construction, input validation, output parsing."""

import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.runner.adapters import AdapterError, RunContext
from tools.runner.adapters.httpx import HttpxAdapter, HttpxParams
from tools.runner.adapters.nuclei import NucleiAdapter, NucleiParams

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
PROXY = "http://task.7.nuclei:tok@127.0.0.1:8081"


@pytest.fixture
def ctx(tmp_path: Path) -> RunContext:
    work = tmp_path / "work"
    work.mkdir()
    return RunContext(
        proxy_url=PROXY,
        workdir=work,
        bin_dir=Path("/opt/tools/bin"),
        template_dir=REPO / "templates" / "nuclei",
    )


def _flag_value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


# httpx --------------------------------------------------------------------------------


def test_httpx_command(ctx: RunContext) -> None:
    params = HttpxParams(
        urls=["http://testapp:8080", "https://testapp:8443/login"],
        headers={"Cookie": "sid=1"},
    )
    argv = HttpxAdapter().command(params, ctx)
    assert argv[0] == "/opt/tools/bin/httpx"
    assert _flag_value(argv, "-proxy") == PROXY
    assert "-fr" in argv and "-json" in argv and "-td" in argv
    assert "-nfs" in argv  # no silent switch from http:// to https:// or back
    assert argv[-2:] == ["-H", "Cookie: sid=1"]
    targets = Path(_flag_value(argv, "-l")).read_text().splitlines()
    assert targets == ["http://testapp:8080", "https://testapp:8443/login"]


@pytest.mark.parametrize(
    "params",
    [
        {"urls": []},
        {"urls": ["ftp://testapp"]},
        {"urls": ["http://testapp/ ;rm -rf /"]},
        {"urls": ["http://testapp"], "headers": {"X-A": "1\r\nInjected: 2"}},
        {"urls": ["http://testapp"], "headers": {"Bad Name": "x"}},
        {"urls": ["http://testapp"], "threads": 500},
        {"urls": ["http://testapp"], "shell": "id"},  # unknown fields are refused
    ],
)
def test_httpx_rejects_bad_params(params: dict) -> None:
    with pytest.raises(ValidationError):
        HttpxParams.model_validate(params)


def test_httpx_parse(ctx: RunContext) -> None:
    shutil.copy(FIXTURES / "httpx_testapp.jsonl", ctx.workdir / "out.jsonl")
    result = HttpxAdapter().parse(ctx, "")
    by_url = {e["url"]: e for e in result["endpoints"]}
    assert by_url["http://127.0.0.1:18080"]["title"] == "RAJDOLL testapp"
    assert by_url["http://127.0.0.1:18080"]["server"] == "rajdoll-testapp/1.0"
    profile = by_url["http://127.0.0.1:18080/profil"]
    assert profile["redirect_chain"] == [302, 200]
    assert profile["final_url"] == "http://127.0.0.1:18080/login"
    assert result["technologies"] == []


def test_httpx_parse_without_output_is_empty(ctx: RunContext) -> None:
    assert HttpxAdapter().parse(ctx, "") == {"endpoints": [], "technologies": []}


# nuclei -------------------------------------------------------------------------------


def test_nuclei_command_defaults(ctx: RunContext) -> None:
    params = NucleiParams(targets=["http://testapp:8080"])
    argv = NucleiAdapter().command(params, ctx)
    assert argv[0] == "/opt/tools/bin/nuclei"
    assert _flag_value(argv, "-proxy") == PROXY
    assert _flag_value(argv, "-t") == str((ctx.template_dir / "rajdoll").resolve())
    assert "-ni" in argv  # out-of-band testing off unless asked for
    assert "-dast" not in argv
    assert "-jsonl" in argv and "-duc" in argv


def test_nuclei_command_options(ctx: RunContext) -> None:
    params = NucleiParams(
        targets=["http://testapp:8080"],
        templates=["rajdoll/exposure"],
        tags=["exposure", "config"],
        severities=["high", "critical"],
        dast=True,
        oob=True,
        headers={"Authorization": "Bearer x"},
    )
    argv = NucleiAdapter().command(params, ctx)
    assert _flag_value(argv, "-tags") == "exposure,config"
    assert _flag_value(argv, "-s") == "high,critical"
    assert "-dast" in argv
    assert "-ni" not in argv
    assert argv[-2:] == ["-H", "Authorization: Bearer x"]


@pytest.mark.parametrize(
    "templates",
    [["../../etc/passwd"], ["/etc"], ["rajdoll/../.."], ["Rajdoll"], ["rajdoll exposure"]],
)
def test_nuclei_rejects_template_paths_outside_the_root(templates: list[str]) -> None:
    with pytest.raises(ValidationError):
        NucleiParams(targets=["http://testapp"], templates=templates)


def test_nuclei_missing_template_is_an_adapter_error(ctx: RunContext) -> None:
    params = NucleiParams(targets=["http://testapp"], templates=["rajdoll/nope"])
    with pytest.raises(AdapterError, match="template not found"):
        NucleiAdapter().command(params, ctx)


def test_nuclei_parse(ctx: RunContext) -> None:
    shutil.copy(FIXTURES / "nuclei_exposed_env.jsonl", ctx.workdir / "out.jsonl")
    (candidate,) = NucleiAdapter().parse(ctx, "")["candidates"]
    assert candidate["template_id"] == "rajdoll-exposed-env-file"
    assert candidate["severity"] == "high"
    assert candidate["cwe_ids"] == ["CWE-538"]
    assert candidate["matched_at"] == "http://127.0.0.1:18080/.env"
    assert candidate["request"].startswith("GET /.env HTTP/1.1")
    assert "DB_PASSWORD" in candidate["response"]
    assert candidate["curl"].startswith("curl ")


def test_custom_templates_are_valid_yaml_with_ids() -> None:
    import yaml

    for path in (REPO / "templates" / "nuclei" / "rajdoll").rglob("*.yaml"):
        data = yaml.safe_load(path.read_text())
        assert data["id"].startswith("rajdoll-"), path
        assert data["info"]["severity"] in {"info", "low", "medium", "high", "critical"}, path
        assert data["info"]["classification"]["cwe-id"], path


def test_official_dast_templates_are_pinned_and_typed() -> None:
    import yaml

    from rajdoll.data import vuln_types

    root = REPO / "templates" / "nuclei" / "dast"
    assert "v10.5.0" in (root / "README.md").read_text()
    assert (root / "LICENSE.md").read_text().startswith("MIT License")
    paths = sorted(root.rglob("*.yaml"))
    assert len(paths) == 9
    for path in paths:
        # The directory names the RAJDOLL vulnerability type a match is reported as.
        assert path.parent.name in vuln_types.CATALOG, path
        text = path.read_text()
        assert "# digest: " in text, path  # unchanged upstream copy, still signed
        data = yaml.safe_load(text)
        assert "dast" in data["info"]["tags"], path
        assert "interactsh" not in text, path  # no out-of-band templates


# katana -------------------------------------------------------------------------------


def test_katana_command(ctx: RunContext) -> None:
    from tools.runner.adapters.katana import KatanaAdapter, KatanaParams

    params = KatanaParams(
        urls=["http://testapp:8080/"],
        exclude=["logout", "delete"],
        headers={"Cookie": "sid=abc"},
    )
    argv = KatanaAdapter().command(params, ctx)
    assert argv[0] == "/opt/tools/bin/katana"
    assert _flag_value(argv, "-proxy") == PROXY
    assert _flag_value(argv, "-d") == "3"
    assert _flag_value(argv, "-kf") == "all"
    assert _flag_value(argv, "-cos") == "(?i)(logout|delete)"
    assert _flag_value(argv, "-H") == "Cookie: sid=abc"
    assert "-jc" in argv and "-fx" in argv
    assert (ctx.workdir / "targets.txt").read_text() == "http://testapp:8080/\n"
    shallow = KatanaAdapter().command(KatanaParams(urls=["http://a/"], depth=2), ctx)
    assert "-kf" not in shallow  # known files need depth 3


@pytest.mark.parametrize(
    "params",
    [
        {"urls": []},
        {"urls": ["http://a/"], "exclude": ["a|b"]},
        {"urls": ["http://a/"], "depth": 9},
    ],
)
def test_katana_rejects_bad_params(params: dict) -> None:
    from tools.runner.adapters.katana import KatanaParams

    with pytest.raises(ValidationError):
        KatanaParams.model_validate(params)


def test_katana_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.katana import KatanaAdapter

    shutil.copy(FIXTURES / "katana_testapp.jsonl", ctx.workdir / "out.jsonl")
    result = KatanaAdapter().parse(ctx, "")
    urls = {e["url"] for e in result["endpoints"]}
    assert "http://testapp:8080/akun/1" in urls
    assert "http://testapp:8080/static/app.js" in urls
    script = next(e for e in result["endpoints"] if e["url"].endswith("app.js"))
    assert (script["tag"], script["source"]) == ("script", "http://testapp:8080/")
    forms = {(f["method"], f["url"]): f for f in result["forms"]}
    assert forms[("POST", "http://testapp:8080/upload")]["enctype"] == "multipart/form-data"
    assert forms[("POST", "http://testapp:8080/login")]["params"] == ["username", "password"]


# ffuf ---------------------------------------------------------------------------------


@pytest.fixture
def wordlist_ctx(ctx: RunContext) -> RunContext:
    from dataclasses import replace

    return replace(ctx, wordlist_dir=REPO / "tools" / "wordlists")


def test_ffuf_directory_command(wordlist_ctx: RunContext) -> None:
    from tools.runner.adapters.ffuf import FfufAdapter, FfufParams

    params = FfufParams(url="http://testapp:8080/app/", extensions=[".bak"], exclude=["admin"])
    argv = FfufAdapter().command(params, wordlist_ctx)
    assert _flag_value(argv, "-u") == "http://testapp:8080/app/FUZZ"
    assert _flag_value(argv, "-x") == PROXY
    assert _flag_value(argv, "-e") == ".bak"
    assert "-ac" in argv
    filtered = Path(_flag_value(argv, "-w")).read_text().split()
    assert ".env" in filtered and not any("admin" in w for w in filtered)


def test_ffuf_parameter_command(wordlist_ctx: RunContext) -> None:
    from tools.runner.adapters.ffuf import FfufAdapter, FfufParams

    params = FfufParams(url="http://testapp:8080/cari?q=a", mode="parameter", wordlist="parameters")
    argv = FfufAdapter().command(params, wordlist_ctx)
    assert _flag_value(argv, "-u") == "http://testapp:8080/cari?q=a&FUZZ=rajdoll1"
    assert _flag_value(argv, "-w").endswith("parameters.txt")


def test_ffuf_bundled_wordlists_never_log_out() -> None:
    words = (REPO / "tools" / "wordlists" / "directories.txt").read_text().split()
    assert "logout" not in words
    assert len(words) == len(set(words))


@pytest.mark.parametrize(
    "params",
    [
        {"url": "http://a/FUZZ"},
        {"url": "http://a/", "extensions": ["php"]},
        {"url": "http://a/", "match_codes": [99]},
        {"url": "http://a/", "wordlist": "../../etc/passwd"},
        {"url": "http://a/", "exclude": ["a b"]},
    ],
)
def test_ffuf_rejects_bad_params(params: dict) -> None:
    from tools.runner.adapters.ffuf import FfufParams

    with pytest.raises(ValidationError):
        FfufParams.model_validate(params)


def test_ffuf_missing_wordlist_is_an_adapter_error(ctx: RunContext) -> None:
    from tools.runner.adapters.ffuf import FfufAdapter, FfufParams

    with pytest.raises(AdapterError):
        FfufAdapter().command(FfufParams(url="http://a/"), ctx)


def test_ffuf_parse_uses_the_url_not_the_reported_input(ctx: RunContext) -> None:
    from tools.runner.adapters.ffuf import FfufAdapter

    shutil.copy(FIXTURES / "ffuf_directories.json", ctx.workdir / "out.json")
    results = FfufAdapter().parse(ctx, "")["results"]
    by_url = {r["url"]: r for r in results}
    # In this real run ffuf reported a calibration string as the input of /admin.
    assert by_url["http://testapp:8080/admin"]["status"] == 403
    assert by_url["http://testapp:8080/.env"]["content_type"].startswith("text/plain")
    assert "param" not in by_url["http://testapp:8080/.env"]

    shutil.copy(FIXTURES / "ffuf_parameters.json", ctx.workdir / "out.json")
    assert [r["param"] for r in FfufAdapter().parse(ctx, "")["results"]] == ["debug"]


# nmap ---------------------------------------------------------------------------------


def test_nmap_command_and_audit_summary(ctx: RunContext) -> None:
    from tools.runner.adapters.nmap import NmapAdapter, NmapParams

    adapter = NmapAdapter()
    params = NmapParams(host="Testapp", ports=[443, 80, 80])
    argv = adapter.command(params, ctx)
    assert argv[:4] == ["/opt/tools/bin/nmap", "-sT", "-Pn", "--unprivileged"]
    assert _flag_value(argv, "-p") == "80,443"
    assert argv[-2:] == ["--", "testapp"]
    assert "-sV" in argv
    assert adapter.targets(params) == ["nmap://testapp"]
    assert adapter.audit_exec is True
    assert adapter.audit_summary(params) == "nmap -sT testapp ports=80,443"
    top = adapter.command(NmapParams(host="10.0.0.5", service_detection=False), ctx)
    assert _flag_value(top, "--top-ports") == "1000" and "-sV" not in top


@pytest.mark.parametrize(
    "params",
    [{"host": "-oN/tmp/x"}, {"host": "a b"}, {"host": "a;b"}, {"host": "a", "ports": [0]}],
)
def test_nmap_rejects_bad_params(params: dict) -> None:
    from tools.runner.adapters.nmap import NmapParams

    with pytest.raises(ValidationError):
        NmapParams.model_validate(params)


def test_nmap_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.nmap import NmapAdapter

    shutil.copy(FIXTURES / "nmap_testapp.xml", ctx.workdir / "out.xml")
    ports = NmapAdapter().parse(ctx, "")["ports"]
    assert [p["port"] for p in ports] == [8080, 8081]
    assert all(p["protocol"] == "tcp" for p in ports)
    assert NmapAdapter().parse(
        ctx.__class__(**{**ctx.__dict__, "workdir": ctx.workdir / "x"}), ""
    ) == {"ports": []}


# browser ------------------------------------------------------------------------------


def test_browser_command_writes_a_private_config(ctx: RunContext) -> None:
    import json
    import stat
    import sys

    from tools.runner.adapters.browser import SCRIPT, BrowserAdapter, BrowserParams

    params = BrowserParams(urls=["http://testapp:8080/"], headers={"Cookie": "sid=abc"})
    argv = BrowserAdapter().command(params, ctx)
    assert argv[:2] == [sys.executable, str(SCRIPT)]
    config_path = Path(argv[2])
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    config = json.loads(config_path.read_text())
    assert config["proxy"] == {
        "server": "http://127.0.0.1:8081",
        "username": "task.7.nuclei",
        "password": "tok",
    }
    assert config["headers"] == {"Cookie": "sid=abc"}
    assert config["out"] == str(ctx.workdir / "out.jsonl")


def test_browser_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.browser import BrowserAdapter

    shutil.copy(FIXTURES / "browser_testapp.jsonl", ctx.workdir / "out.jsonl")
    result = BrowserAdapter().parse(ctx, "")
    requests = {(r["method"], r["url"]): r for r in result["requests"]}
    assert requests[("GET", "http://testapp:8080/api/v1/ringkasan")]["resource_type"] == "fetch"
    assert ("GET", "http://cdn.luar.test/lib.js") in requests
    assert len(result["requests"]) == len(requests)  # duplicates removed
    login = next(p for p in result["pages"] if p["url"] == "http://testapp:8080/profil")
    assert login["final_url"] == "http://testapp:8080/login"
    assert {f["action"] for f in result["forms"]} >= {"http://testapp:8080/kontak"}
    assert all(link["followed"] for link in result["links"])


# xss_check (browser) ------------------------------------------------------------------


def test_xss_check_params_are_strict() -> None:
    from tools.runner.adapters.browser import XssCheckParams

    ok = {"attempts": [{"url": "http://testapp:8080/sapa?nama=x"}], "marker": "RJDLA1B2C3"}
    assert XssCheckParams(**ok).attempts[0].method == "GET"
    for bad in (
        {**ok, "marker": "a b"},
        {**ok, "marker": "abc"},
        {**ok, "attempts": []},
        {**ok, "attempts": [{"url": "file:///etc/passwd"}]},
        {**ok, "attempts": [{"url": "http://testapp:8080/", "method": "PUT"}]},
        {**ok, "attempts": [{"url": "http://testapp:8080/"}] * 11},
        {**ok, "extra": 1},
    ):
        with pytest.raises(ValidationError):
            XssCheckParams(**bad)


def test_xss_check_command_and_targets(ctx: RunContext) -> None:
    import json
    import stat

    from tools.runner.adapters import default_adapters
    from tools.runner.adapters.browser import XssCheckAdapter, XssCheckParams

    assert isinstance(default_adapters()["xss_check"], XssCheckAdapter)
    params = XssCheckParams(
        attempts=[
            {"url": "http://testapp:8080/sapa?nama=x"},
            {"method": "POST", "url": "http://testapp:8080/kontak", "form": {"pesan": "x"}},
        ],
        marker="RJDLA1B2C3",
        headers={"Cookie": "sid=abc"},
    )
    adapter = XssCheckAdapter()
    assert adapter.targets(params) == [
        "http://testapp:8080/sapa?nama=x",
        "http://testapp:8080/kontak",
    ]
    config_path = Path(adapter.command(params, ctx)[2])
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    config = json.loads(config_path.read_text())
    assert config["mode"] == "xss" and config["marker"] == "RJDLA1B2C3"
    assert config["attempts"][1] == {
        "method": "POST",
        "url": "http://testapp:8080/kontak",
        "form": {"pesan": "x"},
    }
    assert config["proxy"]["username"] == "task.7.nuclei"
    assert config["headers"] == {"Cookie": "sid=abc"}


def test_xss_check_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.browser import XssCheckAdapter

    shutil.copy(FIXTURES / "xss_check_testapp.jsonl", ctx.workdir / "out.jsonl")
    result = XssCheckAdapter().parse(ctx, "")
    assert result["executed"] is True
    assert (result["attempt"], result["dialogs"]) == (2, ["RJDLA1B2C3"])
    assert [a["executed"] for a in result["attempts"]] == [False, False, True]
    (ctx.workdir / "out.jsonl").write_text(
        '{"type": "xss", "attempt": 0, "status": null, "dialogs": [], "executed": false,'
        ' "error": "Page.goto: net::ERR_NAME_NOT_RESOLVED at http://x/?q=RJDLA1B2C3"}\n'
    )
    assert XssCheckAdapter().parse(ctx, "")["executed"] is False


# request spec (sqlmap, commix, dalfox) ---------------------------------------------------


def test_request_marking_for_each_location() -> None:
    from tools.runner.adapters.request import RequestSpec, build, injected_value, mark

    spec = RequestSpec(url="http://testapp:8080/cari", query={"q": "a b", "page": "1"})
    marked = mark(spec, "q", "query", "*")
    assert marked.url == "http://testapp:8080/cari?q=a%20b*&page=1"
    assert (marked.prefix, marked.suffix, marked.place) == (
        "http://testapp:8080/cari?q=",
        "&page=1",
        "url",
    )
    payload = "http://testapp:8080/cari?q=a%20b' OR 1=1-- x&page=1"
    assert injected_value(marked.model_dump(), payload) == "a%20b' OR 1=1-- x"
    assert injected_value(marked.model_dump(), "something else") is None

    form = RequestSpec(method="POST", url="http://t.test/p", body={"alamat": "x", "n": "1"})
    marked = mark(form, "alamat", "body", "*")
    assert (marked.url, marked.data) == ("http://t.test/p", "alamat=x*&n=1")
    assert (marked.prefix, marked.suffix, marked.place) == ("alamat=", "&n=1", "data")

    body = RequestSpec(
        method="POST", url="http://t.test/api", body={"q": 'a"b'}, body_encoding="json"
    )
    marked = mark(body, "q", "body", "*")
    assert marked.data == '{"q": "a\\"b*"}'
    assert (marked.prefix, marked.suffix) == ('{"q": "', '"}')
    assert build(body) == ("http://t.test/api", '{"q": "a\\"b"}')


@pytest.mark.parametrize(
    "bad",
    [
        {"url": "http://t.test/a?x=1"},
        {"url": "http://t.test/a*"},
        {"url": "ftp://t.test/a"},
        {"url": "http://t.test/a", "query": {"q": "a\nb"}},
        {"url": "http://t.test/a", "method": "TRACE"},
        {"url": "http://t.test/a", "extra": 1},
    ],
)
def test_request_spec_rejects_bad_input(bad: dict) -> None:
    from tools.runner.adapters.request import RequestSpec

    with pytest.raises(ValidationError):
        RequestSpec(**bad)


# sqlmap -------------------------------------------------------------------------------


def test_sqlmap_command(ctx: RunContext) -> None:
    import json

    from tools.runner.adapters.sqlmap import SqlmapAdapter, SqlmapParams

    params = SqlmapParams(
        request={"method": "POST", "url": "http://testapp:8080/login",
                 "query": {"next": "/"}, "body": {"host": "x", "pw": "y"}},
        parameter="host", location="body", headers={"Cookie": "sid=1", "X-A": "b"},
    )  # fmt: skip
    argv = SqlmapAdapter().command(params, ctx)
    assert argv[0].endswith("/sqlmap")
    assert _flag_value(argv, "-u") == "http://testapp:8080/login?next=%2F"
    assert _flag_value(argv, "--data") == "host=x*&pw=y"  # marker, not -p (Host header clash)
    assert "-p" not in argv
    assert _flag_value(argv, "--method") == "POST"
    assert _flag_value(argv, "--proxy") == "http://127.0.0.1:8081"
    assert _flag_value(argv, "--proxy-cred") == "task.7.nuclei:tok"
    assert _flag_value(argv, "--headers") == "Cookie: sid=1\nX-A: b"
    assert (_flag_value(argv, "--level"), _flag_value(argv, "--risk")) == ("1", "1")
    assert {"--batch", "--smart", "--skip-waf"} <= set(argv)
    for forbidden in ("--dump", "--os-shell", "--file-read", "--sql-query", "--crawl", "--forms"):
        assert forbidden not in argv
    assert json.loads((ctx.workdir / "marked.json").read_text())["prefix"] == "host="


@pytest.mark.parametrize(
    "bad",
    [
        {"risk": 3},
        {"level": 4},
        {"techniques": "BEUSTQ"},
        {"parameter": "missing"},
        {"location": "body"},
        {"request": {"url": "http://t.test/a", "body": {"q": "1*"}, "method": "POST"},
         "location": "body"},
    ],
)  # fmt: skip
def test_sqlmap_params_are_strict(bad: dict) -> None:
    from tools.runner.adapters.sqlmap import SqlmapParams

    base = {"request": {"url": "http://t.test/a", "query": {"q": "1"}}, "parameter": "q"}
    with pytest.raises(ValidationError):
        SqlmapParams(**{**base, **bad})


def test_sqlmap_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.sqlmap import SqlmapAdapter

    (ctx.workdir / "out" / "testapp").mkdir(parents=True)
    shutil.copy(FIXTURES / "sqlmap_testapp.log", ctx.workdir / "out" / "testapp" / "log")
    shutil.copy(FIXTURES / "sqlmap_testapp_marked.json", ctx.workdir / "marked.json")
    points = SqlmapAdapter().parse(ctx, "")["candidates"]
    assert [p["technique"] for p in points] == [
        "boolean-based blind",
        "error-based",
        "time-based blind",
    ]
    assert all(p["dbms"] == "SQLite" and p["place"] == "#1* (URI)" for p in points)
    assert points[0]["value"].startswith("rajdoll' AND CASE WHEN")
    assert "http://" not in points[0]["value"]
    (ctx.workdir / "out" / "testapp" / "log").unlink()
    assert SqlmapAdapter().parse(ctx, "") == {"candidates": []}


# commix -------------------------------------------------------------------------------


def test_commix_command_and_environment(ctx: RunContext) -> None:
    from tools.runner.adapters.commix import CommixAdapter, CommixParams

    params = CommixParams(
        request={"method": "POST", "url": "http://testapp:8080/alat/ping",
                 "body": {"alamat": "localhost"}},
        parameter="alamat", location="body",
        headers={"Cookie": "sid=1", "Authorization": "Bearer a.b.c"},
    )  # fmt: skip
    adapter = CommixAdapter()
    argv = adapter.command(params, ctx)
    assert _flag_value(argv, "--url") == "http://testapp:8080/alat/ping"
    assert _flag_value(argv, "--data") == "alamat=localhost*"
    assert _flag_value(argv, "--technique") == "ce"
    assert _flag_value(argv, "--answers") == "pseudo-terminal=N,non-custom=N"
    # commix splits --headers on a literal backslash-n, not on a newline.
    assert _flag_value(argv, "--headers") == "Cookie: sid=1\\nAuthorization: Bearer a.b.c"
    assert "--proxy" not in argv  # commix's own proxy option leaks its first request
    assert {"--batch", "--ignore-stdin"} <= set(argv)
    assert adapter.environment(params, ctx) == {
        "http_proxy": PROXY,
        "https_proxy": PROXY,
        "no_proxy": "",
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"techniques": "f"},
        {"techniques": "cf"},
        {"request": {"url": "http://127.0.0.1:8080/a", "query": {"q": "1"}}},
        {"request": {"url": "http://localhost/a", "query": {"q": "1"}}},
        {"headers": {"Cookie": "a=1\\nX-Injected: 1"}},
    ],
)
def test_commix_params_are_strict(bad: dict) -> None:
    from tools.runner.adapters.commix import CommixParams

    base = {"request": {"url": "http://t.test/a", "query": {"q": "1"}}, "parameter": "q"}
    with pytest.raises(ValidationError):
        CommixParams(**{**base, **bad})


def test_commix_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.commix import CommixAdapter

    (ctx.workdir / "out" / "testapp_8080").mkdir(parents=True)
    shutil.copy(
        FIXTURES / "commix_testapp_logs.txt", ctx.workdir / "out" / "testapp_8080" / "logs.txt"
    )
    shutil.copy(FIXTURES / "commix_testapp_marked.json", ctx.workdir / "marked.json")
    (point,) = CommixAdapter().parse(ctx, "")["candidates"]
    assert point["place"] == "(POST) alamat"
    assert point["technique"] == "Classic Command Injection Technique"
    assert point["value"].startswith("localhost;echo ") and "$((94+66))" in point["value"]


# dalfox -------------------------------------------------------------------------------


def test_dalfox_command(ctx: RunContext) -> None:
    from tools.runner.adapters.dalfox import DalfoxAdapter, DalfoxParams

    params = DalfoxParams(
        request={"method": "POST", "url": "http://testapp:8080/kontak",
                 "body": {"nama": "a", "pesan": "b"}},
        parameters=["nama", "pesan"], location="body", headers={"Cookie": "sid=1"},
    )  # fmt: skip
    argv = DalfoxAdapter().command(params, ctx)
    assert argv[1:3] == ["url", "http://testapp:8080/kontak"]
    assert _flag_value(argv, "-d") == "nama=a&pesan=b"
    assert _flag_value(argv, "-X") == "POST"
    assert _flag_value(argv, "--proxy") == PROXY
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "-p"] == ["nama", "pesan"]
    assert {"--skip-bav", "--skip-mining-all", "--skip-headless", "--skip-discovery"} <= set(argv)
    for forbidden in ("--found-action", "--remote-payloads", "--remote-wordlists"):
        assert forbidden not in argv
    with pytest.raises(ValidationError):
        DalfoxParams(
            request={"method": "POST", "url": "http://t.test/a", "body": {"q": "1"},
                     "body_encoding": "json"},
            parameters=["q"], location="body",
        )  # fmt: skip


def test_dalfox_parse(ctx: RunContext) -> None:
    from tools.runner.adapters.dalfox import DalfoxAdapter

    shutil.copy(FIXTURES / "dalfox_testapp.jsonl", ctx.workdir / "out.jsonl")
    (candidate,) = DalfoxAdapter().parse(ctx, "")["candidates"]
    assert (candidate["type"], candidate["parameter"]) == ("V", "nama")
    assert candidate["value"] == "rajdoll" + candidate["payload"]
    assert candidate["request"].startswith("GET /sapa?nama=")


# nuclei DAST --------------------------------------------------------------------------


def test_nuclei_dast_with_requests(ctx: RunContext) -> None:
    import json

    params = NucleiParams(
        requests=[
            {"url": "http://testapp:8080/katalog", "query": {"nama": "rajdoll"}},
            {"method": "POST", "url": "http://testapp:8080/alat/ping",
             "body": {"alamat": "localhost"}},
        ],
        templates=["dast"], dast=True,
    )  # fmt: skip
    adapter = NucleiAdapter()
    assert adapter.targets(params) == [
        "http://testapp:8080/katalog",
        "http://testapp:8080/alat/ping",
    ]
    argv = adapter.command(params, ctx)
    assert _flag_value(argv, "-im") == "jsonl"
    assert _flag_value(argv, "-fuzz-param-frequency") == "1000000"
    rows = [json.loads(line) for line in (ctx.workdir / "requests.jsonl").read_text().splitlines()]
    assert rows[0] == {
        "url": "http://testapp:8080/katalog?nama=rajdoll",
        "request": {"raw": "GET /katalog?nama=rajdoll HTTP/1.1\r\nHost: testapp:8080\r\n\r\n"},
    }
    assert rows[1]["request"]["raw"].endswith(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 16\r\n\r\n"
        "alamat=localhost"
    )
    with pytest.raises(ValidationError):
        NucleiParams(templates=["dast"])  # neither targets nor requests
    with pytest.raises(ValidationError):
        NucleiParams(targets=["http://a.test/"], requests=[{"url": "http://a.test/"}])


def test_nuclei_dast_parse(tmp_path: Path) -> None:
    ctx = RunContext(
        proxy_url=PROXY, workdir=tmp_path, bin_dir=Path("/opt/tools/bin"),
        template_dir=Path("/opt/rajdoll-templates"),
    )  # fmt: skip
    shutil.copy(FIXTURES / "nuclei_dast_testapp.jsonl", tmp_path / "out.jsonl")
    found = {c["template_id"]: c for c in NucleiAdapter().parse(ctx, "")["candidates"]}
    assert set(found) == {"reflected-xss", "sqli-error-based", "reflection-ssti"}
    sqli = found["sqli-error-based"]
    assert sqli["template_path"] == "dast/sqli/sqli-error-based.yaml"
    assert (sqli["fuzzing_parameter"], sqli["fuzzing_position"]) == ("nama", "query")
    assert "Cookie: ***" in sqli["request"]  # nuclei masks the session itself
    assert found["reflection-ssti"]["fuzzing_parameter"] is None  # derived by the module
