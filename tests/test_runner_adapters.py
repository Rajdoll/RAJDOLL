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

    for path in (REPO / "templates" / "nuclei").rglob("*.yaml"):
        data = yaml.safe_load(path.read_text())
        assert data["id"].startswith("rajdoll-"), path
        assert data["info"]["severity"] in {"info", "low", "medium", "high", "critical"}, path
        assert data["info"]["classification"]["cwe-id"], path


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
