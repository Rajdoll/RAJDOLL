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
