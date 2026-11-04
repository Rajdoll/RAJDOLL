"""Input Validation with the tools (sqlmap, commix, dalfox, nuclei DAST) and the second-run
validators, with a stand-in runner that returns the adapters' parse of real-run fixtures.
"""

import shutil
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.modules import httpkit
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, Verdict
from rajdoll.modules.input_validation import InputValidation
from rajdoll.validators import base as validator_base
from rajdoll.validators import tools as tool_validators
from tests.test_injection_checks import _testapp
from tools.runner.adapters import default_adapters
from tools.runner.adapters.base import RunContext

FIXTURES = Path(__file__).parent / "fixtures"
APP = _testapp().app
T = "http://testapp:8080"


def _parsed(tool: str, files: dict[str, str], tmp: Path) -> dict[str, Any]:
    """The adapter's normalized output for a fixture of a real run."""
    for name, target in files.items():
        (tmp / target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / name, tmp / target)
    ctx = RunContext(
        proxy_url="http://x:y@127.0.0.1:8081",
        workdir=tmp,
        bin_dir=Path("/opt/tools/bin"),
        template_dir=Path("/opt/rajdoll-templates"),
    )
    return default_adapters()[tool].parse(ctx, "")


@pytest.fixture
def outputs(tmp_path: Path) -> dict[str, dict[str, Any]]:
    out = {}
    for tool, files in {
        "sqlmap": {"sqlmap_testapp.log": "out/testapp/log",
                   "sqlmap_testapp_marked.json": "marked.json"},
        "commix": {"commix_testapp_logs.txt": "out/testapp_8080/logs.txt",
                   "commix_testapp_marked.json": "marked.json"},
        "dalfox": {"dalfox_testapp.jsonl": "out.jsonl"},
        "nuclei": {"nuclei_dast_testapp.jsonl": "out.jsonl"},
    }.items():  # fmt: skip
        work = tmp_path / tool
        work.mkdir()
        out[tool] = {"status": "completed", "normalized": _parsed(tool, files, work)}
    return out


def _endpoint(method: str, path: str, query: list[str], body: list[dict] | None = None) -> dict:
    return {
        "id": 1,
        "method": method,
        "url": T + path,
        "query_params": query,
        "body_params": body or [],
        "content_type": None,
        "modules": ["input_validation"],
    }


class Runner:
    """Records run_tool calls; answers with a fixed result per tool (or per parameter)."""

    def __init__(self, results: dict[str, Any]) -> None:
        self.results = results
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, tool: str, params: dict, timeout_s: int) -> dict:
        self.calls.append((tool, params))
        result = self.results.get((tool, params.get("parameter"))) or self.results.get(tool)
        return result or {"status": "completed", "normalized": {"candidates": []}}


def _ctx(target: Any, engine: str, runner: Runner, **hooks: Any) -> TaskContext:
    reported: list[Candidate] = hooks.pop("reported", [])
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url=T + "/",
        scope=["testapp"],
        settings={},
        engine=engine,
        target=target,
        params={},
        cancel_event=threading.Event(),
        run_tool=runner,
        log=hooks.pop("log", lambda _m: None),
        http=lambda _p: TestClient(APP, base_url=T, raise_server_exceptions=False),
        session_headers=lambda _l=None: {"Cookie": "sid=rahasia"},
        report_candidate=lambda c: reported.append(c) or 1,
        **hooks,
    )


def test_plan_adds_tool_tasks_and_nuclei_batches() -> None:
    endpoints = [
        _endpoint("GET", "/katalog", ["nama"]),
        _endpoint("POST", "/upload", [], [{"name": "berkas", "location": "multipart"},
                                          {"name": "judul", "location": "multipart"}]),
    ] + [_endpoint("GET", f"/e{i}", ["q"]) for i in range(60)]  # fmt: skip
    plan = InputValidation().plan(PlanContext(1, 1, "", [], {}, ScanStage.TESTING, endpoints))
    engines = [spec.engine for spec in plan]
    assert engines[:4] == ["custom:inpv", "sqlmap", "commix", "dalfox"]
    assert engines[4] == "custom:inpv"  # multipart only: the tools cannot address it
    assert engines.count("sqlmap") == 61
    batches = [spec.target["endpoints"] for spec in plan if spec.engine == "nuclei:dast"]
    assert [len(b) for b in batches] == [50, 11]


def test_sqlmap_task_reports_sqli_with_resent_evidence(outputs: dict) -> None:
    reported: list[Candidate] = []
    runner = Runner({"sqlmap": outputs["sqlmap"]})
    endpoint = _endpoint("GET", "/katalog", ["nama"])
    summary = InputValidation().run(_ctx(endpoint, "sqlmap", runner, reported=reported))
    assert summary == {"candidates": ["sqli:nama"]}
    ((tool, params),) = runner.calls
    assert params == {
        "request": {"method": "GET", "url": T + "/katalog", "query": {"nama": "rajdoll"}},
        "parameter": "nama", "location": "query", "headers": {"Cookie": "sid=rahasia"},
    }  # fmt: skip
    (candidate,) = reported
    assert candidate.poc["validator_params"]["source"] == "sqlmap"
    assert candidate.poc["validator_params"]["techniques"] == "BET"
    assert candidate.poc["query"]["nama"].startswith("rajdoll' AND CASE WHEN")
    assert len(candidate.evidence) == 3  # the three payloads, re-sent through our client
    assert [e.note for e in candidate.evidence][0] == "payload sqlmap (boolean-based blind)"
    assert "[sesi akun]" in candidate.evidence[0].request
    assert "DBMS SQLite" in candidate.note


def test_commix_task_reports_cmdi_and_skips_loopback(outputs: dict) -> None:
    reported: list[Candidate] = []
    runner = Runner({"commix": outputs["commix"]})
    endpoint = _endpoint("POST", "/alat/ping", [], [{"name": "alamat", "location": "form"}])
    InputValidation().run(_ctx(endpoint, "commix", runner, reported=reported))
    (candidate,) = reported
    assert candidate.vuln_type == "cmdi" and candidate.parameter == "alamat"
    assert candidate.poc["body"]["alamat"].startswith("localhost;echo ")
    assert "PING localhost" in (candidate.evidence[0].response or "")
    assert runner.calls[0][1]["location"] == "body"

    logs: list[str] = []
    loopback = {**endpoint, "url": "http://127.0.0.1:8080/alat/ping"}
    runner = Runner({})
    assert InputValidation().run(_ctx(loopback, "commix", runner, log=logs.append)) == {
        "candidates": []
    }
    assert runner.calls == [] and "loopback" in logs[0]


def test_dalfox_task_reports_xss(outputs: dict) -> None:
    reported: list[Candidate] = []
    runner = Runner({"dalfox": outputs["dalfox"]})
    endpoint = _endpoint("GET", "/sapa", ["nama"])
    InputValidation().run(_ctx(endpoint, "dalfox", runner, reported=reported))
    (candidate,) = reported
    assert candidate.vuln_type == "xss_reflected"
    assert candidate.poc["query"]["nama"].startswith("rajdoll")
    assert candidate.poc["validator_params"]["source"] == "dalfox"
    assert runner.calls[0][1]["parameters"] == ["nama"]


def test_nuclei_dast_maps_matches_to_parameters(outputs: dict) -> None:
    reported: list[Candidate] = []
    runner = Runner({"nuclei": outputs["nuclei"]})
    endpoints = [
        _endpoint("GET", "/katalog", ["nama"]),
        _endpoint("GET", "/sapa", ["nama"]),
        _endpoint("GET", "/pratinjau", ["templat"]),
    ]
    summary = InputValidation().run(
        _ctx({"endpoints": endpoints}, "nuclei:dast", runner, reported=reported)
    )
    assert sorted(summary["candidates"]) == ["sqli:nama", "ssti:templat", "xss_reflected:nama"]
    ((tool, params),) = runner.calls
    assert params["templates"] == ["dast"] and params["dast"] is True
    assert [r["url"] for r in params["requests"]] == [e["url"] for e in endpoints]
    by_type = {c.vuln_type: c for c in reported}
    ssti = by_type["ssti"]  # nuclei omits the parameter name here; it is derived from the URL
    assert ssti.parameter == "templat" and "{{" in ssti.poc["query"]["templat"]
    assert ssti.poc["validator_params"]["template"] == "dast/ssti/reflection-ssti.yaml"
    sqli = by_type["sqli"]
    assert sqli.poc["query"]["nama"] == "rajdoll'"
    assert sqli.evidence[0].status == 500 and "Cookie: [sesi akun]" in sqli.evidence[0].request


def test_mask_raw_masks_session_headers() -> None:
    raw = "GET / HTTP/1.1\r\nHost: a\r\nCookie: sid=1\r\nX-Api-Key: k\r\n\r\nCookie: body"
    assert httpkit.mask_raw(raw) == (
        "GET / HTTP/1.1\r\nHost: a\r\nCookie: [sesi akun]\r\nX-Api-Key: [sesi akun]\r\n\r\n"
        "Cookie: body"
    )
    response = "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; HttpOnly\n\nok"
    assert httpkit.mask_raw(response) == "HTTP/1.1 200 OK\nSet-Cookie: sid=[sesi akun]\n\nok"


def _finding(vuln_type: str, source: str, point: httpkit.Injection, **params: Any) -> dict:
    poc = point.poc("payload", vuln_type, base="rajdoll", source=source, **params)
    return {"id": 9, "vuln_type": vuln_type, "poc": poc, "base_url": T}


def test_second_runs_confirm_with_the_tool_that_found_it(outputs: dict) -> None:
    katalog = httpkit.Injection("GET", T + "/katalog", "nama", "query", {"nama": "x"})
    runner = Runner({"sqlmap": outputs["sqlmap"]})
    finding = _finding("sqli", "sqlmap", katalog, techniques="T")
    verdict = tool_validators.rerun(_ctx({}, "validator:sqli", runner), finding)
    assert verdict is not None and verdict.confirmed
    ((tool, params),) = runner.calls
    assert params["techniques"] == "T" and params["smart"] is False
    assert params["request"]["query"] == {"nama": "rajdoll"}  # starts from the normal value
    assert verdict.evidence[0].note == "ulangan sqlmap (boolean-based blind)"

    empty = Runner({})
    assert not tool_validators.rerun(_ctx({}, "v", empty), finding).confirmed

    ping = httpkit.Injection(
        "POST", T + "/alat/ping", "alamat", "form", {}, {"alamat": "x"}, "form"
    )
    verdict = tool_validators.rerun(
        _ctx({}, "v", Runner({"commix": outputs["commix"]})), _finding("cmdi", "commix", ping)
    )
    assert verdict is not None and verdict.confirmed


def test_nuclei_second_run_needs_the_same_parameter(outputs: dict) -> None:
    pratinjau = httpkit.Injection("GET", T + "/pratinjau", "templat", "query", {"templat": "x"})
    finding = _finding("ssti", "nuclei", pratinjau, template="dast/ssti/reflection-ssti.yaml")
    runner = Runner({"nuclei": outputs["nuclei"]})
    verdict = tool_validators.rerun(_ctx({}, "v", runner), finding)
    assert verdict is not None and verdict.confirmed
    assert runner.calls[0][1]["templates"] == ["dast/ssti/reflection-ssti.yaml"]
    other = httpkit.Injection("GET", T + "/pratinjau", "lain", "query", {"lain": "x"})
    verdict = tool_validators.rerun(
        _ctx({}, "v", runner),
        _finding("ssti", "nuclei", other, template="dast/ssti/reflection-ssti.yaml"),
    )
    assert verdict is not None and not verdict.confirmed
    # A reflection-only template never confirms XSS; Chromium must.
    sapa = httpkit.Injection("GET", T + "/sapa", "nama", "query", {"nama": "x"})
    xss = _finding(
        "xss_reflected", "nuclei", sapa, template="dast/xss_reflected/reflected-xss.yaml"
    )
    assert tool_validators.rerun(_ctx({}, "v", runner), xss) is None


def test_validate_chains_own_validator_then_second_run(
    outputs: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    validator_base._load()
    katalog = httpkit.Injection("GET", T + "/katalog", "nama", "query", {"nama": "x"})
    finding = _finding("sqli", "sqlmap", katalog, techniques="T")
    no = Verdict(False, (), "Bukti tidak berulang.")
    monkeypatch.setitem(validator_base.VALIDATORS, "sqli", lambda _c, _f: no)
    verdict = validator_base.validate(_ctx({}, "v", Runner({"sqlmap": outputs["sqlmap"]})), finding)
    assert verdict is not None and verdict.confirmed
    assert verdict.note.startswith("sqlmap mengonfirmasi ulang")

    yes = Verdict(True, (), "sendiri")
    monkeypatch.setitem(validator_base.VALIDATORS, "sqli", lambda _c, _f: yes)
    runner = Runner({"sqlmap": outputs["sqlmap"]})
    assert validator_base.validate(_ctx({}, "v", runner), finding).note == "sendiri"
    assert runner.calls == []  # no second run once confirmed

    unknown = {**_finding("lfi", "manual", katalog), "vuln_type": "lfi"}
    assert validator_base.validate(_ctx({}, "v", Runner({})), unknown) is None
