"""Input Validation module and validators with a stand-in task context (IPD F6; TRD 6.3).

The target is testapp in-process (TestClient); the end-to-end run through the egress proxy and
the real runner is tests/test_recon_e2e.py.
"""

import json
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, Verdict
from rajdoll.modules.httpkit import Injection
from rajdoll.modules.input_validation import InputValidation
from rajdoll.validators import injection  # noqa: F401  (registers the validators)
from rajdoll.validators.base import VALIDATORS, ValidationModule, base_url
from tests.test_injection_checks import _ssrf_app, _testapp

FIXTURES = Path(__file__).parent / "fixtures"
APP = _testapp().app


def _ctx(target: dict[str, Any] | None = None, **hooks: Any) -> TaskContext:
    hooks.setdefault("http", lambda _purpose: TestClient(APP, raise_server_exceptions=False))
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url="http://testserver/",
        scope=["testserver"],
        settings={},
        engine="custom:inpv",
        target=target or {},
        params={},
        cancel_event=threading.Event(),
        run_tool=hooks.pop("run_tool", lambda *_a, **_k: {"status": "completed"}),
        log=hooks.pop("log", lambda _message: None),
        **hooks,
    )


def _finding(vuln_type: str, method: str, path: str, parameter: str, location: str) -> dict:
    defaults = {parameter: "rajdoll"}
    if location == "query":
        point = Injection(method, "http://testserver" + path, parameter, location, defaults)
    else:
        point = Injection(
            method, "http://testserver" + path, parameter, location, {}, defaults, location
        )
    poc = point.poc("rajdoll", vuln_type, base="rajdoll")
    return {"id": 7, "vuln_type": vuln_type, "parameter": parameter, "poc": poc, "base_url": None}


@pytest.mark.parametrize(
    ("vuln_type", "method", "path", "parameter", "location"),
    [
        ("sqli", "GET", "/katalog", "nama", "query"),
        ("ssti", "GET", "/pratinjau", "templat", "query"),
        ("cmdi", "POST", "/alat/ping", "host", "form"),
    ],
)
def test_validators_confirm_testapp_weaknesses_twice(
    vuln_type: str, method: str, path: str, parameter: str, location: str
) -> None:
    verdict = VALIDATORS[vuln_type](_ctx(), _finding(vuln_type, method, path, parameter, location))
    assert verdict.confirmed, verdict.note
    assert verdict.note.endswith("(terulang 2 kali)")
    assert verdict.evidence


@pytest.mark.parametrize("vuln_type", ["sqli", "ssti", "cmdi"])
def test_validators_do_not_confirm_a_reflection(vuln_type: str) -> None:
    verdict = VALIDATORS[vuln_type](_ctx(), _finding(vuln_type, "GET", "/sapa", "nama", "query"))
    assert not verdict.confirmed
    assert verdict.note == "Bukti tidak berulang; perlu cek manual."


def test_ssrf_validator() -> None:
    def ctx() -> TaskContext:
        context = _ctx(http=lambda _p: httpx.Client(transport=httpx.MockTransport(_ssrf_app)))
        context.target_url = "http://portal.test/"
        return context

    finding = _finding("ssrf", "GET", "/ambil", "url", "query")
    finding["base_url"] = "http://portal.test"
    assert VALIDATORS["ssrf"](ctx(), finding).confirmed
    reflected = _finding("ssrf", "GET", "/login", "next", "query")
    reflected["base_url"] = "http://portal.test"
    assert not VALIDATORS["ssrf"](ctx(), reflected).confirmed


def test_base_url_prefers_the_endpoint_host() -> None:
    ctx = _ctx()
    assert base_url(ctx) == "http://testserver"
    assert base_url(ctx, {"base_url": "https://api.app.test"}) == "https://api.app.test"


def _xss_tool(executed: bool) -> tuple[list[dict], Any]:
    calls: list[dict] = []
    records = [json.loads(line) for line in (FIXTURES / "xss_check_testapp.jsonl").open()]
    if not executed:
        records = [{**r, "executed": False, "dialogs": []} for r in records]

    def run_tool(tool: str, params: dict, timeout_s: int) -> dict:
        calls.append({"tool": tool, "params": params, "timeout_s": timeout_s})
        return {
            "status": "completed",
            "normalized": {"executed": executed, "attempts": records},
        }

    return calls, run_tool


@pytest.mark.parametrize("executed", [True, False])
def test_xss_validator_runs_payloads_in_chromium(executed: bool) -> None:
    calls, run_tool = _xss_tool(executed)
    ctx = _ctx(run_tool=run_tool, session_headers=lambda _l=None: {"Cookie": "sid=x"})
    verdict = VALIDATORS["xss_reflected"](
        ctx, _finding("xss_reflected", "GET", "/sapa", "nama", "query")
    )
    assert verdict.confirmed is executed
    (call,) = calls
    params = call["params"]
    assert call["tool"] == "xss_check" and params["headers"] == {"Cookie": "sid=x"}
    marker = params["marker"]
    assert marker.startswith("RJDL") and len(params["attempts"]) == 4
    first = params["attempts"][0]
    assert first["method"] == "GET" and first["url"].startswith("http://testserver/sapa?nama=")
    assert marker in httpx.URL(first["url"]).params["nama"]
    assert [e.response.startswith("Dialog di Chromium") for e in verdict.evidence] == [True] * 3
    if executed:
        assert marker in verdict.note


def test_xss_validator_posts_forms_and_skips_json() -> None:
    calls, run_tool = _xss_tool(False)
    finding = _finding("xss_reflected", "POST", "/kontak", "pesan", "form")
    VALIDATORS["xss_reflected"](_ctx(run_tool=run_tool), finding)
    attempt = calls[0]["params"]["attempts"][0]
    assert attempt["method"] == "POST" and attempt["url"] == "http://testserver/kontak"
    assert attempt["form"]["pesan"].startswith('rajdoll"><img')

    calls.clear()
    finding = _finding("xss_reflected", "POST", "/api/v1/keranjang", "jumlah", "json")
    verdict = VALIDATORS["xss_reflected"](_ctx(run_tool=run_tool), finding)
    assert not verdict.confirmed and calls == []


def test_xss_validator_reports_a_failed_browser() -> None:
    ctx = _ctx(run_tool=lambda *_a, **_k: {"status": "failed"})
    verdict = VALIDATORS["xss_reflected"](
        ctx, _finding("xss_reflected", "GET", "/sapa", "nama", "query")
    )
    assert not verdict.confirmed and "failed" in verdict.note


def test_validation_module_plans_known_types_in_the_validation_stage() -> None:
    module = ValidationModule()
    findings = [{"id": 1, "vuln_type": "sqli"}, {"id": 2, "vuln_type": "belum_ada"}]
    plan = module.plan(PlanContext(1, 1, "", [], {}, ScanStage.VALIDATION, findings=findings))
    assert [(t.engine, t.target) for t in plan] == [("validator:sqli", {"finding_id": 1})]
    assert module.plan(PlanContext(1, 1, "", [], {}, ScanStage.TESTING, findings=findings)) == []


def test_validation_module_records_the_verdict() -> None:
    recorded: list[tuple[int, Verdict]] = []
    logs: list[str] = []
    finding = _finding("sqli", "GET", "/katalog", "nama", "query")
    ctx = _ctx(
        {"finding_id": 7},
        finding=lambda _id: finding,
        record_verdict=lambda fid, verdict: recorded.append((fid, verdict)),
        log=logs.append,
    )
    summary = ValidationModule().run(ctx)
    assert summary["finding_id"] == 7 and summary["confirmed"] is True
    assert recorded[0][0] == 7 and recorded[0][1].confirmed
    assert logs[0].startswith("sqli #7: terkonfirmasi")
    assert ValidationModule().run(_ctx({"finding_id": 8})) == {
        "skipped": "finding no longer exists"
    }


def _endpoint(method: str, path: str, query: list[str], body: list[dict]) -> dict:
    return {
        "id": 1,
        "method": method,
        "url": "http://testserver" + path,
        "query_params": query,
        "body_params": body,
        "content_type": None,
        "modules": ["input_validation"],
    }


def test_input_validation_plans_one_task_per_endpoint() -> None:
    endpoints = [
        _endpoint("GET", "/katalog", ["nama"], []),
        _endpoint("GET", "/", [], []),  # nothing to inject
        {**_endpoint("GET", "/sapa", ["nama"], []), "modules": ["client_side"]},
    ]
    module = InputValidation()
    ctx = PlanContext(1, 1, "", [], {}, ScanStage.TESTING, endpoints=endpoints)
    (spec,) = module.plan(ctx)
    assert spec.engine == "custom:inpv" and spec.target["url"] == "http://testserver/katalog"
    ctx.stage = ScanStage.RECON
    assert module.plan(ctx) == []


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (_endpoint("GET", "/katalog", ["nama"], []), ["sqli:nama"]),
        (_endpoint("GET", "/sapa", ["nama"], []), ["xss_reflected:nama"]),
        (_endpoint("GET", "/pratinjau", ["templat"], []), ["ssti:templat"]),
        (_endpoint("POST", "/alat/ping", [], [{"name": "host", "location": "form"}]),
         ["cmdi:host"]),
        (_endpoint("GET", "/cari", ["q"], []), []),
        (_endpoint("POST", "/kontak", [], [{"name": "nama", "location": "form"},
                                           {"name": "pesan", "location": "form"}]), []),
    ],
)  # fmt: skip
def test_input_validation_reports_candidates(endpoint: dict, expected: list[str]) -> None:
    reported: list[Candidate] = []
    ctx = _ctx(endpoint, report_candidate=lambda c: reported.append(c) or 1)
    summary = InputValidation().run(ctx)
    assert summary == {"candidates": expected}
    for candidate in reported:
        assert candidate.poc["validator_params"]["base"] == "rajdoll"
        assert candidate.poc["validator"] == candidate.vuln_type
        assert candidate.url == "http://testserver" + endpoint["url"][len("http://testserver") :]
        assert candidate.evidence
