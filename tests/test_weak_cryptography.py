"""Weak Cryptography (IPD F8b): the sslyze adapter on a real report (through the egress proxy's
passthrough tunnel), how TLS results become findings, and credentials over plain HTTP.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, Response
from fastapi.testclient import TestClient
from pydantic import ValidationError

from rajdoll.core.enums import ScanStage
from rajdoll.modules import weak_cryptography
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TransientTaskError
from rajdoll.modules.weak_cryptography import WeakCryptography
from rajdoll.validators import crypto  # noqa: F401  (registers the validators)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp
from tools.runner.adapters.base import RunContext
from tools.runner.adapters.sslyze import SslyzeAdapter, SslyzeParams, normalize

FIXTURE = Path(__file__).parent / "fixtures" / "sslyze_testapp.json"
BASE = "http://testserver"
TESTAPP = _testapp()
PROXY = "http://task.1.sslyze:tok@127.0.0.1:8081"


def _report() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text())


def _normalized() -> dict[str, Any]:
    return normalize(_report(), "127.0.0.1")


# -- adapter ----------------------------------------------------------------------------------


def test_sslyze_command_tunnels_through_the_proxy(tmp_path: Path) -> None:
    ctx = RunContext(PROXY, tmp_path, Path("/opt/tools/bin"), tmp_path)
    params = SslyzeParams(host="app.instansi.test", port=8443)
    argv = SslyzeAdapter().command(params, ctx)
    assert argv[0] == "/opt/tools/bin/sslyze"
    assert argv[argv.index("--https_tunnel") + 1] == PROXY + "/"
    assert argv[argv.index("--mozilla_config") + 1] == "disable"
    assert {"--certinfo", "--tlsv1", "--tlsv1_1", "--heartbleed", "--robot"} <= set(argv)
    assert argv[-1] == "app.instansi.test:8443"
    assert SslyzeAdapter().targets(params) == ["https://app.instansi.test:8443/"]


@pytest.mark.parametrize("host", ["a b", "-x.test", "x.test;id", "", "x" * 300])
def test_sslyze_params_are_strict(host: str) -> None:
    with pytest.raises(ValidationError):
        SslyzeParams(host=host)
    with pytest.raises(ValidationError):
        SslyzeParams(host="app.test", port=70000)
    with pytest.raises(ValidationError):
        SslyzeParams(host="app.test", extra=1)  # type: ignore[call-arg]
    assert SslyzeParams(host="10.0.0.5").host == "10.0.0.5"


def test_sslyze_parse_of_a_real_run_through_the_proxy(tmp_path: Path) -> None:
    (tmp_path / "out.json").write_text(FIXTURE.read_text())
    ctx = RunContext(PROXY, tmp_path, tmp_path, tmp_path)
    result = SslyzeAdapter().parse(ctx, "")
    assert result["connected"] is True
    assert result["legacy_protocols"] == ["TLS 1.0", "TLS 1.1"]
    assert set(result["protocols"]) == {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
    assert result["weak_ciphers"] == []
    certificate = result["certificate"]
    assert (certificate["subject"], certificate["trusted"], certificate["self_signed"]) == (
        "CN=testapp", False, True,
    )  # fmt: skip
    assert certificate["hostname_matches"] is True and certificate["expired"] is False
    assert not any(result["vulnerabilities"].values())
    # The proxy password never reaches the fixture or the normalized result.
    assert "basic_auth_password" not in json.dumps(result)


def test_sslyze_parse_without_a_connection(tmp_path: Path) -> None:
    trace = "Traceback ...\nConnectionToServerFailed: refused"
    server = {"scan_status": "ERROR_NO_CONNECTIVITY", "connectivity_error_trace": trace}
    report = {"server_scan_results": [server]}
    assert normalize(report, "x") == {
        "connected": False,
        "error": "ConnectionToServerFailed: refused",
    }
    ctx = RunContext(PROXY, tmp_path, tmp_path, tmp_path)
    assert SslyzeAdapter().parse(ctx, "") == {"connected": False, "error": "no report"}


def test_tls_issues_mapping() -> None:
    assert weak_cryptography.tls_issues(_normalized()) == {
        "weak_tls_protocol": ["TLS 1.0", "TLS 1.1"],
        "certificate_problem": ["self-signed"],
    }
    bad = {
        "weak_ciphers": ["TLS_RSA_WITH_RC4_128_SHA"],
        "certificate": {"trusted": True, "expired": True, "hostname_matches": False,
                        "sha1_signature": True, "key_algorithm": "RSAPublicKey", "key_size": 1024},
        "vulnerabilities": {"heartbleed": True, "robot": False},
    }  # fmt: skip
    assert weak_cryptography.tls_issues(bad) == {
        "weak_cipher": ["TLS_RSA_WITH_RC4_128_SHA"],
        "certificate_problem": [
            "kedaluwarsa", "nama host tidak cocok", "tanda tangan SHA-1", "kunci RSA 1024 bit",
        ],
        "tls_vulnerability": ["heartbleed"],
    }  # fmt: skip
    good = {"protocols": {"TLS 1.2": ["x"]}, "certificate": {"trusted": True}}
    assert weak_cryptography.tls_issues(good) == {}


# -- module -----------------------------------------------------------------------------------


def _ctx(app: FastAPI | None, engine: str, target: dict, **hooks: Any) -> TaskContext:
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url=BASE + "/",
        scope=["testserver"],
        settings={},
        engine=engine,
        target=target,
        params={},
        cancel_event=threading.Event(),
        run_tool=hooks.pop("run_tool", lambda *_a, **_k: {"status": "completed"}),
        log=hooks.pop("log", lambda _m: None),
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        **hooks,
    )


def _endpoint(number: int, method: str, url: str, body: list[dict] | None = None) -> dict:
    return {"id": number, "method": method, "url": url, "path_template": url.split("/", 3)[-1],
            "body_params": body or [], "query_params": [], "excluded": False}  # fmt: skip


FORM = [{"name": "username", "location": "form"}, {"name": "password", "location": "form"}]
JSON_BODY = [{"name": "username", "location": "json"}, {"name": "password", "location": "json"}]


def test_plan_scans_each_https_origin_and_http_logins() -> None:
    endpoints = [
        _endpoint(1, "GET", "https://app.test:8443/"),
        _endpoint(2, "GET", "https://app.test:8443/profil"),
        _endpoint(3, "GET", "https://api.app.test/v1"),
        _endpoint(4, "POST", "http://app.test/login", FORM),
        _endpoint(5, "POST", "https://app.test:8443/masuk", FORM),
    ]
    ctx = PlanContext(1, 1, "http://app.test/", [], {}, ScanStage.TESTING, endpoints=endpoints)
    specs = WeakCryptography().plan(ctx)
    assert [(s.engine, s.target.get("host"), s.target.get("port")) for s in specs] == [
        ("sslyze", "app.test", 8443),
        ("sslyze", "api.app.test", 443),
        ("custom:cleartext", None, None),
    ]
    assert [e["url"] for e in specs[-1].target["endpoints"]] == ["http://app.test/login"]


def _sslyze_tool(result: dict[str, Any], calls: list | None = None) -> Any:
    def run_tool(tool: str, params: dict, timeout_s: int) -> dict:
        if calls is not None:
            calls.append((tool, params))
        return {"status": "completed", "normalized": result}

    return run_tool


def test_tls_results_become_candidates_and_validators_repeat_the_scan() -> None:
    reported: list[Candidate] = []
    calls: list = []
    target = {"host": "127.0.0.1", "port": 8443, "origin": "https://127.0.0.1:8443"}
    ctx = _ctx(None, "sslyze", target, run_tool=_sslyze_tool(_normalized(), calls),
               report_candidate=lambda c: reported.append(c) or 1)  # fmt: skip
    assert WeakCryptography().run(ctx)["candidates"] == ["weak_tls_protocol", "certificate_problem"]
    assert calls == [("sslyze", {"host": "127.0.0.1", "port": 8443})]
    protocol, certificate = reported
    assert protocol.url == "https://127.0.0.1:8443/"
    assert protocol.poc["validator_params"]["details"] == ["TLS 1.0", "TLS 1.1"]
    assert "TLS diteruskan tanpa didekripsi" in protocol.evidence[0].request
    assert '"self_signed": true' in certificate.evidence[0].response

    for candidate in reported:
        finding = {"id": 1, "vuln_type": candidate.vuln_type, "poc": candidate.poc}
        same = _ctx(None, "v", {}, run_tool=_sslyze_tool(_normalized()))
        assert VALIDATORS[candidate.vuln_type](same, finding).confirmed
        fixed = {"connected": True, "protocols": {"TLS 1.2": ["x"]},
                 "certificate": {"trusted": True, "hostname_matches": True}}  # fmt: skip
        verdict = VALIDATORS[candidate.vuln_type](
            _ctx(None, "v", {}, run_tool=_sslyze_tool(fixed)), finding
        )
        assert not verdict.confirmed and "cek manual" in verdict.note


def test_tls_scan_failures() -> None:
    logs: list[str] = []
    target = {"host": "x.test", "port": 443, "origin": "https://x.test"}
    down = _sslyze_tool({"connected": False, "error": "refused"})
    assert WeakCryptography().run(_ctx(None, "sslyze", target, run_tool=down, log=logs.append)) == {
        "connected": False
    }
    assert "refused" in logs[-1]
    with pytest.raises(TransientTaskError):
        WeakCryptography().run(
            _ctx(None, "sslyze", target, run_tool=lambda *_a, **_k: {"status": "timeout"})
        )


def _https_only() -> FastAPI:
    app = FastAPI()

    @app.post("/login")
    def login() -> Response:
        return RedirectResponse("https://testserver/login", status_code=308)

    return app


def test_testapp_logins_over_http_and_the_validator() -> None:
    endpoints = [
        _endpoint(1, "POST", BASE + "/login", FORM),
        _endpoint(2, "POST", BASE + "/api/v1/token", JSON_BODY),
    ]
    reported: list[Candidate] = []
    ctx = _ctx(TESTAPP.app, "custom:cleartext", {"endpoints": endpoints},
               report_candidate=lambda c: reported.append(c) or 1)  # fmt: skip
    assert WeakCryptography().run(ctx) == {"candidates": ["/login", "/api/v1/token"]}
    assert [c.vuln_type for c in reported] == ["cleartext_credentials"] * 2
    assert "rajdoll-uji-" in reported[0].evidence[0].request
    for candidate in reported:
        finding = {"id": 2, "vuln_type": candidate.vuln_type, "poc": candidate.poc,
                   "base_url": BASE}  # fmt: skip
        assert VALIDATORS["cleartext_credentials"](_ctx(TESTAPP.app, "v", {}), finding).confirmed
    login = {"id": 2, "vuln_type": "cleartext_credentials", "poc": reported[0].poc,
             "base_url": BASE}  # fmt: skip
    assert not VALIDATORS["cleartext_credentials"](_ctx(_https_only(), "v", {}), login).confirmed
    upgraded = _ctx(
        _https_only(),
        "custom:cleartext",
        {"endpoints": endpoints[:1]},
        report_candidate=lambda c: pytest.fail("redirected logins are fine"),
    )
    assert WeakCryptography().run(upgraded) == {"candidates": []}
