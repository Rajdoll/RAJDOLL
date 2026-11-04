"""Session Management (IPD F8a): session cookies without HttpOnly, Secure, or SameSite.

testapp's login page starts the `sid` session cookie without HttpOnly or SameSite.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.modules import session_management
from rajdoll.modules.authz_checks import Fetched
from rajdoll.modules.base import Candidate, Exchange, PlanContext, TaskContext
from rajdoll.modules.session_management import SessionManagement, missing_flags
from rajdoll.services import planning, tagging
from rajdoll.validators import session  # noqa: F401  (registers the validator)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp

BASE = "http://testserver"
TESTAPP = _testapp()


def _ctx(app: FastAPI, target: dict, sessions: dict, **hooks: Any) -> TaskContext:
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url=BASE + "/",
        scope=["testserver"],
        settings={},
        engine="custom:cookies",
        target=target,
        params={},
        cancel_event=threading.Event(),
        run_tool=lambda *_a, **_k: {"status": "completed"},
        log=hooks.pop("log", lambda _m: None),
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        session_headers=lambda label=None: sessions.get(label, {}),
        **hooks,
    )


def _run(app: FastAPI, sessions: dict | None = None) -> list[Candidate]:
    sessions = sessions if sessions is not None else {"Akun A": {"Cookie": "sid=milik-budi"}}
    reported: list[Candidate] = []
    target = {"pages": [BASE + "/", BASE + "/login"], "accounts": list(sessions)}
    ctx = _ctx(app, target, sessions, report_candidate=lambda c: reported.append(c) or 1)
    SessionManagement().run(ctx)
    return reported


def test_plan_fetches_the_root_and_login_pages() -> None:
    rows = []
    for number, (method, path) in enumerate(
        [("GET", "/login"), ("POST", "/login"), ("GET", "/logout"), ("GET", "/akun/{id}")], 1
    ):
        row: dict[str, Any] = {
            "id": number, "method": method, "path_template": path, "url": BASE + path,
            "query_params": [], "body_params": [], "excluded": path == "/logout",
        }  # fmt: skip
        row["tags"] = tagging.rule_tags(row)
        row["modules"] = planning.modules_for(row, ["session"])
        rows.append(row)
    ctx = PlanContext(1, 1, BASE + "/", [], {}, ScanStage.TESTING, endpoints=rows, accounts=["A"])
    (spec,) = SessionManagement().plan(ctx)
    assert spec.target == {"pages": [BASE + "/", BASE + "/login"], "accounts": ["A"]}
    ctx.stage = ScanStage.RECON
    assert SessionManagement().plan(ctx) == []


def test_testapp_login_page_sets_sid_without_flags() -> None:
    (candidate,) = _run(TESTAPP.app)
    assert (candidate.vuln_type, candidate.url, candidate.parameter) == (
        "cookie_flags", BASE + "/login", "sid",
    )  # fmt: skip
    assert candidate.poc["account"] is None
    assert candidate.poc["validator_params"] == {
        "cookie": "sid",
        "missing": ["HttpOnly", "SameSite"],
    }
    (exchange,) = candidate.evidence
    # The evidence keeps the cookie's attributes and masks its value.
    assert "set-cookie: sid=[sesi akun]; Path=/" in exchange.response
    assert "HttpOnly, SameSite" in candidate.note
    finding = {"id": 2, "vuln_type": "cookie_flags", "poc": candidate.poc, "base_url": BASE}
    verdict = VALIDATORS["cookie_flags"](_ctx(TESTAPP.app, {}, {}), finding)
    assert verdict.confirmed and "terulang 2 kali" in verdict.note


def _cookie_app(header: str) -> FastAPI:
    app = FastAPI()

    @app.get("/login")
    def login() -> HTMLResponse:
        response = HTMLResponse("<form></form>")
        response.headers.append("set-cookie", header)
        return response

    app.get("/")(lambda: {"ok": True})
    return app


@pytest.mark.parametrize(
    "header",
    [
        "sid=abc; Path=/; HttpOnly; SameSite=Lax",
        "XSRF-TOKEN=abc; Path=/",  # meant to be read by scripts
        "tema=gelap; Path=/",  # not a session cookie
        "sid=; Path=/; Max-Age=0",  # deletes the cookie
        "sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    ],
)
def test_no_candidate_for_safe_or_irrelevant_cookies(header: str) -> None:
    assert _run(_cookie_app(header)) == []


def test_validator_does_not_confirm_after_a_fix() -> None:
    (candidate,) = _run(TESTAPP.app)
    finding = {"id": 2, "vuln_type": "cookie_flags", "poc": candidate.poc, "base_url": BASE}
    fixed = _cookie_app("sid=abc; Path=/; HttpOnly; SameSite=Strict")
    verdict = VALIDATORS["cookie_flags"](_ctx(fixed, {}, {}), finding)
    assert not verdict.confirmed and "cek manual" in verdict.note


def test_missing_flags() -> None:
    assert missing_flags("sid=1; HttpOnly; SameSite=Lax", https=False) == ()
    assert missing_flags("sid=1; HttpOnly; SameSite=Lax", https=True) == ("Secure",)
    assert missing_flags("sid=1; Secure; HttpOnly; SameSite=None", https=True) == ()
    assert missing_flags("sid=1; HttpOnly; SameSite=None", https=False) == (
        "Secure (wajib untuk SameSite=None)",
    )
    assert missing_flags("sid=1", https=True) == ("HttpOnly", "Secure", "SameSite")


def test_pasted_cookie_names_count_as_session_cookies() -> None:
    fetched = Fetched(200, "", "", Exchange("", "", 200), ("pref_a=1; Path=/",))
    assert session_management.cookie_issues(fetched, BASE, set()) == []
    (issue,) = session_management.cookie_issues(fetched, BASE, {"pref_a"})
    assert issue.header == "pref_a=[sesi akun]; Path=/"
    assert session_management.cookie_names({"Cookie": "a=1; b=2", "X": "c=3"}) == {"a", "b"}
