"""Identity Management (IPD F8b): account enumeration on login endpoints.

testapp's `POST /api/v1/token` answers "Username tidak terdaftar" for unknown usernames and
"Password salah" for known ones; `POST /login` answers both the same way.
"""

from __future__ import annotations

import secrets
import threading
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.modules.base import Candidate, PlanContext, TaskContext
from rajdoll.modules.identity import Identity
from rajdoll.services import planning, tagging
from rajdoll.validators import identity  # noqa: F401  (registers the validator)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp

BASE = "http://testserver"
TESTAPP = _testapp()
FORM = [{"name": "username", "location": "form"}, {"name": "password", "location": "form"}]
JSON_BODY = [{"name": "username", "location": "json"}, {"name": "password", "location": "json"}]


def _endpoint(path: str, body: list[dict]) -> dict[str, Any]:
    return {"method": "POST", "url": BASE + path, "body_params": body}


def _ctx(app: FastAPI, target: dict, usernames: dict[str, str], **hooks: Any) -> TaskContext:
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url=BASE + "/",
        scope=["testserver"],
        settings={},
        engine="custom:enumeration",
        target=target,
        params={},
        cancel_event=threading.Event(),
        run_tool=lambda *_a, **_k: {"status": "completed"},
        log=lambda _m: None,
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        account_username=lambda label: usernames.get(label, ""),
        **hooks,
    )


def _run(app: FastAPI, endpoint: dict, usernames: dict[str, str]) -> list[Candidate]:
    reported: list[Candidate] = []
    target = {**endpoint, "accounts": list(usernames)}
    ctx = _ctx(app, target, usernames, report_candidate=lambda c: reported.append(c) or 1)
    Identity().run(ctx)
    return reported


def _validate(app: FastAPI, candidate: Candidate) -> Any:
    finding = {"id": 6, "vuln_type": candidate.vuln_type, "poc": candidate.poc, "base_url": BASE}
    return VALIDATORS["account_enumeration"](_ctx(app, {}, {}), finding)


def test_plan_one_task_per_login_with_the_account_labels() -> None:
    rows = []
    for number, (path, body) in enumerate([("/login", FORM), ("/kontak", [])], 1):
        row: dict[str, Any] = {
            "id": number, "method": "POST", "path_template": path, "url": BASE + path,
            "query_params": [], "body_params": body, "excluded": False,
        }  # fmt: skip
        row["tags"] = tagging.rule_tags(row)
        row["modules"] = planning.modules_for(row, ["identity"])
        rows.append(row)
    ctx = PlanContext(
        1, 1, BASE + "/", [], {}, ScanStage.TESTING, endpoints=rows, accounts=["Akun A", "Akun B"]
    )
    (spec,) = Identity().plan(ctx)
    assert (spec.engine, spec.target["url"], spec.target["accounts"]) == (
        "custom:enumeration", BASE + "/login", ["Akun A", "Akun B"],
    )  # fmt: skip


def test_testapp_token_endpoint_tells_usernames_apart() -> None:
    usernames = {"Akun A": "budi", "Akun B": ""}
    (candidate,) = _run(TESTAPP.app, _endpoint("/api/v1/token", JSON_BODY), usernames)
    assert (candidate.vuln_type, candidate.parameter) == ("account_enumeration", "username")
    assert candidate.poc["validator_params"]["username"] == "budi"
    assert "budi" not in candidate.note  # usernames stay in the encrypted PoC and evidence
    unknown, known = candidate.evidence
    assert "Username tidak terdaftar" in unknown.response and "Password salah" in known.response
    assert _validate(TESTAPP.app, candidate).confirmed


def test_testapp_login_form_answers_alike() -> None:
    assert _run(TESTAPP.app, _endpoint("/login", FORM), {"Akun A": "budi"}) == []


def test_without_account_usernames_common_names_are_tried() -> None:
    # testapp has no "admin" and the like, so nothing differs.
    assert _run(TESTAPP.app, _endpoint("/api/v1/token", JSON_BODY), {}) == []

    app = FastAPI()

    @app.post("/masuk")
    async def login(request: Request) -> JSONResponse:
        form = await request.form()
        if form.get("username") == "admin":
            return JSONResponse({"detail": "Password salah"}, status_code=401)
        return JSONResponse({"detail": "Akun tidak ditemukan"}, status_code=404)

    (candidate,) = _run(app, _endpoint("/masuk", FORM), {})
    assert candidate.poc["validator_params"]["username"] == "admin"
    assert "username umum" in candidate.note


def _generic(noisy: bool = False) -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/token")
    def token() -> JSONResponse:
        extra = f" ID permintaan {secrets.token_hex(3)}" if noisy else ""
        return JSONResponse({"detail": "Username atau password salah" + extra}, status_code=401)

    return app


@pytest.mark.parametrize("noisy", [False, True])
def test_generic_or_noisy_answers_give_no_candidate(noisy: bool) -> None:
    app = _generic(noisy)
    assert _run(app, _endpoint("/api/v1/token", JSON_BODY), {"Akun A": "budi"}) == []


def test_validator_does_not_confirm_after_a_fix() -> None:
    (candidate,) = _run(TESTAPP.app, _endpoint("/api/v1/token", JSON_BODY), {"Akun A": "budi"})
    verdict = _validate(_generic(), candidate)
    assert not verdict.confirmed and "cek manual" in verdict.note
