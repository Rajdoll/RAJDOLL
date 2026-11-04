"""Authentication (IPD F8a): JWT weaknesses and login attempt limits against testapp, silence
against applications without them, and the validators.

testapp signs its JWTs with the dictionary word `rahasia` and accepts `alg: none`, but it does
verify HS256 signatures; `POST /login` and `POST /api/v1/token` never limit failed attempts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.modules import auth_checks
from rajdoll.modules.authentication import Authentication
from rajdoll.modules.base import Candidate, PlanContext, TaskContext
from rajdoll.services import planning, tagging
from rajdoll.validators import authentication  # noqa: F401  (registers the validators)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp

BASE = "http://testserver"
TESTAPP = _testapp()


def _session(app: FastAPI, user: str, password: str) -> dict[str, str]:
    with TestClient(app) as client:
        form = {"username": user, "password": password}
        sid = client.post("/login", data=form, follow_redirects=False).cookies["sid"]
        token = client.post("/api/v1/token", json=form).json()["token"]
    return {"Cookie": f"sid={sid}", "Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def sessions() -> dict[str, dict[str, str]]:
    return {"Akun A": _session(TESTAPP.app, "budi", "budi123")}


def _ctx(app: FastAPI, engine: str, target: dict, sessions: dict, **hooks: Any) -> TaskContext:
    logs: list[str] = hooks.pop("logs", [])
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
        run_tool=lambda *_a, **_k: {"status": "completed"},
        log=logs.append,
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        session_headers=lambda label=None: sessions.get(label, {}),
        **hooks,
    )


PROBES = [BASE + "/", BASE + "/profil", BASE + "/api/v1/ringkasan", BASE + "/api/v1/saya"]


def _run_jwt(app: FastAPI, sessions: dict, logs: list[str] | None = None) -> list[Candidate]:
    reported: list[Candidate] = []
    target = {"accounts": list(sessions), "probes": PROBES}
    ctx = _ctx(
        app, "custom:jwt", target, sessions, logs=logs if logs is not None else [],
        report_candidate=lambda c: reported.append(c) or 1,
    )  # fmt: skip
    Authentication().run(ctx)
    return reported


# -- planning ---------------------------------------------------------------------------------


def _endpoint(number: int, method: str, path: str, body: list[dict] | None = None) -> dict:
    row: dict[str, Any] = {
        "id": number,
        "method": method,
        "path_template": path,
        "url": BASE + path,
        "query_params": [],
        "body_params": body or [],
        "excluded": "reset" in path,
    }
    row["tags"] = tagging.rule_tags(row)
    row["modules"] = planning.modules_for(row, ["authentication"])
    return row


FORM = [{"name": "username", "location": "form"}, {"name": "password", "location": "form"}]
JSON_BODY = [{"name": "username", "location": "json"}, {"name": "password", "location": "json"}]


def test_plan_lockout_per_login_and_one_jwt_task() -> None:
    endpoints = [
        _endpoint(1, "POST", "/login", FORM),
        _endpoint(2, "POST", "/api/v1/token", JSON_BODY),
        _endpoint(3, "POST", "/lupa-password/reset", [{"name": "email", "location": "form"}]),
        _endpoint(4, "GET", "/api/v1/saya"),
        _endpoint(5, "GET", "/login"),
    ]
    ctx = PlanContext(
        1, 1, BASE + "/", [], {}, ScanStage.TESTING, endpoints=endpoints,
        accounts=["Akun A", "Akun B"], session_check_url=BASE + "/profil",
    )  # fmt: skip
    specs = Authentication().plan(ctx)
    assert [(s.engine, s.target.get("url")) for s in specs] == [
        ("custom:lockout", BASE + "/login"),
        ("custom:lockout", BASE + "/api/v1/token"),
        ("custom:jwt", None),
    ]
    assert specs[-1].target["probes"] == [BASE + "/profil", BASE + "/", BASE + "/api/v1/saya"]
    ctx.accounts = []
    assert [s.engine for s in Authentication().plan(ctx)] == ["custom:lockout"] * 2


# -- JWT --------------------------------------------------------------------------------------


def test_testapp_jwt_alg_none_and_weak_secret(sessions: dict) -> None:
    found = {c.vuln_type: c for c in _run_jwt(TESTAPP.app, sessions)}
    # testapp verifies HS256 signatures, so an altered signature is refused.
    assert set(found) == {"jwt_alg_none", "jwt_weak_secret"}
    for candidate in found.values():
        assert (candidate.url, candidate.parameter) == (BASE + "/api/v1/saya", "Authorization")
        assert candidate.poc["account"] == "Akun A"
        assert candidate.poc["validator_params"]["protected_path"] == "/api/v1/saya"
        assert candidate.poc["headers"]["Authorization"].startswith("Bearer ey")
        notes = [e.note for e in candidate.evidence]
        assert notes[:2] == ["Akun A dengan token asli", "Akun A tanpa token"]
        assert [e.status for e in candidate.evidence] == [200, 401, 200]
        # The real token is never in the evidence; forged tokens show what they are.
        assert sessions["Akun A"]["Authorization"][7:] not in "".join(
            e.request for e in candidate.evidence
        )
    assert "token palsu: alg=none" in found["jwt_alg_none"].evidence[2].request
    weak = found["jwt_weak_secret"]
    assert weak.poc["validator_params"]["secret"] == "rahasia"
    # The secret stays in the encrypted PoC, never in notes (they end up in plaintext logs).
    assert "rahasia" not in weak.note and "diterima" in weak.note


def test_signature_not_verified_is_reported_instead_of_alg_none() -> None:
    app = _jwt_app(verify=False)
    found = _run_jwt(app, {"Akun A": {"Authorization": f"Bearer {_token('kuat-' + 'x' * 40)}"}})
    assert [c.vuln_type for c in found] == ["jwt_signature_not_verified"]


def test_a_correct_jwt_check_gives_no_candidates() -> None:
    app = _jwt_app(verify=True)
    headers = {"Authorization": f"Bearer {_token(STRONG)}"}
    assert _run_jwt(app, {"Akun A": headers}) == []


def test_without_a_jwt_or_a_protected_endpoint_the_task_says_so() -> None:
    logs: list[str] = []
    assert _run_jwt(TESTAPP.app, {"Akun A": {"Cookie": "sid=x"}}, logs) == []
    public = FastAPI()
    public.get("/")(lambda: {"ok": True})
    assert _run_jwt(public, {"Akun A": {"Authorization": f"Bearer {_token(STRONG)}"}}, logs) == []
    assert "tidak ada endpoint yang menolak request tanpa token" in logs[-1]


def test_jwt_validators_confirm_testapp_twice(sessions: dict) -> None:
    for candidate in _run_jwt(TESTAPP.app, sessions):
        finding = {"id": 3, "vuln_type": candidate.vuln_type, "poc": candidate.poc}
        finding["base_url"] = BASE
        verdict = VALIDATORS[candidate.vuln_type](_ctx(TESTAPP.app, "v", {}, sessions), finding)
        assert verdict.confirmed, verdict.note
        assert "terulang 2 kali" in verdict.note and len(verdict.evidence) == 6


def test_jwt_validators_do_not_confirm_after_a_fix(sessions: dict) -> None:
    candidates = _run_jwt(TESTAPP.app, sessions)
    fixed = {"Akun A": {"Authorization": f"Bearer {_token(STRONG)}"}}
    for candidate in candidates:
        finding = {"id": 3, "vuln_type": candidate.vuln_type, "poc": candidate.poc}
        finding["base_url"] = BASE
        ctx = _ctx(_jwt_app(verify=True), "v", {}, fixed)
        verdict = VALIDATORS[candidate.vuln_type](ctx, finding)
        assert not verdict.confirmed and "cek manual" in verdict.note


STRONG = "k" * 48


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _token(secret: str, claims: dict | None = None) -> str:
    head, body = _b64({"alg": "HS256", "typ": "JWT"}), _b64(claims or {"sub": "budi"})
    signature = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def _jwt_app(verify: bool) -> FastAPI:
    """An API whose /api/v1/saya needs a JWT: verified properly with a strong secret, or never
    verified (only decoded)."""
    app = FastAPI()

    @app.get("/api/v1/saya")
    def me(request: Request) -> Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        parts = token.split(".")
        if len(parts) != 3:
            return JSONResponse({"detail": "Token tidak valid"}, status_code=401)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        if verify and (header.get("alg") != "HS256" or _token(STRONG) != token):
            return JSONResponse({"detail": "Token tidak valid"}, status_code=401)
        return JSONResponse({"pengguna": "budi"})

    return app


def test_token_helpers() -> None:
    token = _token("rahasia")
    headers = {"Cookie": f"sid=1; jwt={token}; tema=gelap", "Authorization": f"Bearer {token}"}
    slots = auth_checks.find_tokens(headers)
    assert [(s.location, s.name, s.prefix) for s in slots] == [
        ("cookie", "jwt", ""),
        ("header", "Authorization", "Bearer "),
    ]
    assert auth_checks.with_token(headers, slots[0], None)["Cookie"] == "sid=1; tema=gelap"
    assert auth_checks.with_token(headers, slots[0], "x.y.z")["Cookie"] == (
        "sid=1; jwt=x.y.z; tema=gelap"
    )
    assert "Authorization" not in auth_checks.with_token(headers, slots[1], None)
    altered = auth_checks.bad_signature(token)
    assert altered.split(".")[2][0] != token.split(".")[2][0]
    assert altered.split(".")[2][1:] == token.split(".")[2][1:]
    unsigned = auth_checks.alg_none(token)
    assert unsigned.endswith(".") and auth_checks.decode(unsigned + "x")[0]["alg"] == "none"
    assert auth_checks.crack(token, ["salah", "rahasia"]) == "rahasia"
    assert auth_checks.crack(_token(STRONG), auth_checks.common_secrets()) is None
    forged = auth_checks.forge(token, "rahasia", "abcd")
    assert auth_checks.crack(forged, ["rahasia"]) == "rahasia"
    assert auth_checks.decode(forged)[1] == {"sub": "budi", "rajdoll_uji": "abcd"}
    assert "rahasia" in auth_checks.common_secrets()


# -- login attempts ----------------------------------------------------------------------------


def _lockout(app: FastAPI, endpoint: dict) -> tuple[dict, list[Candidate], list[str]]:
    reported: list[Candidate] = []
    logs: list[str] = []
    ctx = _ctx(
        app, "custom:lockout", endpoint, {}, logs=logs,
        report_candidate=lambda c: reported.append(c) or 1,
    )  # fmt: skip
    return Authentication().run(ctx), reported, logs


@pytest.mark.parametrize(
    ("path", "body", "encoding"),
    [("/login", FORM, "form"), ("/api/v1/token", JSON_BODY, "json")],
)
def test_testapp_logins_are_never_limited(path: str, body: list[dict], encoding: str) -> None:
    summary, reported, _logs = _lockout(TESTAPP.app, _endpoint(1, "POST", path, body))
    assert summary == {"limited": False, "attempts": 12}
    (candidate,) = reported
    assert (candidate.vuln_type, candidate.url, candidate.parameter) == (
        "weak_lockout", BASE + path, None,
    )  # fmt: skip
    assert candidate.poc["body_encoding"] == encoding
    assert candidate.poc["body"]["username"].startswith("rajdoll-uji-")
    assert len(candidate.evidence) == 2 and "12 percobaan login gagal" in candidate.note
    finding = {"id": 4, "vuln_type": "weak_lockout", "poc": candidate.poc, "base_url": BASE}
    verdict = VALIDATORS["weak_lockout"](_ctx(TESTAPP.app, "v", {}, {}), finding)
    assert verdict.confirmed and "dua rangkaian" in verdict.note


def _limited_app(mode: str) -> tuple[FastAPI, list[dict]]:
    app = FastAPI()
    seen: list[dict] = []

    @app.get("/masuk")
    def form() -> HTMLResponse:
        return HTMLResponse('<form><input type="hidden" name="csrf_token" value="tkn-1"></form>')

    @app.post("/masuk")
    async def login(request: Request) -> Response:
        data = dict(await request.form())
        seen.append(data)
        count = len(seen)
        if mode == "csrf-missing":
            return JSONResponse({"detail": "CSRF tidak valid"}, status_code=403)
        if mode == "429" and count > 3:
            return JSONResponse({"detail": "Terlalu banyak"}, status_code=429)
        if mode == "message" and count > 5:
            return HTMLResponse("<p>Akun terkunci sementara, coba lagi dalam 15 menit</p>")
        if mode == "captcha" and count > 4:
            return HTMLResponse("<p>Masukkan kode captcha di bawah</p><img src=/c.png>")
        return HTMLResponse("<p>Username atau password salah</p>")

    return app, seen


@pytest.mark.parametrize("mode", ["429", "message", "captcha"])
def test_limited_logins_are_not_reported(mode: str) -> None:
    app, _seen = _limited_app(mode)
    summary, reported, logs = _lockout(app, _endpoint(1, "POST", "/masuk", FORM))
    assert summary["limited"] is True and reported == []
    assert "dibatasi" in logs[-1]


def test_a_refused_login_is_inconclusive_and_csrf_tokens_are_fetched() -> None:
    app, _seen = _limited_app("csrf-missing")
    summary, reported, logs = _lockout(app, _endpoint(1, "POST", "/masuk", FORM))
    assert "inconclusive" in summary and reported == [] and "cek manual" in logs[-1]

    app, seen = _limited_app("plain")
    body = [*FORM, {"name": "csrf_token", "location": "form"}]
    summary, reported, _logs = _lockout(app, _endpoint(1, "POST", "/masuk", body))
    assert summary["limited"] is False and len(reported) == 1
    assert {row["csrf_token"] for row in seen} == {"tkn-1"}
    assert reported[0].poc["validator_params"]["csrf_field"] == "csrf_token"


def test_login_form_detection() -> None:
    assert auth_checks.login_form(_endpoint(1, "GET", "/login")) is None
    assert auth_checks.login_form(_endpoint(1, "POST", "/kontak", [{"name": "pesan"}])) is None
    form = auth_checks.login_form(
        _endpoint(
            1, "POST", "/masuk",
            [{"name": "_token", "location": "form"}, {"name": "email", "location": "form"},
             {"name": "kata_sandi", "location": "form"}, {"name": "ingat", "location": "form"}],
        )
    )  # fmt: skip
    assert form is not None
    assert (form.user_field, form.password_field, form.csrf_field, form.other_fields) == (
        "email", "kata_sandi", "_token", ("ingat",),
    )  # fmt: skip
    assert auth_checks.random_username("email").endswith("@contoh.test")
