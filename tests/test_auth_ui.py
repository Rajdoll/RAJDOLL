"""Setup, login, logout, CSRF, settings, and password change through the HTTP layer."""

import hashlib
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import sessionmaker

from rajdoll.api.app import create_app
from rajdoll.core.models import AppUser, UiSession
from rajdoll.services.auth import SESSION_COOKIE

PASSWORD = "correct horse battery"
JSON = {"Accept": "application/json"}
HTMX = {"HX-Request": "true"}


@pytest.fixture
def client(db_engine: Engine) -> Iterator[TestClient]:
    with db_engine.begin() as conn:
        conn.execute(text("TRUNCATE app_user, ui_session, app_setting"))
    app = create_app(sessionmaker(bind=db_engine, expire_on_commit=False))
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _setup(client: TestClient) -> None:
    response = client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    page = client.get("/settings").text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match, "csrf token not rendered"
    return match.group(1)


def test_fresh_install_routes_to_setup(client: TestClient) -> None:
    assert client.get("/").headers["location"] == "/login"
    assert client.get("/login").headers["location"] == "/setup"
    assert client.get("/setup").status_code == 200


@pytest.mark.parametrize(
    ("password", "confirm", "message"),
    [("short", "short", "minimal 12"), (PASSWORD, PASSWORD + "x", "tidak sama")],
)
def test_setup_validates_password(
    client: TestClient, password: str, confirm: str, message: str
) -> None:
    response = client.post("/setup", data={"password": password, "password_confirm": confirm})
    assert response.status_code == 422
    assert message in response.text.lower()


def test_setup_logs_in_with_hardened_cookie(client: TestClient, db_engine: Engine) -> None:
    response = client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie or "samesite=strict" in cookie.lower()

    token = client.cookies[SESSION_COOKIE]
    with db_engine.connect() as conn:
        stored = conn.execute(select(UiSession.token_hash)).scalars().all()
        password_hash = conn.execute(select(AppUser.password_hash)).scalar_one()
    assert stored == [hashlib.sha256(token.encode()).hexdigest()]
    assert token not in stored
    assert password_hash.startswith("$argon2id$")

    home = client.get("/")
    assert home.status_code == 200
    assert "Penugasan" in home.text


def test_setup_cannot_run_twice(client: TestClient) -> None:
    _setup(client)
    assert client.get("/setup").headers["location"] == "/login"
    again = client.post(
        "/setup", data={"password": "another password!", "password_confirm": "another password!"}
    )
    assert again.status_code == 409


def test_login_rejects_wrong_password_and_accepts_right_one(client: TestClient) -> None:
    _setup(client)
    client.cookies.clear()
    wrong = client.post("/login", data={"password": "not the password"})
    assert wrong.status_code == 401
    assert SESSION_COOKIE not in client.cookies
    right = client.post("/login", data={"password": PASSWORD})
    assert right.status_code == 303
    assert client.get("/").status_code == 200


def test_json_login_returns_csrf_token(client: TestClient) -> None:
    _setup(client)
    client.cookies.clear()
    response = client.post("/login", json={"password": PASSWORD}, headers=JSON)
    assert response.status_code == 200
    assert len(response.json()["csrf_token"]) > 20


def test_unauthenticated_responses_by_client_type(client: TestClient) -> None:
    _setup(client)
    client.cookies.clear()
    assert client.get("/settings").headers["location"] == "/login"
    htmx = client.get("/settings", headers=HTMX)
    assert (htmx.status_code, htmx.headers["HX-Redirect"]) == (401, "/login")
    api = client.get("/settings", headers=JSON)
    assert api.status_code == 401
    assert api.json()["error"]["code"] == "not_authenticated"


def test_logout_requires_csrf(client: TestClient) -> None:
    _setup(client)
    assert client.post("/logout").status_code == 403
    assert client.post("/logout", headers={"X-CSRF-Token": "forged"}).status_code == 403
    token = _csrf(client)
    response = client.post("/logout", data={"csrf_token": token})
    assert response.headers["location"] == "/login"
    client.cookies.clear()
    assert client.get("/").headers["location"] == "/login"


def test_expired_session_is_rejected(client: TestClient, db_engine: Engine) -> None:
    _setup(client)
    with db_engine.begin() as conn:
        conn.execute(update(UiSession).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
    assert client.get("/").headers["location"] == "/login"


def test_settings_page_shows_defaults(client: TestClient) -> None:
    _setup(client)
    page = client.get("/settings")
    assert page.status_code == 200
    assert 'value="qwen3-4b"' in page.text
    data = client.get("/settings", headers=JSON).json()
    assert data["cvss_primary"] == "3.1"
    assert "api_key_enc" not in data["llm"]


def _settings_form(**overrides: str) -> dict[str, str]:
    form = {
        "llm_base_url": "http://host.docker.internal:1234/v1",
        "llm_model": "qwen3-4b",
        "cvss_primary": "3.1",
        "rate_limit_rps": "10",
        "concurrency": "2",
        "checkpoint_timeout_min": "15",
        "evidence_max_kb": "1024",
        "checkpoint_enabled": "on",
    }
    form.update(overrides)
    return form


def test_settings_update_via_htmx_form(client: TestClient) -> None:
    _setup(client)
    token = _csrf(client)
    headers = {**HTMX, "X-CSRF-Token": token}
    saved = client.patch(
        "/settings", data=_settings_form(concurrency="4", cvss_primary="4.0"), headers=headers
    )
    assert saved.status_code == 200
    assert "Pengaturan disimpan" in saved.text
    assert "<html" not in saved.text  # fragment only
    data = client.get("/settings", headers=JSON).json()
    assert data["defaults"]["concurrency"] == 4
    assert data["cvss_primary"] == "4.0"
    assert data["defaults"]["oob_enabled"] is False  # unchecked box means off


def test_settings_validation_error_is_shown_and_not_saved(client: TestClient) -> None:
    _setup(client)
    headers = {**HTMX, "X-CSRF-Token": _csrf(client)}
    response = client.patch("/settings", data=_settings_form(concurrency="0"), headers=headers)
    assert response.status_code == 422
    assert "Tugas paralel: minimal 1" in response.text
    assert client.get("/settings", headers=JSON).json()["defaults"]["concurrency"] == 2


def test_settings_update_needs_csrf(client: TestClient) -> None:
    _setup(client)
    response = client.patch("/settings", data=_settings_form(concurrency="4"), headers=HTMX)
    assert response.status_code == 403


def test_settings_json_patch(client: TestClient) -> None:
    _setup(client)
    headers = {**JSON, "X-CSRF-Token": _csrf(client)}
    response = client.patch("/settings", json={"llm": {"model": "qwen3-8b"}}, headers=headers)
    assert response.status_code == 200
    assert response.json()["llm"]["model"] == "qwen3-8b"
    bad = client.patch("/settings", json={"unknown": 1}, headers=headers)
    assert bad.status_code == 422
    error = bad.json()["error"]
    assert error["code"] == "invalid_settings"
    assert error["details"]["errors"][0]["field"] == "unknown"


def test_user_content_is_escaped(client: TestClient) -> None:
    _setup(client)
    headers = {**JSON, "X-CSRF-Token": _csrf(client)}
    client.patch(
        "/settings", json={"llm": {"model": '<script>alert(1)</script>"'}}, headers=headers
    )
    page = client.get("/settings").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_password_change_signs_out_other_sessions(client: TestClient, db_engine: Engine) -> None:
    _setup(client)
    other = TestClient(client.app, follow_redirects=False)
    assert other.post("/login", data={"password": PASSWORD}).status_code == 303

    headers = {**HTMX, "X-CSRF-Token": _csrf(client)}
    wrong = client.post(
        "/settings/password",
        data={
            "current_password": "nope",
            "new_password": "a brand new password",
            "new_password_confirm": "a brand new password",
        },
        headers=headers,
    )
    assert wrong.status_code == 422
    assert "salah" in wrong.text

    ok = client.post(
        "/settings/password",
        data={
            "current_password": PASSWORD,
            "new_password": "a brand new password",
            "new_password_confirm": "a brand new password",
        },
        headers=headers,
    )
    assert ok.status_code == 200
    assert client.get("/").status_code == 200  # current session kept
    assert other.get("/").headers["location"] == "/login"  # other session ended

    client.cookies.clear()
    assert client.post("/login", data={"password": PASSWORD}).status_code == 401
    assert client.post("/login", data={"password": "a brand new password"}).status_code == 303


def test_security_headers(client: TestClient) -> None:
    response = client.get("/login")
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_vendored_assets_are_served(client: TestClient) -> None:
    for path in (
        "/static/vendor/htmx-2.0.11.min.js",
        "/static/vendor/htmx-ext-sse-2.2.4.min.js",
        "/static/vendor/pico-2.1.1.min.css",
        "/static/app.css",
    ):
        assert client.get(path).status_code == 200, path


def test_pages_have_no_inline_scripts_or_styles(client: TestClient) -> None:
    _setup(client)
    for path in ("/", "/settings"):
        html = client.get(path).text
        assert re.search(r"<script(?![^>]*\bsrc=)", html) is None, path
        assert "style=" not in html, path
        assert "<style" not in html, path
