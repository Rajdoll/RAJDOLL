"""Engagement routes over HTTP: pages, htmx fragments, JSON API, CSRF (BSD 10.3)."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import sessionmaker

from rajdoll.api.app import create_app
from rajdoll.core.crypto import KeyStore

PASSWORD = "correct horse battery"
JSON = {"Accept": "application/json"}


@dataclass
class Ui:
    client: TestClient
    csrf: str
    secrets: Path

    def htmx(self, **extra: str) -> dict[str, str]:
        return {"HX-Request": "true", "X-CSRF-Token": self.csrf, **extra}

    def api(self) -> dict[str, str]:
        return {**JSON, "X-CSRF-Token": self.csrf}


@pytest.fixture
def ui(db_engine: Engine, tmp_path: Path) -> Iterator[Ui]:
    with db_engine.begin() as conn:
        conn.execute(text("TRUNCATE app_user, ui_session, app_setting, engagement CASCADE"))
    app = create_app(sessionmaker(bind=db_engine, expire_on_commit=False), KeyStore(tmp_path))
    with TestClient(app, follow_redirects=False) as client:
        client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
        match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/settings").text)
        assert match
        yield Ui(client, match.group(1), tmp_path)


def _create(ui: Ui, name: str = "SIMPEG (clone)") -> int:
    response = ui.client.post(
        "/engagements",
        json={"name": name, "target_url": "https://simpeg.instansi.test/", "organization": "A"},
        headers=ui.api(),
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def test_create_via_form_redirects_to_scope_tab(ui: Ui) -> None:
    response = ui.client.post(
        "/engagements",
        data={
            "csrf_token": ui.csrf,
            "name": "SIMPEG (clone)",
            "target_url": "https://simpeg.instansi.test/",
        },
    )
    assert response.status_code == 303
    assert re.fullmatch(r"/engagements/\d+/scope", response.headers["location"])
    page = ui.client.get(response.headers["location"])
    assert page.status_code == 200
    assert "simpeg.instansi.test" in page.text
    assert "Scope &amp; Akun" in page.text


def test_create_form_shows_errors_and_keeps_values(ui: Ui) -> None:
    response = ui.client.post(
        "/engagements", data={"csrf_token": ui.csrf, "name": "Keep me", "target_url": "nope"}
    )
    assert response.status_code == 422
    assert "URL target" in response.text
    assert 'value="Keep me"' in response.text


def test_create_requires_csrf(ui: Ui) -> None:
    response = ui.client.post(
        "/engagements", data={"name": "x", "target_url": "https://simpeg.instansi.test/"}
    )
    assert response.status_code == 403


def test_json_create_and_list(ui: Ui) -> None:
    engagement_id = _create(ui)
    detail = ui.client.get(f"/engagements/{engagement_id}", headers=JSON).json()
    assert detail["status"] == "ready"
    assert detail["scope"] == ["simpeg.instansi.test"]
    assert detail["effective_settings"]["concurrency"] == 2
    listing = ui.client.get("/engagements", headers=JSON).json()["items"]
    assert [item["id"] for item in listing] == [engagement_id]
    home = ui.client.get("/")
    assert "SIMPEG (clone)" in home.text


def test_unknown_engagement_is_404(ui: Ui) -> None:
    assert ui.client.get("/engagements/999999").status_code == 404
    error = ui.client.get("/engagements/999999", headers=JSON).json()["error"]
    assert error["code"] == "not_found"


def test_scope_add_and_remove_with_htmx(ui: Ui) -> None:
    engagement_id = _create(ui)
    added = ui.client.post(
        f"/engagements/{engagement_id}/scope",
        data={"pattern": "*.instansi.test"},
        headers=ui.htmx(),
    )
    assert added.status_code == 200
    assert 'id="scope-section"' in added.text
    assert "*.instansi.test" in added.text
    assert 'hx-swap-oob="true"' in added.text  # header status badge refreshed

    bad = ui.client.post(
        f"/engagements/{engagement_id}/scope", data={"pattern": "*.test"}, headers=ui.htmx()
    )
    assert bad.status_code == 422
    assert "terlalu luas" in bad.text

    rules = ui.client.get(f"/engagements/{engagement_id}/scope", headers=JSON).json()["scope"]
    target_rule = next(r for r in rules if r["pattern"] == "simpeg.instansi.test")
    wildcard = next(r for r in rules if r["pattern"] == "*.instansi.test")
    removed = ui.client.delete(
        f"/engagements/{engagement_id}/scope/{wildcard['id']}", headers=ui.htmx()
    )
    assert removed.status_code == 200
    refused = ui.client.delete(
        f"/engagements/{engagement_id}/scope/{target_rule['id']}", headers=ui.htmx()
    )
    assert refused.status_code == 409
    assert "minimal berisi satu host" in refused.text


def test_accounts_never_render_secret_values(ui: Ui) -> None:
    engagement_id = _create(ui)
    raw_request = (
        "GET /profil HTTP/1.1\nHost: simpeg.instansi.test\n"
        "Cookie: laravel_session=TOPSECRETVALUE\nAuthorization: Bearer TOPSECRETTOKEN\n"
    )
    added = ui.client.post(
        f"/engagements/{engagement_id}/accounts",
        data={"label": "Akun A", "session_text": raw_request},
        headers=ui.htmx(),
    )
    assert added.status_code == 200
    assert "laravel_session" in added.text
    assert "Authorization" in added.text
    assert "TOPSECRET" not in added.text
    page = ui.client.get(f"/engagements/{engagement_id}/scope").text
    assert "TOPSECRET" not in page
    api = ui.client.get(f"/engagements/{engagement_id}/accounts", headers=JSON).text
    assert "TOPSECRET" not in api
    assert "Akun B" in page  # next suggested label

    bad = ui.client.post(
        f"/engagements/{engagement_id}/accounts",
        data={"label": "Akun B", "session_text": "Host: x"},
        headers=ui.htmx(),
    )
    assert bad.status_code == 422
    assert "Tidak ada cookie atau header" in bad.text


def test_session_check_form(ui: Ui) -> None:
    engagement_id = _create(ui)
    bad = ui.client.put(
        f"/engagements/{engagement_id}/session-check",
        data={"url": "https://other.test/me", "marker": ""},
        headers=ui.htmx(),
    )
    assert bad.status_code == 422
    assert "di dalam scope" in bad.text
    ok = ui.client.put(
        f"/engagements/{engagement_id}/session-check",
        data={"url": "https://simpeg.instansi.test/profil", "marker": "Budi"},
        headers=ui.htmx(),
    )
    assert ok.status_code == 200
    assert "Cek sesi disimpan" in ok.text


def test_settings_tab_overrides_and_status(ui: Ui) -> None:
    engagement_id = _create(ui)
    page = ui.client.get(f"/engagements/{engagement_id}/settings")
    assert page.status_code == 200
    saved = ui.client.patch(
        f"/engagements/{engagement_id}",
        data={
            "section": "overrides",
            "concurrency": "4",
            "checkpoint_enabled": "off",
            "oob_enabled": "default",
            "identity_header_name": "X-VA-Team",
            "identity_header_value": "BSSN",
        },
        headers=ui.htmx(),
    )
    assert saved.status_code == 200
    assert "Pengaturan scan disimpan" in saved.text
    effective = ui.client.get(f"/engagements/{engagement_id}/settings", headers=JSON).json()[
        "effective_settings"
    ]
    assert effective["concurrency"] == 4
    assert effective["checkpoint_enabled"] is False
    assert effective["oob_enabled"] is False
    assert effective["identity_header"] == {"name": "X-VA-Team", "value": "BSSN"}

    done = ui.client.patch(
        f"/engagements/{engagement_id}",
        data={"section": "status", "status": "done"},
        headers=ui.htmx(),
    )
    assert done.status_code == 200
    assert "Buka kembali" in done.text
    again = ui.client.patch(
        f"/engagements/{engagement_id}",
        data={"section": "status", "status": "done"},
        headers=ui.htmx(),
    )
    assert again.status_code == 409


def test_details_update_can_move_to_draft(ui: Ui) -> None:
    engagement_id = _create(ui)
    response = ui.client.patch(
        f"/engagements/{engagement_id}",
        json={"name": "SIMPEG v2", "target_url": "https://baru.test/"},
        headers=ui.api(),
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["name"], body["status"]) == ("SIMPEG v2", "draft")
    assert any("di luar scope" in w for w in body["warnings"])


def test_delete_flow(ui: Ui) -> None:
    engagement_id = _create(ui)
    key_id = ui.client.get(f"/engagements/{engagement_id}", headers=JSON).json()
    key_files = list((ui.secrets / "engagements").glob("*.key"))
    assert len(key_files) == 1

    wrong = ui.client.delete(f"/engagements/{engagement_id}?confirm_name=simpeg", headers=ui.htmx())
    assert wrong.status_code == 422
    assert "tidak sama" in wrong.text

    deleted = ui.client.delete(
        f"/engagements/{engagement_id}?confirm_name=SIMPEG%20(clone)", headers=ui.htmx()
    )
    assert deleted.status_code == 204
    assert deleted.headers["HX-Redirect"] == "/"
    assert ui.client.get(f"/engagements/{engagement_id}").status_code == 404
    assert not list((ui.secrets / "engagements").glob("*.key"))
    assert key_id  # detail was readable before deletion


def test_names_are_escaped(ui: Ui) -> None:
    engagement_id = _create(ui, name='<img src=x onerror="alert(1)">')
    for path in ("/", f"/engagements/{engagement_id}", f"/engagements/{engagement_id}/settings"):
        html = ui.client.get(path).text
        assert "<img src=x" not in html, path
        assert "&lt;img src=x" in html, path


def test_pages_have_no_inline_scripts_or_styles(ui: Ui) -> None:
    engagement_id = _create(ui)
    for suffix in ("", "/scope", "/settings"):
        html = ui.client.get(f"/engagements/{engagement_id}{suffix}").text
        assert re.search(r"<script(?![^>]*\bsrc=)", html) is None, suffix
        assert "style=" not in html, suffix
