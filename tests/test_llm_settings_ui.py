"""LLM settings: API key handling, connection test, navigation indicator (IPD F7; AFD 1)."""

import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import sessionmaker

from rajdoll.api.app import create_app
from rajdoll.api.routes import settings as settings_routes
from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import AppSetting
from rajdoll.llm import client as llm_client

PASSWORD = "correct horse battery"
JSON = {"Accept": "application/json"}


@pytest.fixture
def ui(db_engine: Engine, tmp_path: Path) -> Iterator[tuple[TestClient, str, KeyStore]]:
    with db_engine.begin() as conn:
        conn.execute(text("TRUNCATE app_user, ui_session, app_setting, engagement CASCADE"))
    keystore = KeyStore(tmp_path)
    app = create_app(sessionmaker(bind=db_engine, expire_on_commit=False), keystore)
    with TestClient(app, follow_redirects=False) as client:
        client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
        match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/settings").text)
        assert match
        yield client, match.group(1), keystore


def _patch(client: TestClient, csrf: str, llm: dict) -> httpx.Response:
    return client.patch("/settings", json={"llm": llm}, headers={**JSON, "X-CSRF-Token": csrf})


def test_api_key_is_encrypted_and_never_shown(ui: tuple, db_engine: Engine) -> None:
    client, csrf, keystore = ui
    saved = _patch(client, csrf, {"api_key": "sk-rahasia-123", "api_key_enc": "palsu"})
    assert saved.status_code == 200
    assert "sk-rahasia" not in saved.text and "api_key" not in saved.json()["llm"]
    with db_engine.connect() as conn:
        stored = conn.execute(select(AppSetting.value).where(AppSetting.key == "llm")).scalar()
    assert stored["api_key_enc"] and stored["api_key_enc"] != "palsu"
    assert "sk-rahasia" not in str(stored)
    page = client.get("/settings").text
    assert "sk-rahasia" not in page and "tersimpan terenkripsi" in page

    # The HTML form: an empty key keeps the stored one; the checkbox removes it.
    form = {
        "llm_enabled": "on", "llm_base_url": "http://host.docker.internal:1234/v1",
        "llm_model": "qwen3-4b", "llm_timeout_s": "60", "llm_budget_per_scan": "50",
        "cvss_primary": "3.1", "rate_limit_rps": "10", "concurrency": "2",
        "checkpoint_timeout_min": "15", "evidence_max_kb": "1024", "checkpoint_enabled": "on",
    }  # fmt: skip
    htmx = {"HX-Request": "true", "X-CSRF-Token": csrf}
    assert client.patch("/settings", data=form, headers=htmx).status_code == 200
    data = client.get("/settings", headers=JSON).json()
    assert (data["llm"]["timeout_s"], data["llm_budget_per_scan"]) == (60, 50)
    with db_engine.connect() as conn:
        kept = conn.execute(select(AppSetting.value).where(AppSetting.key == "llm")).scalar()
    assert kept["api_key_enc"] == stored["api_key_enc"]
    cleared = client.patch(
        "/settings", data={**form, "llm_api_key_clear": "on"}, headers=htmx
    )  # fmt: skip
    assert cleared.status_code == 200
    with db_engine.connect() as conn:
        gone = conn.execute(select(AppSetting.value).where(AppSetting.key == "llm")).scalar()
    assert gone["api_key_enc"] is None


def test_navigation_shows_where_the_llm_runs(ui: tuple) -> None:
    client, csrf, _ = ui
    assert "LLM: lokal" in client.get("/").text
    _patch(client, csrf, {"base_url": "https://api.penyedia.test/v1"})
    page = client.get("/settings").text
    assert "LLM: API" in page and "dikirim ke penyedia API di luar laptop" in page
    _patch(client, csrf, {"enabled": False})
    assert "LLM: mati" in client.get("/").text
    assert "LLM:" not in client.get("/login").text  # not shown before login


class _Fake:
    def __init__(self, reply: str | Exception) -> None:
        self.reply = reply
        self.seen: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if isinstance(self.reply, Exception):
            raise self.reply
        return httpx.Response(200, json={"choices": [{"message": {"content": self.reply}}]})


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ('{"ok": true}', "Terhubung: qwen3-4b menjawab"),
        ("halo", "bukan JSON"),
        (httpx.ConnectError("refused"), "tidak terjangkau"),
        (httpx.ReadTimeout("lambat"), "tidak menjawab dalam 30 detik"),
    ],
)
def test_connection_test(
    ui: tuple, monkeypatch: pytest.MonkeyPatch, reply: str | Exception, expected: str
) -> None:
    client, csrf, _ = ui
    fake = _Fake(reply)

    def factory(config: llm_client.LlmConfig) -> llm_client.LlmClient:
        return llm_client.LlmClient(config, transport=httpx.MockTransport(fake.handler))

    monkeypatch.setattr(settings_routes, "LlmClient", factory)
    result = client.post(
        "/settings/llm/test",
        data={"llm_base_url": "http://127.0.0.1:1234/v1", "llm_model": "qwen3-4b",
              "llm_api_key": "sk-uji"},
        headers={"HX-Request": "true", "X-CSRF-Token": csrf},
    )  # fmt: skip
    assert result.status_code == 200 and expected in result.text
    assert str(fake.seen[0].url) == "http://127.0.0.1:1234/v1/chat/completions"
    assert fake.seen[0].headers["authorization"] == "Bearer sk-uji"
    assert client.post("/settings/llm/test", data={}).status_code == 403  # CSRF


def test_connection_test_rejects_non_http_urls(ui: tuple) -> None:
    client, csrf, _ = ui
    result = client.post(
        "/settings/llm/test",
        json={"base_url": "file:///etc/passwd"},
        headers={**JSON, "X-CSRF-Token": csrf},
    )
    assert result.json()["ok"] is False and "URL http(s)" in result.json()["error"]
