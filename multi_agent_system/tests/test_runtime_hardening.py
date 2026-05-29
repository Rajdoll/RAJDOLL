from __future__ import annotations

import importlib

import pytest

from multi_agent_system.core.security_guards import data_redactor
from multi_agent_system.utils.session_service import SessionService, create_authenticated_session


def test_session_service_shared_context_is_sanitized():
    service = SessionService("https://example.com")
    service.session_data.update(
        {
            "logged_in": True,
            "username": "admin@example.com",
            "auth_method": "jwt",
            "login_endpoint": "/auth/login",
            "jwt_token": "secret-jwt-token",
            "cookies": {"session": "super-secret-cookie"},
            "headers": {"Authorization": "Bearer super-secret-cookie"},
        }
    )

    payload = service.to_shared_context(secret_ref="session-ref-123")["authenticated_session"]

    assert payload["logged_in"] is True
    assert payload["session_ref"] == "session-ref-123"
    assert payload["auth_method"] == "jwt"
    assert payload["login_endpoint"] == "/auth/login"
    assert "jwt_token" not in payload
    assert "cookies" not in payload
    assert "headers" not in payload
    assert payload["username_masked"] != "admin@example.com"


@pytest.mark.asyncio
async def test_create_authenticated_session_skips_default_fallback_when_disabled(monkeypatch):
    async def fake_attempt_login(self, username, password, login_endpoint=None):
        return False, {}

    async def fail_auto_login(self):
        raise AssertionError("auto_login should not be called when fallback is disabled")

    monkeypatch.setattr(SessionService, "attempt_login", fake_attempt_login)
    monkeypatch.setattr(SessionService, "auto_login", fail_auto_login)

    success, session = await create_authenticated_session(
        "https://example.com",
        credentials=[("user", "pass")],
        allow_default_fallback=False,
    )

    assert success is False
    assert session == {}


@pytest.mark.asyncio
async def test_hitl_manager_bypasses_agent_checkpoint_when_disabled(monkeypatch):
    from multi_agent_system.utils.hitl_manager import HITLManager
    from multi_agent_system.core import config as config_mod

    original_mode = config_mod.settings.hitl_mode
    monkeypatch.setattr(config_mod.settings, "hitl_mode", "agent")
    monkeypatch.setattr(HITLManager, "_fetch_job_options", lambda self: {})

    try:
        manager = HITLManager(
            job_id=999,
            llm_client=object(),
            overrides={"hitl_enabled": False, "hitl_mode": "off"},
        )
        result = await manager.request_agent_checkpoint(
            completed_agent="AuthenticationAgent",
            agent_index=0,
            findings_count=1,
            findings_by_severity={"high": 1},
            agent_summary="summary",
            cumulative_summary="summary",
            key_findings=[],
            next_agent="SessionManagementAgent",
            remaining_agents=["SessionManagementAgent"],
        )
        assert result["action"] == "proceed"
    finally:
        monkeypatch.setattr(config_mod.settings, "hitl_mode", original_mode)


def test_recursive_redaction_masks_nested_values():
    redacted = data_redactor.redact_any(
        {
            "headers": {"Authorization": "Bearer verysecretverysecretverysecret"},
            "cookies": ["session=supersecret", "token=verysecretverysecretverysecret"],
            "email": "user@example.com",
        }
    )

    text = str(redacted)
    assert "verysecretverysecretverysecret" not in text
    assert "user@example.com" not in text


def test_redaction_masks_common_auth_artifacts():
    raw = {
        "cookie": "session=abcdefabcdefabcdefabcdefabcdef",
        "bearer": "Bearer abcdefabcdefabcdefabcdefabcdef",
        "jwt": "jwt: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        "reset": "reset_token: resetresetresetresetreset",
        "password": "password=CorrectHorseBatteryStaple",
        "email": "tester@example.com",
    }

    text = str(data_redactor.redact_any(raw))
    assert "abcdefabcdefabcdefabcdefabcdef" not in text
    assert "eyJhbGciOiJIUzI1NiJ9" not in text
    assert "resetresetresetresetreset" not in text
    assert "CorrectHorseBatteryStaple" not in text
    assert "tester@example.com" not in text


def test_redaction_does_not_mangle_bypass_word():
    assert data_redactor.redact("Auth bypass: Protected resource") == "Auth bypass: Protected resource"


def test_bug_bounty_profile_disables_default_auto_login(monkeypatch):
    from multi_agent_system.core import config as config_mod

    monkeypatch.setenv("SCAN_PROFILE", "bug_bounty")
    monkeypatch.setenv("HITL_MODE", "off")
    monkeypatch.delenv("ALLOW_DEFAULT_AUTO_LOGIN", raising=False)

    importlib.reload(config_mod)
    try:
        assert config_mod.settings.allow_default_auto_login is False
        assert config_mod.settings.hitl_enabled is False
    finally:
        importlib.reload(config_mod)
