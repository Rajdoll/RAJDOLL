"""
Task 10 (evidence-quality phase2): 6 fixes in authentication_agent.py +
authentication-testing/authentication.py --

1. CSRF / login-POST heuristics: downgrade medium -> info (self-acknowledged
   heuristic-only, single static regex check).
2. Password reset / alt-channel findings: evidence must include the real
   endpoint/URL used, not just description+severity.
3. Default credentials: only fire when a genuine authenticated-session signal
   (status 200/302 + token/session cookie) is present; evidence must show the
   password + confirmation fields.
4. JWT: static analyze_jwt decode alone must never produce a finding; only the
   active_flow forge+send confirmation (test_jwt_manipulation) may.
5. test_2fa_bypass direct-access sub-check: removed entirely (no genuine
   2FA-pending state obtainable in this codebase).
6. test_security_questions: "predictable" claim requires an accepted-answer
   signal; otherwise downgrade to info-level "security questions present".
"""
import importlib.util
import json
import pathlib
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

from multi_agent_system.agents import authentication_agent
from multi_agent_system.agents.authentication_agent import AuthenticationAgent

_AUTH_TOOL_PATH = pathlib.Path(__file__).parent.parent.parent / "authentication-testing" / "authentication.py"
_spec = importlib.util.spec_from_file_location("authentication_mod_phase2", _AUTH_TOOL_PATH)
auth_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auth_mod)


def _resp(status_code=200, text="", headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    r.json = lambda: json.loads(text)
    return r


def _default_httpx_mock(get_response=None):
    """Safe default: GET returns non-login HTML so passive checks no-op."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=get_response or _resp(200, "<html>no login form here</html>"))
    client.post = AsyncMock(return_value=_resp(200, ""))
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


class _FakeMCPClient:
    def __init__(self, responses):
        self._responses = responses

    async def call_tool(self, server, tool, args=None, auth_session=None):
        resp = self._responses.get(tool)
        if resp is None:
            return {"status": "error", "message": f"not mocked: {tool}"}
        return resp


def _auth_agent(**overrides):
    a = AuthenticationAgent.__new__(AuthenticationAgent)
    a.log = lambda *args, **kw: None
    a.log_tool_execution_plan = lambda: None
    a.get_auth_session = lambda: None
    a._get_target = lambda: "https://example.test"
    a._shared_context_snapshot = {
        "endpoint_inventory": {
            "by_tag": {"user_login": ["login1"]},
            "endpoints": [{"id": "login1", "url": "https://example.test/login"}],
        }
    }
    a.should_run_tool = lambda name: False
    a.findings = []
    a.add_finding = lambda *args, **kw: a.findings.append((args, kw))
    for k, v in overrides.items():
        setattr(a, k, v)
    return a


_ADD_FINDING_PARAMS = ["category", "title", "severity", "evidence", "details", "confidence"]


def _norm(args, kwargs):
    result = {"severity": "info", "evidence": None, "details": None}
    result.update(dict(zip(_ADD_FINDING_PARAMS, args)))
    result.update(kwargs)
    return result


def _calls(agent):
    return [_norm(args, kw) for args, kw in agent.findings]


# ============================================================================
# Item 1: CSRF / login-POST heuristics downgraded to info
# ============================================================================

async def test_csrf_and_login_post_heuristics_downgraded_to_info(monkeypatch):
    # Login form: has password field + <form>, but no CSRF token and method=GET
    # -- triggers both heuristics under today's code (severity=medium).
    html = '<form method="get"><input type="password" name="pw"></form>'
    mock_httpx = _default_httpx_mock(get_response=_resp(200, html))
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    agent = _auth_agent()
    await agent.run()

    calls = _calls(agent)
    csrf = [c for c in calls if "CSRF" in c["title"]]
    post_method = [c for c in calls if "POST method" in c["title"]]
    assert csrf, calls
    assert post_method, calls
    assert all(c["severity"] == "info" for c in csrf), csrf
    assert all(c["severity"] == "info" for c in post_method), post_method


# ============================================================================
# Item 2a: password reset evidence includes the real endpoint
# ============================================================================

async def test_password_reset_evidence_includes_real_endpoint(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "test_password_reset": {
            "status": "success",
            "data": {
                "vulnerabilities_found": 1,
                "findings": [{"description": "No rate limiting on password reset requests", "severity": "Medium"}],
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(should_run_tool=lambda name: name == "test_password_reset")
    agent._shared_context_snapshot["endpoint_inventory"]["by_tag"]["password_recovery"] = ["reset1"]
    agent._shared_context_snapshot["endpoint_inventory"]["endpoints"].append(
        {"id": "reset1", "url": "https://example.test/rest/user/reset-password"}
    )

    await agent.run()

    calls = _calls(agent)
    reset = [c for c in calls if c["category"] == "WSTG-ATHN-09" and "Password reset" in c["title"]]
    assert reset, calls
    assert reset[0]["evidence"].get("endpoint") == "https://example.test/rest/user/reset-password", reset[0]["evidence"]


# ============================================================================
# Item 2b: alt-channel evidence includes the real endpoint
# ============================================================================

async def test_alt_channel_evidence_includes_real_endpoint(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "test_alternative_channel_auth": {
            "status": "success",
            "data": {
                "vulnerabilities_found": 1,
                "findings": [{
                    "type": "weak_credentials",
                    "endpoint": "/api/v1/login",
                    "severity": "Critical",
                    "description": "Weak credentials accepted on /api/v1/login",
                }],
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(should_run_tool=lambda name: name == "test_alternative_channel_auth")
    await agent.run()

    calls = _calls(agent)
    alt = [c for c in calls if c["category"] == "WSTG-ATHN-10"]
    assert alt, calls
    assert "/api/v1/login" in alt[0]["evidence"].get("endpoint", ""), alt[0]["evidence"]


# ============================================================================
# Item 3: default credentials require a genuine authenticated-session signal
# ============================================================================

async def test_default_credentials_no_finding_without_session_signal(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "test_default_credentials": {
            "status": "success",
            "data": {
                "vulnerabilities_found": 1,
                "findings": [{
                    "endpoint": "https://example.test/rest/user/login",
                    "username": "admin", "password": "admin",
                    "status_code": 401, "token_present": False, "set_cookie": "",
                }],
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(should_run_tool=lambda name: name == "test_default_credentials")
    await agent.run()

    calls = _calls(agent)
    creds = [c for c in calls if c["category"] == "WSTG-ATHN-02"]
    assert creds == [], creds


async def test_default_credentials_finding_requires_and_includes_session_signal(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "test_default_credentials": {
            "status": "success",
            "data": {
                "vulnerabilities_found": 1,
                "findings": [{
                    "endpoint": "https://example.test/rest/user/login",
                    "username": "admin@juice-sh.op", "password": "admin123",
                    "status_code": 200, "token_present": True, "set_cookie": "",
                }],
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(should_run_tool=lambda name: name == "test_default_credentials")
    await agent.run()

    calls = _calls(agent)
    creds = [c for c in calls if c["category"] == "WSTG-ATHN-02"]
    assert len(creds) == 1, calls
    ev = creds[0]["evidence"]
    assert ev.get("password") == "admin123", ev
    assert ev.get("status_code") == 200, ev
    assert ev.get("token_present") is True, ev
    assert creds[0]["severity"] == "critical"


# ============================================================================
# Item 4: JWT -- static analyze_jwt alone must not fire; only active_flow
# forge+send confirmation may.
# ============================================================================

async def test_jwt_static_analysis_alone_produces_no_finding(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "analyze_jwt": {
            "status": "success",
            "data": {
                "header": {"alg": "none"}, "payload": {},
                "vulnerabilities": [{"type": "alg_none", "severity": "Critical", "description": "alg none"}],
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(
        should_run_tool=lambda name: name == "analyze_jwt",
        get_auth_session=lambda: {"token": "aaa.bbb.ccc"},
    )
    await agent.run()

    calls = _calls(agent)
    jwt_findings = [c for c in calls if "JWT" in c["title"]]
    assert jwt_findings == [], jwt_findings


async def test_jwt_active_flow_forge_confirmation_produces_finding(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    monkeypatch.setattr(authentication_agent._settings, "use_framework", True)
    monkeypatch.setattr(authentication_agent._settings, "use_active_flow", True)

    class _FakeFlowResult:
        success = True
        severity = "critical"
        evidence = {
            "endpoint": "https://example.test/api/whoami",
            "technique": "alg=none",
            "response_status": 200,
        }

    class _FakeActiveFlow:
        async def test_jwt_manipulation(self, token, ep):
            return _FakeFlowResult()

    agent = _auth_agent(
        should_run_tool=lambda name: False,
        get_auth_session=lambda: {"token": "aaa.bbb.ccc"},
        active_flow=_FakeActiveFlow(),
    )
    await agent.run()

    calls = _calls(agent)
    jwt_findings = [c for c in calls if "JWT" in c["title"] and c["category"] == "WSTG-ATHN-09"]
    assert len(jwt_findings) == 1, calls
    assert jwt_findings[0]["severity"] == "critical"
    assert jwt_findings[0]["evidence"]["technique"] == "alg=none"


# ============================================================================
# Item 5: test_2fa_bypass direct-access sub-check removed
# ============================================================================

async def test_2fa_direct_access_subcheck_removed(monkeypatch):
    post_auth_paths = (
        "/api/Users", "/rest/user/whoami", "/api/Products",
        "/api/Feedbacks", "/api/Complaints", "/profile", "/administration",
    )

    async def get_side_effect(url, **kwargs):
        if any(p in url for p in post_auth_paths):
            return _resp(200, '{"data": [{"id": 1, "email": "a@b.com", "role": "user", "note": "padding to exceed 50 chars"}]}')
        return _resp(404, "")

    async def post_side_effect(url, **kwargs):
        return _resp(404, "")

    client = AsyncMock()
    client.get = AsyncMock(side_effect=get_side_effect)
    client.post = AsyncMock(side_effect=post_side_effect)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = cm
    monkeypatch.setattr(auth_mod, "httpx", mock_httpx)

    result = await auth_mod.test_2fa_bypass("https://example.test", auth_session={"token": "abc"})
    findings = result["data"]["findings"]
    direct_access = [f for f in findings if f.get("type") == "2fa_direct_access_bypass"]
    assert direct_access == [], findings
    assert findings == [], findings


async def test_2fa_totp_brute_force_still_fires(monkeypatch):
    # Regression guard: removing the direct-access sub-check must not affect
    # the (already-proven A-tier) TOTP brute-force / rate-limit checks.
    async def get_side_effect(url, **kwargs):
        return _resp(404, "")

    async def post_side_effect(url, json=None, **kwargs):
        if "/rest/2fa/verify" in url:
            return _resp(200, '{"token": "forged-session-token"}')
        return _resp(404, "")

    client = AsyncMock()
    client.get = AsyncMock(side_effect=get_side_effect)
    client.post = AsyncMock(side_effect=post_side_effect)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = cm
    monkeypatch.setattr(auth_mod, "httpx", mock_httpx)
    monkeypatch.setattr(auth_mod.asyncio, "sleep", AsyncMock())

    result = await auth_mod.test_2fa_bypass("https://example.test")
    findings = result["data"]["findings"]
    brute = [f for f in findings if f.get("type") == "2fa_totp_brute_force"]
    assert len(brute) == 1, findings


# ============================================================================
# Item 6: test_security_questions requires an accepted-answer signal
# ============================================================================

async def test_security_questions_tool_no_accepted_signal(monkeypatch):
    html = "<html>What is your favorite pet's name?</html>"
    reject_text = "Incorrect answer, please try again"
    post_responses = [_resp(200, reject_text) for _ in range(4)]

    client = AsyncMock()
    client.get = AsyncMock(return_value=_resp(200, html))
    client.post = AsyncMock(side_effect=post_responses)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = cm
    monkeypatch.setattr(auth_mod, "httpx", mock_httpx)
    monkeypatch.setattr(auth_mod.asyncio, "sleep", AsyncMock())

    result = await auth_mod.test_security_questions("https://example.test/security")
    data = result["data"]
    assert data["security_questions_found"] is True
    assert data.get("answer_accepted") is False, data


async def test_security_questions_tool_accepted_signal_detected(monkeypatch):
    html = "<html>What is your favorite pet's name?</html>"
    reject_text = "Incorrect answer, please try again"
    accept_text = "Answer verified, reset link sent!"
    post_responses = [
        _resp(200, reject_text),   # baseline (deliberately-wrong answer)
        _resp(200, reject_text),   # candidate 1: rejected
        _resp(200, accept_text),   # candidate 2: accepted
    ]

    client = AsyncMock()
    client.get = AsyncMock(return_value=_resp(200, html))
    client.post = AsyncMock(side_effect=post_responses)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = cm
    monkeypatch.setattr(auth_mod, "httpx", mock_httpx)
    monkeypatch.setattr(auth_mod.asyncio, "sleep", AsyncMock())

    result = await auth_mod.test_security_questions("https://example.test/security")
    data = result["data"]
    assert data.get("answer_accepted") is True, data
    assert data.get("accepted_answer") is not None


async def test_security_questions_agent_downgrades_without_accepted_answer(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "test_security_questions": {
            "status": "success",
            "data": {
                "security_questions_found": True,
                "sample_questions": ["favorite"],
                "rate_limiting": False,
                "answer_accepted": False,
                "accepted_answer": None,
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(should_run_tool=lambda name: name == "test_security_questions")
    await agent.run()

    calls = _calls(agent)
    sq = [c for c in calls if c["category"] == "WSTG-ATHN-08"]
    assert len(sq) == 1, calls
    assert sq[0]["severity"] == "info", sq
    assert "predictable" not in sq[0]["title"].lower(), sq


async def test_security_questions_agent_reports_predictable_when_accepted(monkeypatch):
    mock_httpx = _default_httpx_mock()
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)

    responses = {
        "test_security_questions": {
            "status": "success",
            "data": {
                "security_questions_found": True,
                "sample_questions": ["favorite"],
                "rate_limiting": False,
                "answer_accepted": True,
                "accepted_answer": "blue",
            },
        },
    }
    monkeypatch.setattr(authentication_agent, "MCPClient", lambda: _FakeMCPClient(responses))

    agent = _auth_agent(should_run_tool=lambda name: name == "test_security_questions")
    await agent.run()

    calls = _calls(agent)
    sq = [c for c in calls if c["category"] == "WSTG-ATHN-08"]
    assert len(sq) == 1, calls
    assert sq[0]["severity"] == "high", sq
    assert "guessed" in sq[0]["title"].lower() or "accepted" in sq[0]["title"].lower(), sq
