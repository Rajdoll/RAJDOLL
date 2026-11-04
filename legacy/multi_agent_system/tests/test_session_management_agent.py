import importlib.util
from pathlib import Path

from multi_agent_system.agents.session_management_agent import SessionManagementAgent


def _load_session_tool():
    path = Path(__file__).resolve().parents[2] / "session-management-testing" / "session-management.py"
    spec = importlib.util.spec_from_file_location("session_management_tool", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeHeaders:
    def __init__(self, set_cookie=None, **plain):
        self._set_cookie = set_cookie or []
        self._plain = plain

    def get_list(self, key):
        if key.lower() == "set-cookie":
            return self._set_cookie
        return []

    def get(self, key, default=""):
        return self._plain.get(key, default)


class FakeResp:
    def __init__(self, status_code=200, text="", set_cookie=None, **headers):
        self.status_code = status_code
        self.text = text
        self.headers = FakeHeaders(set_cookie=set_cookie, **headers)


def _agent(tool_name):
    a = SessionManagementAgent.__new__(SessionManagementAgent)
    a.log = lambda *args, **kw: None
    a.log_tool_execution_plan = lambda: None
    a.get_auth_session = lambda: None
    a._get_target = lambda: "https://example.com"
    a._shared_context_snapshot = {
        "endpoint_inventory": {
            "by_tag": {"user_login": ["ep1"]},
            "endpoints": [{"id": "ep1", "url": "https://example.com/login"}],
        }
    }
    a.should_run_tool = lambda name: name == tool_name
    a.findings = []
    a.add_finding = lambda *args, **kw: a.findings.append((args, kw))
    return a


def _fake_mcp(payload):
    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            return payload
    return FakeMCP()


def _finding(agent, category, title_substr):
    return next(
        kw for args, kw in agent.findings
        if args[0] == category and title_substr.lower() in args[1].lower()
    )


# ============================================================================
# Site 1: CSRF (agent ~347-349) -- evidence must carry real tool detail
# (endpoint + samesite cookie check), not just two bare booleans.
# ============================================================================

async def test_csrf_finding_evidence_carries_real_detail(monkeypatch):
    agent = _agent("test_csrf_protection")
    samesite_check = [{"cookie": "session", "samesite": "Not Set", "secure": True}]
    payload = {
        "status": "success",
        "data": {
            "has_csrf_token_in_form": False,
            "csrf_vulnerable": True,
            "cookies_samesite_check": samesite_check,
            "description": "CSRF protection requires tokens in forms AND SameSite=Strict/Lax on cookies",
        },
    }
    monkeypatch.setattr(
        "multi_agent_system.agents.session_management_agent.MCPClient",
        lambda: _fake_mcp(payload),
    )

    await agent.run()

    finding = _finding(agent, "WSTG-SESS-05", "Missing or weak CSRF protection")
    ev = finding["evidence"]
    assert ev["endpoint"] == "https://example.com"
    assert ev["cookies_samesite_check"] == samesite_check
    assert ev["csrf_token_present"] is False
    assert ev["vulnerable"] is True


# ============================================================================
# Sites 2 & 3: session puzzling (agent ~376-381) -- array injection evidence
# must carry endpoint/payload/status, not a hardcoded {"array_injection": True}.
# Variable pollution evidence must carry the reflected VALUE, not just names.
# ============================================================================

async def test_array_injection_finding_evidence_is_not_hardcoded_bool(monkeypatch):
    agent = _agent("test_session_puzzling")
    array_url = "https://example.com?_SESSION[user]=attacker&_SESSION[role]=admin"
    payload = {
        "status": "success",
        "data": {
            "parameter_pollution_tests": [],
            "array_injection_vulnerable": True,
            "array_injection_url": array_url,
            "array_injection_status_code": 200,
            "custom_tests": {},
            "description": "Session puzzling occurs when attackers can overwrite session variables via URL parameters",
        },
    }
    monkeypatch.setattr(
        "multi_agent_system.agents.session_management_agent.MCPClient",
        lambda: _fake_mcp(payload),
    )

    await agent.run()

    finding = _finding(agent, "WSTG-SESS-08", "array injection")
    ev = finding["evidence"]
    assert ev != {"array_injection": True}
    assert ev["endpoint"] == array_url
    assert ev["status_code"] == 200
    assert "payload" in ev


async def test_variable_pollution_finding_evidence_carries_reflected_value(monkeypatch):
    agent = _agent("test_session_puzzling")
    payload = {
        "status": "success",
        "data": {
            "parameter_pollution_tests": [
                {
                    "variable": "role",
                    "test_url": "https://example.com?role=attacker_value&role=1&session[role]=malicious",
                    "reflected_in_response": True,
                    "reflected_value": "attacker_value",
                    "status_code": 200,
                },
                {
                    "variable": "admin",
                    "test_url": "https://example.com?admin=attacker_value&admin=1&session[admin]=malicious",
                    "reflected_in_response": False,
                    "reflected_value": None,
                    "status_code": 200,
                },
            ],
            "array_injection_vulnerable": False,
            "array_injection_url": "https://example.com?_SESSION[user]=attacker&_SESSION[role]=admin",
            "array_injection_status_code": 200,
            "custom_tests": {},
            "description": "Session puzzling occurs when attackers can overwrite session variables via URL parameters",
        },
    }
    monkeypatch.setattr(
        "multi_agent_system.agents.session_management_agent.MCPClient",
        lambda: _fake_mcp(payload),
    )

    await agent.run()

    finding = _finding(agent, "WSTG-SESS-08", "pollution")
    ev = finding["evidence"]
    reflected = ev["reflected_variables"]
    assert reflected == [{
        "variable": "role",
        "reflected_value": "attacker_value",
        "test_url": "https://example.com?role=attacker_value&role=1&session[role]=malicious",
    }]


# ============================================================================
# Sites 4 & 5: session hijacking (agent ~407-412) -- HttpOnly evidence must
# carry the real cookie name + endpoint. Session-reuse-after-logout evidence
# must carry the real logout endpoint tested, not a hardcoded bool.
# ============================================================================

async def test_httponly_and_session_reuse_findings_carry_real_detail(monkeypatch):
    agent = _agent("test_session_hijacking")
    agent.get_auth_session = lambda: {
        "cookies": {"sid": "abc123"},
        "logout_url": "https://example.com/api/logout",
    }
    payload = {
        "status": "success",
        "data": {
            "token_analysis": [],
            "httponly_protection": False,
            "httponly_cookie_name": "sid",
            "session_reusable_after_logout": True,
            "logout_url_tested": "https://example.com/api/logout",
            "description": "Strong sessions need: high entropy (128+ bits), HTTPOnly flag, invalidation after logout",
        },
    }
    captured = {}

    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            captured["args"] = args
            return payload

    monkeypatch.setattr(
        "multi_agent_system.agents.session_management_agent.MCPClient",
        lambda: FakeMCP(),
    )

    await agent.run()

    httponly_finding = _finding(agent, "WSTG-SESS-09", "HTTPOnly")
    ev = httponly_finding["evidence"]
    assert ev != {"httponly": False}
    assert ev["cookie_name"] == "sid"
    assert ev["endpoint"] == "https://example.com"

    reuse_finding = _finding(agent, "WSTG-SESS-09", "logout")
    ev2 = reuse_finding["evidence"]
    assert ev2 != {"session_reuse": True}
    assert ev2["logout_url_tested"] == "https://example.com/api/logout"

    # Agent must forward a real logout URL from auth context, not rely on the
    # tool's own /profile-or-/dashboard string-guessing.
    assert captured["args"]["logout_url"] == "https://example.com/api/logout"


# ============================================================================
# Site 6: test_session_hijacking's logout-URL guessing (tool ~373-380) must
# not silently no-op to session_reusable=None -- it should accept a real
# logout_url, or explicitly report it could not determine reuse.
# ============================================================================

async def test_session_hijacking_uses_explicit_logout_url_when_provided(monkeypatch):
    module = _load_session_tool()
    calls = []

    async def fake_quick_req(method, url, auth_session=None, **kwargs):
        calls.append(url)
        if url == "https://example.com/account":
            return FakeResp(200, text="ok")
        if url == "https://example.com/api/logout":
            return FakeResp(200, text="logged out")
        return FakeResp(404)

    monkeypatch.setattr(module, "quick_req", fake_quick_req)

    result = await module.test_session_hijacking(
        "https://example.com/account",
        {"sid": "abc123"},
        logout_url="https://example.com/api/logout",
    )
    data = result["data"]
    assert "https://example.com/api/logout" in calls
    assert data["logout_url_tested"] == "https://example.com/api/logout"
    assert data.get("logout_test_skipped_reason") is None


async def test_session_hijacking_explicitly_reports_skip_when_no_logout_url_available(monkeypatch):
    module = _load_session_tool()

    async def fake_quick_req(method, url, auth_session=None, **kwargs):
        return FakeResp(200, text="ok")

    monkeypatch.setattr(module, "quick_req", fake_quick_req)

    # No logout_url provided, and URL doesn't contain /profile or /dashboard,
    # so the old code guessed a logout URL == url (no-op) and silently set
    # session_reusable_after_logout=None with no explanation.
    result = await module.test_session_hijacking(
        "https://example.com/account",
        {"sid": "abc123"},
    )
    data = result["data"]
    assert data["session_reusable_after_logout"] is None
    assert data.get("logout_test_skipped_reason"), "must explicitly report why reuse could not be determined"


# ============================================================================
# Site 7: test_session_timeout (tool ~173) must issue a control request with
# an invalidated cookie and only flag "timeout not enforced" when the
# original session's 200 differs from the control's non-200/redirect.
# ============================================================================

async def test_session_timeout_flags_only_when_control_request_differs(monkeypatch):
    module = _load_session_tool()

    async def fake_quick_req(method, url, auth_session=None, **kwargs):
        cookies = kwargs.get("cookies")
        if cookies == {"sid": "real"}:
            return FakeResp(200)
        return FakeResp(302)  # garbage cookie -> redirected: page genuinely needs auth

    monkeypatch.setattr(module, "quick_req", fake_quick_req)

    result = await module.test_session_timeout(
        "https://example.com/profile", {"cookies": {"sid": "real"}}, wait_seconds=0
    )
    data = result["data"]
    assert data["session_still_valid"] is True
    assert data["control_status_code"] == 302


async def test_session_timeout_does_not_flag_when_page_is_public(monkeypatch):
    module = _load_session_tool()

    async def fake_quick_req(method, url, auth_session=None, **kwargs):
        # Both the real session cookie and the garbage control cookie get 200:
        # this is just a public page, not an unenforced timeout.
        return FakeResp(200)

    monkeypatch.setattr(module, "quick_req", fake_quick_req)

    result = await module.test_session_timeout(
        "https://example.com/public", {"cookies": {"sid": "real"}}, wait_seconds=0
    )
    data = result["data"]
    assert data["session_still_valid"] is False
    assert data["control_status_code"] == 200
