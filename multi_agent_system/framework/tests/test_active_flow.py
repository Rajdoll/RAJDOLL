import pytest
import httpx
from multi_agent_system.framework.types import EndpointSpec
from multi_agent_system.framework.active_flow import ActiveFlowTester, FlowResult, SessionRef


def test_flow_result_construct():
    r = FlowResult(success=True, proof_type="exploit_success",
                    evidence={"a": 1}, severity="high")
    assert r.success is True
    assert r.proof_type == "exploit_success"
    assert r.evidence == {"a": 1}
    assert r.severity == "high"


def test_active_flow_tester_construct():
    tester = ActiveFlowTester()
    assert tester is not None


@pytest.mark.asyncio
async def test_csrf_succeeds_when_no_token_required():
    """Endpoint accepts POST without CSRF token from different origin -> vulnerable."""
    calls = []
    def handler(req):
        calls.append({"url": str(req.url), "origin": req.headers.get("origin"),
                       "referer": req.headers.get("referer")})
        # Both A (same-origin) and B (cross-origin) return 200 + state change
        return httpx.Response(200, json={"status": "ok", "changed": True})

    tester = ActiveFlowTester()
    ep = EndpointSpec(url="http://target.test/api/change", method="POST")
    session = SessionRef(cookies={"session": "abc"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tester._http_client = client   # inject
        result = await tester.test_csrf(ep, session)
    assert result.success is True
    assert result.proof_type == "verified_state_change"
    assert result.severity in ("high", "critical")


@pytest.mark.asyncio
async def test_csrf_blocked_when_cross_origin_rejected():
    """Endpoint rejects cross-origin POST -> safe."""
    def handler(req):
        if req.headers.get("origin", "") and "target.test" not in req.headers.get("origin", ""):
            return httpx.Response(403, json={"error": "CSRF"})
        return httpx.Response(200, json={"changed": True})
    tester = ActiveFlowTester()
    ep = EndpointSpec(url="http://target.test/api/change", method="POST")
    session = SessionRef(cookies={"session": "abc"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tester._http_client = client
        result = await tester.test_csrf(ep, session)
    assert result.success is False


@pytest.mark.asyncio
async def test_password_reset_detects_user_enumeration():
    """Valid email returns different response than invalid -> user enumeration."""
    def handler(req):
        import json
        body_bytes = b""
        # httpx MockTransport - req.content has the body
        try:
            body_str = req.content.decode("utf-8") if req.content else ""
        except Exception:
            body_str = ""
        if "valid@target.test" in body_str or "valid@target.test" in str(req.url):
            return httpx.Response(200, text="Reset link sent")
        else:
            return httpx.Response(200, text="No account found")
    tester = ActiveFlowTester()
    ep = EndpointSpec(url="http://target.test/api/reset", method="POST",
                      params=["email"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tester._http_client = client
        result = await tester.test_password_reset(ep, valid_identity="valid@target.test")
    assert result.success is True
    assert "enumeration" in result.evidence.get("issue", "").lower()
