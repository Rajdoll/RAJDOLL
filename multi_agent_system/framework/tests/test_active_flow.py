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
