"""Tests for key-mismatch bugs in business_logic_agent.py where the agent read
a key the underlying tool never returns, so a finding could never fire.

WSTG-BUSL-02 (line ~389): business-logic-testing/business-logic.py's
test_parameter_tampering (fixed in commit 86e14a1) returns
{"tampering_detected": bool, "original_response": ..., "tampered_response": ...,
"control_response": ..., "description": ...} -- it has never returned a
"vulnerable" key. The agent read data.get("vulnerable"), so the WSTG-BUSL-02
finding could never fire regardless of the tool's verdict.

WSTG-BUSL-05 (line ~440): test_forge_requests returns {"forgery_attempts": int,
"successful_bypasses": int (count of findings), "findings": [...],
"description": ...} -- it has never returned a "vulnerable" key either. The
agent read data.get("vulnerable"), so the critical forged-payment-request
finding could never fire regardless of successful_bypasses.
"""
from multi_agent_system.agents.business_logic_agent import BusinessLogicAgent


def _agent(tool_name):
    a = BusinessLogicAgent.__new__(BusinessLogicAgent)
    a.log = lambda *args, **kw: None
    a.log_tool_execution_plan = lambda: None
    a.get_auth_session = lambda: None
    a._get_target = lambda: "https://example.com"
    a._shared_context_snapshot = {
        "endpoint_inventory": {
            "by_tag": {"state_changing_money": ["ep1"]},
            "endpoints": [
                {"id": "ep1", "url": "https://example.com/api/basket/1?price=9.99"},
            ],
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


# Real return shape of the fixed test_parameter_tampering (commit 86e14a1).
_TAMPERING_DETECTED_DATA = {
    "tampering_detected": True,
    "original_response": {"status": 200, "length": 512},
    "tampered_response": {"status": 200, "length": 512},
    "control_response": {"status": 403, "length": 40},
    "description": (
        "If the tampered (parameter-removed) response matches the original "
        "but the control (bogus-value) response does not, the server is not "
        "re-validating data after parameter removal."
    ),
}


async def test_parameter_tampering_detected_adds_finding(monkeypatch):
    agent = _agent("test_parameter_tampering")

    monkeypatch.setattr(
        "multi_agent_system.agents.business_logic_agent.MCPClient",
        lambda: _fake_mcp({"status": "success", "data": dict(_TAMPERING_DETECTED_DATA)}),
    )

    await agent.run()

    assert any(args[0] == "WSTG-BUSL-02" and "Parameter tampering" in args[1] for args, kw in agent.findings), (
        f"expected a WSTG-BUSL-02 parameter-tampering finding, got {agent.findings}"
    )
    finding_kw = next(kw for args, kw in agent.findings if args[0] == "WSTG-BUSL-02" and "Parameter tampering" in args[1])
    evidence = finding_kw["evidence"]
    assert evidence["tampering_detected"] is True
    assert evidence["control_response"] == _TAMPERING_DETECTED_DATA["control_response"]


async def test_parameter_tampering_not_detected_adds_no_finding(monkeypatch):
    agent = _agent("test_parameter_tampering")

    not_detected_data = dict(_TAMPERING_DETECTED_DATA)
    not_detected_data["tampering_detected"] = False

    monkeypatch.setattr(
        "multi_agent_system.agents.business_logic_agent.MCPClient",
        lambda: _fake_mcp({"status": "success", "data": not_detected_data}),
    )

    await agent.run()

    assert agent.findings == []


# Real return shape of test_forge_requests (business-logic-testing/business-logic.py
# lines 364-428). It has never returned a "vulnerable" key -- only
# "forgery_attempts", "successful_bypasses" (a count: len(findings)), "findings",
# and "description". The agent read data.get("vulnerable"), so the WSTG-BUSL-05
# critical finding could never fire regardless of successful_bypasses.
_FORGE_BYPASS_DATA = {
    "forgery_attempts": 5,
    "successful_bypasses": 2,
    "findings": [
        {
            "test_name": "mark_as_paid",
            "forged_parameters": {"paid": True},
            "status_code": 200,
            "severity": "Critical",
            "description": "Payment bypass: mark_as_paid succeeded",
        },
        {
            "test_name": "modify_amount_zero",
            "forged_parameters": {"amount": 0},
            "status_code": 200,
            "severity": "Critical",
            "description": "Payment bypass: modify_amount_zero succeeded",
        },
    ],
    "description": "Payment systems must validate all order parameters server-side",
}


async def test_forge_requests_bypass_detected_adds_finding(monkeypatch):
    agent = _agent("test_forge_requests")

    monkeypatch.setattr(
        "multi_agent_system.agents.business_logic_agent.MCPClient",
        lambda: _fake_mcp({"status": "success", "data": dict(_FORGE_BYPASS_DATA)}),
    )

    await agent.run()

    assert any(args[0] == "WSTG-BUSL-05" for args, kw in agent.findings), (
        f"expected a WSTG-BUSL-05 forged-payment-request finding, got {agent.findings}"
    )
    finding_kw = next(kw for args, kw in agent.findings if args[0] == "WSTG-BUSL-05")
    evidence = finding_kw["evidence"]
    assert evidence["successful_bypasses"] == 2
    assert evidence["findings"] == _FORGE_BYPASS_DATA["findings"]


async def test_forge_requests_no_bypass_adds_no_finding(monkeypatch):
    agent = _agent("test_forge_requests")

    no_bypass_data = dict(_FORGE_BYPASS_DATA)
    no_bypass_data["successful_bypasses"] = 0
    no_bypass_data["findings"] = []

    monkeypatch.setattr(
        "multi_agent_system.agents.business_logic_agent.MCPClient",
        lambda: _fake_mcp({"status": "success", "data": no_bypass_data}),
    )

    await agent.run()

    assert agent.findings == []
