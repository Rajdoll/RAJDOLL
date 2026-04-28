import pytest
from multi_agent_system.utils.orchestrator_directive import (
    OrchestratorDirective, merge_directives, NEVER_SKIP
)

def test_merge_directives_union_skips():
    a = OrchestratorDirective(skip_agents=["SessionManagementAgent"])
    b = OrchestratorDirective(skip_agents=["AuthorizationAgent"])
    result = merge_directives(a, b)
    assert set(result.skip_agents) == {"SessionManagementAgent", "AuthorizationAgent"}

def test_merge_directives_focus_overwrites():
    a = OrchestratorDirective(focus_instructions={"InputValidationAgent": "focus on SQL"})
    b = OrchestratorDirective(focus_instructions={"InputValidationAgent": "focus on XSS"})
    result = merge_directives(a, b)
    assert result.focus_instructions["InputValidationAgent"] == "focus on XSS"

def test_merge_directives_inject_tools_appends():
    a = OrchestratorDirective(inject_tools={"InputValidationAgent": [{"tool": "run_sqlmap"}]})
    b = OrchestratorDirective(inject_tools={"InputValidationAgent": [{"tool": "test_xss_dalfox"}]})
    result = merge_directives(a, b)
    tools = [t["tool"] for t in result.inject_tools["InputValidationAgent"]]
    assert tools == ["run_sqlmap", "test_xss_dalfox"]

def test_never_skip_blocklist():
    d = OrchestratorDirective(skip_agents=["ReconnaissanceAgent", "AuthenticationAgent"])
    result = merge_directives(OrchestratorDirective(), d)
    assert "ReconnaissanceAgent" not in result.skip_agents
    assert "AuthenticationAgent" in result.skip_agents

def test_roundtrip_serialization():
    d = OrchestratorDirective(
        skip_agents=["ErrorHandlingAgent"],
        focus_instructions={"AuthorizationAgent": "test IDOR on /api/users/"},
        inject_tools={"SessionManagementAgent": [{"tool": "test_session_fixation", "arguments": {}}]},
        reasoning="JWT vulnerabilities found — skip low-value agents",
    )
    assert OrchestratorDirective.from_dict(d.to_dict()) == d
