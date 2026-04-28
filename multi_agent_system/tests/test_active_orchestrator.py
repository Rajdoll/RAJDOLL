import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from multi_agent_system.utils.orchestrator_directive import (
    OrchestratorDirective, merge_directives, NEVER_SKIP
)
from multi_agent_system.utils.simple_llm_client import SimpleLLMClient

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


def test_generate_orchestrator_directive_parses_valid_response():
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client.provider = "openai"
    client.model = "gpt-4o-mini"
    client._strip_thinking_tags = lambda x: x

    llm_response = '''{
        "skip_agents": ["WeakCryptographyAgent"],
        "focus_instructions": {"AuthorizationAgent": "focus IDOR on /api/users/"},
        "inject_tools": {},
        "reasoning": "Auth bypass found; skip crypto, deepen authz"
    }'''

    async def _run():
        with patch.object(client, 'chat_completion', new=AsyncMock(return_value=llm_response)):
            result = await client.generate_orchestrator_directive(
                completed_agent="AuthenticationAgent",
                remaining_agents=["SessionManagementAgent", "InputValidationAgent", "AuthorizationAgent"],
                agent_summary="Found JWT none-algorithm bypass",
                cumulative_summary="Auth: JWT bypass. Session: cookie httponly missing.",
            )
        return result

    directive = asyncio.run(_run())
    assert directive is not None
    assert "WeakCryptographyAgent" in directive.skip_agents
    assert "AuthorizationAgent" in directive.focus_instructions
    assert "IDOR" in directive.focus_instructions["AuthorizationAgent"]


def test_generate_orchestrator_directive_returns_none_on_bad_json():
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client.provider = "openai"
    client.model = "gpt-4o-mini"
    client._strip_thinking_tags = lambda x: x

    async def _run():
        with patch.object(client, 'chat_completion', new=AsyncMock(side_effect=Exception("HTTP 500"))):
            return await client.generate_orchestrator_directive(
                completed_agent="AuthenticationAgent",
                remaining_agents=["AuthorizationAgent"],
                agent_summary="No findings",
                cumulative_summary="",
            )

    assert asyncio.run(_run()) is None
