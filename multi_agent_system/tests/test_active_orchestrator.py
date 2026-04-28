import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
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


def test_review_round1_selects_escalation_tools():
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client.provider = "openai"
    client.model = "gpt-4o-mini"
    client._strip_thinking_tags = lambda x: x

    llm_response = '''{
        "round2_tools": [
            {"tool": "run_sqlmap", "server": "input-validation-testing",
             "arguments": {"url": "http://juice-shop:3000/rest/products/search?q=test", "level": 5},
             "reason": "search endpoint reflected input in error — union injection likely"}
        ]
    }'''

    async def _run():
        with patch.object(client, 'chat_completion', new=AsyncMock(return_value=llm_response)):
            return await client.review_round1_for_escalation(
                agent_name="InputValidationAgent",
                tool_server_map={"run_sqlmap": "input-validation-testing"},
                round1_summary="run_sqlmap on /login: no vuln. test_sqli on /search?q=: SQL error in response.",
            )

    tools = asyncio.run(_run())
    assert len(tools) == 1
    assert tools[0]["tool"] == "run_sqlmap"
    assert tools[0]["server"] == "input-validation-testing"


def test_review_round1_returns_empty_when_nothing_interesting():
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client.provider = "openai"
    client.model = "gpt-4o-mini"
    client._strip_thinking_tags = lambda x: x

    llm_response = '{"round2_tools": []}'

    async def _run():
        with patch.object(client, 'chat_completion', new=AsyncMock(return_value=llm_response)):
            return await client.review_round1_for_escalation(
                agent_name="ErrorHandlingAgent",
                tool_server_map={"check_stack_traces": "error-handling-testing"},
                round1_summary="No error disclosure found.",
            )

    assert asyncio.run(_run()) == []


def test_skip_guardrail_recon_and_report_never_skipped():
    directive = OrchestratorDirective(
        skip_agents=["ReconnaissanceAgent", "ReportGenerationAgent", "WeakCryptographyAgent"]
    )
    result = merge_directives(OrchestratorDirective(), directive)
    assert "ReconnaissanceAgent" not in result.skip_agents
    assert "ReportGenerationAgent" not in result.skip_agents
    assert "WeakCryptographyAgent" in result.skip_agents


def test_focus_injected_into_director_instructions_text():
    directive = OrchestratorDirective(
        focus_instructions={"InputValidationAgent": "focus SSTI on /profile/bio"}
    )
    ctx = {}
    agent_name = "InputValidationAgent"
    focus = directive.focus_instructions.get(agent_name)
    if focus:
        ctx["llm_orchestrator_focus"] = focus
        existing = ctx.get("director_instructions_text", "")
        ctx["director_instructions_text"] = f"{existing}\nLLM ORCHESTRATOR FOCUS: {focus}".strip()

    assert "SSTI" in ctx.get("director_instructions_text", "")
    assert "SSTI" in ctx.get("llm_orchestrator_focus", "")


def _make_agent():
    """Create a BaseAgent-like object without DB access for unit testing."""
    from multi_agent_system.agents.base_agent import BaseAgent
    agent = object.__new__(BaseAgent)
    agent.job_id = 999
    agent.agent_name = "TestAgent"
    agent._tool_arguments_map = {}
    agent.tool_plan = {"tools": ["tool_a", "tool_b"], "reasoning": "test"}
    agent.log = MagicMock()
    return agent


def test_inject_directive_tools_adds_new_tools():
    agent = _make_agent()
    agent._inject_directive_tools([
        {"tool": "tool_c", "arguments": {"url": "http://example.com"}}
    ])
    assert "tool_c" in agent.tool_plan["tools"]
    assert agent._tool_arguments_map.get("tool_c") == {"url": "http://example.com"}


def test_inject_directive_tools_skips_duplicates():
    agent = _make_agent()
    original_count = len(agent.tool_plan["tools"])
    agent._inject_directive_tools([{"tool": "tool_a", "arguments": {}}])
    assert len(agent.tool_plan["tools"]) == original_count


def test_inject_directive_tools_handles_no_tool_plan():
    agent = _make_agent()
    agent.tool_plan = None
    agent._inject_directive_tools([{"tool": "tool_x"}])
    # Should not raise, just log warning
    agent.log.assert_called()
