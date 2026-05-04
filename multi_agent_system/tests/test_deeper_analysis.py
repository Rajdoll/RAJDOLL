# multi_agent_system/tests/test_deeper_analysis.py
"""Tests for enriched summarize_agent_findings() return schema."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.fixture
def llm_client():
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient
    with patch.dict("os.environ", {
        "LLM_PROVIDER": "openai",
        "LLM_API_KEY": "test-key",
        "LLM_MODEL": "gpt-4o-mini",
        "LLM_BASE_URL": "https://api.openai.com/v1",
    }):
        return SimpleLLMClient()


@pytest.mark.asyncio
async def test_summarize_returns_dict_with_required_keys(llm_client):
    """summarize_agent_findings() must return a dict with summary, root_causes, impact_chains."""
    mock_response = """{
        "summary": "Found SQL injection at /search endpoint.",
        "root_causes": [
            {
                "finding": "SQL Injection in /search",
                "root_cause": "Raw user input concatenated into SQL query",
                "why_it_exists": "No parameterized queries used in search handler"
            }
        ],
        "impact_chains": [
            {
                "finding": "SQL Injection in /search",
                "steps": ["Extract password hashes", "Crack hashes offline", "Login as admin"],
                "worst_case": "Full database dump and admin account takeover"
            }
        ]
    }"""
    with patch.object(llm_client, "chat_completion", new=AsyncMock(return_value=mock_response)):
        result = await llm_client.summarize_agent_findings(
            agent_name="InputValidationAgent",
            raw_outputs="sqlmap found SQLi at /rest/products/search",
            task_tree="INPV-01: pending"
        )
    assert isinstance(result, dict), "Must return dict, not str"
    assert "summary" in result
    assert "root_causes" in result
    assert "impact_chains" in result


@pytest.mark.asyncio
async def test_summarize_root_causes_schema(llm_client):
    """Each root_cause entry must have finding, root_cause, why_it_exists."""
    mock_response = """{
        "summary": "XSS found.",
        "root_causes": [{"finding": "XSS", "root_cause": "No output encoding", "why_it_exists": "Template renders raw HTML"}],
        "impact_chains": [{"finding": "XSS", "steps": ["Inject payload", "Steal cookie"], "worst_case": "Session hijack"}]
    }"""
    with patch.object(llm_client, "chat_completion", new=AsyncMock(return_value=mock_response)):
        result = await llm_client.summarize_agent_findings("ClientSideAgent", "xss found", "")
    rc = result["root_causes"][0]
    assert "finding" in rc
    assert "root_cause" in rc
    assert "why_it_exists" in rc


@pytest.mark.asyncio
async def test_summarize_impact_chains_schema(llm_client):
    """Each impact_chain entry must have finding, steps (list), worst_case."""
    mock_response = """{
        "summary": "IDOR found.",
        "root_causes": [{"finding": "IDOR", "root_cause": "No authz check", "why_it_exists": "Missing ownership validation"}],
        "impact_chains": [{"finding": "IDOR", "steps": ["Access other user data"], "worst_case": "Data breach"}]
    }"""
    with patch.object(llm_client, "chat_completion", new=AsyncMock(return_value=mock_response)):
        result = await llm_client.summarize_agent_findings("AuthorizationAgent", "idor found", "")
    ic = result["impact_chains"][0]
    assert "finding" in ic
    assert isinstance(ic["steps"], list)
    assert "worst_case" in ic


@pytest.mark.asyncio
async def test_summarize_empty_findings_returns_empty_arrays(llm_client):
    """When no findings, root_causes and impact_chains should be empty lists."""
    mock_response = '{"summary": "No vulnerabilities found.", "root_causes": [], "impact_chains": []}'
    with patch.object(llm_client, "chat_completion", new=AsyncMock(return_value=mock_response)):
        result = await llm_client.summarize_agent_findings("ErrorHandlingAgent", "no issues", "")
    assert result["root_causes"] == []
    assert result["impact_chains"] == []


@pytest.mark.asyncio
async def test_summarize_fallback_on_llm_failure(llm_client):
    """On LLM error, must return fallback dict (not crash, not return str)."""
    with patch.object(llm_client, "chat_completion", new=AsyncMock(side_effect=Exception("timeout"))):
        result = await llm_client.summarize_agent_findings("ReconnaissanceAgent", "raw output here", "")
    assert isinstance(result, dict)
    assert "summary" in result
    assert result["root_causes"] == []
    assert result["impact_chains"] == []
