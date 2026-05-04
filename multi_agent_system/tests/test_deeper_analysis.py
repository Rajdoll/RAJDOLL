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


# ── Orchestrator tests ────────────────────────────────────────────────────────

def _make_fake_orchestrator(mock_llm, writes):
    """Construct a minimal Orchestrator instance for unit testing."""
    import asyncio

    class FakeContextManager:
        def write(self, key, value):
            writes[key] = value
        def read(self, key):
            return writes.get(key)

    with patch("multi_agent_system.orchestrator.build_task_tree", return_value=""), \
         patch.object(
             __import__("multi_agent_system.orchestrator", fromlist=["Orchestrator"]).Orchestrator,
             "_collect_agent_findings_text", return_value="raw findings text"
         ), \
         patch.object(
             __import__("multi_agent_system.orchestrator", fromlist=["Orchestrator"]).Orchestrator,
             "_get_llm_summarizer", return_value=mock_llm
         ), \
         patch.object(
             __import__("multi_agent_system.orchestrator", fromlist=["Orchestrator"]).Orchestrator,
             "_ensure_event_loop", return_value=asyncio.new_event_loop()
         ):
        from multi_agent_system.orchestrator import Orchestrator
        orc = object.__new__(Orchestrator)
        orc.job_id = 1
        orc.cumulative_summary = ""
        orc._timing_summarization_s = 0.0
        orc.context_manager = FakeContextManager()
        return orc


def test_orchestrator_stores_agent_analyses_in_shared_context():
    """_summarize_agent_and_accumulate must write agent_analyses to SharedContext."""
    import asyncio

    mock_llm = MagicMock()
    mock_llm.summarize_agent_findings = AsyncMock(return_value={
        "summary": "SQL injection found.",
        "root_causes": [{"finding": "SQLi", "root_cause": "Raw query", "why_it_exists": "No ORM"}],
        "impact_chains": [{"finding": "SQLi", "steps": ["Dump DB"], "worst_case": "Full DB access"}]
    })

    writes = {}

    with patch("multi_agent_system.orchestrator.build_task_tree", return_value=""), \
         patch("multi_agent_system.orchestrator.Orchestrator._collect_agent_findings_text", return_value="raw"), \
         patch("multi_agent_system.orchestrator.Orchestrator._get_llm_summarizer", return_value=mock_llm), \
         patch("multi_agent_system.orchestrator.Orchestrator._ensure_event_loop", return_value=asyncio.new_event_loop()):

        from multi_agent_system.orchestrator import Orchestrator

        class FakeContextManager:
            def write(self, key, value): writes[key] = value
            def read(self, key): return writes.get(key)

        orc = object.__new__(Orchestrator)
        orc.job_id = 1
        orc.cumulative_summary = ""
        orc._timing_summarization_s = 0.0
        orc.context_manager = FakeContextManager()
        orc._summarize_agent_and_accumulate("InputValidationAgent")

    assert "agent_analyses" in writes, "agent_analyses must be written to SharedContext"
    assert "InputValidationAgent" in writes["agent_analyses"]
    analysis = writes["agent_analyses"]["InputValidationAgent"]
    assert "root_causes" in analysis
    assert "impact_chains" in analysis
    assert len(analysis["root_causes"]) == 1


def test_orchestrator_cumulative_summary_still_gets_text():
    """cumulative_summary must still accumulate summary text (backward compat)."""
    import asyncio

    mock_llm = MagicMock()
    mock_llm.summarize_agent_findings = AsyncMock(return_value={
        "summary": "XSS found at /search.",
        "root_causes": [],
        "impact_chains": []
    })

    writes = {}

    with patch("multi_agent_system.orchestrator.build_task_tree", return_value=""), \
         patch("multi_agent_system.orchestrator.Orchestrator._collect_agent_findings_text", return_value="raw"), \
         patch("multi_agent_system.orchestrator.Orchestrator._get_llm_summarizer", return_value=mock_llm), \
         patch("multi_agent_system.orchestrator.Orchestrator._ensure_event_loop", return_value=asyncio.new_event_loop()):

        from multi_agent_system.orchestrator import Orchestrator

        class FakeContextManager:
            def write(self, key, value): writes[key] = value
            def read(self, key): return writes.get(key)

        orc = object.__new__(Orchestrator)
        orc.job_id = 1
        orc.cumulative_summary = ""
        orc._timing_summarization_s = 0.0
        orc.context_manager = FakeContextManager()
        orc._summarize_agent_and_accumulate("ClientSideAgent")

    assert "XSS found at /search." in writes.get("cumulative_summary", "")
