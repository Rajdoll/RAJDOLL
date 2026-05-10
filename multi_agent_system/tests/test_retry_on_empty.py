import pytest
from unittest.mock import MagicMock, AsyncMock, patch


@pytest.mark.asyncio
async def test_retry_invoked_on_empty_findings_high_risk(monkeypatch):
    from multi_agent_system.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.agent_name = "InputValidationAgent"
    agent.job_id = 1
    agent._shared_context_snapshot = {"tech_stack": {"server": "nginx"}}
    agent._tool_retry_counter = {}
    agent.log = MagicMock()

    llm = MagicMock()
    llm.propose_retry_arguments = AsyncMock(
        return_value={"args": {"vector": "blind"}, "rationale": "try blind"}
    )
    agent._llm_client = llm

    calls = []
    async def fake_execute(*, server, tool, args, **kw):
        calls.append((tool, dict(args)))
        return {"status": "success", "findings": []}
    agent.execute_tool = fake_execute  # type: ignore[method-assign]

    result = await agent._execute_with_retry_on_empty(
        server="input-validation-testing",
        tool="test_sqli",
        args={"url": "http://x/api/products"},
        subtest_id="WSTG-INPV-05",
    )
    assert len(calls) == 2
    # second call has the LLM-proposed override merged in
    assert calls[1][1].get("vector") == "blind"


@pytest.mark.asyncio
async def test_no_retry_for_low_risk_subtest(monkeypatch):
    from multi_agent_system.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.agent_name = "ReconnaissanceAgent"
    agent.job_id = 1
    agent._shared_context_snapshot = {}
    agent._tool_retry_counter = {}
    agent.log = MagicMock()
    agent._llm_client = MagicMock()
    agent._llm_client.propose_retry_arguments = AsyncMock()

    calls = []
    async def fake_execute(*, server, tool, args, **kw):
        calls.append((tool, dict(args)))
        return {"status": "success", "findings": []}
    agent.execute_tool = fake_execute  # type: ignore[method-assign]

    # WSTG-INFO-03 is not high_risk in the catalog
    await agent._execute_with_retry_on_empty(
        server="info", tool="check_metafiles",
        args={"url": "http://x/"}, subtest_id="WSTG-INFO-03",
    )
    assert len(calls) == 1
    agent._llm_client.propose_retry_arguments.assert_not_called()


@pytest.mark.asyncio
async def test_no_retry_when_findings_present(monkeypatch):
    from multi_agent_system.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.agent_name = "InputValidationAgent"
    agent.job_id = 1
    agent._shared_context_snapshot = {}
    agent._tool_retry_counter = {}
    agent.log = MagicMock()
    agent._llm_client = MagicMock()
    agent._llm_client.propose_retry_arguments = AsyncMock()

    calls = []
    async def fake_execute(*, server, tool, args, **kw):
        calls.append((tool, dict(args)))
        return {"status": "success", "findings": [{"id": 1}]}
    agent.execute_tool = fake_execute  # type: ignore[method-assign]

    await agent._execute_with_retry_on_empty(
        server="x", tool="test_sqli", args={}, subtest_id="WSTG-INPV-05",
    )
    assert len(calls) == 1
    agent._llm_client.propose_retry_arguments.assert_not_called()


@pytest.mark.asyncio
async def test_retry_caps_at_two(monkeypatch):
    from multi_agent_system.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.agent_name = "InputValidationAgent"
    agent.job_id = 1
    agent._shared_context_snapshot = {}
    agent._tool_retry_counter = {("test_sqli", "WSTG-INPV-05"): 2}
    agent.log = MagicMock()
    agent._llm_client = MagicMock()
    agent._llm_client.propose_retry_arguments = AsyncMock(
        return_value={"args": {"vector": "blind"}}
    )

    calls = []
    async def fake_execute(*, server, tool, args, **kw):
        calls.append((tool, dict(args)))
        return {"status": "success", "findings": []}
    agent.execute_tool = fake_execute  # type: ignore[method-assign]

    await agent._execute_with_retry_on_empty(
        server="x", tool="test_sqli", args={}, subtest_id="WSTG-INPV-05",
    )
    assert len(calls) == 1
    agent._llm_client.propose_retry_arguments.assert_not_called()


@pytest.mark.asyncio
async def test_no_retry_when_subtest_not_in_catalog(monkeypatch):
    from multi_agent_system.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.agent_name = "X"
    agent.job_id = 1
    agent._shared_context_snapshot = {}
    agent._tool_retry_counter = {}
    agent.log = MagicMock()
    agent._llm_client = MagicMock()
    agent._llm_client.propose_retry_arguments = AsyncMock()

    calls = []
    async def fake_execute(*, server, tool, args, **kw):
        calls.append((tool, dict(args)))
        return {"status": "success", "findings": []}
    agent.execute_tool = fake_execute  # type: ignore[method-assign]

    await agent._execute_with_retry_on_empty(
        server="x", tool="x", args={}, subtest_id="WSTG-FAKE-99",
    )
    assert len(calls) == 1
    agent._llm_client.propose_retry_arguments.assert_not_called()
