import pytest
from unittest.mock import MagicMock, patch


def _make_agent(agent_name="InputValidationAgent"):
    from multi_agent_system.agents.base_agent import BaseAgent
    agent = BaseAgent.__new__(BaseAgent)
    agent.agent_name = agent_name
    agent.job_id = 1
    agent._shared_context_snapshot = {"tech_stack": {"backend": "Node.js"}}
    agent.log = MagicMock()
    agent.context_manager = MagicMock()
    return agent


def test_server_for_tool_uses_tool_server_map():
    agent = _make_agent()
    agent._get_tool_server_map = MagicMock(return_value={"test_sqli": "input-validation-testing"})
    assert agent._server_for_tool("test_sqli") == "input-validation-testing"


def test_server_for_tool_returns_none_for_unknown():
    agent = _make_agent()
    agent._get_tool_server_map = MagicMock(return_value={})
    assert agent._server_for_tool("nonexistent_tool") is None


def test_build_slot_args_includes_url_and_params():
    from multi_agent_system.core.slot_registry import TestSlot
    from multi_agent_system.core.wstg_catalog import load_catalog
    agent = _make_agent()
    slot = TestSlot.make("http://t/api/products", "GET", "WSTG-INPV-05", load_catalog())
    slot.params = ["q", "category"]
    args = agent._build_slot_args(slot)
    assert args["url"] == "http://t/api/products"
    assert args["params"] == ["q", "category"]


def test_persist_slot_statuses_writes_to_context():
    from multi_agent_system.core.slot_registry import TestSlot
    from multi_agent_system.core.wstg_catalog import load_catalog
    agent = _make_agent()
    slot = TestSlot.make("http://t/", "GET", "WSTG-INPV-05", load_catalog())
    slot.status = "vulnerable"
    agent._persist_slot_statuses([slot])
    agent.context_manager.write.assert_called_once()
    call_args = agent.context_manager.write.call_args
    assert call_args[0][0] == "test_slots_status"


import asyncio
from unittest.mock import AsyncMock


@pytest.mark.asyncio
async def test_run_test_slots_marks_vulnerable_on_findings():
    from multi_agent_system.core.slot_registry import TestSlot
    from multi_agent_system.core.wstg_catalog import load_catalog
    agent = _make_agent()
    agent._get_tool_server_map = MagicMock(return_value={"test_sqli": "input-validation-testing"})
    agent._execute_with_retry_on_empty = AsyncMock(
        return_value={"status": "success", "findings": [{"id": 1}]}
    )
    slot = TestSlot.make("http://t/api", "GET", "WSTG-INPV-05", load_catalog())
    await agent.run_test_slots([slot], time_budget_s=60.0)
    assert slot.status == "vulnerable"
    assert slot.finding_count == 1


@pytest.mark.asyncio
async def test_run_test_slots_marks_tested_clean_on_empty_findings():
    from multi_agent_system.core.slot_registry import TestSlot
    from multi_agent_system.core.wstg_catalog import load_catalog
    agent = _make_agent()
    agent._get_tool_server_map = MagicMock(return_value={"test_sqli": "input-validation-testing"})
    agent._execute_with_retry_on_empty = AsyncMock(
        return_value={"status": "success", "findings": []}
    )
    slot = TestSlot.make("http://t/api", "GET", "WSTG-INPV-05", load_catalog())
    await agent.run_test_slots([slot], time_budget_s=60.0)
    assert slot.status == "tested-clean"


@pytest.mark.asyncio
async def test_run_test_slots_skips_slot_with_no_mapped_tools():
    from multi_agent_system.core.slot_registry import TestSlot
    from multi_agent_system.core.wstg_catalog import load_catalog, tools_for_subtest
    agent = _make_agent()
    agent._get_tool_server_map = MagicMock(return_value={})
    agent._execute_with_retry_on_empty = AsyncMock()
    cat = load_catalog()
    unmapped = [k for k in cat if not tools_for_subtest(k)]
    if not unmapped:
        pytest.skip("All sub-tests have tool mappings")
    slot = TestSlot.make("http://t/", "GET", unmapped[0], cat)
    await agent.run_test_slots([slot], time_budget_s=60.0)
    assert slot.status == "skipped"
    agent._execute_with_retry_on_empty.assert_not_called()


@pytest.mark.asyncio
async def test_run_test_slots_respects_time_budget():
    from multi_agent_system.core.slot_registry import TestSlot
    from multi_agent_system.core.wstg_catalog import load_catalog
    agent = _make_agent()
    agent._get_tool_server_map = MagicMock(return_value={"test_sqli": "input-validation-testing"})

    call_count = 0
    async def slow_execute(**kw):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.15)
        return {"status": "success", "findings": []}
    agent._execute_with_retry_on_empty = slow_execute

    cat = load_catalog()
    slots = [TestSlot.make("http://t/api", "GET", "WSTG-INPV-05", cat) for _ in range(10)]
    await agent.run_test_slots(slots, time_budget_s=0.3)
    skipped = [s for s in slots if s.status == "skipped"]
    assert len(skipped) > 0
