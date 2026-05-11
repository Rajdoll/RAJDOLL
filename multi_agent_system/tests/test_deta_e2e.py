from multi_agent_system.core.wstg_catalog import load_catalog
from multi_agent_system.orchestrator import AGENT_TO_OWASP_MAP


def test_every_non_report_agent_has_at_least_one_subtest():
    cat = load_catalog()
    owners = {st.owasp_agent for st in cat.values()}
    for agent in AGENT_TO_OWASP_MAP:
        if agent == "ReportGenerationAgent":
            continue
        assert agent in owners, f"{agent} owns zero sub-tests in catalog"


def test_build_and_persist_test_slots_writes_to_context(monkeypatch):
    from unittest.mock import MagicMock, AsyncMock
    from multi_agent_system.orchestrator import Orchestrator
    orch = Orchestrator.__new__(Orchestrator)
    orch.job_id = 99
    orch.shared_context = {
        "endpoint_inventory": {
            "endpoints": [
                {"url": "http://t/api/products", "method": "GET", "params": ["q"], "content_type": ""},
            ]
        },
        "tech_stack": {"backend": "Node.js"},
    }
    orch.context_manager = MagicMock()

    fake_llm = MagicMock()
    fake_llm.tag_endpoints_with_subtests = AsyncMock(
        return_value={"http://t/api/products": ["WSTG-INPV-05"]}
    )
    monkeypatch.setattr(Orchestrator, "_get_llm_summarizer", lambda self: fake_llm)

    import asyncio
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(Orchestrator, "_ensure_event_loop", lambda self: loop)

    orch._build_and_persist_test_slots()

    orch.context_manager.write.assert_called_once()
    key = orch.context_manager.write.call_args[0][0]
    assert key == "test_slots"
    loop.close()


def test_inject_test_slots_for_agent_adds_my_test_slots():
    from multi_agent_system.orchestrator import Orchestrator
    from multi_agent_system.core.slot_registry import TestSlot, TestSlotRegistry
    cat = load_catalog()
    slot = TestSlot.make("http://t/api", "GET", "WSTG-INPV-05", cat)
    reg = TestSlotRegistry([slot])
    orch = Orchestrator.__new__(Orchestrator)
    orch.shared_context = {}
    shared_ctx = {"test_slots": reg.to_dict()}
    result = orch._inject_test_slots_for_agent(shared_ctx, "InputValidationAgent")
    assert "my_test_slots" in result
    assert len(result["my_test_slots"]) == 1
    assert result["my_test_slots"][0]["wstg_id"] == "WSTG-INPV-05"
