# multi_agent_system/tests/test_top_level_replanner.py
from multi_agent_system.core.config import Settings


def test_adaptive_replan_defaults_off(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_REPLAN", raising=False)
    assert Settings().adaptive_replan is False


def test_adaptive_replan_reads_env(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_REPLAN", "true")
    assert Settings().adaptive_replan is True


import asyncio
from unittest.mock import AsyncMock
from multi_agent_system.utils.simple_llm_client import SimpleLLMClient


def _bare_client():
    return SimpleLLMClient.__new__(SimpleLLMClient)


def test_propose_agent_reorder_returns_permutation():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value='{"order": ["B", "A", "C"]}')
    out = asyncio.run(c.propose_agent_reorder(
        remaining_agents=["A", "B", "C"], findings_summary="SQLi found"))
    assert out == ["B", "A", "C"]


def test_propose_agent_reorder_rejects_dropped_agent():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value='{"order": ["B", "A"]}')  # C missing
    out = asyncio.run(c.propose_agent_reorder(
        remaining_agents=["A", "B", "C"], findings_summary="x"))
    assert out is None


def test_propose_agent_reorder_none_on_unparseable():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value="not json at all")
    out = asyncio.run(c.propose_agent_reorder(
        remaining_agents=["A", "B"], findings_summary="x"))
    assert out is None


from multi_agent_system.orchestrator import Orchestrator


def test_apply_reorder_permutes_tail():
    orch = Orchestrator.__new__(Orchestrator)
    plan = ["Recon", "A", "B", "C", "ReportGenerationAgent"]
    assert orch._apply_reorder(plan, 0, ["B", "C", "A"]) is True
    assert plan == ["Recon", "B", "C", "A", "ReportGenerationAgent"]


def test_apply_reorder_pins_report_last():
    orch = Orchestrator.__new__(Orchestrator)
    plan = ["Recon", "A", "B", "ReportGenerationAgent"]
    orch._apply_reorder(plan, 0, ["B", "A"])
    assert plan[-1] == "ReportGenerationAgent"


def test_apply_reorder_rejects_dropped_agent():
    orch = Orchestrator.__new__(Orchestrator)
    plan = ["Recon", "A", "B", "C", "ReportGenerationAgent"]
    assert orch._apply_reorder(plan, 0, ["B", "A"]) is False  # C dropped
    assert plan == ["Recon", "A", "B", "C", "ReportGenerationAgent"]


def test_apply_reorder_rejects_added_agent():
    orch = Orchestrator.__new__(Orchestrator)
    plan = ["Recon", "A", "B", "ReportGenerationAgent"]
    assert orch._apply_reorder(plan, 0, ["A", "B", "X"]) is False
    assert plan == ["Recon", "A", "B", "ReportGenerationAgent"]


import asyncio as _asyncio
from unittest.mock import MagicMock, AsyncMock, patch


def test_replan_noop_when_flag_off():
    orch = Orchestrator.__new__(Orchestrator)
    plan = ["Recon", "A", "B", "ReportGenerationAgent"]
    with patch("multi_agent_system.orchestrator.settings") as s:
        s.adaptive_reorder = False
        orch._replan_remaining_agents(plan, 0)
    assert plan == ["Recon", "A", "B", "ReportGenerationAgent"]


def test_replan_applies_when_flag_on():
    orch = Orchestrator.__new__(Orchestrator)
    orch.cumulative_summary = "SQLi found"
    plan = ["Recon", "A", "B", "C", "ReportGenerationAgent"]
    summarizer = MagicMock()
    summarizer.propose_agent_reorder = AsyncMock(return_value=["C", "A", "B"])
    loop = _asyncio.new_event_loop()
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop", return_value=loop):
        s.adaptive_reorder = True
        orch._replan_remaining_agents(plan, 0)
    loop.close()
    assert plan == ["Recon", "C", "A", "B", "ReportGenerationAgent"]


def test_replan_noop_when_summarizer_none():
    orch = Orchestrator.__new__(Orchestrator)
    orch.cumulative_summary = "x"
    plan = ["Recon", "A", "B", "ReportGenerationAgent"]
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=None):
        s.adaptive_reorder = True
        orch._replan_remaining_agents(plan, 0)
    assert plan == ["Recon", "A", "B", "ReportGenerationAgent"]
