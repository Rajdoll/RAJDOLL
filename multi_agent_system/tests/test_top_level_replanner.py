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
