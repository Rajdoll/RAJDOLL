from multi_agent_system.core.config import Settings


def test_adaptive_reorder_defaults_off(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_REORDER", raising=False)
    assert Settings().adaptive_reorder is False


def test_adaptive_reorder_reads_env(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_REORDER", "true")
    assert Settings().adaptive_reorder is True


def test_max_followup_probes_default(monkeypatch):
    monkeypatch.delenv("MAX_FOLLOWUP_PROBES", raising=False)
    assert Settings().max_followup_probes == 4


import asyncio
from unittest.mock import AsyncMock
from multi_agent_system.utils.simple_llm_client import SimpleLLMClient


def _bare_client():
    return SimpleLLMClient.__new__(SimpleLLMClient)


def test_followup_probes_parses_and_filters():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value=(
        '{"probes": ['
        '{"agent": "ClientSideAgent", "focus": "test XSS on /rest/products q=", "reason": "sqli surface"},'
        '{"agent": "UnknownAgent", "focus": "x", "reason": "y"}'
        ']}'
    ))
    out = asyncio.run(c.propose_followup_probes(
        analysis="SQLi confirmed at /rest/products",
        findings_summary="...",
        available_agents=["ClientSideAgent", "InputValidationAgent"]))
    assert out == [{"agent": "ClientSideAgent",
                    "focus": "test XSS on /rest/products q=",
                    "reason": "sqli surface"}]


def test_followup_probes_empty_on_unparseable():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value="no json here")
    out = asyncio.run(c.propose_followup_probes(
        analysis="x", findings_summary="y", available_agents=["A"]))
    assert out == []


def test_followup_probes_empty_when_no_available_agents():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value='{"probes": [{"agent": "A", "focus": "f", "reason": "r"}]}')
    out = asyncio.run(c.propose_followup_probes(
        analysis="x", findings_summary="y", available_agents=[]))
    assert out == []
