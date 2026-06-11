# multi_agent_system/tests/test_top_level_replanner.py
from multi_agent_system.core.config import Settings


def test_adaptive_replan_defaults_off(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_REPLAN", raising=False)
    assert Settings().adaptive_replan is False


def test_adaptive_replan_reads_env(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_REPLAN", "true")
    assert Settings().adaptive_replan is True
