"""Tests for HITL_CHECKPOINT_TIMEOUT_SECONDS setting and propagation."""
import importlib
import os

from multi_agent_system.core import config as _config_mod


def test_default_hitl_checkpoint_timeout_is_600_seconds(monkeypatch):
    monkeypatch.delenv("HITL_CHECKPOINT_TIMEOUT_SECONDS", raising=False)
    importlib.reload(_config_mod)
    assert _config_mod.settings.hitl_checkpoint_timeout_seconds == 600


def test_hitl_checkpoint_timeout_reads_from_env(monkeypatch):
    monkeypatch.setenv("HITL_CHECKPOINT_TIMEOUT_SECONDS", "120")
    importlib.reload(_config_mod)
    assert _config_mod.settings.hitl_checkpoint_timeout_seconds == 120
