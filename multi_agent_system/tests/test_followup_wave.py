from multi_agent_system.core.config import Settings


def test_adaptive_reorder_defaults_off(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_REORDER", raising=False)
    assert Settings().adaptive_reorder is False


def test_adaptive_reorder_reads_env(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_REORDER", "true")
    assert Settings().adaptive_reorder is True


def test_max_followup_probes_default(monkeypatch):
    # max_followup_probes now caps the targeted-probe runner (was the follow-up wave).
    monkeypatch.delenv("MAX_FOLLOWUP_PROBES", raising=False)
    assert Settings().max_followup_probes == 4
