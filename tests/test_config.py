import pytest

from rajdoll.core.config import Settings


def test_settings_read_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAJDOLL_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("RAJDOLL_WORKER_HEARTBEAT_SECONDS", "5")
    settings = Settings(_env_file=None)
    assert settings.log_level == "DEBUG"
    assert settings.worker_heartbeat_seconds == 5.0


def test_settings_ignore_unprefixed_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    monkeypatch.delenv("RAJDOLL_LOG_LEVEL", raising=False)
    assert Settings(_env_file=None).log_level == "INFO"
