import pytest

from rajdoll.core.config import Settings


def test_settings_read_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAJDOLL_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("RAJDOLL_WORKER_POLL_SECONDS", "1.5")
    settings = Settings(_env_file=None)
    assert settings.log_level == "DEBUG"
    assert settings.worker_poll_seconds == 1.5


def test_worker_defaults_follow_trd() -> None:
    settings = Settings(_env_file=None)
    assert settings.worker_poll_seconds == 5.0  # TRD 3.2
    assert settings.session_check_seconds == 300.0  # TRD 3.5


def test_settings_ignore_unprefixed_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    monkeypatch.delenv("RAJDOLL_LOG_LEVEL", raising=False)
    assert Settings(_env_file=None).log_level == "INFO"
