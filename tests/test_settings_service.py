import pytest
from sqlalchemy.orm import Session

from rajdoll.services import settings as settings_service
from rajdoll.services.settings import SettingsError


def test_defaults_match_bsd(db_session: Session) -> None:
    settings = settings_service.load(db_session)
    assert str(settings.llm.base_url) == "http://host.docker.internal:1234/v1"
    assert settings.llm.model == "qwen3-4b"
    assert settings.cvss_primary == "3.1"
    assert settings.defaults.checkpoint_timeout_min == 15
    assert settings.defaults.oob_enabled is False
    assert "logout" in settings.excluded_patterns


def test_nested_update_merges_and_persists(db_session: Session) -> None:
    settings_service.update(db_session, {"defaults": {"concurrency": 4}})
    reloaded = settings_service.load(db_session)
    assert reloaded.defaults.concurrency == 4
    assert reloaded.defaults.rate_limit_rps == 10  # untouched sibling kept


def test_invalid_value_is_rejected_with_location(db_session: Session) -> None:
    with pytest.raises(SettingsError) as info:
        settings_service.update(db_session, {"defaults": {"concurrency": 0}})
    assert info.value.errors == ["Tugas paralel: minimal 1"]
    assert info.value.field_errors[0].field == "defaults.concurrency"
    assert settings_service.load(db_session).defaults.concurrency == 2


def test_unknown_key_is_rejected(db_session: Session) -> None:
    with pytest.raises(SettingsError):
        settings_service.update(db_session, {"theme": "dark"})


def test_cvss_primary_is_restricted(db_session: Session) -> None:
    with pytest.raises(SettingsError):
        settings_service.update(db_session, {"cvss_primary": "2.0"})
    settings_service.update(db_session, {"cvss_primary": "both"})
    assert settings_service.load(db_session).cvss_primary == "both"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"llm": {"base_url": "not a url"}}, "Alamat server LLM: harus alamat URL yang valid"),
        ({"llm": {"model": ""}}, "Model LLM: tidak boleh kosong"),
        ({"defaults": {"concurrency": "dua"}}, "Tugas paralel: harus bilangan bulat"),
        ({"defaults": {"evidence_max_bytes": 1024}}, "body evidence (KB): minimal 4"),
        ({"cvss_primary": "2.0"}, "Versi CVSS utama: pilihan tidak valid"),
    ],
)
def test_validation_messages_are_indonesian(
    db_session: Session, changes: dict[str, object], message: str
) -> None:
    with pytest.raises(SettingsError) as info:
        settings_service.update(db_session, changes)
    assert any(message in text for text in info.value.errors), info.value.errors
