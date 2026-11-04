"""Engagement service rules (AFD A1, A2, A11; AFD 6; BSD 7)."""

from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyNotFoundError, KeyStore
from rajdoll.core.models import Engagement, Scan, ScopeRule, TargetAccount
from rajdoll.services import engagements as svc
from rajdoll.services.errors import Conflict, NotFound, ValidationFailed

TARGET = "https://simpeg.instansi.test/login"


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    return KeyStore(tmp_path)


def _create(session: Session, keystore: KeyStore, **overrides: object) -> Engagement:
    data: dict[str, object] = {"name": "SIMPEG (clone)", "target_url": TARGET}
    data.update(overrides)
    return svc.create(session, keystore, data)


def test_create_adds_target_host_to_scope_and_is_ready(
    db_session: Session, keystore: KeyStore, tmp_path: Path
) -> None:
    engagement = _create(db_session, keystore, organization="Instansi A", start_date="2026-11-10")
    assert svc.scope_patterns(db_session, engagement.id) == ["simpeg.instansi.test"]
    assert engagement.status == "ready"
    assert engagement.start_date.isoformat() == "2026-11-10"
    assert (tmp_path / "engagements" / f"{engagement.key_id}.key").exists()


@pytest.mark.parametrize(
    ("data", "field"),
    [
        ({"name": "", "target_url": TARGET}, "name"),
        ({"name": "x", "target_url": ""}, "target_url"),
        ({"name": "x", "target_url": "ftp://simpeg.instansi.test"}, "target_url"),
        ({"name": "x", "target_url": "simpeg.instansi.test"}, "target_url"),
        ({"name": "x", "target_url": TARGET, "start_date": "10/11/2026"}, "start_date"),
        (
            {
                "name": "x",
                "target_url": TARGET,
                "start_date": "2026-11-10",
                "end_date": "2026-11-01",
            },
            "end_date",
        ),
    ],
)
def test_create_validation(
    db_session: Session, keystore: KeyStore, data: dict[str, str], field: str
) -> None:
    with pytest.raises(ValidationFailed) as info:
        svc.create(db_session, keystore, data)
    assert field in [e.field for e in info.value.field_errors]


def test_target_outside_scope_makes_engagement_draft(
    db_session: Session, keystore: KeyStore
) -> None:
    engagement = _create(db_session, keystore)
    svc.update_details(
        db_session, engagement, {"name": "SIMPEG (clone)", "target_url": "https://other.test/"}
    )
    assert engagement.status == "draft"
    assert any("di luar scope" in w for w in svc.warnings(db_session, engagement))
    svc.add_scope(db_session, engagement, "other.test")
    assert engagement.status == "ready"


def test_scope_add_rejects_duplicates_and_bad_patterns(
    db_session: Session, keystore: KeyStore
) -> None:
    engagement = _create(db_session, keystore)
    with pytest.raises(ValidationFailed, match="sudah ada"):
        svc.add_scope(db_session, engagement, "https://SIMPEG.instansi.test/")
    with pytest.raises(ValidationFailed, match="terlalu luas"):
        svc.add_scope(db_session, engagement, "*.test")
    rule = svc.add_scope(db_session, engagement, "*.instansi.test")
    assert rule.pattern == "*.instansi.test"


def test_scope_remove_keeps_target_and_session_check_in_scope(
    db_session: Session, keystore: KeyStore
) -> None:
    engagement = _create(db_session, keystore)
    only_rule = svc.scope_rule_rows(db_session, engagement.id)[0]
    with pytest.raises(Conflict, match="minimal berisi satu"):
        svc.remove_scope(db_session, engagement, only_rule.id)

    svc.add_scope(db_session, engagement, "api.instansi.test")
    with pytest.raises(Conflict, match="URL target"):
        svc.remove_scope(db_session, engagement, only_rule.id)

    wildcard = svc.add_scope(db_session, engagement, "*.instansi.test")
    api_rule = next(
        r
        for r in svc.scope_rule_rows(db_session, engagement.id)
        if r.pattern == "api.instansi.test"
    )
    svc.set_session_check(db_session, engagement, "https://api.instansi.test/me", "Budi")
    svc.remove_scope(db_session, engagement, wildcard.id)
    with pytest.raises(Conflict, match="URL cek sesi"):
        svc.remove_scope(db_session, engagement, api_rule.id)

    with pytest.raises(NotFound):
        svc.remove_scope(db_session, engagement, 999_999)


def test_session_check_rules(db_session: Session, keystore: KeyStore) -> None:
    engagement = _create(db_session, keystore)
    with pytest.raises(ValidationFailed) as info:
        svc.set_session_check(db_session, engagement, "https://other.test/me", "")
    assert {e.field for e in info.value.field_errors} == {"url", "marker"}
    svc.set_session_check(db_session, engagement, "https://simpeg.instansi.test/profil", "Budi")
    assert engagement.session_check_marker == "Budi"
    svc.set_session_check(db_session, engagement, "", "ignored")
    assert engagement.session_check_url is None
    assert engagement.session_check_marker is None


def test_accounts_are_encrypted_and_labelled(db_session: Session, keystore: KeyStore) -> None:
    engagement = _create(db_session, keystore)
    first = svc.add_account(
        db_session, keystore, engagement, {"session_text": "Cookie: sid=TOPSECRET-1"}
    )
    second = svc.add_account(
        db_session,
        keystore,
        engagement,
        {"session": {"headers": {"Authorization": "Bearer TOPSECRET-2"}}},
    )
    assert (first.label, second.label) == ("Akun A", "Akun B")
    assert svc.next_account_label(db_session, engagement.id) == "Akun C"
    assert b"TOPSECRET" not in (first.session_enc or b"")
    assert svc.account_session(keystore, engagement, first)["cookies"] == {"sid": "TOPSECRET-1"}
    summary = svc.account_summary(keystore, engagement, second)
    assert summary["header_names"] == ["Authorization"]
    assert "TOPSECRET" not in str(summary)

    with pytest.raises(ValidationFailed, match="sudah dipakai"):
        svc.add_account(
            db_session, keystore, engagement, {"label": "Akun A", "session_text": "a=1"}
        )
    with pytest.raises(ValidationFailed, match="Auto-login"):
        svc.add_account(db_session, keystore, engagement, {"auth_method": "auto_login"})
    with pytest.raises(ValidationFailed, match="Tempel"):
        svc.add_account(db_session, keystore, engagement, {"session_text": "  "})


def test_updating_session_resets_status(db_session: Session, keystore: KeyStore) -> None:
    engagement = _create(db_session, keystore)
    account = svc.add_account(db_session, keystore, engagement, {"session_text": "sid=old"})
    account.session_status = "valid"
    svc.update_account(
        db_session, keystore, engagement, account, {"label": "Admin", "session_text": "sid=new"}
    )
    assert account.label == "Admin"
    assert account.session_status == "unknown"
    assert svc.account_session(keystore, engagement, account)["cookies"] == {"sid": "new"}


def test_account_username_is_optional_and_encrypted(
    db_session: Session, keystore: KeyStore
) -> None:
    engagement = _create(db_session, keystore)
    account = svc.add_account(
        db_session, keystore, engagement, {"session_text": "sid=1", "username": " budi.santoso "}
    )
    assert b"budi" not in (account.credentials_enc or b"")
    assert svc.account_username(keystore, engagement, account) == "budi.santoso"
    assert svc.account_summary(keystore, engagement, account)["username"] == "budi.santoso"
    svc.update_account(db_session, keystore, engagement, account, {"username": "sari"})
    assert svc.account_username(keystore, engagement, account) == "sari"
    assert svc.account_session(keystore, engagement, account)["cookies"] == {"sid": "1"}
    svc.update_account(db_session, keystore, engagement, account, {"username": ""})
    assert account.credentials_enc is None
    assert svc.account_summary(keystore, engagement, account)["username"] == ""
    with pytest.raises(ValidationFailed, match="Username"):
        svc.update_account(db_session, keystore, engagement, account, {"username": "a\nb"})
    plain = svc.add_account(db_session, keystore, engagement, {"session_text": "sid=2"})
    assert svc.account_username(keystore, engagement, plain) == ""


def test_account_warnings(db_session: Session, keystore: KeyStore) -> None:
    engagement = _create(db_session, keystore)
    assert any("Belum ada akun" in w for w in svc.warnings(db_session, engagement))
    svc.add_account(db_session, keystore, engagement, {"session_text": "sid=1"})
    current = svc.warnings(db_session, engagement)
    assert any("Kurang dari dua akun" in w for w in current)
    assert any("Cek sesi belum diatur" in w for w in current)


def test_overrides_merge_over_app_defaults(db_session: Session, keystore: KeyStore) -> None:
    engagement = _create(db_session, keystore)
    svc.update_overrides(
        db_session,
        engagement,
        {"concurrency": 4, "identity_header": {"name": "X-VA-Team", "value": "BSSN VA"}},
    )
    effective = svc.effective_settings(db_session, engagement)
    assert effective["concurrency"] == 4
    assert effective["rate_limit_rps"] == 10  # app default
    assert effective["identity_header"] == {"name": "X-VA-Team", "value": "BSSN VA"}
    assert engagement.settings == {
        "concurrency": 4,
        "identity_header": {"name": "X-VA-Team", "value": "BSSN VA"},
    }


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"concurrency": 0}, "Tugas paralel: minimal 1"),
        ({"identity_header": {"name": "Bad Name", "value": "x"}}, "Nama header identitas"),
        ({"identity_header": {"name": "X-VA", "value": "a\r\nInjected: 1"}}, "Nilai header"),
    ],
)
def test_overrides_validation(
    db_session: Session, keystore: KeyStore, changes: dict[str, object], message: str
) -> None:
    engagement = _create(db_session, keystore)
    with pytest.raises(ValidationFailed) as info:
        svc.update_overrides(db_session, engagement, changes)
    assert any(message in text for text in info.value.errors), info.value.errors


def test_status_transitions(db_session: Session, keystore: KeyStore) -> None:
    engagement = _create(db_session, keystore)
    with pytest.raises(Conflict):
        svc.set_status(db_session, engagement, "reopen")
    svc.set_status(db_session, engagement, "done")
    assert engagement.status == "done"
    svc.set_status(db_session, engagement, "reopen")
    assert engagement.status == "ready"


def test_delete_requires_exact_name_and_no_running_scan(
    db_session: Session, keystore: KeyStore, tmp_path: Path
) -> None:
    engagement = _create(db_session, keystore)
    svc.add_account(db_session, keystore, engagement, {"session_text": "sid=1"})
    key_file = tmp_path / "engagements" / f"{engagement.key_id}.key"

    with pytest.raises(ValidationFailed, match="tidak sama"):
        svc.delete(db_session, keystore, engagement, "simpeg (clone)")

    scan = Scan(
        engagement_id=engagement.id, kind="scan", number=1, profile="full", status="running"
    )
    db_session.add(scan)
    db_session.flush()
    with pytest.raises(Conflict, match="belum selesai"):
        svc.delete(db_session, keystore, engagement, engagement.name)
    assert key_file.exists()

    scan.status = "completed"
    db_session.flush()
    engagement_id, key_id = engagement.id, engagement.key_id
    svc.delete(db_session, keystore, engagement, engagement.name)
    db_session.flush()

    assert not key_file.exists()
    with pytest.raises(KeyNotFoundError):
        KeyStore(tmp_path).engagement_key(key_id)
    for model in (Engagement, ScopeRule, TargetAccount, Scan):
        column = model.id if model is Engagement else model.engagement_id
        count = db_session.scalar(
            select(func.count()).select_from(model).where(column == engagement_id)
        )
        assert count == 0, model.__name__


def test_check_account_records_outcome(db_session: Session, keystore: KeyStore) -> None:
    from rajdoll.services.session_check import CheckResult

    engagement = _create(db_session, keystore)
    account = svc.add_account(db_session, keystore, engagement, {"session_text": "sid=abc"})
    calls: list[tuple] = []

    def prober(url: str, marker: str, session: dict, engagement_id: int) -> CheckResult:
        calls.append((url, marker, session, engagement_id))
        return CheckResult(True, True, "Sesi valid.", 200)

    with pytest.raises(ValidationFailed, match="Atur URL cek sesi"):
        svc.check_account(db_session, keystore, engagement, account, prober)

    svc.set_session_check(db_session, engagement, "https://simpeg.instansi.test/profil", "Budi")
    result = svc.check_account(db_session, keystore, engagement, account, prober)
    db_session.flush()
    db_session.refresh(account)
    assert result.valid
    assert account.session_status == "valid"
    assert account.session_checked_at is not None
    assert calls == [
        (
            "https://simpeg.instansi.test/profil",
            "Budi",
            {"cookies": {"sid": "abc"}, "headers": {}},
            engagement.id,
        )
    ]

    def unreachable(*_: object) -> CheckResult:
        return CheckResult(False, False, "Tidak bisa menghubungi target lewat proxy: x")

    svc.check_account(db_session, keystore, engagement, account, unreachable)
    db_session.flush()
    db_session.refresh(account)
    assert account.session_status == "valid"  # an inconclusive check changes nothing
