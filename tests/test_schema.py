"""Database constraints that enforce BSD rules, exercised through the ORM models."""

import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.bootstrap import prepare_secrets
from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import (
    AppUser,
    Engagement,
    Evidence,
    Finding,
    ReportExport,
    RequestLog,
    Scan,
    ScopeRule,
    Task,
)


def _engagement(session: Session, **overrides: object) -> Engagement:
    values: dict[str, object] = {
        "name": "SIMPEG (clone)",
        "target_url": "https://simpeg.instansi.test",
        "key_id": uuid.uuid4(),
    }
    values.update(overrides)
    engagement = Engagement(**values)
    session.add(engagement)
    session.flush()
    return engagement


def _scan(session: Session, engagement: Engagement, **overrides: object) -> Scan:
    values: dict[str, object] = {
        "engagement_id": engagement.id,
        "kind": "scan",
        "number": 1,
        "profile": "full",
    }
    values.update(overrides)
    scan = Scan(**values)
    session.add(scan)
    session.flush()
    return scan


def _finding(session: Session, engagement: Engagement, **overrides: object) -> Finding:
    values: dict[str, object] = {
        "engagement_id": engagement.id,
        "fingerprint": uuid.uuid4().hex,
        "title": "IDOR pada /api/users/{id}",
        "vuln_type": "idor",
        "module": "authorization",
        "severity": "high",
        "validation": "confirmed",
    }
    values.update(overrides)
    finding = Finding(**values)
    session.add(finding)
    session.flush()
    return finding


def _rejected(session: Session, action: Callable[[], object]) -> None:
    with pytest.raises(IntegrityError), session.begin_nested():
        action()
        session.flush()


def test_defaults_are_applied(db_session: Session) -> None:
    engagement = _engagement(db_session)
    db_session.refresh(engagement)
    assert engagement.status == "draft"
    assert engagement.settings == {}
    finding = _finding(db_session, engagement)
    db_session.refresh(finding)
    assert (finding.decision, finding.retest_result) == ("pending", "not_tested")


def test_status_values_are_checked(db_session: Session) -> None:
    _rejected(db_session, lambda: _engagement(db_session, status="archived"))


def test_end_date_cannot_precede_start_date(db_session: Session) -> None:
    from datetime import date

    _rejected(
        db_session,
        lambda: _engagement(db_session, start_date=date(2026, 11, 10), end_date=date(2026, 11, 1)),
    )


def test_single_user_only(db_session: Session) -> None:
    _rejected(db_session, lambda: db_session.add(AppUser(id=2, password_hash="x")))


def test_paused_scan_needs_reason_and_reason_needs_pause(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _rejected(db_session, lambda: _scan(db_session, engagement, status="paused"))
    _rejected(
        db_session,
        lambda: _scan(db_session, engagement, number=2, status="running", paused_reason="manual"),
    )
    scan = _scan(db_session, engagement, number=3, status="paused", paused_reason="manual")
    assert scan.id is not None


def test_profile_must_match_scan_kind(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _rejected(db_session, lambda: _scan(db_session, engagement, profile=None))
    _rejected(db_session, lambda: _scan(db_session, engagement, kind="retest", profile="full"))
    retest = _scan(db_session, engagement, kind="retest", profile=None, stage="retest")
    assert retest.id is not None


def test_scan_numbers_are_unique_per_engagement_and_kind(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _scan(db_session, engagement)
    _rejected(db_session, lambda: _scan(db_session, engagement))


def test_rejection_requires_reason(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _rejected(db_session, lambda: _finding(db_session, engagement, decision="rejected"))
    _rejected(
        db_session,
        lambda: _finding(db_session, engagement, decision="rejected", decision_reason="   "),
    )
    finding = _finding(
        db_session, engagement, decision="rejected", decision_reason="False positive"
    )
    assert finding.id is not None


def test_retest_result_requires_accepted_decision(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _rejected(db_session, lambda: _finding(db_session, engagement, retest_result="fixed"))
    finding = _finding(db_session, engagement, decision="accepted", retest_result="fixed")
    assert finding.id is not None


def test_fingerprint_unique_per_engagement(db_session: Session) -> None:
    first, second = _engagement(db_session), _engagement(db_session)
    _finding(db_session, first, fingerprint="same")
    _finding(db_session, second, fingerprint="same")
    _rejected(db_session, lambda: _finding(db_session, first, fingerprint="same"))


def test_cvss_score_range(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _rejected(db_session, lambda: _finding(db_session, engagement, cvss31_score=10.5))


def test_retest_report_needs_scan(db_session: Session) -> None:
    engagement = _engagement(db_session)
    _rejected(
        db_session,
        lambda: db_session.add(
            ReportExport(
                engagement_id=engagement.id, kind="retest", finding_count=0, content_enc=b"x"
            )
        ),
    )


def test_deleting_engagement_cascades(db_session: Session) -> None:
    engagement = _engagement(db_session)
    scan = _scan(db_session, engagement)
    db_session.add_all(
        [
            ScopeRule(engagement_id=engagement.id, pattern="simpeg.instansi.test"),
            Task(scan_id=scan.id, stage="recon", module="information_gathering", engine="katana"),
            RequestLog(
                engagement_id=engagement.id,
                scan_id=scan.id,
                kind="http",
                tool="katana",
                url="https://simpeg.instansi.test/",
                host="simpeg.instansi.test",
                outcome="forwarded",
            ),
        ]
    )
    finding = _finding(db_session, engagement)
    db_session.add(
        Evidence(finding_id=finding.id, kind="detection", sequence=1, request_enc=b"enc")
    )
    db_session.flush()

    db_session.delete(engagement)
    db_session.flush()

    for model in (Scan, ScopeRule, Task, RequestLog, Finding, Evidence):
        assert db_session.scalar(select(func.count()).select_from(model)) == 0, model.__name__


def test_prepare_secrets_removes_only_orphans(db_session: Session, tmp_path: Path) -> None:
    import os
    import time

    store = KeyStore(tmp_path)
    in_use = store.create_engagement_key()
    orphan = store.create_engagement_key()
    hour_ago = time.time() - 3600
    for key_id in (in_use, orphan):
        os.utime(tmp_path / "engagements" / f"{key_id}.key", (hour_ago, hour_ago))
    _engagement(db_session, key_id=in_use)

    factory = sessionmaker(bind=db_session.connection())
    removed = prepare_secrets(store, factory)

    assert removed == [str(orphan)]
    assert (tmp_path / "master.key").exists()
    assert (tmp_path / "engagements" / f"{in_use}.key").exists()
