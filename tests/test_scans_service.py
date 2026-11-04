"""Starting and controlling scans (AFD A3–A7, 3.2) without the worker."""

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import PausedReason, ScanStatus, SessionStatus
from rajdoll.core.models import Engagement, Scan, ScanEvent, Task
from rajdoll.services import engagements, scans
from rajdoll.services.errors import Conflict, NotFound, ValidationFailed


@pytest.fixture
def engagement(db_session: Session, tmp_path: Path) -> Engagement:
    return engagements.create(
        db_session, KeyStore(tmp_path), {"name": "SIMPEG", "target_url": "https://app.test/"}
    )


def _events(session: Session, scan: Scan) -> list[str]:
    return list(
        session.scalars(
            select(ScanEvent.type).where(ScanEvent.scan_id == scan.id).order_by(ScanEvent.id)
        )
    )


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://host.docker.internal:1234/v1", True),
        ("http://localhost:1234/v1", True),
        ("http://127.0.0.1:1234/v1", True),
        ("http://192.168.1.20:1234/v1", True),
        ("https://api.example.com/v1", False),
        ("http://8.8.8.8/v1", False),
    ],
)
def test_is_local_llm(url: str, local: bool) -> None:
    assert scans.is_local_llm(url) is local


def test_start_snapshots_settings_and_activates_engagement(
    db_session: Session, engagement: Engagement
) -> None:
    engagements.update_overrides(db_session, engagement, {"rate_limit_rps": 3})
    scan = scans.start(db_session, engagement, "full")
    assert (scan.kind, scan.number, scan.status, scan.stage) == ("scan", 1, "queued", None)
    assert len(scan.modules) == 12
    assert scan.settings_snapshot["rate_limit_rps"] == 3
    assert scan.settings_snapshot["checkpoint_enabled"] is True
    assert scan.llm_snapshot == {
        "base_url": "http://host.docker.internal:1234/v1",
        "model": "qwen3-4b",
        "is_local": True,
    }
    assert engagement.status == "active"
    assert _events(db_session, scan) == ["notice"]


def test_start_custom_and_numbering(db_session: Session, engagement: Engagement) -> None:
    first = scans.start(db_session, engagement, "custom", ["session", "authorization"])
    assert first.profile == "custom"
    assert first.modules == ["authorization", "session"]
    scans.cancel(db_session, first)
    second = scans.start(db_session, engagement, "full")
    assert second.number == 2
    assert [s.number for s in scans.list_for(db_session, engagement.id)] == [2, 1]


def test_start_refusals(db_session: Session, engagement: Engagement) -> None:
    with pytest.raises(ValidationFailed):
        scans.start(db_session, engagement, "custom", [])
    scans.start(db_session, engagement, "full")
    with pytest.raises(Conflict, match="belum selesai"):
        scans.start(db_session, engagement, "full")
    engagement.status = "draft"
    with pytest.raises(Conflict, match="draf"):
        scans.start(db_session, engagement, "full")


def test_get_missing_scan(db_session: Session) -> None:
    with pytest.raises(NotFound):
        scans.get(db_session, 999_999)


def test_pause_resume_cancel(db_session: Session, engagement: Engagement) -> None:
    scan = scans.start(db_session, engagement, "full")
    scans.pause(db_session, scan)
    assert (scan.status, scan.paused_reason) == ("paused", "manual")
    with pytest.raises(Conflict, match="tidak bisa dijeda"):
        scans.pause(db_session, scan)
    scans.resume(db_session, scan)
    assert (scan.status, scan.paused_reason) == ("queued", None)  # paused before it started

    scan.status, scan.stage = ScanStatus.RUNNING, "testing"
    scans.pause(db_session, scan)
    scans.resume(db_session, scan, rate_limit_rps=2.5)
    assert scan.status == "running"
    assert scan.settings_snapshot["rate_limit_rps"] == 2.5
    with pytest.raises(Conflict, match="tidak bisa dilanjutkan"):
        scans.resume(db_session, scan)

    db_session.add_all(
        [
            Task(scan_id=scan.id, stage="testing", module="m", engine="e", status="pending"),
            Task(scan_id=scan.id, stage="testing", module="m", engine="e", status="done"),
        ]
    )
    db_session.flush()
    scans.cancel(db_session, scan)
    assert scan.status == "cancelled" and scan.finished_at is not None
    statuses = db_session.scalars(
        select(Task.status).where(Task.scan_id == scan.id).order_by(Task.id)
    )
    assert list(statuses) == ["skipped", "done"]
    assert engagement.status == "ready"
    with pytest.raises(Conflict):
        scans.cancel(db_session, scan)
    assert _events(db_session, scan) == [
        "notice",
        "paused",
        "resumed",
        "paused",
        "resumed",
        "cancelled",
    ]


@pytest.mark.parametrize("rate", [0, -1, 1001])
def test_resume_rejects_bad_rate_limit(
    db_session: Session, engagement: Engagement, rate: float
) -> None:
    scan = scans.start(db_session, engagement, "full")
    scans.pause(db_session, scan)
    with pytest.raises(Conflict, match="Rate limit"):
        scans.resume(db_session, scan, rate_limit_rps=rate)


def test_resume_after_session_expiry_needs_valid_sessions(
    db_session: Session, engagement: Engagement, tmp_path: Path
) -> None:
    account = engagements.add_account(
        db_session, KeyStore(tmp_path), engagement, {"label": "A", "session_text": "sid=1"}
    )
    scan = scans.start(db_session, engagement, "full")
    scan.status, scan.stage = ScanStatus.RUNNING, "recon"
    scans.pause(db_session, scan, PausedReason.SESSION_EXPIRED)
    with pytest.raises(Conflict, match="Perbarui dan uji sesi A"):
        scans.resume(db_session, scan)
    account.session_status = SessionStatus.VALID
    scans.resume(db_session, scan)
    assert scan.status == "running"


def test_resume_failed_scan(db_session: Session, engagement: Engagement) -> None:
    scan = scans.start(db_session, engagement, "full")
    scan.status, scan.stage, scan.error = ScanStatus.FAILED, "planning", "boom"
    scans.release_engagement(db_session, engagement.id)
    assert engagement.status == "ready"

    other = scans.start(db_session, engagement, "full")
    with pytest.raises(Conflict, match="belum selesai"):
        scans.resume(db_session, scan)
    scans.cancel(db_session, other)

    scans.resume(db_session, scan)
    assert (scan.status, scan.error, scan.finished_at) == ("running", None, None)
    assert engagement.status == "active"


def test_checkpoint_hold_and_continue(db_session: Session, engagement: Engagement) -> None:
    scan = scans.start(db_session, engagement, "full")
    with pytest.raises(Conflict):
        scans.checkpoint_hold(db_session, scan)
    with pytest.raises(Conflict):
        scans.checkpoint_continue(db_session, scan)
    scan.status, scan.stage = ScanStatus.AWAITING_CHECKPOINT, "planning"
    scan.checkpoint_deadline = scans.utcnow()
    scans.checkpoint_hold(db_session, scan)
    assert scan.checkpoint_deadline is None
    scans.checkpoint_continue(db_session, scan)
    assert (scan.status, scan.checkpoint_resolution) == ("running", "user_continued")


def test_summary_counts_tasks(db_session: Session, engagement: Engagement) -> None:
    scan = scans.start(db_session, engagement, "full")
    db_session.add_all(
        [
            Task(scan_id=scan.id, stage="recon", module="a", engine="httpx", status="done"),
            Task(scan_id=scan.id, stage="recon", module="a", engine="httpx", status="pending"),
            Task(scan_id=scan.id, stage="recon", module="b", engine="x", status="done"),
        ]
    )
    db_session.flush()
    summary = scans.summary(db_session, scan)
    assert summary["tasks"] == {"a": {"done": 1, "pending": 1}, "b": {"done": 1}}
    assert summary["status"] == "queued"
