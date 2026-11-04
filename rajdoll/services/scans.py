"""Starting and controlling scans (AFD A3–A7, state machine AFD 3.2).

The API calls these functions; the worker's engine moves scans between stages. Both sides
change `scan.status` only through the transitions allowed here or in the engine.
"""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from rajdoll.core.enums import (
    CheckpointResolution,
    EngagementStatus,
    EventType,
    PausedReason,
    ScanKind,
    ScanProfile,
    ScanStage,
    ScanStatus,
    SessionStatus,
    TaskStatus,
)
from rajdoll.core.models import Engagement, Scan, TargetAccount, Task
from rajdoll.services import engagements
from rajdoll.services import settings as app_settings
from rajdoll.services.errors import Conflict, NotFound
from rajdoll.services.events import emit
from rajdoll.services.profiles import resolve_modules

UNFINISHED = (
    ScanStatus.QUEUED,
    ScanStatus.RUNNING,
    ScanStatus.AWAITING_CHECKPOINT,
    ScanStatus.PAUSED,
)
_LOCAL_HOSTS = {"localhost", "host.docker.internal"}
# The worker LISTENs on this channel, so state changes made here reach it without polling.
WORKER_CHANNEL = "rajdoll_worker"

STAGE_LABELS: dict[str, str] = {
    ScanStage.RECON: "Recon",
    ScanStage.PLANNING: "Perencanaan",
    ScanStage.TESTING: "Pengujian",
    ScanStage.VALIDATION: "Validasi",
    ScanStage.AI_TRIAGE: "Triase AI",
    ScanStage.RETEST: "Retest",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def is_local_llm(base_url: str) -> bool:
    host = urlsplit(base_url).hostname or ""
    if host in _LOCAL_HOSTS:
        return True
    try:
        address = ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def wake_worker(session: Session) -> None:
    """Notify the worker when the current transaction commits."""
    session.execute(text(f"NOTIFY {WORKER_CHANNEL}"))


def get(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise NotFound("Scan tidak ditemukan.")
    return scan


def list_for(session: Session, engagement_id: int, kind: str = ScanKind.SCAN) -> list[Scan]:
    return list(
        session.scalars(
            select(Scan)
            .where(Scan.engagement_id == engagement_id, Scan.kind == kind)
            .order_by(Scan.number.desc())
        )
    )


def _next_number(session: Session, engagement_id: int, kind: str) -> int:
    current = session.scalar(
        select(func.max(Scan.number)).where(Scan.engagement_id == engagement_id, Scan.kind == kind)
    )
    return (current or 0) + 1


def start(
    session: Session, engagement: Engagement, profile: str, modules: list[str] | None = None
) -> Scan:
    """Queue a new scan (AFD A3). One unfinished scan per engagement at a time."""
    if engagement.status == EngagementStatus.DRAFT:
        raise Conflict("Penugasan masih draf: pastikan URL target berada di dalam scope.")
    if engagements.has_unfinished_scan(session, engagement.id):
        raise Conflict("Masih ada scan atau retest yang belum selesai untuk penugasan ini.")
    chosen = resolve_modules(profile, modules)
    config = app_settings.load(session)
    scan = Scan(
        engagement_id=engagement.id,
        kind=ScanKind.SCAN,
        number=_next_number(session, engagement.id, ScanKind.SCAN),
        profile=ScanProfile(profile),
        modules=chosen,
        status=ScanStatus.QUEUED,
        settings_snapshot=engagements.effective_settings(session, engagement),
        llm_snapshot={
            "base_url": str(config.llm.base_url),
            "model": config.llm.model,
            "is_local": is_local_llm(str(config.llm.base_url)),
        },
        stats={},
    )
    session.add(scan)
    engagement.status = EngagementStatus.ACTIVE
    session.flush()
    emit(session, scan.id, EventType.NOTICE, "Scan masuk antrean.")
    wake_worker(session)
    return scan


def _require(scan: Scan, allowed: tuple[ScanStatus, ...], action: str) -> None:
    if scan.status not in allowed:
        raise Conflict(f"Scan berstatus {scan.status} tidak bisa {action}.")


def pause(session: Session, scan: Scan, reason: PausedReason = PausedReason.MANUAL) -> None:
    _require(
        scan,
        (ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.AWAITING_CHECKPOINT),
        "dijeda",
    )
    scan.status = ScanStatus.PAUSED
    scan.paused_reason = reason
    scan.checkpoint_deadline = None
    messages = {
        PausedReason.MANUAL: "Scan dijeda oleh asesor.",
        PausedReason.SESSION_EXPIRED: "Scan dijeda: sesi akun kedaluwarsa.",
        PausedReason.WAF_BLOCKED: "Scan dijeda: kemungkinan diblokir WAF.",
    }
    emit(session, scan.id, EventType.PAUSED, messages[reason], data={"reason": str(reason)})
    wake_worker(session)


def resume(session: Session, scan: Scan, rate_limit_rps: float | None = None) -> None:
    """Continue a paused scan, or a failed one from its last unfinished task (AFD 3.2)."""
    _require(scan, (ScanStatus.PAUSED, ScanStatus.FAILED), "dilanjutkan")
    if scan.paused_reason == PausedReason.SESSION_EXPIRED:
        invalid = session.scalars(
            select(TargetAccount.label).where(
                TargetAccount.engagement_id == scan.engagement_id,
                TargetAccount.session_status != SessionStatus.VALID,
            )
        ).all()
        if invalid:
            raise Conflict(
                f"Perbarui dan uji sesi {', '.join(invalid)} dulu sebelum melanjutkan scan."
            )
    if rate_limit_rps is not None:
        if not 0 < rate_limit_rps <= 1000:
            raise Conflict("Rate limit harus di antara 0 dan 1000 request per detik.")
        snapshot = dict(scan.settings_snapshot)
        snapshot["rate_limit_rps"] = rate_limit_rps
        scan.settings_snapshot = snapshot
    if scan.status == ScanStatus.FAILED:
        engagement = session.get(Engagement, scan.engagement_id)
        if engagement is None or engagement.status == EngagementStatus.DRAFT:
            raise Conflict("Penugasan masih draf: pastikan URL target berada di dalam scope.")
        if engagements.has_unfinished_scan(session, scan.engagement_id):
            raise Conflict("Masih ada scan atau retest yang belum selesai untuk penugasan ini.")
        engagement.status = EngagementStatus.ACTIVE
        scan.error = None
        scan.finished_at = None
    # A scan stopped before it started goes back to the queue; otherwise the engine picks up
    # where it stopped (a scan stopped at the checkpoint gets a fresh countdown).
    scan.status = ScanStatus.QUEUED if scan.stage is None else ScanStatus.RUNNING
    scan.paused_reason = None
    emit(session, scan.id, EventType.RESUMED, "Scan dilanjutkan.")
    wake_worker(session)


def cancel(session: Session, scan: Scan) -> None:
    _require(scan, UNFINISHED, "dibatalkan")
    scan.status = ScanStatus.CANCELLED
    scan.paused_reason = None
    scan.checkpoint_deadline = None
    scan.finished_at = utcnow()
    # Running tasks are stopped by the worker, which marks them skipped.
    session.execute(
        update(Task)
        .where(Task.scan_id == scan.id, Task.status == TaskStatus.PENDING)
        .values(status=TaskStatus.SKIPPED)
    )
    emit(session, scan.id, EventType.CANCELLED, "Scan dibatalkan. Temuan yang sudah ada disimpan.")
    release_engagement(session, scan.engagement_id)
    wake_worker(session)


def checkpoint_hold(session: Session, scan: Scan) -> None:
    """Stop the auto-continue countdown while the assessor edits the plan (AFD A5)."""
    _require(scan, (ScanStatus.AWAITING_CHECKPOINT,), "ditahan di checkpoint")
    if scan.checkpoint_deadline is not None:
        scan.checkpoint_deadline = None
        emit(session, scan.id, EventType.NOTICE, "Hitung mundur checkpoint ditahan oleh asesor.")


def checkpoint_continue(session: Session, scan: Scan) -> None:
    _require(scan, (ScanStatus.AWAITING_CHECKPOINT,), "dilanjutkan dari checkpoint")
    scan.status = ScanStatus.RUNNING
    scan.checkpoint_deadline = None
    scan.checkpoint_resolution = CheckpointResolution.USER_CONTINUED
    emit(session, scan.id, EventType.RESUMED, "Checkpoint dilanjutkan oleh asesor.")
    wake_worker(session)


def release_engagement(session: Session, engagement_id: int) -> None:
    """After a scan ends, an engagement with no other unfinished scan is no longer active."""
    engagement = session.get(Engagement, engagement_id)
    if engagement is None or engagement.status != EngagementStatus.ACTIVE:
        return
    session.flush()
    if not engagements.has_unfinished_scan(session, engagement_id):
        engagement.status = EngagementStatus.READY
        engagements.recompute_status(session, engagement)


def task_counts(session: Session, scan_id: int) -> dict[str, dict[str, int]]:
    """Task counts per module and status, for the monitor (AFD 5.3)."""
    rows = session.execute(
        select(Task.module, Task.status, func.count())
        .where(Task.scan_id == scan_id)
        .group_by(Task.module, Task.status)
    )
    result: dict[str, dict[str, int]] = {}
    for module, status, count in rows:
        result.setdefault(module, {})[status] = count
    return result


def summary(session: Session, scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "engagement_id": scan.engagement_id,
        "kind": scan.kind,
        "number": scan.number,
        "profile": scan.profile,
        "modules": scan.modules,
        "status": scan.status,
        "stage": scan.stage,
        "paused_reason": scan.paused_reason,
        "checkpoint_deadline": scan.checkpoint_deadline,
        "checkpoint_resolution": scan.checkpoint_resolution,
        "error": scan.error,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "tasks": task_counts(session, scan.id),
    }
