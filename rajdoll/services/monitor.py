"""What the scan monitor, the Scan tab, and the scan banners show (AFD A4, 4, 5.3)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rajdoll.core.enums import ScanKind, ScanStage, ScanStatus, TaskStatus
from rajdoll.core.models import Finding, RequestLog, Scan, ScanEvent, Task
from rajdoll.modules.registry import label as module_label
from rajdoll.services import scans

STATUS_LABELS: dict[str, str] = {
    ScanStatus.QUEUED: "antre",
    ScanStatus.RUNNING: "berjalan",
    ScanStatus.AWAITING_CHECKPOINT: "menunggu checkpoint",
    ScanStatus.PAUSED: "dijeda",
    ScanStatus.COMPLETED: "selesai",
    ScanStatus.CANCELLED: "dibatalkan",
    ScanStatus.FAILED: "gagal",
}
PAUSED_LABELS: dict[str, str] = {
    "manual": "dijeda oleh asesor",
    "session_expired": "sesi akun kedaluwarsa",
    "waf_blocked": "kemungkinan diblokir WAF",
}
TASK_STATUS_LABELS: dict[str, str] = {
    TaskStatus.PENDING: "menunggu",
    TaskStatus.RUNNING: "berjalan",
    TaskStatus.DONE: "selesai",
    TaskStatus.FAILED: "gagal",
    TaskStatus.SKIPPED: "dilewati",
    TaskStatus.BLOCKED: "terblokir",
}
PROFILE_LABELS = {"full": "Lengkap", "custom": "Kustom"}
ENDPOINT_SOURCE_LABELS = {
    "crawl": "crawl",
    "fuzz": "fuzzing",
    "js": "JavaScript",
    "openapi": "OpenAPI",
    "manual": "manual",
    "burp_paste": "tempel Burp",
}
RESOLUTION_LABELS = {
    "user_continued": "dilanjutkan asesor",
    "auto_continued": "dilewati otomatis",
    "disabled": "dimatikan",
}
FINISHED = (ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED)
# Hosts tools contact on their own, not part of the target: ProjectDiscovery tools (katana)
# request http://burpsuite/ to detect whether their proxy is Burp. The egress proxy refuses it;
# it is not offered as an out-of-scope host at the checkpoint.
TOOL_PROBE_HOSTS = {"burpsuite"}
LOG_LIMIT = 50


def is_finished(scan: Scan) -> bool:
    return scan.status in FINISHED


@dataclass(frozen=True)
class Step:
    key: str
    label: str
    state: str  # done | current | waiting | pending


def stage_steps(scan: Scan) -> list[Step]:
    """recon → perencanaan → checkpoint → pengujian → validasi → triase AI, with progress."""
    if scan.kind == ScanKind.RETEST:
        order = [ScanStage.RETEST.value]
    else:
        order = [
            ScanStage.RECON.value,
            ScanStage.PLANNING.value,
            "checkpoint",
            ScanStage.TESTING.value,
            ScanStage.VALIDATION.value,
            ScanStage.AI_TRIAGE.value,
        ]
    labels = {**scans.STAGE_LABELS, "checkpoint": "Checkpoint"}
    if scan.status == ScanStatus.AWAITING_CHECKPOINT:
        current = "checkpoint"
    elif scan.stage is None:
        current = None
    else:
        current = scan.stage
    done_all = scan.status == ScanStatus.COMPLETED
    index = order.index(current) if current in order else -1
    steps = []
    for position, key in enumerate(order):
        if done_all or position < index:
            state = "done"
        elif position == index:
            state = "waiting" if scan.status != ScanStatus.RUNNING else "current"
        else:
            state = "pending"
        if key == "checkpoint" and scan.checkpoint_resolution == "disabled" and state == "done":
            state = "skipped"
        steps.append(Step(key, labels[key], state))
    return steps


def module_rows(session: Session, scan: Scan) -> list[dict[str, Any]]:
    """Task counts per module in profile order, for the monitor table."""
    counts = scans.task_counts(session, scan.id)
    order = list(scan.modules) + sorted(set(counts) - set(scan.modules))
    rows = []
    for name in order:
        per_status = counts.get(name, {})
        total = sum(per_status.values())
        finished = sum(
            per_status.get(s, 0)
            for s in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.SKIPPED, TaskStatus.BLOCKED)
        )
        rows.append(
            {
                "name": name,
                "label": module_label(name),
                "total": total,
                "done": per_status.get(TaskStatus.DONE, 0),
                "failed": per_status.get(TaskStatus.FAILED, 0),
                "blocked": per_status.get(TaskStatus.BLOCKED, 0),
                "skipped": per_status.get(TaskStatus.SKIPPED, 0),
                "running": per_status.get(TaskStatus.RUNNING, 0),
                "pending": per_status.get(TaskStatus.PENDING, 0),
                "finished": finished,
            }
        )
    return rows


def request_stats(session: Session, scan: Scan, now: datetime | None = None) -> dict[str, Any]:
    """Requests through the egress proxy for this scan: total, current rate, scope refusals."""
    now = now or scans.utcnow()
    total, blocked = session.execute(
        select(
            func.count(),
            func.count().filter(RequestLog.outcome == "blocked_scope"),
        ).where(RequestLog.scan_id == scan.id)
    ).one()
    recent = session.scalar(
        select(func.count()).where(
            RequestLog.scan_id == scan.id, RequestLog.ts >= now - timedelta(seconds=60)
        )
    )
    return {"total": total or 0, "rate": round((recent or 0) / 60, 1), "blocked_scope": blocked}


def finding_stats(session: Session, scan: Scan) -> dict[str, int]:
    """Findings seen by this scan, by validation status."""
    rows = session.execute(
        select(Finding.validation, func.count())
        .where(Finding.last_scan_id == scan.id)
        .group_by(Finding.validation)
    ).all()
    counts = {str(validation): count for validation, count in rows}
    return {
        "confirmed": counts.get("confirmed", 0),
        "needs_manual_check": counts.get("needs_manual_check", 0),
        "total": sum(counts.values()),
    }


def events(
    session: Session, scan_id: int, after_id: int = 0, limit: int = LOG_LIMIT
) -> list[ScanEvent]:
    """Events newer than `after_id`, newest first (the latest `limit` of them)."""
    return list(
        session.scalars(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id, ScanEvent.id > after_id)
            .order_by(ScanEvent.id.desc())
            .limit(limit)
        )
    )


def last_event_id(session: Session, scan_id: int) -> int:
    return session.scalar(select(func.max(ScanEvent.id)).where(ScanEvent.scan_id == scan_id)) or 0


def banner_scan(session: Session, engagement_id: int) -> Scan | None:
    """The scan the engagement pages should mention: an unfinished one, else a failed latest."""
    latest = session.scalars(
        select(Scan)
        .where(Scan.engagement_id == engagement_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    ).first()
    unfinished = session.scalars(
        select(Scan)
        .where(Scan.engagement_id == engagement_id, Scan.status.in_(scans.UNFINISHED))
        .order_by(Scan.id.desc())
        .limit(1)
    ).first()
    if unfinished is not None:
        return unfinished
    if latest is not None and latest.status == ScanStatus.FAILED:
        return latest
    return None


def latest_scans(session: Session, engagement_ids: list[int]) -> dict[int, Scan]:
    """The newest scan of each engagement (for the engagement list)."""
    if not engagement_ids:
        return {}
    newest = (
        select(Scan.engagement_id, func.max(Scan.id).label("id"))
        .where(Scan.engagement_id.in_(engagement_ids))
        .group_by(Scan.engagement_id)
        .subquery()
    )
    rows = session.scalars(select(Scan).join(newest, Scan.id == newest.c.id))
    return {scan.engagement_id: scan for scan in rows}


def minutes_left(deadline: datetime | None, now: datetime | None = None) -> int | None:
    if deadline is None:
        return None
    seconds = (deadline - (now or scans.utcnow())).total_seconds()
    return max(0, int((seconds + 59) // 60))


def scan_json(session: Session, scan: Scan) -> dict[str, Any]:
    """`GET /scans/{id}` body (BSD 10.4)."""
    return {
        **scans.summary(session, scan),
        "requests": request_stats(session, scan),
        "findings": finding_stats(session, scan),
        "stats": scan.stats,
    }


def event_json(event: ScanEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "ts": event.ts,
        "level": event.level,
        "type": event.type,
        "message": event.message,
        "data": event.data,
    }


def task_json(task: Task) -> dict[str, Any]:
    return {
        "id": task.id,
        "stage": task.stage,
        "module": task.module,
        "engine": task.engine,
        "target": task.target,
        "status": task.status,
        "attempt": task.attempt,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
        "result_summary": task.result_summary,
        "error": task.error,
    }


def tasks(
    session: Session, scan_id: int, status: str | None = None, module: str | None = None
) -> list[Task]:
    query = select(Task).where(Task.scan_id == scan_id).order_by(Task.id)
    if status:
        query = query.where(Task.status == status)
    if module:
        query = query.where(Task.module == module)
    return list(session.scalars(query))


def recon_summary(session: Session, scan: Scan) -> dict[str, Any]:
    """Checkpoint summary (BSD 10.4): what recon stored, plus hosts the proxy refused."""
    stored = dict(scan.recon_summary or {})
    hosts = dict(stored.get("out_of_scope_hosts") or {})
    for host, count in session.execute(
        select(RequestLog.host, func.count())
        .where(RequestLog.scan_id == scan.id, RequestLog.outcome == "blocked_scope")
        .group_by(RequestLog.host)
    ):
        hosts[host] = max(hosts.get(host, 0), count)
    for host in TOOL_PROBE_HOSTS:
        hosts.pop(host, None)
    return {
        "technologies": stored.get("technologies", []),
        "servers": stored.get("servers", []),
        "waf": stored.get("waf"),
        "open_ports": stored.get("open_ports", []),
        "api_specs": stored.get("api_specs", []),
        "out_of_scope_hosts": [
            {"host": host, "count": count}
            for host, count in sorted(hosts.items(), key=lambda item: (-item[1], item[0]))
        ],
    }
