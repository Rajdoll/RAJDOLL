"""Report exports (AFD A9, BSD 6.8 and 10.7): the VA report from accepted findings.

Every export is kept (encrypted, with its warnings and finding count), so an earlier version can
be downloaded again. Retest reports arrive with retest (F10).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import Decision, ReportKind, ScanKind, TaskStatus
from rajdoll.core.models import Engagement, Finding, ReportExport, Scan, Task
from rajdoll.modules.registry import label as module_label
from rajdoll.reporting import va
from rajdoll.reporting.va import SEVERITY_NAMES, wib
from rajdoll.services import engagements, findings
from rajdoll.services.errors import NotFound, ValidationFailed

KIND_LABELS = {ReportKind.VA: "Laporan VA", ReportKind.RETEST: "Laporan retest"}


def _blocked_tasks(session: Session, engagement_id: int) -> list[Task]:
    return list(
        session.scalars(
            select(Task)
            .join(Scan, Task.scan_id == Scan.id)
            .where(Scan.engagement_id == engagement_id, Task.status == TaskStatus.BLOCKED)
            .order_by(Task.id)
        )
    )


def warnings(session: Session, engagement_id: int) -> dict[str, int]:
    """Non-blocking warnings before an export (AFD A9 step 2)."""
    counts = findings.decision_counts(session, engagement_id)
    return {
        "pending_findings": counts.get(Decision.PENDING, 0),
        "blocked_tasks": len(_blocked_tasks(session, engagement_id)),
    }


def warning_messages(values: dict[str, int]) -> list[str]:
    messages = []
    if values.get("pending_findings"):
        messages.append(
            f"Masih ada {values['pending_findings']} temuan yang belum diputuskan; "
            "temuan tersebut tidak masuk laporan."
        )
    if values.get("blocked_tasks"):
        messages.append(f"{values['blocked_tasks']} pengujian terblokir; dicantumkan di laporan.")
    return messages


def _evidence(session: Session, keystore: KeyStore, finding: Finding) -> list[dict[str, Any]]:
    """The first detection and the last validation evidence, clipped for the report."""
    rows = findings.evidence_rows(session, keystore, finding)
    chosen = []
    detection = next((r for r in rows if r["kind"] == "detection"), None)
    validation = next((r for r in reversed(rows) if r["kind"] == "validation"), None)
    for row in (detection, validation):
        if row is None:
            continue
        request, cut_request = va.clip(row["request"])
        response, cut_response = va.clip(row["response"])
        chosen.append(
            {
                "label": findings.EVIDENCE_KIND_LABELS.get(row["kind"], row["kind"]).capitalize(),
                "note": row["note"],
                "request": request or "",
                "response": response,
                "cut": cut_request or cut_response or row["truncated"],
            }
        )
    return chosen


def _finding_context(
    session: Session, keystore: KeyStore, finding: Finding, number: int
) -> dict[str, Any]:
    detail = findings.detail(session, keystore, finding)
    endpoint = detail["endpoint"]
    try:
        curl = findings.poc_text(session, keystore, finding, "curl")
    except NotFound:
        curl = None
    accounts = findings.poc_accounts(findings.poc(session, keystore, finding)) if curl else None
    return {
        **detail,
        "number": number,
        "severity_label": SEVERITY_NAMES.get(finding.severity, finding.severity),
        "validation_label": findings.VALIDATION_LABELS.get(finding.validation, finding.validation),
        "cvss31_vector": finding.cvss31_vector,
        "cvss31_score": float(finding.cvss31_score) if finding.cvss31_score is not None else None,
        "endpoint": f"{endpoint['method']} {endpoint['url']}" if endpoint else None,
        "curl": curl,
        "poc_accounts": accounts,
        "evidence": _evidence(session, keystore, finding),
    }


def _period(engagement: Engagement) -> str | None:
    if not engagement.start_date:
        return None
    start = engagement.start_date.strftime("%d-%m-%Y")
    end = engagement.end_date.strftime("%d-%m-%Y") if engagement.end_date else None
    return f"{start} s.d. {end}" if end else start


def build_va(
    session: Session, keystore: KeyStore, engagement: Engagement, now: datetime | None = None
) -> tuple[str, int]:
    """The VA report's Markdown and the number of findings in it (accepted only)."""
    accepted = findings.list_for(session, engagement.id, {"decision": Decision.ACCEPTED})
    order = {s: i for i, s in enumerate(findings.SEVERITY_ORDER)}
    accepted.sort(key=lambda f: (order.get(f.severity, 99), -(f.cvss31_score or 0), f.id))
    items = [_finding_context(session, keystore, f, i) for i, f in enumerate(accepted, start=1)]
    scans = list(
        session.scalars(
            select(Scan)
            .where(Scan.engagement_id == engagement.id, Scan.kind == ScanKind.SCAN)
            .order_by(Scan.number)
        )
    )
    modules: list[str] = []
    for scan in scans:
        for name in scan.modules:
            if module_label(name) not in modules:
                modules.append(module_label(name))
    blocked = [
        {
            "module": module_label(task.module),
            "engine": task.engine,
            "target": (task.target or {}).get("url"),
            "error": task.error,
        }
        for task in _blocked_tasks(session, engagement.id)
    ]
    context = {
        "engagement": engagement,
        "period": _period(engagement),
        "generated": wib(now or datetime.now(UTC), "%d-%m-%Y %H:%M WIB"),
        "scans": [
            {"number": s.number, "date": wib(s.started_at or s.created_at, "%d-%m-%Y")}
            for s in scans
        ],
        "severity_counts": [
            {"label": SEVERITY_NAMES[s], "count": sum(f.severity == s for f in accepted)}
            for s in findings.SEVERITY_ORDER
        ],
        "findings": items,
        "blocked": blocked,
        "scope": engagements.scope_patterns(session, engagement.id),
        "modules": modules,
    }
    return va.render(context), len(items)


def create(
    session: Session, keystore: KeyStore, engagement: Engagement, kind: str = ReportKind.VA
) -> ReportExport:
    if kind == ReportKind.RETEST:
        raise ValidationFailed.one("kind", "Laporan retest tersedia bersama fitur retest (F10).")
    if kind != ReportKind.VA:
        raise ValidationFailed.one("kind", "Jenis laporan harus va atau retest.")
    content, count = build_va(session, keystore, engagement)
    cipher = engagements.cipher(keystore, engagement)
    report = ReportExport(
        engagement_id=engagement.id,
        kind=kind,
        finding_count=count,
        warnings=warnings(session, engagement.id),
        content_enc=cipher.encrypt_text("report_export", "content_enc", content),
    )
    session.add(report)
    session.flush()
    return report


def list_for(session: Session, engagement_id: int) -> list[ReportExport]:
    return list(
        session.scalars(
            select(ReportExport)
            .where(ReportExport.engagement_id == engagement_id)
            .order_by(ReportExport.id.desc())
        )
    )


def get(session: Session, report_id: int) -> ReportExport:
    report = session.get(ReportExport, report_id)
    if report is None:
        raise NotFound("Laporan tidak ditemukan.")
    return report


def content(session: Session, keystore: KeyStore, report: ReportExport) -> str:
    cipher = engagements.cipher(keystore, session.get(Engagement, report.engagement_id))
    return cipher.decrypt_text("report_export", "content_enc", report.content_enc)


def filename(engagement: Engagement, report: ReportExport) -> str:
    """`<aplikasi>-<jenis>-<tanggal>.md` (BSD 10.7), ASCII only."""
    slug = re.sub(r"[^a-z0-9]+", "-", engagement.name.lower()).strip("-") or "aplikasi"
    return f"{slug[:60]}-{report.kind}-{wib(report.created_at, '%Y-%m-%d')}.md"


def as_dict(report: ReportExport) -> dict[str, Any]:
    return {
        "id": report.id,
        "kind": report.kind,
        "finding_count": report.finding_count,
        "warnings": report.warnings,
        "created_at": report.created_at,
    }


def count_for(session: Session, engagement_id: int) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(ReportExport)
            .where(ReportExport.engagement_id == engagement_id)
        )
        or 0
    )
