from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, Finding
import json


router = APIRouter()


@router.get("/scans/{job_id}/report/compliance", response_class=PlainTextResponse)
def get_compliance_report(job_id: int):
    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        findings = db.query(Finding).filter(Finding.job_id == job_id).all()

    # Build a simple markdown summary suitable for compliance attachments
    counts = {}
    for f in findings:
        key = (f.severity.value if hasattr(f.severity, 'value') else str(f.severity), f.category)
        counts[key] = counts.get(key, 0) + 1

    lines = [
        f"# Compliance Summary for Job {job_id}",
        f"Target: {job.target}",
        "",
        "## Findings by Severity and Category",
    ]
    if not counts:
        lines.append("No findings recorded.")
    else:
        for (sev, cat), n in sorted(counts.items(), key=lambda x: x[0]):
            lines.append(f"- {sev.upper()} — {cat}: {n}")

    # Detailed section
    lines.append("")
    lines.append("## Detailed Findings")
    if not findings:
        lines.append("None.")
    else:
        # Sort by severity (High->Low->Info) then by created time
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        def sev_key(f: Finding):
            sev = (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).lower()
            return (order.get(sev, 9), getattr(f, 'created_at', None) or 0)
        for f in sorted(findings, key=sev_key):
            sev = (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper()
            title = f.title or "Untitled Finding"
            agent = getattr(f, 'agent_name', 'Unknown')
            created = getattr(f, 'created_at', None)
            created_s = created.isoformat() if created else ""
            lines.append(f"- [{sev}] {f.category} — {title} (Agent: {agent}, ID: {f.id})")
            if created_s:
                lines.append(f"  - When: {created_s}")
            if f.details:
                lines.append(f"  - Details: {f.details}")
            if f.evidence is not None:
                try:
                    ev = f.evidence if isinstance(f.evidence, dict) else json.loads(str(f.evidence))
                    lines.append("  - Evidence:")
                    lines.append("\n".join(["    " + l for l in ("```json\n" + json.dumps(ev, indent=2) + "\n```").splitlines()]))
                except Exception:
                    # Fallback to raw string block
                    lines.append("  - Evidence (raw):")
                    lines.append("\n".join(["    " + l for l in ("```\n" + str(f.evidence) + "\n```").splitlines()]))

    return "\n".join(lines)


# Legacy compatibility: support old path `/api/reporting/compliance?job_id=...`
@router.get("/reporting/compliance", response_class=PlainTextResponse)
def legacy_get_compliance_report(job_id: int):
    return get_compliance_report(job_id)
