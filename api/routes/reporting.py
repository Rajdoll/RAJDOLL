from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job
from multi_agent_system.utils.report_service import final_report_mode, serialize_findings_for_job
import json


router = APIRouter()


@router.get("/scans/{job_id}/report/compliance", response_class=PlainTextResponse)
def get_compliance_report(job_id: int):
    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        findings = serialize_findings_for_job(db, job_id, mode=final_report_mode(), for_report=True)

    # Build a simple markdown summary suitable for compliance attachments
    counts = {}
    for f in findings:
        key = (f.get("severity", "info"), f.get("category", "Uncategorized"))
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
        def sev_key(f: dict):
            sev = f.get("severity", "info").lower()
            return (order.get(sev, 9), f.get("created_at") or 0)
        for f in sorted(findings, key=sev_key):
            sev = f.get("severity", "info").upper()
            title = f.get("title") or "Untitled Finding"
            agent = f.get("agent_name") or "Unknown"
            created = f.get("created_at")
            created_s = created.isoformat() if created else ""
            lines.append(f"- [{sev}] {f.get('category')} - {title} (Agent: {agent}, ID: {f.get('id')})")
            if created_s:
                lines.append(f"  - When: {created_s}")
            if f.get("details"):
                lines.append(f"  - Details: {f.get('details')}")
            if f.get("evidence") is not None:
                try:
                    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else json.loads(str(f.get("evidence")))
                    lines.append("  - Evidence:")
                    lines.append("\n".join(["    " + l for l in ("```json\n" + json.dumps(ev, indent=2) + "\n```").splitlines()]))
                except Exception:
                    # Fallback to raw string block
                    lines.append("  - Evidence (raw):")
                    lines.append("\n".join(["    " + l for l in ("```\n" + str(f.get("evidence")) + "\n```").splitlines()]))

    return "\n".join(lines)


# Legacy compatibility: support old path `/api/reporting/compliance?job_id=...`
@router.get("/reporting/compliance", response_class=PlainTextResponse)
def legacy_get_compliance_report(job_id: int):
    return get_compliance_report(job_id)
