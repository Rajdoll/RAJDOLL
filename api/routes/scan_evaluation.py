from __future__ import annotations

from fastapi import APIRouter, HTTPException

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Finding
from multi_agent_system.evaluation.job_evaluation import load_gt_entries, compare_findings_to_gt

router = APIRouter()


def get_job_findings(job_id: int) -> list[dict]:
    with get_db() as db:
        rows = db.query(Finding).filter(Finding.job_id == job_id).all()
        return [
            {
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "agent_name": f.agent_name,
            }
            for f in rows
        ]


@router.get("/scans/{job_id}/evaluation")
def get_scan_evaluation(job_id: int, target_profile: str = "juiceshop"):
    findings = get_job_findings(job_id)
    try:
        gt = load_gt_entries(target_profile)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"No ground truth for profile '{target_profile}'")
    result = compare_findings_to_gt(findings, gt)
    result["job_id"] = job_id
    result["target_profile"] = target_profile
    return result
