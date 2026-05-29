from __future__ import annotations

from typing import Any

from ..core.config import settings
from ..models.models import Finding
from .finding_policy import FINDING_MODES, classify_finding, filter_findings
from .finding_serializer import serialize_finding


def _value(finding: Any, key: str) -> Any:
    return finding.get(key) if isinstance(finding, dict) else getattr(finding, key, None)


def get_findings_for_job(db: Any, job_id: int, *, mode: str = "reportable") -> list[Finding]:
    normalized_mode = mode if mode in FINDING_MODES else "reportable"
    findings = (
        db.query(Finding)
        .filter(Finding.job_id == job_id)
        .order_by(Finding.created_at.asc())
        .all()
    )
    return filter_findings(findings, normalized_mode)


def final_report_mode() -> str:
    """Use strict validated-only final reports for real programs, but keep lab reports useful."""
    profile = str(getattr(settings, "scan_profile", "lab") or "lab").lower()
    return "validated" if profile in {"bug_bounty", "vdp"} else "raw"


def serialize_findings_for_job(
    db: Any,
    job_id: int,
    *,
    mode: str = "reportable",
    include_evidence: bool = True,
    include_internal_evidence: bool = False,
    uppercase_severity: bool = False,
    for_report: bool = False,
) -> list[dict[str, Any]]:
    return [
        serialize_finding(
            finding,
            include_evidence=include_evidence,
            include_internal_evidence=include_internal_evidence,
            uppercase_severity=uppercase_severity,
            for_report=for_report,
        )
        for finding in get_findings_for_job(db, job_id, mode=mode)
    ]


def summarize_findings(findings: list[Any]) -> dict[str, Any]:
    raw_count = len(findings)
    reportable = filter_findings(findings, "reportable")
    validated = filter_findings(findings, "validated")
    classifications = [classify_finding(finding) for finding in findings]
    false_positive_count = sum(1 for finding in findings if getattr(finding, "is_true_positive", None) is False)
    out_of_scope_count = sum(
        1
        for item in classifications
        if item.get("scope_status") == "out_of_scope"
        or item.get("reportability_status") == "excluded_out_of_scope"
    )
    needs_validation_count = sum(1 for item in classifications if item.get("reportability_status") == "needs_validation")
    duplicate_keys = {
        (
            _value(finding, "agent_name"),
            _value(finding, "category"),
            _value(finding, "title"),
        )
        for finding in findings
    }
    duplicate_count = max(raw_count - len(duplicate_keys), 0)
    suppress_count = raw_count - len(reportable)
    denominator = len(validated) + needs_validation_count
    return {
        "raw_count": raw_count,
        "reportable_count": len(reportable),
        "validated_count": len(validated),
        "suppressed_count": suppress_count,
        "false_positive_count": false_positive_count,
        "out_of_scope_count": out_of_scope_count,
        "needs_validation_count": needs_validation_count,
        "duplicate_count": duplicate_count,
        "leads_to_validated_conversion_rate": round((len(validated) / denominator) * 100, 2) if denominator else None,
        "out_of_scope_suppression_rate": round((out_of_scope_count / raw_count) * 100, 2) if raw_count else 0.0,
        "duplicate_suppression_rate": round((duplicate_count / raw_count) * 100, 2) if raw_count else 0.0,
    }
