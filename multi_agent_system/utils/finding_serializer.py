from __future__ import annotations

import re
from typing import Any

from ..core.security_guards import data_redactor
from .finding_policy import classify_finding


def normalize_severity(severity: Any, *, uppercase: bool = False) -> str:
    value = severity.value if hasattr(severity, "value") else severity
    normalized = str(value or "info").lower()
    if normalized in {"informational", "information"}:
        normalized = "info"
    return normalized.upper() if uppercase else normalized


def normalize_wstg_id(wstg_id: Any, *, fallback_category: Any = None) -> str:
    value = str(wstg_id or fallback_category or "").strip().upper()
    if not value:
        return ""
    value = value.replace("_", "-").replace(" ", "-")
    match = re.search(r"(WSTG-[A-Z]{4})(?:-(\d{1,2}))?", value)
    if not match:
        return value if value.startswith("WSTG-") else ""
    category, number = match.groups()
    return f"{category}-{int(number):02d}" if number else category


def normalize_cwe_id(cwe_id: Any) -> str:
    value = str(cwe_id or "").strip().upper()
    if not value:
        return ""
    match = re.search(r"CWE[-_\s]?(\d+)", value)
    if match:
        return f"CWE-{int(match.group(1))}"
    if value.isdigit():
        return f"CWE-{int(value)}"
    return value


def _clean_evidence(evidence: Any, *, include_internal: bool) -> Any:
    redacted = data_redactor.redact_any(evidence)
    if include_internal or not isinstance(redacted, dict):
        return redacted
    return {k: v for k, v in redacted.items() if not str(k).startswith("_")}


def _serialize_datetime(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def serialize_finding(
    finding: Any,
    *,
    include_evidence: bool = True,
    include_internal_evidence: bool = False,
    uppercase_severity: bool = False,
    for_report: bool = False,
) -> dict[str, Any]:
    """Canonical serializer for findings exposed by APIs and reports."""
    classification = classify_finding(finding)
    severity = normalize_severity(getattr(finding, "severity", "info"), uppercase=uppercase_severity)
    evidence = getattr(finding, "evidence", None)

    serialized = {
        "id": getattr(finding, "id", None),
        "agent_name": getattr(finding, "agent_name", None) or "Unknown",
        "category": getattr(finding, "category", None) or "Uncategorized",
        "title": data_redactor.redact(getattr(finding, "title", None) or "Untitled Finding"),
        "severity": severity,
        "details": data_redactor.redact(getattr(finding, "details", None) or ""),
        "created_at": _serialize_datetime(getattr(finding, "created_at", None)),
        "is_true_positive": getattr(finding, "is_true_positive", None),
        "validation_notes": data_redactor.redact(getattr(finding, "validation_notes", None) or ""),
        "confidence_score": classification.get("confidence_score"),
        "confidence_level": classification.get("confidence_level"),
        "finding_state": classification.get("finding_state"),
        "reportability_status": classification.get("reportability_status"),
        "scope_status": classification.get("scope_status"),
        "target_scope_status": classification.get("target_scope_status"),
        "program_reportability_status": classification.get("program_reportability_status"),
        "evidence_quality": classification.get("evidence_quality"),
        "proof_type": classification.get("proof_type"),
        "impact_class": classification.get("impact_class"),
        "validation_errors": classification.get("validation_errors", []),
    }
    if include_evidence:
        serialized["evidence"] = _clean_evidence(evidence, include_internal=include_internal_evidence)

    if for_report:
        wstg_id = normalize_wstg_id(getattr(finding, "wstg_id", None), fallback_category=getattr(finding, "category", None))
        cwe_id = normalize_cwe_id(getattr(finding, "cwe_id", None))
        serialized.update(
            {
                "explanation": data_redactor.redact(getattr(finding, "explanation", None) or ""),
                "remediation": data_redactor.redact(getattr(finding, "remediation", None) or ""),
                "cwe_id": cwe_id,
                "wstg_id": wstg_id,
                "wstg_category": wstg_id.rsplit("-", 1)[0] if re.match(r"^WSTG-[A-Z]{4}-\d{2}$", wstg_id) else wstg_id,
                "cvss_score_v4": getattr(finding, "cvss_score_v4", None),
                "references": data_redactor.redact_any(getattr(finding, "references", None) or []),
                "enrichment_source": getattr(finding, "enrichment_source", None) or "fallback",
            }
        )

    return serialized
