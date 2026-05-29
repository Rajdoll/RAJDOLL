from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from ..core.config import settings


REPORTABLE_CONFIDENCE_LEVELS = {"high", "confirmed"}
FINDING_MODES = {"raw", "reportable", "validated"}
AUTO_VALIDATION_PROOF_TYPES = {
    "exploit_success",
    "sensitive_data_exposure",
    "verified_state_change",
    "data_exposure",
    "accessible_file",
    "directory_listing",
    "corroborated",
    "manual_validation",
}
AUTO_VALIDATION_PROOF_PREFIXES = ("validated_", "exploit_", "verified_")
AUTO_VALIDATION_MIN_SCORE = 0.8
LAB_PROOF_PROFILES = {"lab", "authorized_internal"}
NON_REPORTABLE_PROOF_TYPES = {
    "heuristic",
    "partial",
    "inference",
    "scope_excluded",
    "invalidated",
    "dangerous_pattern",
    "inventory_only",
    "source_observation",
}
CONCRETE_PROOF_TYPES = {
    "accessible_file",
    "directory_listing",
    "transport_configuration_check",
    "cache_header_check",
    "manual_validation",
    "corroborated",
    "exploit_success",
    "verified_state_change",
    "sensitive_data_exposure",
}
BUG_BOUNTY_OUT_OF_SCOPE_PATTERNS = (
    "rate limit",
    "rate-limit",
    "account lockout",
    "missing security header",
    "weak security header",
    "missing or weak security headers",
    "cookie attributes",
    "without samesite",
    "clickjacking",
    "version disclosure",
    "server info disclosure",
    "x-powered-by",
    "robots.txt",
    "html comments",
)


def _get_value(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_finding_evidence(finding: Any) -> dict[str, Any]:
    evidence = _get_value(finding, "evidence") or {}
    return evidence if isinstance(evidence, dict) else {}


def get_finding_confidence_score(finding: Any) -> float | None:
    direct_score = _as_float(_get_value(finding, "confidence_score"))
    if direct_score is not None:
        return direct_score

    evidence = get_finding_evidence(finding)
    confidence = evidence.get("_confidence") or {}
    return _as_float(confidence.get("score") or confidence.get("final_score"))


def get_finding_confidence_level(finding: Any) -> str | None:
    direct_level = _enum_value(_get_value(finding, "confidence_level"))
    if direct_level:
        return str(direct_level).lower()

    evidence = get_finding_evidence(finding)
    confidence = evidence.get("_confidence") or {}
    level = confidence.get("level") or confidence.get("confidence_level")
    return str(level).lower() if level else None


def extract_finding_meta(finding: Any) -> dict[str, Any]:
    evidence = get_finding_evidence(finding)
    meta = evidence.get("_meta") or {}
    if not isinstance(meta, dict):
        meta = {}

    merged = dict(meta)
    if "_scope" in evidence and "scope" not in merged:
        merged["scope"] = evidence["_scope"]
    if "_confidence" in evidence and "confidence" not in merged:
        merged["confidence"] = evidence["_confidence"]
    return merged


def _non_internal_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in evidence.items() if not str(k).startswith("_") and v not in (None, "", [], {})}


def _iter_nested_evidence_items(evidence: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for key in ("findings", "validated_findings", "evidence_items", "results"):
        items = evidence.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield item
    nested = evidence.get("evidence")
    if isinstance(nested, dict):
        yield nested


def _has_location(evidence: dict[str, Any], meta: dict[str, Any]) -> bool:
    direct_keys = {
        "url",
        "uri",
        "endpoint",
        "location",
        "path",
        "route",
        "target_url",
        "affected_url",
        "parameter",
        "host",
    }
    if any(evidence.get(key) for key in direct_keys):
        return True
    if any(meta.get(key) for key in ("url", "endpoint", "location", "affected_url")):
        return True
    for item in _iter_nested_evidence_items(evidence):
        if any(item.get(key) for key in direct_keys):
            return True

    request = evidence.get("request")
    if isinstance(request, dict) and any(request.get(key) for key in ("url", "path", "endpoint", "method")):
        return True
    if isinstance(request, str) and request.strip():
        return True
    return False


def _has_proof(evidence: dict[str, Any], meta: dict[str, Any]) -> bool:
    proof_type = str(evidence.get("proof_type") or meta.get("proof_type") or "").lower()
    if proof_type in NON_REPORTABLE_PROOF_TYPES:
        return False
    if proof_type:
        return True

    confidence = evidence.get("_confidence") if isinstance(evidence.get("_confidence"), dict) else {}
    if confidence.get("evidence_count"):
        return True

    proof_keys = {
        "payload",
        "request",
        "response",
        "evidence",
        "findings",
        "validated_findings",
        "status_code",
        "reproduction_steps",
        "repro_steps",
        "verified",
        "exploit_success",
        "data_extracted",
        "impact_evidence",
        "before",
        "after",
    }
    if any(evidence.get(key) not in (None, "", [], {}) for key in proof_keys):
        return True
    for item in _iter_nested_evidence_items(evidence):
        if any(item.get(key) not in (None, "", [], {}) for key in proof_keys | {"url", "path", "endpoint", "description"}):
            return True
    return False


def _has_severity_rationale(evidence: dict[str, Any], details: str | None, meta: dict[str, Any]) -> bool:
    if meta.get("severity_rationale") or meta.get("impact_class"):
        return True
    if evidence.get("severity_rationale") or evidence.get("impact") or evidence.get("business_impact"):
        return True
    return bool(details and details.strip())


def assess_finding_contract(
    *,
    severity: str,
    evidence: dict[str, Any] | None = None,
    details: str | None = None,
    meta: dict[str, Any] | None = None,
) -> list[str]:
    """Return contract errors that should keep a finding out of reportable output."""
    severity_value = (severity or "info").lower()
    if severity_value in {"info", "informational"}:
        return []

    evidence_dict = evidence if isinstance(evidence, dict) else {}
    meta_dict = meta if isinstance(meta, dict) else {}
    errors: list[str] = []

    if not _non_internal_evidence(evidence_dict):
        errors.append("missing_evidence_payload")
    if not _has_location(evidence_dict, meta_dict):
        errors.append("missing_endpoint_or_location")
    if not _has_proof(evidence_dict, meta_dict):
        errors.append("missing_proof_type")
    if not _has_severity_rationale(evidence_dict, details, meta_dict):
        errors.append("missing_severity_rationale")

    return errors


def _is_bug_bounty_suppressed(title: str | None, category: str | None, meta: dict[str, Any]) -> bool:
    profile = str(getattr(settings, "scan_profile", "lab") or "lab").lower()
    if profile not in {"bug_bounty", "vdp"}:
        return False
    if str(meta.get("scope_status") or "").lower() in {"in_scope", "confirmed_in_scope"}:
        return False
    text = f"{title or ''} {category or ''} {meta.get('proof_type') or ''}".lower()
    return any(pattern in text for pattern in BUG_BOUNTY_OUT_OF_SCOPE_PATTERNS)


def _scan_profile() -> str:
    return str(getattr(settings, "scan_profile", "lab") or "lab").lower()


def _evidence_proof_type(evidence: dict[str, Any] | None, meta: dict[str, Any]) -> str | None:
    if isinstance(evidence, dict) and evidence.get("proof_type"):
        return str(evidence["proof_type"]).lower()
    if meta.get("proof_type"):
        return str(meta["proof_type"]).lower()
    return None


def _lab_evidence_is_reportable(
    *,
    severity: str,
    evidence: dict[str, Any] | None,
    meta: dict[str, Any],
    contract_errors: list[str],
) -> bool:
    if _scan_profile() not in LAB_PROOF_PROFILES:
        return False
    if severity in {"info", "informational", "low"}:
        return False

    evidence_dict = evidence if isinstance(evidence, dict) else {}
    evidence_proof_type = str(evidence_dict.get("proof_type") or "").lower()
    if evidence_proof_type in NON_REPORTABLE_PROOF_TYPES:
        return False
    if not _has_location(evidence_dict, meta):
        return False
    proof_type = _evidence_proof_type(evidence, meta)
    if proof_type in CONCRETE_PROOF_TYPES:
        return True

    if _has_location(evidence_dict, meta) and _has_proof(evidence_dict, meta):
        return True
    if _non_internal_evidence(evidence_dict):
        return True
    return False


def build_finding_meta(
    *,
    severity: str,
    confidence_score: float | None = None,
    confidence_level: str | None = None,
    is_true_positive: bool | None = None,
    existing_meta: dict[str, Any] | None = None,
    preserve_existing_state: bool = True,
    evidence: dict[str, Any] | None = None,
    details: str | None = None,
    title: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    meta = dict(existing_meta or {})

    score = confidence_score
    level = confidence_level.lower() if confidence_level else None
    severity_value = (severity or "info").lower()

    scope = meta.get("scope") if isinstance(meta.get("scope"), dict) else {}
    target_scope_status = str(
        meta.get("target_scope_status") or meta.get("scope_status") or scope.get("status") or "unknown"
    ).lower()
    scope_status = target_scope_status

    if is_true_positive is True:
        finding_state = "validated_true_positive"
        reportability_status = "reportable"
        evidence_quality = "validated"
        proof_type = "manual_validation"
    elif is_true_positive is False:
        finding_state = "rejected_false_positive"
        reportability_status = "excluded_false_positive"
        evidence_quality = "rejected"
        proof_type = "invalidated"
    elif scope_status in {"out_of_scope", "oos", "excluded"}:
        finding_state = "scope_rejected"
        reportability_status = "excluded_out_of_scope"
        evidence_quality = meta.get("evidence_quality") or "weak"
        proof_type = meta.get("proof_type") or "scope_excluded"
    elif level in REPORTABLE_CONFIDENCE_LEVELS or (score is not None and score >= 0.7):
        finding_state = "pending_manual_review"
        reportability_status = "reportable"
        evidence_quality = meta.get("evidence_quality") or "strong"
        proof_type = meta.get("proof_type") or "corroborated"
    elif level == "medium" or (score is not None and score >= 0.5 and severity_value in {"high", "critical"}):
        finding_state = "triage_required"
        reportability_status = "needs_validation"
        evidence_quality = meta.get("evidence_quality") or "moderate"
        proof_type = meta.get("proof_type") or "partial"
    else:
        finding_state = "triage_required"
        reportability_status = "excluded_low_confidence"
        evidence_quality = meta.get("evidence_quality") or "weak"
        proof_type = meta.get("proof_type") or "heuristic"

    contract_errors = assess_finding_contract(
        severity=severity_value,
        evidence=evidence,
        details=details,
        meta=meta,
    )
    lab_evidence_reportable = is_true_positive is None and _lab_evidence_is_reportable(
        severity=severity_value,
        evidence=evidence,
        meta=meta,
        contract_errors=contract_errors,
    )
    if lab_evidence_reportable:
        finding_state = "pending_manual_review"
        reportability_status = "reportable"
        evidence_quality = "moderate"
        proof_type = _evidence_proof_type(evidence, meta) or "structured_evidence"
    if contract_errors and not lab_evidence_reportable and is_true_positive is None and reportability_status == "reportable":
        finding_state = "lead"
        reportability_status = "needs_validation"
        evidence_quality = "weak"
        proof_type = meta.get("proof_type") or "partial"
    if is_true_positive is None and _is_bug_bounty_suppressed(title, category, meta):
        finding_state = "scope_rejected"
        reportability_status = "excluded_out_of_scope"
        evidence_quality = "weak"
        proof_type = meta.get("proof_type") or "program_out_of_scope"
        scope_status = "out_of_scope"
        target_scope_status = "out_of_scope"

    meta.update(
        {
            "finding_state": meta.get("finding_state") if preserve_existing_state and meta.get("finding_state") else finding_state,
            "reportability_status": (
                meta.get("reportability_status")
                if preserve_existing_state and meta.get("reportability_status")
                else reportability_status
            ),
            "program_reportability_status": (
                meta.get("program_reportability_status")
                if preserve_existing_state and meta.get("program_reportability_status")
                else reportability_status
            ),
            "scope_status": scope_status,
            "target_scope_status": target_scope_status,
            "evidence_quality": evidence_quality,
            "proof_type": proof_type,
            "impact_class": meta.get("impact_class") or ("none" if severity_value in {"info", "informational"} else "unclassified"),
        }
    )
    if contract_errors:
        meta["validation_errors"] = contract_errors
    else:
        meta.pop("validation_errors", None)
    return meta


def classify_finding(finding: Any) -> dict[str, Any]:
    severity = str(_enum_value(_get_value(finding, "severity", "info"))).lower()
    is_true_positive = _get_value(finding, "is_true_positive")
    confidence_score = get_finding_confidence_score(finding)
    confidence_level = get_finding_confidence_level(finding)
    meta = build_finding_meta(
        severity=severity,
        confidence_score=confidence_score,
        confidence_level=confidence_level,
        is_true_positive=is_true_positive,
        existing_meta=extract_finding_meta(finding),
        preserve_existing_state=False,
        evidence=get_finding_evidence(finding),
        details=_get_value(finding, "details"),
        title=_get_value(finding, "title"),
        category=_get_value(finding, "category"),
    )
    return {
        "severity": severity,
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "is_true_positive": is_true_positive,
        **meta,
    }


def is_reportable_finding(finding: Any) -> bool:
    classification = classify_finding(finding)
    return classification.get("reportability_status") == "reportable"


def _is_strong_proof_type(proof_type: str) -> bool:
    if not proof_type:
        return False
    if proof_type in AUTO_VALIDATION_PROOF_TYPES:
        return True
    return any(proof_type.startswith(prefix) for prefix in AUTO_VALIDATION_PROOF_PREFIXES)


def is_auto_validated_finding(finding: Any) -> bool:
    """Promote a lead to validated when proof type is strong.

    A strong proof type is itself the verification signal — the agent or tool already
    confirmed the issue (e.g. `validated_upload_size_bypass`, `accessible_file`,
    `exploit_success`). When confidence metadata is also present, require it to be at
    least `high`/0.8. When confidence is missing (current persistence gap), the strong
    proof type alone is sufficient.

    Manual rejection (`is_true_positive is False`) always wins.
    """
    if _get_value(finding, "is_true_positive") is False:
        return False
    evidence = get_finding_evidence(finding)
    meta = extract_finding_meta(finding)
    proof_type = str(evidence.get("proof_type") or meta.get("proof_type") or "").lower()
    if not _is_strong_proof_type(proof_type):
        return False
    score = get_finding_confidence_score(finding)
    level = get_finding_confidence_level(finding)
    if level is None and score is None:
        return True
    if level in REPORTABLE_CONFIDENCE_LEVELS:
        return True
    return score is not None and score >= AUTO_VALIDATION_MIN_SCORE


def finding_matches_mode(finding: Any, mode: str = "reportable") -> bool:
    normalized_mode = (mode or "reportable").lower()
    if normalized_mode not in FINDING_MODES:
        normalized_mode = "reportable"

    if normalized_mode == "raw":
        return True
    if normalized_mode == "validated":
        if _get_value(finding, "is_true_positive") is True:
            return True
        return is_auto_validated_finding(finding)
    return is_reportable_finding(finding)


def filter_findings(findings: Iterable[Any], mode: str = "reportable") -> list[Any]:
    return [finding for finding in findings if finding_matches_mode(finding, mode)]


def apply_manual_validation(
    finding: Any,
    *,
    is_true_positive: bool,
    notes: str | None = None,
    source: str = "admin_review",
) -> dict[str, Any]:
    """Apply manual validation to a finding object and synchronize evidence metadata."""
    evidence = get_finding_evidence(finding)
    meta = extract_finding_meta(finding)
    classification = build_finding_meta(
        severity=str(_enum_value(_get_value(finding, "severity", "info"))).lower(),
        confidence_score=get_finding_confidence_score(finding),
        confidence_level=get_finding_confidence_level(finding),
        is_true_positive=is_true_positive,
        existing_meta=meta,
        preserve_existing_state=False,
        evidence=evidence,
        details=_get_value(finding, "details"),
        title=_get_value(finding, "title"),
        category=_get_value(finding, "category"),
    )
    classification.update(
        {
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "validation_source": source,
        }
    )
    if notes:
        classification["validation_notes"] = notes

    updated_evidence = dict(evidence)
    updated_evidence["_meta"] = classification

    finding.is_true_positive = is_true_positive
    finding.validation_notes = notes
    finding.evidence = updated_evidence
    return classification
