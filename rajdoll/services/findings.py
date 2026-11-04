"""Findings: creation by fingerprint, encrypted evidence and PoC, validation (BSD 6.1–6.3).

A finding is identified by its fingerprint (module, vulnerability type, method, host, path
template, parameter), so a test repeated in a later scan adds evidence to the existing finding
instead of creating a duplicate, and never touches the assessor's decision (AFD 3.4).
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rajdoll.core import cvss
from rajdoll.core.crypto import FieldCipher, KeyStore
from rajdoll.core.enums import EvidenceKind, Validation
from rajdoll.core.models import Endpoint, Engagement, Evidence, Finding
from rajdoll.data import vuln_types
from rajdoll.modules.base import Candidate, Exchange, Verdict
from rajdoll.services import engagements, inventory

DEFAULT_EVIDENCE_BYTES = 1_048_576


def fingerprint(
    module: str, vuln_type: str, method: str, host: str, path_template: str, parameter: str | None
) -> str:
    parts = [module, vuln_type, method.upper(), host.lower(), path_template, parameter or ""]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _cipher(keystore: KeyStore, session: Session, engagement_id: int) -> FieldCipher:
    return engagements.cipher(keystore, session.get(Engagement, engagement_id))


def _clip(text: str | None, limit: int) -> tuple[str | None, bool]:
    if text is None:
        return None, False
    data = text.encode("utf-8", errors="replace")
    if len(data) <= limit:
        return text, False
    return data[:limit].decode("utf-8", errors="ignore"), True


def add_evidence(
    session: Session,
    cipher: FieldCipher,
    finding: Finding,
    scan_id: int | None,
    kind: EvidenceKind,
    exchange: Exchange,
    max_bytes: int = DEFAULT_EVIDENCE_BYTES,
) -> Evidence:
    """Store one request/response pair encrypted; the response is cut at `max_bytes`."""
    sequence = (
        session.scalar(select(func.max(Evidence.sequence)).where(Evidence.finding_id == finding.id))
        or 0
    ) + 1
    response, truncated = _clip(exchange.response, max_bytes)
    request, request_cut = _clip(exchange.request, max_bytes)
    evidence = Evidence(
        finding_id=finding.id,
        scan_id=scan_id,
        kind=kind,
        sequence=sequence,
        request_enc=cipher.encrypt_text("evidence", "request_enc", request or ""),
        response_enc=(
            cipher.encrypt_text("evidence", "response_enc", response)
            if response is not None
            else None
        ),
        response_status=exchange.status,
        truncated=truncated or request_cut,
        note=exchange.note,
    )
    session.add(evidence)
    session.flush()
    return evidence


def _scores(vector: str) -> tuple[Decimal, str]:
    score = cvss.score31(vector)
    return Decimal(str(score)), cvss.severity(score)


def record_candidate(
    session: Session,
    keystore: KeyStore,
    engagement_id: int,
    scan_id: int | None,
    module: str,
    candidate: Candidate,
    max_bytes: int = DEFAULT_EVIDENCE_BYTES,
) -> tuple[Finding, bool]:
    """Create the finding or add evidence to the existing one. Returns (finding, created)."""
    norm = inventory.normalize(candidate.method, candidate.url)
    if norm is None:
        raise ValueError(f"cannot normalize {candidate.method} {candidate.url}")
    kind = vuln_types.get(candidate.vuln_type)
    fp = fingerprint(
        module, kind.key, norm.method, norm.host, norm.path_template, candidate.parameter
    )
    cipher = _cipher(keystore, session, engagement_id)
    # Two tasks may report the same candidate at once: serialize on the fingerprint so the
    # second one finds the first one's row instead of violating the unique constraint.
    lock_key = func.hashtextextended(f"finding:{engagement_id}:{fp}", 0)
    session.execute(select(func.pg_advisory_xact_lock(lock_key)))
    finding = session.scalars(
        select(Finding)
        .where(Finding.engagement_id == engagement_id, Finding.fingerprint == fp)
        .with_for_update()
    ).first()
    created = finding is None
    if finding is None:
        endpoint_id = session.scalar(
            select(Endpoint.id).where(
                Endpoint.engagement_id == engagement_id,
                Endpoint.method == norm.method,
                Endpoint.host == norm.host,
                Endpoint.path_template == norm.path_template,
            )
        )
        score, severity = _scores(kind.cvss31)
        location = f" pada parameter {candidate.parameter}" if candidate.parameter else ""
        finding = Finding(
            engagement_id=engagement_id,
            fingerprint=fp,
            title=f"{kind.title} di {norm.path_template}{location}",
            vuln_type=kind.key,
            module=module,
            wstg_id=kind.wstg_id,
            cwe_id=kind.cwe_id,
            endpoint_id=endpoint_id,
            parameter=candidate.parameter,
            severity=severity,
            cvss31_vector=kind.cvss31,
            cvss31_score=score,
            validation=Validation.NEEDS_MANUAL_CHECK,
            description=kind.description,
            impact=kind.impact,
            recommendation=kind.recommendation,
            references=list(kind.references),
            first_scan_id=scan_id,
            last_scan_id=scan_id,
        )
        session.add(finding)
        session.flush()
    else:
        finding.last_scan_id = scan_id
    if finding.poc_spec_enc is None or created:
        finding.poc_spec_enc = cipher.encrypt_json("finding", "poc_spec_enc", candidate.poc)
    for exchange in candidate.evidence:
        add_evidence(session, cipher, finding, scan_id, EvidenceKind.DETECTION, exchange, max_bytes)
    return finding, created


def poc(session: Session, keystore: KeyStore, finding: Finding) -> dict[str, Any]:
    if finding.poc_spec_enc is None:
        return {}
    cipher = _cipher(keystore, session, finding.engagement_id)
    return cipher.decrypt_json("finding", "poc_spec_enc", finding.poc_spec_enc)


def record_verdict(
    session: Session,
    keystore: KeyStore,
    finding: Finding,
    scan_id: int | None,
    verdict: Verdict,
    max_bytes: int = DEFAULT_EVIDENCE_BYTES,
) -> None:
    """Store validation evidence; a confirmed verdict makes the finding `confirmed` (TRD 6.3).

    A finding is never downgraded here: once confirmed, later inconclusive runs only add evidence.
    """
    cipher = _cipher(keystore, session, finding.engagement_id)
    for exchange in verdict.evidence:
        add_evidence(
            session, cipher, finding, scan_id, EvidenceKind.VALIDATION, exchange, max_bytes
        )
    if verdict.confirmed:
        finding.validation = Validation.CONFIRMED


def evidence_rows(session: Session, keystore: KeyStore, finding: Finding) -> list[dict[str, Any]]:
    """Decrypted evidence for display, in order."""
    cipher = _cipher(keystore, session, finding.engagement_id)
    rows = session.scalars(
        select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.sequence)
    )
    return [
        {
            "id": e.id,
            "kind": e.kind,
            "sequence": e.sequence,
            "scan_id": e.scan_id,
            "request": cipher.decrypt_text("evidence", "request_enc", e.request_enc),
            "response": (
                cipher.decrypt_text("evidence", "response_enc", e.response_enc)
                if e.response_enc is not None
                else None
            ),
            "status": e.response_status,
            "truncated": e.truncated,
            "note": e.note,
            "created_at": e.created_at,
        }
        for e in rows
    ]


def for_validation(session: Session, scan_id: int) -> list[dict[str, Any]]:
    """Findings this scan found or saw again that are not confirmed yet."""
    rows = session.scalars(
        select(Finding)
        .where(
            Finding.last_scan_id == scan_id,
            Finding.validation == Validation.NEEDS_MANUAL_CHECK,
            Finding.merged_into_id.is_(None),
        )
        .order_by(Finding.id)
    )
    return [{"id": f.id, "vuln_type": f.vuln_type} for f in rows]


def as_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "vuln_type": finding.vuln_type,
        "module": finding.module,
        "wstg_id": finding.wstg_id,
        "cwe_id": finding.cwe_id,
        "endpoint_id": finding.endpoint_id,
        "parameter": finding.parameter,
        "severity": finding.severity,
        "cvss31_vector": finding.cvss31_vector,
        "cvss31_score": float(finding.cvss31_score) if finding.cvss31_score is not None else None,
        "validation": finding.validation,
        "decision": finding.decision,
        "retest_result": finding.retest_result,
        "first_scan_id": finding.first_scan_id,
        "last_scan_id": finding.last_scan_id,
    }


def dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)
