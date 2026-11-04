"""Findings: creation by fingerprint, encrypted evidence and PoC, validation (BSD 6.1–6.3).

A finding is identified by its fingerprint (module, vulnerability type, method, host, path
template, parameter), so a test repeated in a later scan adds evidence to the existing finding
instead of creating a duplicate, and never touches the assessor's decision (AFD 3.4).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from rajdoll.core import cvss
from rajdoll.core.crypto import FieldCipher, KeyStore
from rajdoll.core.enums import Decision, EvidenceKind, RetestResult, Validation
from rajdoll.core.models import Endpoint, Engagement, Evidence, Finding
from rajdoll.data import vuln_types
from rajdoll.modules import httpkit
from rajdoll.modules.base import Candidate, Exchange, Verdict
from rajdoll.services import engagements, inventory
from rajdoll.services.errors import NotFound, ValidationFailed

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


def for_triage(session: Session, scan_id: int) -> list[dict[str, Any]]:
    """Every finding this scan found or saw again (AI_TRIAGE stage)."""
    rows = session.scalars(
        select(Finding)
        .where(Finding.last_scan_id == scan_id, Finding.merged_into_id.is_(None))
        .order_by(Finding.id)
    )
    return [{"id": f.id, "vuln_type": f.vuln_type, "title": f.title} for f in rows]


def llm_notes(session: Session, keystore: KeyStore, finding: Finding) -> dict[str, Any]:
    """AI notes (BSD 6.1 `llm_notes_enc`): explanation, suggestions, verification rounds."""
    if finding.llm_notes_enc is None:
        return {}
    cipher = _cipher(keystore, session, finding.engagement_id)
    return cipher.decrypt_json("finding", "llm_notes_enc", finding.llm_notes_enc)


def save_llm_notes(
    session: Session, keystore: KeyStore, finding: Finding, notes: dict[str, Any]
) -> None:
    current = llm_notes(session, keystore, finding)
    rounds = list(current.get("verification_rounds") or [])
    rounds += list(notes.get("verification_rounds") or [])
    merged = {**current, **{k: v for k, v in notes.items() if k != "verification_rounds"}}
    if rounds:
        merged["verification_rounds"] = rounds
    cipher = _cipher(keystore, session, finding.engagement_id)
    finding.llm_notes_enc = cipher.encrypt_json("finding", "llm_notes_enc", merged)
    session.flush()


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


# --------------------------------------------------------------------------------------
# Triage (AFD A8, BSD 10.5)
# --------------------------------------------------------------------------------------

VALIDATION_LABELS = {
    Validation.CONFIRMED: "terkonfirmasi",
    Validation.NEEDS_MANUAL_CHECK: "perlu cek manual",
    Validation.MANUAL: "manual",
}
DECISION_LABELS = {
    Decision.PENDING: "belum diputuskan",
    Decision.ACCEPTED: "diterima",
    Decision.REJECTED: "ditolak",
}
EVIDENCE_KIND_LABELS = {
    "detection": "deteksi",
    "validation": "validasi",
    "verification_round": "putaran verifikasi",
    "resend": "kirim ulang",
    "retest": "retest",
    "manual": "manual",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
FILTERS = ("validation", "decision", "severity", "module", "scan_id")
MAX_REASON = 2000


def _filter_values(filters: dict[str, Any]) -> dict[str, Any]:
    """Known filters with a non-empty value; unknown values are a validation error."""
    allowed = {
        "validation": set(Validation),
        "decision": set(Decision),
        "severity": set(SEVERITY_ORDER),
    }
    chosen: dict[str, Any] = {}
    for name in FILTERS:
        value = str(filters.get(name) or "").strip()
        if not value:
            continue
        if name in allowed and value not in allowed[name]:
            raise ValidationFailed.one(name, f"Nilai filter {name} tidak dikenal.")
        if name == "scan_id":
            if not value.isdigit():
                raise ValidationFailed.one("scan_id", "Filter scan harus berupa nomor.")
            chosen[name] = int(value)
        else:
            chosen[name] = value
    return chosen


def list_for(
    session: Session, engagement_id: int, filters: dict[str, Any] | None = None
) -> list[Finding]:
    """Findings of an engagement in the AFD A8 order: undecided first, then confirmed before
    needs-manual-check, then highest severity. Merged findings are hidden."""
    chosen = _filter_values(filters or {})
    query = select(Finding).where(
        Finding.engagement_id == engagement_id, Finding.merged_into_id.is_(None)
    )
    for name in ("validation", "decision", "severity", "module"):
        if name in chosen:
            query = query.where(getattr(Finding, name) == chosen[name])
    if "scan_id" in chosen:
        query = query.where(
            or_(
                Finding.first_scan_id == chosen["scan_id"],
                Finding.last_scan_id == chosen["scan_id"],
            )
        )
    decision_rank = case({"pending": 0, "accepted": 1, "rejected": 2}, value=Finding.decision)
    validation_rank = case(
        {"confirmed": 0, "manual": 1, "needs_manual_check": 2}, value=Finding.validation
    )
    severity_rank = case({s: i for i, s in enumerate(SEVERITY_ORDER)}, value=Finding.severity)
    return list(
        session.scalars(query.order_by(decision_rank, validation_rank, severity_rank, Finding.id))
    )


def decision_counts(session: Session, engagement_id: int) -> dict[str, int]:
    rows = session.execute(
        select(Finding.decision, func.count())
        .where(Finding.engagement_id == engagement_id, Finding.merged_into_id.is_(None))
        .group_by(Finding.decision)
    )
    counts = {d.value: 0 for d in Decision}
    counts.update({decision: count for decision, count in rows})
    return counts


def get(session: Session, finding_id: int) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.merged_into_id is not None:
        raise NotFound("Temuan tidak ditemukan.")
    return finding


def decide(session: Session, finding: Finding, decision: str, reason: str | None = None) -> None:
    """The assessor's decision (AFD 3.4). Rejecting needs a reason; leaving `accepted` clears
    the retest result first (BSD 6.1)."""
    if decision not in set(Decision):
        raise ValidationFailed.one(
            "decision", "Keputusan harus diterima, ditolak, atau belum diputuskan."
        )
    reason = (reason or "").strip()
    if decision == Decision.REJECTED and not reason:
        raise ValidationFailed.one("reason", "Alasan wajib diisi saat menolak temuan.")
    if len(reason) > MAX_REASON:
        raise ValidationFailed.one("reason", f"Alasan paling panjang {MAX_REASON} karakter.")
    if decision != Decision.ACCEPTED:
        finding.retest_result = RetestResult.NOT_TESTED
    finding.decision = decision
    finding.decision_reason = reason if decision == Decision.REJECTED else None
    finding.decided_at = None if decision == Decision.PENDING else datetime.now(UTC)
    session.flush()


def base_url_of(session: Session, finding: Finding) -> str:
    """Where the PoC path is sent: the finding's endpoint host, else the engagement target."""
    endpoint = session.get(Endpoint, finding.endpoint_id) if finding.endpoint_id else None
    if endpoint is not None:
        return f"{endpoint.scheme}://{endpoint.host}"
    target = urlsplit(session.get(Engagement, finding.engagement_id).target_url)
    return f"{target.scheme}://{target.netloc}"


def poc_text(session: Session, keystore: KeyStore, finding: Finding, fmt: str) -> str:
    """The PoC as a curl command or a raw HTTP request (Burp Repeater), without the session."""
    spec = poc(session, keystore, finding)
    if not spec:
        raise NotFound("Temuan ini tidak punya PoC.")
    base = base_url_of(session, finding)
    if fmt == "curl":
        return httpkit.curl(base, spec)
    if fmt == "raw":
        return httpkit.raw_from_poc(base, spec)
    raise ValidationFailed.one("format", "Format PoC harus curl atau raw.")


def poc_accounts(spec: dict[str, Any] | None) -> str | None:
    """Which account's session the PoC needs (authorization findings), as a sentence."""
    account = (spec or {}).get("account")
    if not account:
        return None
    params = (spec or {}).get("validator_params") or {}
    text = f"Kirim dengan sesi {account}"
    if params.get("owner_account"):
        text += f"; objeknya milik {params['owner_account']}"
    if params.get("privileged_account"):
        text += f"; fungsi ini untuk akun dengan hak seperti {params['privileged_account']}"
    return text + "."


def detail(session: Session, keystore: KeyStore, finding: Finding) -> dict[str, Any]:
    """BSD 10.5 `GET /findings/{id}` (without evidence)."""
    endpoint = session.get(Endpoint, finding.endpoint_id) if finding.endpoint_id else None
    evidence_count = session.scalar(
        select(func.count()).select_from(Evidence).where(Evidence.finding_id == finding.id)
    )
    return {
        "id": finding.id,
        "title": finding.title,
        "vuln_type": finding.vuln_type,
        "module": finding.module,
        "wstg_id": finding.wstg_id,
        "cwe_id": finding.cwe_id,
        "endpoint": (
            {
                "id": endpoint.id,
                "method": endpoint.method,
                "path_template": endpoint.path_template,
                "url": inventory.url_of(endpoint),
            }
            if endpoint is not None
            else None
        ),  # fmt: skip
        "parameter": finding.parameter,
        "severity": finding.severity,
        "cvss31": _cvss(finding.cvss31_vector, finding.cvss31_score),
        "cvss40": _cvss(finding.cvss40_vector, finding.cvss40_score),
        "validation": finding.validation,
        "decision": finding.decision,
        "decision_reason": finding.decision_reason,
        "decided_at": finding.decided_at,
        "retest_result": finding.retest_result,
        "description": finding.description,
        "impact": finding.impact,
        "recommendation": finding.recommendation,
        "references": list(finding.references or []),
        "evidence_count": evidence_count or 0,
        "first_scan_id": finding.first_scan_id,
        "last_scan_id": finding.last_scan_id,
        "has_poc": finding.poc_spec_enc is not None,
    }


def _cvss(vector: str | None, score: Decimal | None) -> dict[str, Any] | None:
    if not vector:
        return None
    return {"vector": vector, "score": float(score) if score is not None else None}
