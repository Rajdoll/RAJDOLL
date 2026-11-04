"""Findings: fingerprint deduplication, encrypted evidence and PoC, verdicts (BSD 6.1–6.3)."""

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Engagement, Evidence, Finding, Scan
from rajdoll.modules.base import Candidate, EndpointSeen, Exchange, Verdict
from rajdoll.services import engagements, findings, inventory, scans

TARGET = "https://simpeg.instansi.test/"
URL = "https://simpeg.instansi.test/pegawai/123/cari?nama=budi"


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    return KeyStore(tmp_path)


@pytest.fixture
def engagement(db_session: Session, keystore: KeyStore) -> Engagement:
    engagement = engagements.create(
        db_session, keystore, {"name": "Uji temuan", "target_url": TARGET}
    )
    inventory.record(
        db_session,
        engagement.id,
        None,
        [EndpointSeen("GET", URL, "crawl", query_params=("nama",))],
        ["simpeg.instansi.test"],
    )
    return engagement


def _scan(session: Session, engagement: Engagement) -> Scan:
    for previous in session.scalars(select(Scan).where(Scan.engagement_id == engagement.id)):
        previous.status = "completed"
    session.flush()
    return scans.start(session, engagement, "custom", ["input_validation"])


def _candidate(
    parameter: str = "nama", response: str = "HTTP/1.1 500\r\n\r\nSQL syntax"
) -> Candidate:
    request = "GET /pegawai/1/cari?nama=budi' HTTP/1.1\r\nCookie: [sesi akun]"
    return Candidate(
        vuln_type="sqli",
        method="GET",
        url=URL,
        parameter=parameter,
        poc={"method": "GET", "path": "/pegawai/1/cari", "query": {parameter: "budi'"}},
        evidence=(Exchange(request, response, 500, "kutip tunggal"),),
        note="error SQL",
    )


def test_fingerprint_depends_on_every_part() -> None:
    base = ("input_validation", "sqli", "GET", "app.test", "/a/{id}", "q")
    fp = findings.fingerprint(*base)
    assert len(fp) == 64
    assert findings.fingerprint("input_validation", "sqli", "get", "APP.test", "/a/{id}", "q") == fp
    for index, other in enumerate(("x", "ssti", "POST", "b.test", "/b", "r")):
        changed = list(base)
        changed[index] = other
        assert findings.fingerprint(*changed) != fp
    assert findings.fingerprint(*base[:5], None) == findings.fingerprint(*base[:5], "")


def test_candidate_creates_a_finding_from_the_catalog(
    db_session: Session, keystore: KeyStore, engagement: Engagement
) -> None:
    scan = _scan(db_session, engagement)
    finding, created = findings.record_candidate(
        db_session, keystore, engagement.id, scan.id, "input_validation", _candidate()
    )
    assert created
    assert finding.title == "SQL Injection di /pegawai/{id}/cari pada parameter nama"
    assert (finding.severity, float(finding.cvss31_score)) == ("critical", 9.8)
    assert (finding.wstg_id, finding.cwe_id) == ("WSTG-INPV-05", "CWE-89")
    assert finding.validation == "needs_manual_check"
    assert finding.decision == "pending"
    assert finding.endpoint_id is not None
    assert (finding.first_scan_id, finding.last_scan_id) == (scan.id, scan.id)

    # Evidence and PoC are encrypted at rest and readable through the service.
    raw = db_session.scalar(select(Evidence).where(Evidence.finding_id == finding.id))
    assert raw is not None and b"pegawai" not in raw.request_enc and raw.kind == "detection"
    assert b"cari" not in finding.poc_spec_enc
    assert findings.poc(db_session, keystore, finding)["query"] == {"nama": "budi'"}
    rows = findings.evidence_rows(db_session, keystore, finding)
    assert [(r["kind"], r["sequence"], r["status"], r["note"]) for r in rows] == [
        ("detection", 1, 500, "kutip tunggal")
    ]
    assert rows[0]["response"].endswith("SQL syntax")
    assert findings.for_validation(db_session, scan.id) == [{"id": finding.id, "vuln_type": "sqli"}]


def test_repeat_in_a_later_scan_adds_evidence_to_the_same_finding(
    db_session: Session, keystore: KeyStore, engagement: Engagement
) -> None:
    first = _scan(db_session, engagement)
    finding, _ = findings.record_candidate(
        db_session, keystore, engagement.id, first.id, "input_validation", _candidate()
    )
    finding.decision = "accepted"
    second = _scan(db_session, engagement)
    again, created = findings.record_candidate(
        db_session, keystore, engagement.id, second.id, "input_validation", _candidate()
    )
    assert not created and again.id == finding.id
    assert (again.first_scan_id, again.last_scan_id) == (first.id, second.id)
    assert again.decision == "accepted"  # the assessor's decision is never touched
    assert [r["sequence"] for r in findings.evidence_rows(db_session, keystore, again)] == [1, 2]
    assert findings.for_validation(db_session, first.id) == []

    other, created = findings.record_candidate(
        db_session, keystore, engagement.id, second.id, "input_validation", _candidate("urut")
    )
    assert created and other.id != finding.id


def test_verdicts_confirm_and_never_downgrade(
    db_session: Session, keystore: KeyStore, engagement: Engagement
) -> None:
    scan = _scan(db_session, engagement)
    finding, _ = findings.record_candidate(
        db_session, keystore, engagement.id, scan.id, "input_validation", _candidate()
    )
    proof = (Exchange("GET /pegawai/1/cari?nama=x'", "SQL syntax", 500, "ulang"),)
    findings.record_verdict(db_session, keystore, finding, scan.id, Verdict(False, proof))
    assert finding.validation == "needs_manual_check"
    findings.record_verdict(db_session, keystore, finding, scan.id, Verdict(True, proof))
    assert finding.validation == "confirmed"
    findings.record_verdict(db_session, keystore, finding, scan.id, Verdict(False, proof))
    assert finding.validation == "confirmed"
    kinds = [r["kind"] for r in findings.evidence_rows(db_session, keystore, finding)]
    assert kinds == ["detection", "validation", "validation", "validation"]
    assert findings.for_validation(db_session, scan.id) == []
    assert findings.as_dict(finding)["validation"] == "confirmed"


def test_large_responses_are_truncated(
    db_session: Session, keystore: KeyStore, engagement: Engagement
) -> None:
    scan = _scan(db_session, engagement)
    finding, _ = findings.record_candidate(
        db_session,
        keystore,
        engagement.id,
        scan.id,
        "input_validation",
        _candidate(response="é" * 100),
        max_bytes=51,
    )
    (row,) = findings.evidence_rows(db_session, keystore, finding)
    assert row["truncated"] is True
    assert row["response"] == "é" * 25  # cut on a character boundary


def test_unknown_type_or_url_is_rejected(
    db_session: Session, keystore: KeyStore, engagement: Engagement
) -> None:
    with pytest.raises(KeyError):
        findings.record_candidate(
            db_session,
            keystore,
            engagement.id,
            None,
            "input_validation",
            Candidate("tidak_ada", "GET", URL, None, {}),
        )
    with pytest.raises(ValueError, match="normalize"):
        findings.record_candidate(
            db_session,
            keystore,
            engagement.id,
            None,
            "input_validation",
            Candidate("sqli", "GET", "bukan-url", None, {}),
        )
    assert (
        db_session.scalar(select(Finding.id).where(Finding.engagement_id == engagement.id)) is None
    )
