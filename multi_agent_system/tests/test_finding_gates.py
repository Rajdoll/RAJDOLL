from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.routes.results import get_findings, get_findings_summary
from api.routes.validation import (
    BulkValidateBody,
    BulkValidation,
    ValidateBody,
    bulk_validate_findings,
    validate_finding,
)
from multi_agent_system.agents import base_agent as base_agent_module
from multi_agent_system.models.models import AgentEvent, Finding, Job, JobAgent
from multi_agent_system.utils.confidence_scorer import Evidence, EvidenceType
from multi_agent_system.utils.finding_policy import classify_finding, filter_findings
from multi_agent_system.utils.finding_serializer import normalize_cwe_id, normalize_wstg_id, serialize_finding


class DummyAgent(base_agent_module.BaseAgent):
    agent_name = "DummyAgent"


@pytest.fixture
def test_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    Job.__table__.create(bind=engine)
    JobAgent.__table__.create(bind=engine)
    AgentEvent.__table__.create(bind=engine)
    Finding.__table__.create(bind=engine)

    @contextmanager
    def _get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(base_agent_module, "get_db", _get_db)
    monkeypatch.setattr("api.routes.results.get_db", _get_db)
    monkeypatch.setattr("api.routes.validation.get_db", _get_db)
    monkeypatch.setattr(
        base_agent_module,
        "EnrichmentService",
        SimpleNamespace(
            enrich=lambda *args, **kwargs: SimpleNamespace(
                explanation="",
                remediation="",
                cwe_id=None,
                wstg_id=None,
                cvss_score_v4=None,
                references=[],
                source="test",
            )
        ),
    )
    monkeypatch.setattr(base_agent_module, "SimpleLLMClient", lambda: MagicMock())

    with _get_db() as db:
        db.add(Job(id=1, target="https://example.test"))
        db.add(JobAgent(job_id=1, agent_name="DummyAgent", status="completed"))
        db.commit()

    return TestingSessionLocal


def test_add_finding_with_confidence_persists_columns(test_db):
    agent = DummyAgent(job_id=1)
    evidences = [
        Evidence(
            evidence_type=EvidenceType.EXPLOIT_SUCCESS,
            description="Exploit confirmed by tool",
            tool_used="sqlmap",
        )
    ]

    confidence = agent.add_finding_with_confidence(
        category="WSTG-INPV-05",
        title="Confirmed SQL Injection",
        severity="high",
        evidence={"endpoint": "/login", "parameter": "email"},
        details="Injection reproduced with exploit tool",
        tool_name="sqlmap",
        evidences=evidences,
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "Confirmed SQL Injection").one()
        assert finding.confidence_score == pytest.approx(confidence.final_score)
        assert finding.confidence_level.value == confidence.confidence_level.value
        assert finding.evidence["_meta"]["reportability_status"] == "reportable"
        assert finding.evidence["_meta"]["finding_state"] == "pending_manual_review"
    finally:
        session.close()


def test_finding_policy_filters_low_confidence_candidates():
    reportable = {
        "severity": "high",
        "confidence_score": 0.82,
        "confidence_level": "high",
        "is_true_positive": None,
        "details": "Confirmed impact on /api/search",
        "evidence": {
            "_confidence": {"score": 0.82, "level": "high", "evidence_count": 1},
            "endpoint": "/api/search",
            "payload": "' OR 1=1--",
            "response": "SQL syntax error",
            "impact": "Database error confirms injectable parameter",
        },
    }
    weak = {
        "severity": "medium",
        "confidence_score": 0.24,
        "confidence_level": "speculative",
        "is_true_positive": None,
        "evidence": {"_confidence": {"score": 0.24, "level": "speculative"}},
    }

    assert classify_finding(reportable)["reportability_status"] == "reportable"
    assert classify_finding(weak)["reportability_status"] == "excluded_low_confidence"
    assert filter_findings([reportable, weak], "reportable") == [reportable]


def test_bug_bounty_profile_suppresses_common_out_of_scope_noise(monkeypatch):
    from multi_agent_system.core import config as config_mod

    monkeypatch.setattr(config_mod.settings, "scan_profile", "bug_bounty")
    finding = {
        "title": "No account lockout or rate limiting detected",
        "category": "WSTG-ATHN",
        "severity": "high",
        "confidence_score": 0.9,
        "confidence_level": "confirmed",
        "is_true_positive": None,
        "details": "Scanner observed repeated attempts without 429",
        "evidence": {
            "_confidence": {"score": 0.9, "level": "confirmed", "evidence_count": 1},
            "endpoint": "/auth/login",
            "payload": "six failed attempts",
            "impact": "Missing rate limit class",
        },
    }

    classification = classify_finding(finding)
    assert classification["scope_status"] == "out_of_scope"
    assert classification["reportability_status"] == "excluded_out_of_scope"
    assert filter_findings([finding], "reportable") == []


def test_inventory_only_recon_signal_requires_validation():
    finding = {
        "title": "Hidden workflow paths identified",
        "category": "WSTG-INFO",
        "severity": "low",
        "confidence_score": 0.92,
        "confidence_level": "confirmed",
        "is_true_positive": None,
        "details": "Discovered paths are supporting context only",
        "evidence": {
            "_confidence": {"score": 0.92, "level": "confirmed", "evidence_count": 1},
            "endpoint": "/internal",
            "proof_type": "inventory_only",
            "impact": "No sensitive data or privileged action confirmed",
        },
    }

    classification = classify_finding(finding)
    assert classification["reportability_status"] == "needs_validation"
    assert classification["finding_state"] == "lead"
    assert filter_findings([finding], "reportable") == []


def test_lab_profile_allows_concrete_proof_without_confidence(monkeypatch):
    from multi_agent_system.core import config as config_mod

    monkeypatch.setattr(config_mod.settings, "scan_profile", "lab")
    finding = {
        "title": "Sensitive file discovered",
        "category": "WSTG-CONF-04",
        "severity": "high",
        "is_true_positive": None,
        "details": "",
        "evidence": {
            "path": "/ftp/acquisitions.md",
            "status_code": 200,
            "proof_type": "accessible_file",
            "impact": "Sensitive file returned HTTP 200",
        },
    }

    classification = classify_finding(finding)
    assert classification["reportability_status"] == "reportable"
    assert classification["finding_state"] == "pending_manual_review"
    assert filter_findings([finding], "reportable") == [finding]


def test_bug_bounty_profile_still_requires_manual_validation_for_final_report(monkeypatch):
    from multi_agent_system.core import config as config_mod
    from multi_agent_system.utils.report_service import final_report_mode

    monkeypatch.setattr(config_mod.settings, "scan_profile", "bug_bounty")
    assert final_report_mode() == "validated"

    monkeypatch.setattr(config_mod.settings, "scan_profile", "lab")
    assert final_report_mode() == "reportable"


def test_high_confidence_without_location_stays_in_validation(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding(
        category="WSTG-INPV-05",
        title="High Confidence But Missing Location",
        severity="high",
        evidence={
            "_confidence": {"score": 0.9, "level": "confirmed", "evidence_count": 1},
            "payload": "' OR 1=1--",
            "response": "database error",
        },
        details="Potential injection impact",
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "High Confidence But Missing Location").one()
        classification = classify_finding(finding)
        assert classification["reportability_status"] == "needs_validation"
        assert classification["finding_state"] == "lead"
        assert "missing_endpoint_or_location" in classification["validation_errors"]
        assert filter_findings([finding], "reportable") == []
    finally:
        session.close()


def test_minimum_contract_allows_reportable_finding(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding(
        category="WSTG-INPV-05",
        title="Reportable Finding With Minimum Proof",
        severity="high",
        evidence={
            "_confidence": {"score": 0.9, "level": "confirmed", "evidence_count": 1},
            "endpoint": "/api/search",
            "payload": "' OR 1=1--",
            "response": "SQL syntax error",
            "impact": "Database error confirms injectable parameter",
        },
        details="Confirmed injection on /api/search",
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "Reportable Finding With Minimum Proof").one()
        classification = classify_finding(finding)
        assert classification["reportability_status"] == "reportable"
        assert "validation_errors" not in classification
        assert filter_findings([finding], "reportable") == [finding]
    finally:
        session.close()


def test_serializer_redacts_and_hides_internal_metadata(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding(
        category="WSTG-INPV-05",
        title="Token Exposure",
        severity="high",
        evidence={
            "_confidence": {"score": 0.9, "level": "confirmed", "evidence_count": 1},
            "endpoint": "/api/session",
            "response": {"Authorization": "Bearer verysecretverysecretverysecret"},
            "impact": "Sensitive token disclosure",
        },
        details="user@example.com token exposed",
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "Token Exposure").one()
        serialized = serialize_finding(finding, include_evidence=True, include_internal_evidence=False)
        assert "_confidence" not in serialized["evidence"]
        assert "_meta" not in serialized["evidence"]
        assert "verysecretverysecretverysecret" not in str(serialized)
        assert "user@example.com" not in str(serialized)
    finally:
        session.close()


def test_serializer_normalizes_wstg_and_cwe_identifiers(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding(
        category="wstg-inpv-5",
        title="Normalized Enrichment",
        severity="high",
        evidence={
            "_confidence": {"score": 0.9, "level": "confirmed", "evidence_count": 1},
            "endpoint": "/api/search",
            "payload": "'",
            "impact": "Confirmed input validation impact",
        },
        details="Confirmed input validation issue",
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "Normalized Enrichment").one()
        finding.wstg_id = "wstg-inpv-5"
        finding.cwe_id = "cwe 89"
        session.commit()
        serialized = serialize_finding(finding, for_report=True)
        assert serialized["wstg_id"] == "WSTG-INPV-05"
        assert serialized["wstg_category"] == "WSTG-INPV"
        assert serialized["cwe_id"] == "CWE-89"
    finally:
        session.close()


def test_identifier_normalizers_handle_empty_values():
    assert normalize_wstg_id(None, fallback_category="WSTG-ATHZ-1") == "WSTG-ATHZ-01"
    assert normalize_cwe_id("89") == "CWE-89"


def test_results_route_defaults_to_reportable_mode(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding_with_confidence(
        category="WSTG-INPV-05",
        title="Reportable SQL Injection",
        severity="critical",
        evidence={"endpoint": "/api/login"},
        details="High-confidence finding",
        tool_name="sqlmap",
        evidences=[
            Evidence(
                evidence_type=EvidenceType.EXPLOIT_SUCCESS,
                description="Exploit confirmed by tool",
                tool_used="sqlmap",
            )
        ],
    )
    agent.add_finding(
        category="WSTG-INFO-01",
        title="Heuristic Header Observation",
        severity="low",
        evidence={"header": "x-powered-by"},
        details="Heuristic-only signal",
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "Reportable SQL Injection").one()
        finding.is_true_positive = True
        session.commit()
    finally:
        session.close()

    default_findings = get_findings(1)
    raw_findings = get_findings(1, mode="raw")
    validated_findings = get_findings(1, mode="validated")
    summary = get_findings_summary(1)

    assert [finding["title"] for finding in default_findings] == ["Reportable SQL Injection"]
    assert {finding["title"] for finding in raw_findings} == {
        "Reportable SQL Injection",
        "Heuristic Header Observation",
    }
    assert [finding["title"] for finding in validated_findings] == ["Reportable SQL Injection"]
    assert summary["raw_count"] == 2
    assert summary["reportable_count"] == 1
    assert summary["validated_count"] == 1
    assert summary["suppressed_count"] == 1


def test_validation_route_updates_finding_lifecycle(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding(
        category="WSTG-INFO-01",
        title="Weak Header Lead",
        severity="low",
        evidence={"header": "x-powered-by"},
        details="Needs review",
    )

    session = test_db()
    try:
        finding = session.query(Finding).filter(Finding.title == "Weak Header Lead").one()
        finding_id = finding.id
    finally:
        session.close()

    result = validate_finding(finding_id, ValidateBody(is_true_positive=False, notes="Noise", source="triage"))

    assert result["is_true_positive"] is False
    assert result["classification"]["reportability_status"] == "excluded_false_positive"
    assert result["classification"]["finding_state"] == "rejected_false_positive"

    session = test_db()
    try:
        finding = session.query(Finding).get(finding_id)
        assert finding.is_true_positive is False
        assert finding.validation_notes == "Noise"
        assert finding.evidence["_meta"]["reportability_status"] == "excluded_false_positive"
        assert finding.evidence["_meta"]["validation_source"] == "triage"
    finally:
        session.close()


def test_bulk_validation_returns_updated_summary(test_db):
    agent = DummyAgent(job_id=1)
    agent.add_finding(
        category="WSTG-INPV-05",
        title="Candidate A",
        severity="high",
        evidence={"_confidence": {"score": 0.8, "level": "high"}},
        details="Candidate",
    )
    agent.add_finding(
        category="WSTG-INFO-01",
        title="Candidate B",
        severity="low",
        evidence={"header": "server"},
        details="Lead",
    )

    session = test_db()
    try:
        findings = session.query(Finding).order_by(Finding.id.asc()).all()
        first_id = findings[-2].id
        second_id = findings[-1].id
    finally:
        session.close()

    result = bulk_validate_findings(
        1,
        BulkValidateBody(
            validations=[
                BulkValidation(finding_id=first_id, is_true_positive=True, notes="Confirmed"),
                BulkValidation(finding_id=second_id, is_true_positive=False, notes="False positive"),
            ]
        ),
    )

    assert result["updated"] == 2
    assert result["summary"]["validated_true_positive"] >= 1
    assert result["summary"]["validated_false_positive"] >= 1
