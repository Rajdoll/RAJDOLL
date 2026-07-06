from multi_agent_system.utils.finding_policy import (
    assess_finding_contract,
    build_finding_meta,
    DIFFERENTIAL_PROOF_TYPES,
)


def test_differential_proof_types_membership():
    assert "exploit_success" in DIFFERENTIAL_PROOF_TYPES
    assert "verified_state_change" in DIFFERENTIAL_PROOF_TYPES
    assert "sensitive_data_exposure" in DIFFERENTIAL_PROOF_TYPES
    assert "data_exposure" in DIFFERENTIAL_PROOF_TYPES
    assert "accessible_file" not in DIFFERENTIAL_PROOF_TYPES
    assert "corroborated" not in DIFFERENTIAL_PROOF_TYPES
    assert "manual_validation" not in DIFFERENTIAL_PROOF_TYPES


def _full_evidence(proof_type, baseline_absent=None, raw_reflected=None):
    ev = {"proof_type": proof_type, "url": "http://x/a", "endpoint": "http://x/a", "status_code": 200}
    if baseline_absent is not None:
        ev["baseline_absent"] = baseline_absent
    if raw_reflected is not None:
        ev["raw_reflected"] = raw_reflected
    return ev


def test_contract_passes_with_full_differential_proof():
    evidence = _full_evidence("exploit_success", baseline_absent=True, raw_reflected=False)
    errors = assess_finding_contract(severity="critical", evidence=evidence, details="d", meta={})
    assert "missing_differential_proof" not in errors


def test_contract_fails_without_baseline_absent():
    evidence = _full_evidence("exploit_success", raw_reflected=False)
    errors = assess_finding_contract(severity="critical", evidence=evidence, details="d", meta={})
    assert "missing_differential_proof" in errors


def test_contract_fails_without_raw_reflected():
    evidence = _full_evidence("exploit_success", baseline_absent=True)
    errors = assess_finding_contract(severity="critical", evidence=evidence, details="d", meta={})
    assert "missing_differential_proof" in errors


def test_contract_fails_with_no_differential_fields_at_all():
    evidence = _full_evidence("exploit_success")
    errors = assess_finding_contract(severity="critical", evidence=evidence, details="d", meta={})
    assert "missing_differential_proof" in errors


def test_contract_unaffected_for_inherently_concrete_proof_type():
    evidence = _full_evidence("accessible_file")
    errors = assess_finding_contract(severity="high", evidence=evidence, details="d", meta={})
    assert "missing_differential_proof" not in errors


def test_build_finding_meta_forces_lead_when_differential_proof_missing():
    evidence = _full_evidence("exploit_success")
    meta = build_finding_meta(
        severity="critical", confidence_score=None, confidence_level=None,
        evidence=evidence, details="d", title="t", category="WSTG-X",
    )
    assert meta["reportability_status"] == "needs_validation"
    assert meta["finding_state"] == "lead"


def test_build_finding_meta_stays_reportable_with_full_differential_proof():
    evidence = _full_evidence("exploit_success", baseline_absent=True, raw_reflected=False)
    meta = build_finding_meta(
        severity="critical", confidence_score=None, confidence_level=None,
        evidence=evidence, details="d", title="t", category="WSTG-X",
    )
    assert meta["reportability_status"] == "reportable"


def test_build_finding_meta_unaffected_for_accessible_file_proof_type():
    evidence = _full_evidence("accessible_file")
    meta = build_finding_meta(
        severity="high", confidence_score=None, confidence_level=None,
        evidence=evidence, details="d", title="t", category="WSTG-X",
    )
    assert meta["reportability_status"] == "reportable"


def test_build_finding_meta_true_positive_overrides_differential_requirement():
    evidence = _full_evidence("exploit_success")
    meta = build_finding_meta(
        severity="critical", confidence_score=None, confidence_level=None,
        is_true_positive=True, evidence=evidence, details="d", title="t", category="WSTG-X",
    )
    assert meta["reportability_status"] == "reportable"
