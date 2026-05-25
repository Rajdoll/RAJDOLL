def test_load_gt_entries_juiceshop_has_57():
    from multi_agent_system.evaluation.job_evaluation import load_gt_entries
    entries = load_gt_entries("juiceshop")
    assert len(entries) == 57
    assert all("owasp_wstg" in e for e in entries)


def test_load_gt_entries_unknown_profile_raises():
    import pytest
    from multi_agent_system.evaluation.job_evaluation import load_gt_entries
    with pytest.raises(FileNotFoundError):
        load_gt_entries("does-not-exist")


def test_compare_all_detected_no_fp():
    from multi_agent_system.evaluation.job_evaluation import compare_findings_to_gt
    gt = [
        {"owasp_wstg": "WSTG-INPV-05", "challenge": "Login Admin",
         "vuln_category": "SQL Injection", "severity": "high"},
        {"owasp_wstg": "WSTG-ATHN-07", "challenge": "Password Strength",
         "vuln_category": "Weak Password Policy", "severity": "medium"},
    ]
    findings = [
        {"category": "WSTG-INPV-05", "title": "SQLi", "severity": "critical", "agent_name": "InputValidationAgent"},
        {"category": "WSTG-ATHN-07", "title": "Weak pw", "severity": "medium", "agent_name": "AuthenticationAgent"},
    ]
    result = compare_findings_to_gt(findings, gt)
    assert result["summary"]["recall"] == 100.0
    assert result["summary"]["precision"] == 100.0
    assert result["summary"]["fp_findings"] == 0
    assert all(r["status"] == "TP" for r in result["ground_truth_rows"])


def test_compare_false_positive_lowers_precision():
    from multi_agent_system.evaluation.job_evaluation import compare_findings_to_gt
    gt = [{"owasp_wstg": "WSTG-INPV-05", "challenge": "Login Admin",
           "vuln_category": "SQL Injection", "severity": "high"}]
    findings = [
        {"category": "WSTG-INPV-05", "title": "SQLi", "severity": "high", "agent_name": "A"},
        {"category": "WSTG-CRYP-04", "title": "bogus", "severity": "low", "agent_name": "B"},
    ]
    result = compare_findings_to_gt(findings, gt)
    assert result["summary"]["fp_findings"] == 1
    assert result["summary"]["precision"] == 50.0
    assert len(result["false_positives"]) == 1
    assert result["false_positives"][0]["wstg"] == "WSTG-CRYP-04"


def test_compare_false_negative_marks_fn():
    from multi_agent_system.evaluation.job_evaluation import compare_findings_to_gt
    gt = [
        {"owasp_wstg": "WSTG-INPV-05", "challenge": "Login Admin",
         "vuln_category": "SQL Injection", "severity": "high"},
        {"owasp_wstg": "WSTG-INPV-19", "challenge": "SSRF",
         "vuln_category": "SSRF", "severity": "high"},
    ]
    findings = [{"category": "WSTG-INPV-05", "title": "SQLi", "severity": "high", "agent_name": "A"}]
    result = compare_findings_to_gt(findings, gt)
    assert result["summary"]["recall"] == 50.0
    fn_rows = [r for r in result["ground_truth_rows"] if r["status"] == "FN"]
    assert len(fn_rows) == 1
    assert fn_rows[0]["wstg"] == "WSTG-INPV-19"
    assert fn_rows[0]["detected"] is False


def test_compare_info_findings_excluded_from_precision():
    from multi_agent_system.evaluation.job_evaluation import compare_findings_to_gt
    gt = [{"owasp_wstg": "WSTG-INPV-05", "challenge": "Login Admin",
           "vuln_category": "SQL Injection", "severity": "high"}]
    findings = [
        {"category": "WSTG-INPV-05", "title": "SQLi", "severity": "high", "agent_name": "A"},
        {"category": "WSTG-INFO-01", "title": "banner", "severity": "info", "agent_name": "C"},
    ]
    result = compare_findings_to_gt(findings, gt)
    assert result["summary"]["fp_findings"] == 0
    assert result["summary"]["precision"] == 100.0
    assert result["summary"]["total_findings_non_info"] == 1
