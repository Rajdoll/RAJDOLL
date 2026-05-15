import json


def test_extract_findings_accepts_api_envelope():
    from multi_agent_system.evaluation.coverage_matrix import _extract_findings

    findings = [{"title": "DOM XSS detected"}]

    assert _extract_findings(findings) == findings
    assert _extract_findings({"findings": findings}) == findings
    assert _extract_findings({"data": findings}) == findings
    assert _extract_findings({"results": findings}) == findings


def test_coverage_matches_evidence_and_reports_research_target():
    from multi_agent_system.evaluation.coverage_matrix import analyze_scan_findings

    findings = [
        {
            "title": "Client-side template injection detected",
            "details": "AngularJS expression evaluated",
            "evidence": {"payload": "{{7*7}}", "evidence": "Expression evaluated to 49"},
        },
        {
            "title": "Sensitive file discovered: /ftp/acquisitions.md",
            "details": "file_access confirmed",
            "evidence": {"url": "http://juice-shop:3000/ftp/acquisitions.md"},
        },
        {
            "title": "Unrelated lab note",
            "details": "does not map to a known Juice Shop challenge",
        },
    ]

    result = analyze_scan_findings(findings)

    assert "DOM XSS" in result["detected"]
    assert "Confidential Document" in result["detected"]
    assert result["total_detected"] >= 2
    assert len(result["unmatched_findings"]) == 1


def test_json_report_records_mode_source_and_target(tmp_path):
    from multi_agent_system.evaluation.coverage_matrix import (
        analyze_scan_findings,
        calculate_thesis_metrics,
        load_findings_from_file,
        write_json_report,
    )

    findings = [{"title": "SSRF via server-side request endpoint", "details": ""}]
    input_path = tmp_path / "findings.json"
    output_path = tmp_path / "coverage.json"
    input_path.write_text(json.dumps({"findings": findings}), encoding="utf-8")

    loaded = load_findings_from_file(input_path)
    result = analyze_scan_findings(loaded)
    metrics = calculate_thesis_metrics(loaded, result)
    write_json_report(output_path, loaded, result, metrics, mode="raw", source=str(input_path), target_pct=95.0)

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["mode"] == "raw"
    assert report["source"] == str(input_path)
    assert report["target_pct"] == 95.0
    assert report["result"]["total_detected"] == 1


def test_wstg_coverage_uses_category_when_agent_name_missing():
    from multi_agent_system.evaluation.coverage_matrix import (
        analyze_scan_findings,
        calculate_thesis_metrics,
    )

    findings = [
        {"title": "SQL Injection detected", "category": "WSTG-INPV-05"},
        {"title": "JWT vulnerabilities found", "category": "WSTG-CRYP-04"},
        {"title": "IDOR vulnerability", "agent": "AuthorizationAgent"},
    ]

    result = analyze_scan_findings(findings)
    metrics = calculate_thesis_metrics(findings, result)

    assert result["wstg_coverage"]["WSTG-INPV"]["has_findings"] is True
    assert result["wstg_coverage"]["WSTG-CRYP"]["has_findings"] is True
    assert result["wstg_coverage"]["WSTG-ATHZ"]["has_findings"] is True
    assert metrics["owasp_top10_covered"] >= 3
