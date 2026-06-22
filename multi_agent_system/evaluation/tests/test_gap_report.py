import importlib.util, pathlib
_p = pathlib.Path(__file__).parents[1] / "gap_report.py"
_s = importlib.util.spec_from_file_location("gap_report", _p)
gr = importlib.util.module_from_spec(_s); _s.loader.exec_module(gr)

def test_detects_when_category_emitted():
    gt = [{"id": "x", "challenge": "C", "owasp_wstg": "WSTG-INPV-05"}]
    findings = [{"category": "WSTG-INPV-05", "severity": "critical"}]
    out = gr.gap_against_gt(findings, gt)
    assert out["detected_ids"] == {"x"} and out["missed_entries"] == []

def test_misses_when_category_absent():
    gt = [{"id": "y", "challenge": "D", "owasp_wstg": "WSTG-CONF-01"}]
    findings = [{"category": "WSTG-INPV-05", "severity": "high"}]
    out = gr.gap_against_gt(findings, gt)
    assert out["detected_ids"] == set() and out["missed_entries"][0]["id"] == "y"
