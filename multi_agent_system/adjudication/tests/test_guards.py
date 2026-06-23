from multi_agent_system.adjudication.artifact import artifact_from_dict
from multi_agent_system.adjudication.guards import guards_pass

def _art(body):
    return artifact_from_dict(dict(tool="t", wstg="WSTG-ATHZ-04", method="GET", url="http://t/x",
                                   role="user:2", status=200, headers_subset={}, body=body, baseline_status=None))

def test_pass_when_span_in_body_and_confident():
    v = {"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04", "evidence_span": "owner:1", "confidence": 0.9}
    assert guards_pass(v, _art('{"owner:1"}')) is True

def test_fail_when_span_not_in_body():
    v = {"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04", "evidence_span": "owner:99", "confidence": 0.9}
    assert guards_pass(v, _art('{"owner:1"}')) is False

def test_fail_low_confidence():
    v = {"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04", "evidence_span": "owner:1", "confidence": 0.5}
    assert guards_pass(v, _art('{"owner:1"}')) is False

def test_fail_non_vulnerable_verdict():
    v = {"verdict": "uncertain", "vuln_class": "WSTG-ATHZ-04", "evidence_span": "owner:1", "confidence": 0.95}
    assert guards_pass(v, _art('{"owner:1"}')) is False

def test_fail_empty_span():
    v = {"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04", "evidence_span": "", "confidence": 0.95}
    assert guards_pass(v, _art('{"owner:1"}')) is False

def test_fail_garbage_confidence():
    v = {"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04", "evidence_span": "owner:1", "confidence": "high"}
    assert guards_pass(v, _art('{"owner:1"}')) is False

def test_fail_non_dict():
    assert guards_pass(None, _art("x")) is False
