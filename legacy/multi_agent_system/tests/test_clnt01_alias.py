from multi_agent_system.evaluation.compute_metrics import matches


def test_xss_findings_match_clnt01_gt():
    assert matches("WSTG-INPV-02", "WSTG-CLNT-01")   # stored XSS -> CLNT-01 GT
    assert matches("WSTG-INPV-01", "WSTG-CLNT-01")   # reflected XSS -> CLNT-01 GT


def test_unrelated_pair_still_false():
    assert not matches("WSTG-CONF-01", "WSTG-CLNT-01")
