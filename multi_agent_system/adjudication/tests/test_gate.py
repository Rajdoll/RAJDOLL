from multi_agent_system.adjudication.artifact import artifact_from_dict
from multi_agent_system.adjudication.gate import should_adjudicate

def _art(**kw):
    base = dict(tool="t", wstg="WSTG-ATHZ-04", method="GET", url="http://t/x",
                role="user:2", status=200, headers_subset={}, body="data", baseline_status=None)
    base.update(kw)
    return artifact_from_dict(base)

def test_athz_2xx_with_body_passes():
    assert should_adjudicate(_art(wstg="WSTG-ATHZ-04", status=200, body="{owner:1}")) is True

def test_athz_403_skipped():
    assert should_adjudicate(_art(wstg="WSTG-ATHZ-04", status=403, body="denied")) is False

def test_busl_2xx_with_body_passes():
    assert should_adjudicate(_art(wstg="WSTG-BUSL-07", status=200, body="ok")) is True

def test_errh_5xx_passes_even_short_body():
    assert should_adjudicate(_art(wstg="WSTG-ERRH-01", status=500, body="")) is True

def test_errh_200_with_leak_marker_passes():
    assert should_adjudicate(_art(wstg="WSTG-INFO-05", status=200, body="Traceback (most recent call last)")) is True

def test_errh_200_clean_skipped():
    assert should_adjudicate(_art(wstg="WSTG-ERRH-01", status=200, body="all good")) is False

def test_unknown_class_skipped():
    assert should_adjudicate(_art(wstg="WSTG-CLNT-01", status=200, body="x")) is False
