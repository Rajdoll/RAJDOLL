from multi_agent_system.adjudication.artifact import build_artifact, artifact_from_dict, BODY_LIMIT

def test_build_truncates_body_and_filters_headers():
    d = build_artifact(tool="authz", wstg="WSTG-ATHZ-04", method="GET", url="http://t/api/user/1",
                       role="user:2", status=200, headers={"Content-Type": "application/json", "Set-Cookie": "x"},
                       body="A" * (BODY_LIMIT + 50))
    assert len(d["body"]) == BODY_LIMIT
    assert d["headers_subset"] == {"Content-Type": "application/json"}
    assert d["role"] == "user:2"
    assert d["baseline_status"] is None

def test_round_trip_dict_to_artifact():
    d = build_artifact(tool="errh", wstg="WSTG-ERRH-01", method="GET", url="http://t/x",
                       role="anonymous", status=500, headers={}, body="trace", baseline_status=200)
    a = artifact_from_dict(d)
    assert a.status == 500 and a.wstg == "WSTG-ERRH-01" and a.baseline_status == 200

def test_role_defaults_to_anonymous_when_empty():
    d = build_artifact(tool="biz", wstg="WSTG-BUSL-01", method="POST", url="http://t/y",
                       role="", status=200, headers={}, body="")
    assert d["role"] == "anonymous"
