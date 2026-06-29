from multi_agent_system.agents.input_validation_agent import _select_stored_xss_endpoints


def test_includes_keywordless_form_path():
    target = "http://dvwa/"
    links = [
        "http://dvwa/vulnerabilities/xss_s/",      # no content keyword
        "http://dvwa/feedback",                     # keyword: feedback
        "http://other-host/comment",                # different host -> excluded
    ]
    out = _select_stored_xss_endpoints(links, target)
    assert "/feedback" in out and out.index("/feedback") == 0       # keyworded first
    assert "/vulnerabilities/xss_s/" in out                          # keywordless still included
    assert all("other-host" not in p for p in out)                   # host filtered


def test_fallback_root_when_empty():
    assert _select_stored_xss_endpoints([], "http://dvwa/") == ["/"]
