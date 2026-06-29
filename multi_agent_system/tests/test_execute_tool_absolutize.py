from multi_agent_system.agents.base_agent import _maybe_absolutize_args_url


def test_maybe_absolutize_rewrites_relative():
    args = {"url": "/vulnerabilities/sqli/?id=1", "param": "id"}
    out = _maybe_absolutize_args_url(args, "http://dvwa/")
    assert out["url"] == "http://dvwa/vulnerabilities/sqli/?id=1"
    assert out["param"] == "id"


def test_maybe_absolutize_leaves_absolute():
    args = {"url": "http://juice-shop:3000/rest/x?q=1"}
    out = _maybe_absolutize_args_url(args, "http://juice-shop:3000")
    assert out["url"] == "http://juice-shop:3000/rest/x?q=1"


def test_maybe_absolutize_noop_without_url_or_target():
    assert _maybe_absolutize_args_url({"domain": "dvwa"}, "http://dvwa/") == {"domain": "dvwa"}
    assert _maybe_absolutize_args_url({"url": "/x"}, None) == {"url": "/x"}
