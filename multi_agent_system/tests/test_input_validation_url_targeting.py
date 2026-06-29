from multi_agent_system.core.url_utils import absolutize_url, prefer_query_params


def test_discovered_urls_absolutized():
    target = "http://dvwa/"
    raw = ["/vulnerabilities/sqli/?id=1", "http://dvwa/login.php"]
    out = [absolutize_url(u, target) for u in raw]
    assert out == ["http://dvwa/vulnerabilities/sqli/?id=1", "http://dvwa/login.php"]


def test_lfi_param_taken_from_url():
    # fi page exposes ?page=...; default list must not win over it
    params = prefer_query_params("http://dvwa/vulnerabilities/fi/?page=include.php",
                                 ["id", "q", "search"])
    assert params[0] == "page"


def test_juiceshop_absolute_url_unchanged():
    # detection-neutrality: absolute URL + its own param survive untouched
    u = "http://juice-shop:3000/rest/products/search?q=apple"
    assert absolutize_url(u, "http://juice-shop:3000") == u
    assert prefer_query_params(u, ["q"]) == ["q"]
