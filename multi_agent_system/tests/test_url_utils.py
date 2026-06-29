from multi_agent_system.core.url_utils import absolutize_url, prefer_query_params


def test_absolutize_relative_joins_against_base():
    assert absolutize_url("/vulnerabilities/sqli/?id=1", "http://dvwa/") == \
        "http://dvwa/vulnerabilities/sqli/?id=1"


def test_absolutize_leaves_absolute_unchanged():
    u = "http://juice-shop:3000/rest/products/search?q=x"
    assert absolutize_url(u, "http://juice-shop:3000") == u


def test_absolutize_safe_on_empty_or_no_base():
    assert absolutize_url("", "http://dvwa/") == ""
    assert absolutize_url("/x", None) == "/x"


def test_prefer_query_params_puts_url_param_first():
    assert prefer_query_params("http://dvwa/vulnerabilities/fi/?page=include.php",
                               ["id", "q"]) == ["page", "id", "q"]


def test_prefer_query_params_no_query_keeps_defaults():
    assert prefer_query_params("http://dvwa/vulnerabilities/sqli/", ["id", "q"]) == ["id", "q"]


def test_prefer_query_params_dedups_overlap():
    assert prefer_query_params("http://dvwa/vulnerabilities/sqli/?id=1",
                               ["id", "q"]) == ["id", "q"]


def test_prefer_query_params_keeps_flag_param():
    assert prefer_query_params("http://dvwa/vulnerabilities/fi/?page", ["id"]) == ["page", "id"]
