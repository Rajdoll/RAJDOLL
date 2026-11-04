from multi_agent_system.agents.input_validation_agent import (
    _select_stored_xss_endpoints,
    _xss_priority_paths,
)


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


def test_xss_priority_paths_extracts_tagged():
    purls = [
        {"url": "http://dvwa/vulnerabilities/sqli/", "tests": ["sqli"]},
        {"url": "http://dvwa/vulnerabilities/xss_s/", "tests": ["xss"]},
        {"url": "http://dvwa/vulnerabilities/xss_r/", "tests": ["xss"]},
        {"url": "http://dvwa/login.php"},
    ]
    assert _xss_priority_paths(purls) == [
        "http://dvwa/vulnerabilities/xss_s/",
        "http://dvwa/vulnerabilities/xss_r/",
    ]


def test_xss_s_included_from_large_untagged_set():
    # Real DVWA case: no content-keyword pages, xss_s buried at ~pos 16. The sweep
    # must still include it (cap covers all non-static pages); no LLM tags relied on.
    links = [f"http://dvwa/p{i}.php" for i in range(15)] + [
        "http://dvwa/vulnerabilities/xss_s/",
        "http://dvwa/vulnerabilities/xss_r/",
    ]
    sel = _select_stored_xss_endpoints(links, "http://dvwa/")
    assert "/vulnerabilities/xss_s/" in sel


def test_static_assets_filtered():
    links = [
        "http://dvwa/dvwa/css/main.css",
        "http://dvwa/.well-known/security.txt",
        "http://dvwa/vulnerabilities/xss_s/",
    ]
    sel = _select_stored_xss_endpoints(links, "http://dvwa/")
    assert "/vulnerabilities/xss_s/" in sel
    assert not any(p.endswith((".css", ".txt")) for p in sel)


def test_xss_tagged_pages_land_in_tested_window():
    # xss_s buried past the cap/[:6] in raw discovery; prepending the xss-tagged
    # url must pull it into the tested window (first 6).
    others = [f"http://dvwa/p{i}/" for i in range(15)] + ["http://dvwa/vulnerabilities/xss_s/"]
    xss_priority = _xss_priority_paths([{"url": "http://dvwa/vulnerabilities/xss_s/", "tests": ["xss"]}])
    sel = _select_stored_xss_endpoints(xss_priority + others, "http://dvwa/")
    assert "/vulnerabilities/xss_s/" in sel[:6]
