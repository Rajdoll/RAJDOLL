from multi_agent_system.agents.client_side_agent import _xss_candidate_urls


def test_includes_spa_hash_routes_from_js_routes_analysis():
    shared_context = {
        "js_routes_analysis": {"all_routes": ["search", "reviews"]},
        "endpoint_inventory": {"endpoints": []},
        "discovered_endpoints": {"endpoints": []},
    }
    target = "http://example-app:3000"
    cands = _xss_candidate_urls(shared_context, target)
    urls = [c["url"] for c in cands]
    assert "http://example-app:3000/#/search" in urls
    assert "http://example-app:3000/#/reviews" in urls


def test_filters_external_host_candidates():
    shared_context = {
        "js_routes_analysis": {"all_routes": []},
        "endpoint_inventory": {"endpoints": [
            {"url": "http://example-app:3000/./redirect?to=https://blockchain.info/address/x"},
            {"url": "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token="},
            {"url": "http://example-app:3000/rest/user/change-password?current=abc"},
        ]},
        "discovered_endpoints": {"endpoints": []},
    }
    target = "http://example-app:3000"
    cands = _xss_candidate_urls(shared_context, target)
    urls = [c["url"] for c in cands]
    assert "http://example-app:3000/rest/user/change-password?current=abc" in urls
    assert not any("blockchain.info" in u for u in urls)
    assert not any("googleapis.com" in u for u in urls)


def test_resolves_real_param_name_instead_of_hardcoded_q():
    shared_context = {
        "js_routes_analysis": {"all_routes": []},
        "endpoint_inventory": {"endpoints": [
            {"url": "http://example-app:3000/rest/user/change-password?current=abc"},
        ]},
        "discovered_endpoints": {"endpoints": []},
    }
    target = "http://example-app:3000"
    cands = _xss_candidate_urls(shared_context, target)
    match = [c for c in cands if "change-password" in c["url"]][0]
    assert "current" in match["params"]
    assert match["params"] != ["q"]


def test_spa_route_with_no_query_string_defaults_to_q_param():
    shared_context = {
        "js_routes_analysis": {"all_routes": ["search"]},
        "endpoint_inventory": {"endpoints": []},
        "discovered_endpoints": {"endpoints": []},
    }
    target = "http://example-app:3000"
    cands = _xss_candidate_urls(shared_context, target)
    match = [c for c in cands if c["url"].endswith("/#/search")][0]
    assert match["params"] == ["q"]


def test_spa_routes_survive_truncation_when_many_param_endpoints_exist():
    # job#138 follow-up: real param endpoints are appended before SPA routes,
    # so callers slicing to a cap (e.g. [:10]) starve out the SPA routes that
    # exist specifically to catch hash-routed XSS.
    many_eps = [
        {"url": f"http://example-app:3000/rest/thing{i}?q=x"} for i in range(30)
    ]
    shared_context = {
        "js_routes_analysis": {"all_routes": ["search"]},
        "endpoint_inventory": {"endpoints": many_eps},
        "discovered_endpoints": {"endpoints": []},
    }
    target = "http://example-app:3000"
    cands = _xss_candidate_urls(shared_context, target)[:10]
    urls = [c["url"] for c in cands]
    assert "http://example-app:3000/#/search" in urls


def test_no_hardcoded_target_specific_literals_in_source():
    import pathlib
    src = pathlib.Path(__file__).parents[1].joinpath("client_side_agent.py").read_text()
    forbidden = ["juice", "juice-shop", "JuiceShop"]
    helper_src = src[src.index("_xss_candidate_urls"):]
    for word in forbidden:
        assert word.lower() not in helper_src.lower(), f"found hardcoded literal: {word}"
