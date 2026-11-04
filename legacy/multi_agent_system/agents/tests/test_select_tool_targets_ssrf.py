from multi_agent_system.agents.base_agent import BaseAgent


def _make_agent(endpoints):
    agent = object.__new__(BaseAgent)
    agent._shared_context_snapshot = {"endpoint_inventory": {"endpoints": endpoints}}
    return agent


def test_matches_path_style_url_endpoint_not_just_query_string():
    # Juice Shop's SSRF sink is a path-style endpoint (/profile/image/url),
    # not a query-string "url=" param. The pattern must catch both shapes.
    agent = _make_agent([
        {"url": "http://t:3000/profile/image/url"},
        {"url": "http://t:3000/rest/products/search"},
    ])
    targets = agent._select_tool_targets("test_ssrf_comprehensive", "http://t:3000/fallback")
    assert "http://t:3000/profile/image/url" in targets


def test_still_matches_query_string_style():
    agent = _make_agent([{"url": "http://t:3000/fetch?url=http://x"}])
    targets = agent._select_tool_targets("test_ssrf_comprehensive", "http://t:3000/fallback")
    assert "http://t:3000/fetch?url=http://x" in targets
