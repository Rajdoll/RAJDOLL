import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from multi_agent_system.evaluation.compute_metrics import matches


def test_ssti_alias_wstg_clnt13_matches_inpv18():
    assert matches("WSTG-CLNT-13", "WSTG-INPV-18") is True


def test_clnt04_client_allowlist_alias():
    assert matches("WSTG-CLNT-12", "WSTG-CLNT-04") is True


def test_existing_exact_match_still_works():
    assert matches("WSTG-INPV-05", "WSTG-INPV-05") is True


def test_prefix_match_still_works():
    assert matches("WSTG-ATHN", "WSTG-ATHN-09") is True


def test_no_match():
    assert matches("WSTG-SESS-05", "WSTG-INPV-05") is False


def test_conf_prefix_match():
    # WSTG-CONF should match WSTG-CONF-05 via existing prefix logic
    assert matches("WSTG-CONF", "WSTG-CONF-05") is True


def test_athz_prefix_match():
    # WSTG-ATHZ should match WSTG-ATHZ-02 via existing prefix logic
    assert matches("WSTG-ATHZ", "WSTG-ATHZ-02") is True


def _make_base_agent_with_context(endpoints):
    from multi_agent_system.agents.base_agent import BaseAgent
    from unittest.mock import MagicMock
    agent = object.__new__(BaseAgent)
    agent.job_id = 999
    agent.agent_name = "TestAgent"
    agent._shared_context_snapshot = {"discovered_endpoints": endpoints}
    agent.log = MagicMock()
    return agent


def test_select_tool_targets_returns_matching_endpoints():
    agent = _make_base_agent_with_context([
        "http://target/profile/image",
        "http://target/api/users",
        "http://target/upload/avatar",
        "http://target/products",
    ])
    result = agent._select_tool_targets("test_unrestricted_upload", "http://target/")
    assert "http://target/profile/image" in result
    assert "http://target/upload/avatar" in result
    assert "http://target/products" not in result


def test_select_tool_targets_fallback_when_no_match():
    agent = _make_base_agent_with_context(["http://target/api/users"])
    result = agent._select_tool_targets("test_unrestricted_upload", "http://target/")
    assert result == ["http://target/"]


def test_select_tool_targets_fallback_when_no_endpoints():
    agent = _make_base_agent_with_context([])
    result = agent._select_tool_targets("test_ssrf_comprehensive", "http://target/")
    assert result == ["http://target/"]


def test_select_tool_targets_caps_at_three():
    agent = _make_base_agent_with_context([
        "http://target/upload/a",
        "http://target/upload/b",
        "http://target/upload/c",
        "http://target/upload/d",
        "http://target/image/e",
    ])
    result = agent._select_tool_targets("test_unrestricted_upload", "http://target/")
    assert len(result) <= 3
