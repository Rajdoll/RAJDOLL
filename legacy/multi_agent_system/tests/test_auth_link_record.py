from multi_agent_system.agents.reconnaissance_agent import _auth_link_inventory_record


def test_record_path_is_absolute_url():
    ep = {"url": "http://dvwa/vulnerabilities/sqli/", "endpoint": "/vulnerabilities/sqli/",
          "method": "GET", "source": "auth_link"}
    rec = _auth_link_inventory_record(ep, "ep_auth_001")
    assert rec["path"] == "http://dvwa/vulnerabilities/sqli/"
    assert rec["id"] == "ep_auth_001"
    assert rec["tags"] == ["error_prone_param"]
    # original fields preserved
    assert rec["method"] == "GET"
