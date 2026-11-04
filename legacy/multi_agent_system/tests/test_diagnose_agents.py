import pytest


def test_categorize_result_connection_error():
    from multi_agent_system.tools.diagnose_agents import categorize_result
    result = {"status": "error", "error": "Connection refused"}
    cat = categorize_result(result, elapsed_s=0.1)
    assert cat["category"] == "CONTAINER_DOWN"
    assert "container" in cat["suggestion"].lower() or "docker" in cat["suggestion"].lower()


def test_categorize_result_tool_ok_no_findings():
    from multi_agent_system.tools.diagnose_agents import categorize_result
    result = {"status": "success", "findings": []}
    cat = categorize_result(result, elapsed_s=1.0)
    assert cat["category"] == "TOOL_OK_NO_VULN"


def test_categorize_result_tool_found():
    from multi_agent_system.tools.diagnose_agents import categorize_result
    result = {"status": "success", "findings": [{"id": 1, "title": "XSS"}]}
    cat = categorize_result(result, elapsed_s=0.5)
    assert cat["category"] == "TOOL_FOUND"


def test_categorize_result_timeout():
    from multi_agent_system.tools.diagnose_agents import categorize_result
    result = {"status": "error", "error": "timed out"}
    cat = categorize_result(result, elapsed_s=10.1)
    assert cat["category"] == "TIMEOUT"


def test_categorize_result_binary_missing():
    from multi_agent_system.tools.diagnose_agents import categorize_result
    result = {"status": "error", "error": "command not found: dalfox"}
    cat = categorize_result(result, elapsed_s=0.1)
    assert cat["category"] == "BINARY_MISSING"
    assert "install" in cat["suggestion"].lower() or "dockerfile" in cat["suggestion"].lower()


def test_categorize_result_auth_required():
    from multi_agent_system.tools.diagnose_agents import categorize_result
    result = {"status": "success", "findings": [], "raw_output": "401 Unauthorized"}
    cat = categorize_result(result, elapsed_s=0.5)
    assert cat["category"] in ("AUTH_REQUIRED", "TOOL_OK_NO_VULN")


def test_agent_config_has_five_zero_agents():
    from multi_agent_system.tools.diagnose_agents import ZERO_AGENTS
    expected = {"ClientSideAgent", "FileUploadAgent",
                "ErrorHandlingAgent", "BusinessLogicAgent"}
    assert set(ZERO_AGENTS.keys()) == expected
    for name, cfg in ZERO_AGENTS.items():
        assert "server" in cfg
        assert "tools_sample" in cfg
        assert len(cfg["tools_sample"]) >= 1
