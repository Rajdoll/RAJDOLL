"""Verify no agent or MCP tool contains hardcoded application-specific endpoints."""
import os
import pytest

AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agents")
SESSION_MANAGER_PATH = os.path.join(os.path.dirname(__file__), "..", "utils", "session_manager.py")
MCP_DIRS = [
    os.path.join(os.path.dirname(__file__), "..", "..", "business-logic-testing"),
    os.path.join(os.path.dirname(__file__), "..", "..", "authorization-testing"),
    os.path.join(os.path.dirname(__file__), "..", "..", "configuration-and-deployment-testing"),
]

JUICE_SHOP_PATTERNS = [
    "/api/BasketItems",
    "/api/Quantitys",
    "/api/Feedbacks",
    "/api/Complaints",
    "/api/Products/",
    "/api/Users/",
    "/rest/basket/",
    "/rest/user/login",
    "/rest/products/",
    "/api/SecurityQuestions",
    "/api/Recycles",
    "/api/Addresss",
    "/api/Cards",
    "/api/Deliverys",
    "/api/Wallets",
    "/ftp/legal.md",
    "/ftp/acquisitions.md",
    "/encryptionkeys",
    "admin@juice-sh.op",
    "jim@juice-sh.op",
    "bender@juice-sh.op",
    "JUICE_SHOP_PATTERNS",
]

EXCLUDED_SUBSTRINGS = [
    "test_",
    "evaluation",
    "__pycache__",
    "juice_shop_coverage",
]


def _should_check(filepath: str) -> bool:
    basename = os.path.basename(filepath)
    return basename.endswith(".py") and not any(ex in filepath for ex in EXCLUDED_SUBSTRINGS)


def _scan_file_for_patterns(filepath: str) -> list[str]:
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return [p for p in JUICE_SHOP_PATTERNS if p in content]


def test_no_juiceshop_patterns_in_agents():
    """No agent file should contain hardcoded Juice Shop endpoints."""
    violations: dict[str, list[str]] = {}
    for fname in os.listdir(AGENT_DIR):
        fpath = os.path.join(AGENT_DIR, fname)
        if not _should_check(fpath):
            continue
        found = _scan_file_for_patterns(fpath)
        if found:
            violations[fname] = found
    assert not violations, f"Hardcoded Juice Shop patterns found in agents: {violations}"


def test_no_juiceshop_patterns_in_mcp_tools():
    """No MCP tool should contain hardcoded Juice Shop endpoints."""
    violations: dict[str, list[str]] = {}
    for mcp_dir in MCP_DIRS:
        if not os.path.isdir(mcp_dir):
            continue
        for fname in os.listdir(mcp_dir):
            fpath = os.path.join(mcp_dir, fname)
            if not _should_check(fpath):
                continue
            found = _scan_file_for_patterns(fpath)
            if found:
                violations[f"{os.path.basename(mcp_dir)}/{fname}"] = found
    assert not violations, f"Hardcoded Juice Shop patterns found in MCP tools: {violations}"


def test_no_juiceshop_in_session_manager():
    """session_manager.py should not contain Juice Shop references."""
    found = _scan_file_for_patterns(SESSION_MANAGER_PATH)
    assert not found, f"Juice Shop patterns in session_manager.py: {found}"
