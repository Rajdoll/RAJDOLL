"""Guard: AuthenticationAgent must only use the registered MCP server name. No Docker."""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "agents" / "authentication_agent.py"


def test_no_unregistered_auth_mcp_server_name():
    text = SRC.read_text(encoding="utf-8")
    # The MCP registry name is "authentication-testing"; "auth-mcp" is unregistered.
    assert 'server="auth-mcp"' not in text
    assert "server='auth-mcp'" not in text


def test_uses_registered_name_for_password_policy():
    text = SRC.read_text(encoding="utf-8")
    # Every server= reference in this file must be the registered name.
    servers = set(re.findall(r"""server=["']([^"']+)["']""", text))
    assert servers == {"authentication-testing"}, f"unexpected server names: {servers}"
