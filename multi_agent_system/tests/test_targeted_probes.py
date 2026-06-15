import asyncio, json, os
from unittest.mock import patch, MagicMock

from multi_agent_system.orchestrator import Orchestrator


def _mock_get_db(monkeypatch):
    db = MagicMock()
    db.query.return_value.get.return_value = None
    cm = MagicMock()
    cm.__enter__.return_value = db
    cm.__exit__.return_value = False
    monkeypatch.setattr("multi_agent_system.orchestrator.get_db", lambda: cm)
    return db


def test_build_tool_catalog_aggregates_and_skips_unknown(monkeypatch):
    class FakeAgent:
        def __init__(self, job_id): pass
        def _get_tool_server_map(self):
            return {"test_sqli": "input-validation-testing",
                    "test_xss_reflected": "input-validation-testing"}

    from multi_agent_system.agents.base_agent import AgentRegistry
    monkeypatch.setattr(AgentRegistry, "get",
                        classmethod(lambda cls, name: FakeAgent if name == "InputValidationAgent"
                                    else (_ for _ in ()).throw(KeyError(name))))

    o = Orchestrator.__new__(Orchestrator)   # no __init__ (avoids DB)
    o.job_id = 1
    cat = o._build_tool_catalog(["InputValidationAgent", "GhostAgent"])
    assert cat == {"input-validation-testing": ["test_sqli", "test_xss_reflected"]}


def _make_orch():
    o = Orchestrator.__new__(Orchestrator)
    o.job_id = 99
    return o


def test_run_targeted_probes_calls_mcp_and_caps(monkeypatch):
    os.environ["MCP_SERVER_URLS"] = json.dumps({"input-validation-testing": "http://x/jsonrpc"})
    monkeypatch.setattr("multi_agent_system.orchestrator.settings",
                        type("S", (), {"max_followup_probes": 2})())
    calls = []

    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            calls.append((server, tool, args.get("param")))
            return {"status": "success", "data": {"vulnerable": False}}

    o = _make_orch()
    monkeypatch.setattr(o, "_get_target", lambda: "http://t")
    monkeypatch.setattr(o, "context_manager",
                        type("C", (), {"read": lambda self, k: None})(), raising=False)
    monkeypatch.setattr("multi_agent_system.orchestrator.MCPClient", lambda: FakeMCP())
    probes = [{"finding_id": i, "server": "input-validation-testing", "tool": "test_sqli",
               "args": {"url": "http://t", "param": f"p{i}"}, "hypothesis": "h"} for i in range(5)]
    _mock_get_db(monkeypatch)
    new_ids = o._run_targeted_probes(probes)
    assert len(calls) == 2          # capped at max_followup_probes
    assert new_ids == []            # no vulnerable result -> no new findings


def test_run_targeted_probes_skips_unknown_server(monkeypatch):
    os.environ["MCP_SERVER_URLS"] = json.dumps({"input-validation-testing": "http://x/jsonrpc"})
    monkeypatch.setattr("multi_agent_system.orchestrator.settings",
                        type("S", (), {"max_followup_probes": 4})())
    calls = []

    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            calls.append(server)
            return {"status": "success", "data": {"vulnerable": False}}

    o = _make_orch()
    monkeypatch.setattr(o, "_get_target", lambda: "http://t")
    monkeypatch.setattr(o, "context_manager",
                        type("C", (), {"read": lambda self, k: None})(), raising=False)
    monkeypatch.setattr("multi_agent_system.orchestrator.MCPClient", lambda: FakeMCP())
    probes = [{"finding_id": 1, "server": "no-such-server", "tool": "t", "args": {}, "hypothesis": "h"}]
    _mock_get_db(monkeypatch)
    new_ids = o._run_targeted_probes(probes)
    assert calls == []              # unknown server never dispatched
    assert new_ids == []


def test_run_targeted_probes_integrity_error_is_skipped(monkeypatch):
    import multi_agent_system.orchestrator as orch_mod
    os.environ["MCP_SERVER_URLS"] = json.dumps({"input-validation-testing": "http://x/jsonrpc"})
    monkeypatch.setattr("multi_agent_system.orchestrator.settings",
                        type("S", (), {"max_followup_probes": 4})())

    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            return {"status": "success", "data": {"vulnerable": True}}

    db = MagicMock()
    db.query.return_value.get.return_value = None
    db.commit.side_effect = orch_mod.IntegrityError("dup", None, None)
    cm = MagicMock()
    cm.__enter__.return_value = db
    cm.__exit__.return_value = False
    monkeypatch.setattr("multi_agent_system.orchestrator.get_db", lambda: cm)
    monkeypatch.setattr("multi_agent_system.orchestrator.MCPClient", lambda: FakeMCP())

    o = _make_orch()
    monkeypatch.setattr(o, "context_manager",
                        type("C", (), {"read": lambda self, k: None})(), raising=False)
    probes = [{"finding_id": 1, "server": "input-validation-testing", "tool": "test_sqli",
               "args": {"url": "http://t", "param": "q"}, "hypothesis": "h"}]
    new_ids = o._run_targeted_probes(probes)   # must NOT raise
    assert new_ids == []                       # duplicate -> skipped, no id collected
    db.rollback.assert_called_once()
