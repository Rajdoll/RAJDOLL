from multi_agent_system.orchestrator import Orchestrator


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
