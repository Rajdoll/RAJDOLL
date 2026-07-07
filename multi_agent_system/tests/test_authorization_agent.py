from multi_agent_system.agents.authorization_agent import AuthorizationAgent


def _agent(tool_name):
    a = AuthorizationAgent.__new__(AuthorizationAgent)
    a.log = lambda *args, **kw: None
    a.log_tool_execution_plan = lambda: None
    a.get_auth_session = lambda: None
    a._get_target = lambda: "https://example.com"
    a._shared_context_snapshot = {
        "endpoint_inventory": {
            "by_tag": {"idor_candidate": ["ep1"], "admin_panel": ["ep2"]},
            "endpoints": [
                {"id": "ep1", "url": "https://example.com/api/resource/1"},
                {"id": "ep2", "url": "https://example.com/admin"},
            ],
        }
    }
    a.should_run_tool = lambda name: name == tool_name
    a.findings = []
    a.add_finding = lambda *args, **kw: a.findings.append((args, kw))
    return a


def _fake_mcp(payload):
    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            return payload
    return FakeMCP()


async def test_method_tampering_with_no_impact_proof_adds_no_finding(monkeypatch):
    # Mirrors test_http_method_tampering's real return shape: an "interesting"
    # status-code difference with no owner/data/state-change signal at all.
    agent = _agent("test_http_method_tampering")

    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            return {
                "status": "success",
                "data": {
                    "results": [
                        {
                            "method": "PUT",
                            "status": "VULNERABLE",
                            "original_status": 403,
                            "new_status": 200,
                            "description": "The server responded differently to a tampered HTTP method.",
                        }
                    ]
                },
            }

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient", lambda: FakeMCP()
    )

    await agent.run()

    assert agent.findings == []


async def test_method_tampering_with_owner_mismatch_adds_finding(monkeypatch):
    # Positive control: the same gate must still confirm a finding when real
    # impact proof is present, not just suppress everything unconditionally.
    agent = _agent("test_http_method_tampering")

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "results": [
                    {"method": "PUT", "status": "VULNERABLE", "url": "https://example.com/x", "owner_mismatch": True}
                ]
            },
        }),
    )

    await agent.run()

    assert any(args[0] == "WSTG-ATHZ-02" for args, kw in agent.findings)


async def test_user_spoofing_with_weak_evidence_adds_no_finding(monkeypatch):
    # Mirrors the confirmed job-164/job-165 garbage finding: test_user_spoofing's
    # "missing_rate_limit" entries carry no evidence at all beyond a bare status code.
    agent = _agent("test_user_spoofing")

    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": [
                        {
                            "type": "missing_rate_limit",
                            "severity": "medium",
                            "description": "Same action succeeded 3 times without rate limiting",
                            "endpoint": "https://example.com/api/feedback",
                            "evidence": "",
                        }
                    ],
                },
            }

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient", lambda: FakeMCP()
    )

    await agent.run()

    assert agent.findings == []


async def test_user_spoofing_with_data_extracted_adds_finding(monkeypatch):
    # Positive control for the newly-gated user-spoofing path.
    agent = _agent("test_user_spoofing")

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [
                    {
                        "type": "user_spoofing",
                        "status": "VULNERABLE",
                        "severity": "high",
                        "endpoint": "https://example.com/api/feedback",
                        "evidence": "posted as user_id=2",
                        "data_extracted": True,
                    }
                ],
            },
        }),
    )

    await agent.run()

    assert any(args[0] == "WSTG-ATHZ-02" for args, kw in agent.findings)


async def test_vertical_privilege_escalation_still_confirms_with_owner_mismatch(monkeypatch):
    # Regression: the three already-good findings must be unaffected by this change.
    agent = _agent("test_vertical_privilege_escalation")

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "results": [
                    {"status": "VULNERABLE", "url": "https://example.com/admin", "owner_mismatch": True}
                ]
            },
        }),
    )

    await agent.run()

    assert any(args[0] == "WSTG-ATHZ-04" for args, kw in agent.findings)


async def test_idor_vulnerability_still_confirms_with_sensitive_data(monkeypatch):
    # Regression: the three already-good findings must be unaffected by this change.
    agent = _agent("test_idor_vulnerability")

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "results": [
                    {"status": "VULNERABLE", "url": "https://example.com/api/resource/1", "sensitive_data": True}
                ]
            },
        }),
    )

    await agent.run()

    assert any(args[0] == "WSTG-ATHZ-02" for args, kw in agent.findings)


async def test_idor_comprehensive_still_confirms_with_state_change(monkeypatch):
    # Regression: the three already-good findings must be unaffected by this change.
    agent = _agent("test_idor_comprehensive")

    monkeypatch.setattr(
        "multi_agent_system.agents.authorization_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerabilities_found": 1,
                "findings": [
                    {
                        "status": "VULNERABLE",
                        "endpoint": "/api/users/{id}",
                        "url": "https://example.com/api/users/1",
                        "id_tested": 1,
                        "state_change_verified": True,
                    }
                ],
            },
        }),
    )

    await agent.run()

    assert any(args[0] == "WSTG-ATHZ-02" for args, kw in agent.findings)
