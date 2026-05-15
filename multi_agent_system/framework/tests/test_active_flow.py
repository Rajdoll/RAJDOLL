from multi_agent_system.framework.active_flow import ActiveFlowTester, FlowResult


def test_flow_result_construct():
    r = FlowResult(success=True, proof_type="exploit_success",
                    evidence={"a": 1}, severity="high")
    assert r.success is True
    assert r.proof_type == "exploit_success"
    assert r.evidence == {"a": 1}
    assert r.severity == "high"


def test_active_flow_tester_construct():
    tester = ActiveFlowTester()
    assert tester is not None
