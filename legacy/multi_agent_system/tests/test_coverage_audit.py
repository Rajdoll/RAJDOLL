from unittest.mock import patch, MagicMock, AsyncMock
from multi_agent_system.orchestrator import Orchestrator


def test_identify_gaps_returns_high_risk_pending_in_agent_category():
    fake_tree = {
        "WSTG-INPV-05": {"category": "WSTG-INPV", "status": "vulnerable",
                         "owner_agent": "InputValidationAgent", "high_risk": True,
                         "id": "WSTG-INPV-05", "title": "SQLi", "finding_count": 1},
        "WSTG-INPV-12": {"category": "WSTG-INPV", "status": "tested-clean",
                         "owner_agent": "InputValidationAgent", "high_risk": False,
                         "id": "WSTG-INPV-12", "title": "X", "finding_count": 0},
        "WSTG-INPV-11": {"category": "WSTG-INPV", "status": "pending",
                         "owner_agent": "InputValidationAgent", "high_risk": True,
                         "id": "WSTG-INPV-11", "title": "Code injection",
                         "finding_count": 0},
        "WSTG-CRYP-01": {"category": "WSTG-CRYP", "status": "pending",
                         "owner_agent": "WeakCryptographyAgent", "high_risk": True,
                         "id": "WSTG-CRYP-01", "title": "TLS", "finding_count": 0},
    }
    orch = Orchestrator.__new__(Orchestrator)
    gaps = orch._identify_subtest_gaps("InputValidationAgent", fake_tree)
    ids = {g["id"] for g in gaps}
    assert ids == {"WSTG-INPV-11"}


def test_identify_gaps_excludes_low_risk_pending():
    fake_tree = {
        "WSTG-INPV-90": {"category": "WSTG-INPV", "status": "pending",
                         "owner_agent": "InputValidationAgent", "high_risk": False,
                         "id": "WSTG-INPV-90", "title": "Low", "finding_count": 0},
    }
    orch = Orchestrator.__new__(Orchestrator)
    assert orch._identify_subtest_gaps("InputValidationAgent", fake_tree) == []


def test_identify_gaps_empty_for_unknown_agent():
    fake_tree = {
        "WSTG-INPV-11": {"category": "WSTG-INPV", "status": "pending",
                         "owner_agent": "InputValidationAgent", "high_risk": True,
                         "id": "WSTG-INPV-11", "title": "Code injection",
                         "finding_count": 0},
    }
    orch = Orchestrator.__new__(Orchestrator)
    assert orch._identify_subtest_gaps("ReconnaissanceAgent", fake_tree) == []


def _make_orch():
    """Build a bare Orchestrator with the minimum attrs needed for the audit method."""
    orch = Orchestrator.__new__(Orchestrator)
    orch.job_id = 1
    orch.shared_context = {"tech_stack": {"server": "nginx", "tech": ["Node.js"]}}
    from multi_agent_system.utils.orchestrator_directive import OrchestratorDirective
    orch._accumulated_directive = OrchestratorDirective()
    orch.context_manager = MagicMock()
    return orch


def test_audit_no_summarizer_early_exit():
    orch = _make_orch()
    with patch.object(Orchestrator, "_get_llm_summarizer", return_value=None):
        orch._run_post_agent_coverage_audit("InputValidationAgent")
    orch.context_manager.write.assert_not_called()


def test_audit_marks_attempted_only_on_success_and_skips_second_call():
    orch = _make_orch()
    fake_tree = {"WSTG-INPV-11": {"category": "WSTG-INPV", "status": "pending",
                  "owner_agent": "InputValidationAgent", "high_risk": True,
                  "id": "WSTG-INPV-11", "title": "Code injection",
                  "finding_count": 0}}
    summarizer = MagicMock()
    summarizer.propose_subtest_directive = AsyncMock(
        return_value={"focus_instructions": "test guidance",
                      "preferred_tools": ["test_sqli"]}
    )
    with patch("multi_agent_system.orchestrator.build_subtest_task_tree",
               return_value=fake_tree), \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop") as ev_loop:
        loop = MagicMock()
        loop.run_until_complete.side_effect = lambda coro: {"focus_instructions": "test guidance",
                                                              "preferred_tools": ["test_sqli"]}
        ev_loop.return_value = loop
        orch._run_post_agent_coverage_audit("InputValidationAgent")
    assert "InputValidationAgent" in orch._audit_attempted
    assert orch._accumulated_directive.focus_instructions["InputValidationAgent"] == "test guidance"
    assert orch._accumulated_directive.inject_tools["InputValidationAgent"] == [
        {"tool": "test_sqli", "arguments": {}}
    ]
    # Second call: should no-op
    orch.context_manager.write.reset_mock()
    orch._run_post_agent_coverage_audit("InputValidationAgent")
    orch.context_manager.write.assert_not_called()


def test_audit_does_not_mark_attempted_on_llm_failure():
    orch = _make_orch()
    fake_tree = {"WSTG-INPV-11": {"category": "WSTG-INPV", "status": "pending",
                  "owner_agent": "InputValidationAgent", "high_risk": True,
                  "id": "WSTG-INPV-11", "title": "Code injection",
                  "finding_count": 0}}
    summarizer = MagicMock()
    with patch("multi_agent_system.orchestrator.build_subtest_task_tree",
               return_value=fake_tree), \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop") as ev_loop:
        loop = MagicMock()
        loop.run_until_complete.side_effect = RuntimeError("LLM blip")
        ev_loop.return_value = loop
        orch._run_post_agent_coverage_audit("InputValidationAgent")
    assert "InputValidationAgent" not in getattr(orch, "_audit_attempted", set())
