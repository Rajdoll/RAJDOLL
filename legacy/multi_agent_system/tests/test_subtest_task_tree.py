from unittest.mock import patch, MagicMock
from multi_agent_system.core.task_tree import build_subtest_task_tree
from multi_agent_system.models.models import AgentStatus


def _mock_db(job_agents, findings):
    fake_db = MagicMock()
    def query_side_effect(model):
        from multi_agent_system.models.models import JobAgent, Finding
        q = MagicMock()
        if model is JobAgent:
            q.filter.return_value.all.return_value = job_agents
        elif model is Finding:
            q.filter.return_value.all.return_value = findings
        return q
    fake_db.query.side_effect = query_side_effect
    cm = MagicMock()
    cm.__enter__.return_value = fake_db
    cm.__exit__.return_value = False
    return cm


def _ja(agent_name, status):
    m = MagicMock()
    m.agent_name = agent_name
    m.status = status
    return m


def _f(agent_name, category, severity="high", title="X"):
    m = MagicMock()
    m.agent_name = agent_name
    m.category = category
    m.severity = severity
    m.title = title
    return m


def test_subtest_tree_marks_vulnerable_when_finding_uses_subtest_id():
    job_agents = [_ja("InputValidationAgent", AgentStatus.completed)]
    findings = [_f("InputValidationAgent", "WSTG-INPV-05")]
    with patch("multi_agent_system.core.task_tree.get_db",
               return_value=_mock_db(job_agents, findings)):
        tree = build_subtest_task_tree(job_id=1)
    assert tree["WSTG-INPV-05"]["status"] == "vulnerable"
    assert tree["WSTG-INPV-05"]["finding_count"] == 1


def test_subtest_tree_marks_pending_for_unstarted_agent():
    with patch("multi_agent_system.core.task_tree.get_db",
               return_value=_mock_db([], [])):
        tree = build_subtest_task_tree(job_id=1)
    assert tree["WSTG-CRYP-01"]["status"] == "pending"


def test_subtest_tree_marks_tested_clean_when_completed_with_no_findings():
    job_agents = [_ja("InputValidationAgent", AgentStatus.completed)]
    findings = []
    with patch("multi_agent_system.core.task_tree.get_db",
               return_value=_mock_db(job_agents, findings)):
        tree = build_subtest_task_tree(job_id=1)
    inpv_entries = [v for k, v in tree.items() if k.startswith("WSTG-INPV")]
    assert inpv_entries
    assert all(v["status"] == "tested-clean" for v in inpv_entries)


def test_subtest_tree_ignores_non_wstg_finding_category():
    job_agents = [_ja("InputValidationAgent", AgentStatus.completed)]
    findings = [_f("InputValidationAgent", "info"),
                _f("InputValidationAgent", None),
                _f("InputValidationAgent", "")]
    with patch("multi_agent_system.core.task_tree.get_db",
               return_value=_mock_db(job_agents, findings)):
        tree = build_subtest_task_tree(job_id=1)
    inpv_entries = [v for k, v in tree.items() if k.startswith("WSTG-INPV")]
    assert all(v["finding_count"] == 0 for v in inpv_entries)
    assert all(v["status"] == "tested-clean" for v in inpv_entries)


def test_subtest_tree_returns_full_catalog_size():
    with patch("multi_agent_system.core.task_tree.get_db",
               return_value=_mock_db([], [])):
        tree = build_subtest_task_tree(job_id=1)
    assert len(tree) == 97


def test_subtest_tree_entry_shape():
    with patch("multi_agent_system.core.task_tree.get_db",
               return_value=_mock_db([], [])):
        tree = build_subtest_task_tree(job_id=1)
    entry = tree["WSTG-INPV-05"]
    assert set(entry.keys()) >= {"id", "title", "category", "owner_agent",
                                  "high_risk", "status", "finding_count"}
    assert entry["category"] == "WSTG-INPV"
    assert entry["owner_agent"] == "InputValidationAgent"
