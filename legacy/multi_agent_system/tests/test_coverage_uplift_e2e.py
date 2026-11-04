"""Smoke tests for Coverage Uplift (Opsi C) end-to-end integration.

Verifies that the catalog, tool map, task tree, and pattern store
are all wired together correctly without requiring real DB or LLM calls.
"""
from multi_agent_system.core.wstg_catalog import (
    load_catalog, subtests_for_agent, subtests_for_tool,
    tools_for_subtest, subtests_for_category,
)
from multi_agent_system.orchestrator import AGENT_TO_OWASP_MAP


# ---------- catalog coverage ----------

def test_every_non_report_agent_has_at_least_one_subtest():
    """Each scanning agent must own at least one WSTG sub-test."""
    cat = load_catalog()
    owners = {st.owasp_agent for st in cat.values()}
    for agent in AGENT_TO_OWASP_MAP:
        if agent == "ReportGenerationAgent":
            continue
        assert agent in owners, f"{agent} owns zero sub-tests in catalog"


def test_every_owasp_category_has_at_least_one_subtest():
    """Every WSTG category in the orchestrator map must appear in the catalog."""
    cat = load_catalog()
    catalog_categories = {st.category for st in cat.values()}
    for agent, category in AGENT_TO_OWASP_MAP.items():
        if agent == "ReportGenerationAgent" or category == "WSTG-REPORT":
            continue
        assert category in catalog_categories, \
            f"Category {category} (from {agent}) absent from catalog"


def test_high_risk_subtests_have_mapped_tools():
    """Every high-risk sub-test should have at least one tool mapped to it."""
    cat = load_catalog()
    high_risk_with_no_tool = [
        st_id for st_id, st in cat.items()
        if st.high_risk and not tools_for_subtest(st_id)
    ]
    # Allow at most 5 unmapped high-risk sub-tests (manual-only or no tool exists)
    assert len(high_risk_with_no_tool) <= 5, (
        f"Too many high-risk sub-tests without tools: {high_risk_with_no_tool}"
    )


def test_subtest_tree_integrates_with_catalog():
    """build_subtest_task_tree output keys match catalog keys exactly."""
    from unittest.mock import patch, MagicMock
    from multi_agent_system.core.task_tree import build_subtest_task_tree

    cat = load_catalog()
    fake_db = MagicMock()
    fake_db.query.return_value.filter.return_value.all.return_value = []
    cm = MagicMock()
    cm.__enter__.return_value = fake_db
    cm.__exit__.return_value = False
    with patch("multi_agent_system.core.task_tree.get_db", return_value=cm):
        tree = build_subtest_task_tree(job_id=999)
    assert set(tree.keys()) == set(cat.keys()), "tree keys don't match catalog keys"


def test_coverage_audit_gap_finder_uses_catalog_high_risk_flag():
    """_identify_subtest_gaps should return only high_risk sub-tests."""
    from multi_agent_system.orchestrator import Orchestrator
    # Build fake tree from real catalog
    cat = load_catalog()
    fake_tree = {
        st_id: {
            "id": st_id,
            "title": st.title,
            "category": st.category,
            "owner_agent": st.owasp_agent,
            "high_risk": st.high_risk,
            "status": "pending",
            "finding_count": 0,
        }
        for st_id, st in cat.items()
        if st.owasp_agent == "InputValidationAgent"
    }
    orch = Orchestrator.__new__(Orchestrator)
    gaps = orch._identify_subtest_gaps("InputValidationAgent", fake_tree)
    assert all(g["high_risk"] for g in gaps)
    assert len(gaps) > 0, "InputValidationAgent should have high-risk INPV sub-tests"


def test_learned_pattern_round_trip(tmp_path, monkeypatch):
    """target_signature + record + top_patterns_for round trip."""
    import multi_agent_system.utils.learned_patterns as lp_mod
    monkeypatch.setattr(lp_mod, "_DEFAULT_PATH", tmp_path / "lp.db")
    from multi_agent_system.utils.learned_patterns import (
        target_signature, LearnedPatternStore,
    )
    store = LearnedPatternStore(tmp_path / "lp.db")
    tech = {"server": "nginx", "tech": ["Node.js", "Express"]}
    sig = target_signature(tech)
    store.record(sig, "WSTG-INPV-05", "test_sqli", {"vector": "blind"}, True, 3)
    top = store.top_patterns_for(sig, "WSTG-INPV")
    assert top[0]["tool"] == "test_sqli"
    assert top[0]["finding_count"] == 3


def test_retry_helper_exists_on_base_agent():
    """_execute_with_retry_on_empty must be callable on BaseAgent."""
    from multi_agent_system.agents.base_agent import BaseAgent
    assert callable(getattr(BaseAgent, "_execute_with_retry_on_empty", None))


def test_propose_retry_arguments_exists_on_llm_client():
    """SimpleLLMClient must expose propose_retry_arguments."""
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient
    assert callable(getattr(SimpleLLMClient, "propose_retry_arguments", None))


def test_propose_subtest_directive_exists_on_llm_client():
    """SimpleLLMClient must expose propose_subtest_directive."""
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient
    assert callable(getattr(SimpleLLMClient, "propose_subtest_directive", None))
