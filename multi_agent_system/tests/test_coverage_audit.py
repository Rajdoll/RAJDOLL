from unittest.mock import patch, MagicMock
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
