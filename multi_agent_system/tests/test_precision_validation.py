import pytest
from unittest.mock import MagicMock


class TestGroundTruthEntry:
    def test_model_has_required_fields(self):
        from multi_agent_system.models.ground_truth import GroundTruthEntry
        entry = GroundTruthEntry(
            target_profile="juice-shop",
            vuln_name="Login Admin",
            category="WSTG-INPV-05",
            severity="critical",
            cvss=9.8,
        )
        assert entry.target_profile == "juice-shop"
        assert entry.vuln_name == "Login Admin"
        assert entry.category == "WSTG-INPV-05"
        assert entry.severity == "critical"
        assert entry.cvss == 9.8

    def test_model_tablename(self):
        from multi_agent_system.models.ground_truth import GroundTruthEntry
        assert GroundTruthEntry.__tablename__ == "ground_truth_entries"


class TestFindingValidationFields:
    def test_finding_has_is_true_positive(self):
        from multi_agent_system.models.models import Finding
        f = Finding()
        assert hasattr(f, "is_true_positive")
        assert f.is_true_positive is None  # nullable default

    def test_finding_has_validation_notes(self):
        from multi_agent_system.models.models import Finding
        f = Finding()
        assert hasattr(f, "validation_notes")
        assert f.validation_notes is None
