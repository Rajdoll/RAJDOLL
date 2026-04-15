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


class TestPrecisionCalculation:
    def _make_finding(self, is_tp):
        f = MagicMock()
        f.is_true_positive = is_tp
        return f

    def test_precision_returns_none_when_no_labels(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding(None), self._make_finding(None)]
        assert m.calculate_precision(findings) is None

    def test_precision_all_tp(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding(True), self._make_finding(True), self._make_finding(True)]
        assert m.calculate_precision(findings) == 100.0

    def test_precision_mixed(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding(True)] * 3 + [self._make_finding(False)]
        assert m.calculate_precision(findings) == 75.0

    def test_precision_partial_review(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding(True), self._make_finding(True), self._make_finding(None)]
        assert m.calculate_precision(findings) == 100.0


class TestRecallCalculation:
    def _make_finding(self, title, category):
        f = MagicMock()
        f.title = title
        f.details = ""
        f.category = category
        return f

    def _make_gt(self, vuln_name, category):
        gt = MagicMock()
        gt.id = id(gt)
        gt.vuln_name = vuln_name
        gt.category = category
        return gt

    def test_recall_returns_none_when_no_ground_truth(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        assert m.calculate_recall([], []) is None

    def test_recall_all_detected(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding("SQL Injection Login Bypass admin", "WSTG-INPV-05")]
        gt = [self._make_gt("Login Admin", "WSTG-INPV-05")]
        assert m.calculate_recall(findings, gt) == 100.0

    def test_recall_none_detected(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding("XSS found", "WSTG-CLNT-01")]
        gt = [self._make_gt("Login Admin", "WSTG-INPV-05")]
        assert m.calculate_recall(findings, gt) == 0.0


class TestGroundTruthManager:
    def test_derive_profile_juice_shop(self):
        from multi_agent_system.evaluation.metrics import GroundTruthManager
        assert GroundTruthManager.derive_profile("http://juice-shop:3000") == "juice-shop"

    def test_derive_profile_webgoat(self):
        from multi_agent_system.evaluation.metrics import GroundTruthManager
        assert GroundTruthManager.derive_profile("http://webgoat:8080/WebGoat") == "webgoat"

    def test_derive_profile_external(self):
        from multi_agent_system.evaluation.metrics import GroundTruthManager
        assert GroundTruthManager.derive_profile("https://target.bssn.go.id") == "target.bssn.go.id"

    def test_no_hardcoded_dicts(self):
        import multi_agent_system.evaluation.metrics as m
        assert not hasattr(m, "JUICE_SHOP_GROUND_TRUTH"), "Hardcoded dict must be removed"
        assert not hasattr(m, "DVWA_GROUND_TRUTH"), "Hardcoded dict must be removed"
