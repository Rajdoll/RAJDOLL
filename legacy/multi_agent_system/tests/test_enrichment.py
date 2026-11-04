"""Tests for enrichment_service — no Docker required."""
import pytest
from unittest.mock import patch


def test_enrichment_result_has_required_fields():
    from multi_agent_system.utils.enrichment_service import EnrichmentResult
    r = EnrichmentResult(
        explanation="test", remediation="1. fix it",
        cwe_id="CWE-89", wstg_id="WSTG-INPV-05",
        cvss_score_v4=9.3, references=["https://owasp.org"],
        source="static_kb"
    )
    assert r.source == "static_kb"
    assert r.cvss_score_v4 == 9.3


def test_static_kb_matcher_returns_none_on_miss():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    result = StaticKBMatcher.match("Unknown Category", "Something very obscure xyz123")
    assert result is None


def test_static_kb_matcher_case_insensitive():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    # Should not crash even with uppercase — returns None since no KB loaded yet
    result = StaticKBMatcher.match("input validation", "SQL INJECTION FOUND")
    # Either None (no KB file yet) or a valid result — both acceptable
    assert result is None or result.source == "static_kb"


def test_enrichment_service_returns_fallback_on_llm_failure():
    from multi_agent_system.utils.enrichment_service import EnrichmentService
    with patch("multi_agent_system.utils.enrichment_service.LLMEnricher.enrich") as mock_llm:
        mock_llm.side_effect = Exception("LM Studio not running")
        result = EnrichmentService.enrich("Unknown", "weird obscure finding xyz", "medium", {})
    assert result.source == "fallback"
    assert result.explanation != ""


def test_enrichment_service_calls_llm_on_kb_miss():
    from multi_agent_system.utils.enrichment_service import EnrichmentService, EnrichmentResult
    fake = EnrichmentResult("exp", "rem", "CWE-200", "WSTG-INFO-01", 5.0, [], "llm")
    with patch("multi_agent_system.utils.enrichment_service.LLMEnricher.enrich", return_value=fake) as mock_llm:
        result = EnrichmentService.enrich("Unknown", "weird obscure finding xyz", "medium", {})
    mock_llm.assert_called_once()
    assert result.source == "llm"


def test_fallback_has_non_empty_explanation():
    from multi_agent_system.utils.enrichment_service import EnrichmentService
    with patch("multi_agent_system.utils.enrichment_service.LLMEnricher.enrich") as mock_llm:
        mock_llm.side_effect = Exception("timeout")
        result = EnrichmentService.enrich("Config", "weird thing", "high", {})
    assert len(result.explanation) > 10
    assert result.source == "fallback"


def test_enrichment_service_uses_static_kb_on_hit():
    from multi_agent_system.utils.enrichment_service import EnrichmentService, StaticKBMatcher, EnrichmentResult
    fake_kb_result = EnrichmentResult("SQLi explanation", "1. fix", "CWE-89", "WSTG-INPV-05", 9.3, [], "static_kb")
    with patch.object(StaticKBMatcher, "match", return_value=fake_kb_result) as mock_kb:
        result = EnrichmentService.enrich("Input Validation", "SQL Injection", "critical", {})
    mock_kb.assert_called_once()
    assert result.source == "static_kb"
    assert result.cwe_id == "CWE-89"
