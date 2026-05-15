from multi_agent_system.framework.semantic_classifier import (
    ClassificationMatch, SemanticClassifier
)


def test_classification_match():
    m = ClassificationMatch(challenge_id="C1", confidence=0.8, rationale="WSTG match")
    assert m.challenge_id == "C1"
    assert m.confidence == 0.8
    assert m.rationale == "WSTG match"


def test_classifier_construct():
    c = SemanticClassifier(llm_client=None, similarity_threshold=0.6, enabled=True)
    assert c.enabled is True
    assert c.similarity_threshold == 0.6


def test_wstg_match_returns_high_confidence():
    classifier = SemanticClassifier(llm_client=None)
    finding = {
        "title": "SQL Injection Login Bypass",
        "category": "WSTG-INPV-05",
        "details": "Bypass via ' OR 1=1--",
    }
    ground_truth = [
        {"id": "login_admin", "wstg": "WSTG-INPV-05", "description": "Login admin via SQLi"},
        {"id": "login_bender", "wstg": "WSTG-INPV-05", "description": "Login bender via SQLi"},
        {"id": "xss_dom", "wstg": "WSTG-CLNT-01", "description": "DOM XSS"},
    ]
    matches = classifier._match_by_wstg(finding, ground_truth)
    ids = {m.challenge_id for m in matches}
    assert "login_admin" in ids
    assert "login_bender" in ids
    assert "xss_dom" not in ids
    assert all(m.confidence >= 0.7 for m in matches)


def test_wstg_match_returns_empty_when_no_category():
    classifier = SemanticClassifier(llm_client=None)
    finding = {"title": "Unknown", "category": None}
    gt = [{"id": "x", "wstg": "WSTG-INPV-05"}]
    matches = classifier._match_by_wstg(finding, gt)
    assert matches == []


def test_cwe_match_boosts_confidence():
    classifier = SemanticClassifier(llm_client=None)
    finding = {
        "title": "SQLi",
        "category": "WSTG-INPV-05",
        "evidence": {"cwe_id": "CWE-89"},
    }
    gt = [
        {"id": "g1", "wstg": "WSTG-INPV-05", "cwe": "CWE-89", "description": "..."},
        {"id": "g2", "wstg": "WSTG-INPV-05", "cwe": "CWE-79", "description": "..."},
    ]
    matches = classifier._match_by_cwe(finding, gt)
    ids = {m.challenge_id for m in matches}
    assert "g1" in ids
    assert "g2" not in ids


def test_classify_aggregates_tiers():
    classifier = SemanticClassifier(llm_client=None)
    finding = {
        "title": "SQLi", "category": "WSTG-INPV-05",
        "evidence": {"cwe_id": "CWE-89"},
    }
    gt = [
        {"id": "g1", "wstg": "WSTG-INPV-05", "cwe": "CWE-89"},
        {"id": "g2", "wstg": "WSTG-INPV-05"},   # no CWE, only WSTG
        {"id": "g3", "wstg": "WSTG-CLNT-01"},   # no match
    ]
    matches = classifier.classify(finding, gt)
    ids = [m.challenge_id for m in matches]
    assert "g1" in ids
    assert "g2" in ids
    assert "g3" not in ids
    # g1 should have higher confidence than g2 (CWE boost)
    by_id = {m.challenge_id: m for m in matches}
    assert by_id["g1"].confidence >= by_id["g2"].confidence


def test_classify_disabled_returns_empty():
    classifier = SemanticClassifier(llm_client=None, enabled=False)
    finding = {"title": "x", "category": "WSTG-INPV-05"}
    gt = [{"id": "g1", "wstg": "WSTG-INPV-05"}]
    assert classifier.classify(finding, gt) == []


def test_classify_filters_below_threshold():
    classifier = SemanticClassifier(llm_client=None, similarity_threshold=0.8)
    finding = {"title": "x", "category": "WSTG-INPV-05"}
    # No CWE -> only WSTG match (0.75) which is below threshold
    gt = [{"id": "g1", "wstg": "WSTG-INPV-05"}]
    matches = classifier.classify(finding, gt)
    assert matches == []
