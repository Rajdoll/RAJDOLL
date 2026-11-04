from multi_agent_system.evaluation.adjudication_ablation import split_by_source


def test_split_counts_sources():
    findings = [
        {"category": "WSTG-XSS", "evidence": {}},
        {"category": "WSTG-ATHZ-04", "evidence": {"source": "llm-adjudicated"}},
        {"category": "WSTG-CONF-01", "evidence": {"source": "tool"}},
    ]
    out = split_by_source(findings)
    assert len(out["llm-adjudicated"]) == 1
    assert len(out["deterministic"]) == 2
