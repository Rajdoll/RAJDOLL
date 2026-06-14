from multi_agent_system.utils.simple_llm_client import _parse_triage_verdicts


def test_parse_clean_verdicts():
    text = '{"verdicts":[{"id":1,"verdict":"false_positive","severity":"info","confidence":0.9,"reason":"reflected only"}]}'
    out = _parse_triage_verdicts(text)
    assert len(out) == 1
    assert out[0]["id"] == 1 and out[0]["verdict"] == "false_positive"


def test_parse_truncated_verdicts_salvages_complete_objects():
    # second object cut off mid-string -> first must still be recovered
    text = ('{"verdicts":[{"id":1,"verdict":"true_positive","severity":"high","confidence":0.8,"reason":"sqlmap confirmed"},'
            '{"id":2,"verdict":"false_positi')
    out = _parse_triage_verdicts(text)
    assert [v["id"] for v in out] == [1]


def test_parse_garbage_returns_empty():
    assert _parse_triage_verdicts("not json at all") == []
