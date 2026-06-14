import asyncio

from multi_agent_system.utils.simple_llm_client import SimpleLLMClient, _parse_triage_verdicts


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


def test_triage_findings_chunks_and_fills_missing(monkeypatch):
    client = SimpleLLMClient()

    calls = {"n": 0}
    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        calls["n"] += 1
        # Echo a verdict only for the first item in the chunk -> tests "missing -> needs_review"
        import re as _re
        first_id = _re.search(r'"id":\s*(\d+)', messages[-1]["content"]).group(1)
        return '{"verdicts":[{"id":%s,"verdict":"false_positive","severity":"info","confidence":0.7,"reason":"x"}]}' % first_id

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    items = [{"id": i, "category": "WSTG-INPV-05", "title": f"f{i}", "current_severity": "high",
              "source": "heuristic", "agent": "X", "evidence": "e"} for i in range(1, 6)]
    out = asyncio.get_event_loop().run_until_complete(client.triage_findings(items, {"target": "t"}, chunk_size=2))
    by_id = {v["id"]: v for v in out}
    assert set(by_id) == {1, 2, 3, 4, 5}                    # every input id present
    assert by_id[1]["verdict"] == "false_positive"          # echoed
    assert by_id[2]["verdict"] == "needs_review"            # missing -> filled
    assert calls["n"] == 3                                   # 5 items / chunk_size 2 = 3 calls
