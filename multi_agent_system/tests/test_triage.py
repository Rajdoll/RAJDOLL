import asyncio

from multi_agent_system.utils.simple_llm_client import SimpleLLMClient, _parse_triage_verdicts, _parse_probe_proposals
from multi_agent_system.orchestrator import _finding_source, _resolve_triage_verdict


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


def test_triage_findings_retries_recover_omitted_ids(monkeypatch):
    client = SimpleLLMClient()

    calls = {"n": 0}
    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        calls["n"] += 1
        # Echo a verdict only for the FIRST item in the chunk -> omitted ids must be re-sent
        # in later rounds (where they eventually become a chunk's first item) and recovered.
        import re as _re
        first_id = _re.search(r'"id":\s*(\d+)', messages[-1]["content"]).group(1)
        return '{"verdicts":[{"id":%s,"verdict":"false_positive","severity":"info","confidence":0.7,"reason":"x"}]}' % first_id

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    items = [{"id": i, "category": "WSTG-INPV-05", "title": f"f{i}", "current_severity": "high",
              "source": "heuristic", "agent": "X", "evidence": "e"} for i in range(1, 6)]
    out = asyncio.get_event_loop().run_until_complete(client.triage_findings(items, {"target": "t"}, chunk_size=2))
    by_id = {v["id"]: v for v in out}
    assert set(by_id) == {1, 2, 3, 4, 5}                    # every input id present
    # Round1 echoes 1,3,5; round2 re-sends [2,4] -> echoes 2; round3 re-sends [4] -> echoes 4.
    assert all(by_id[i]["verdict"] == "false_positive" for i in range(1, 6))  # all recovered, none fell to fallback
    assert calls["n"] == 5                                   # 3 (round1) + 1 (round2) + 1 (round3)


def test_triage_findings_stubborn_id_falls_to_fallback(monkeypatch):
    client = SimpleLLMClient()

    calls = {"n": 0}
    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        calls["n"] += 1
        # Answer every id EXCEPT 99 -> 99 is never returned and must end as bounded fallback.
        import re as _re
        ids = _re.findall(r'"id":\s*(\d+)', messages[-1]["content"])
        verdicts = ",".join(
            '{"id":%s,"verdict":"true_positive","severity":"low"}' % i for i in ids if i != "99")
        return '{"verdicts":[%s]}' % verdicts

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    items = [{"id": i, "category": "WSTG-INPV-05", "title": f"f{i}", "current_severity": "high",
              "source": "heuristic", "agent": "X", "evidence": "e"} for i in (1, 2, 99)]
    out = asyncio.get_event_loop().run_until_complete(
        client.triage_findings(items, {"target": "t"}, chunk_size=8, max_rounds=3))
    by_id = {v["id"]: v for v in out}
    assert set(by_id) == {1, 2, 99}
    assert by_id[99]["verdict"] == "needs_review"
    assert by_id[99]["reason"] == "not returned after retries"
    assert calls["n"] == 3                                   # 1 per round, bounded by max_rounds (no infinite loop)


def test_finding_source_detects_authoritative_tools():
    assert _finding_source({"source": "sqlmap", "raw": "..."}, None, "InputValidationAgent") == "tool-confirmed"
    assert _finding_source({"dalfox": {}}, "poc", "ClientSideAgent") == "tool-confirmed"
    assert _finding_source({"note": "reflected"}, "heuristic check", "ClientSideAgent") == "heuristic"


def test_resolve_verdict_protects_tool_confirmed():
    # FP verdict on a tool-confirmed finding must be ignored (kept TP), severity may change
    r = _resolve_triage_verdict("tool-confirmed",
                                {"verdict": "false_positive", "severity": "low", "confidence": 0.6, "reason": "r"})
    assert r["is_true_positive"] is True          # NOT suppressed
    assert r["severity"] == "low"                 # severity still adjusted


def test_resolve_verdict_heuristic_fp_suppresses():
    r = _resolve_triage_verdict("heuristic",
                                {"verdict": "false_positive", "severity": "info", "confidence": 0.9, "reason": "echo"})
    assert r["is_true_positive"] is False
    assert r["severity"] == "info"


def test_resolve_verdict_needs_review_leaves_validity_none():
    r = _resolve_triage_verdict("heuristic",
                                {"verdict": "needs_review", "severity": None, "confidence": None, "reason": ""})
    assert r["is_true_positive"] is None
    assert "severity" not in r or r["severity"] is None  # no severity change when None


def test_resolve_verdict_fallback_does_not_clobber_confidence():
    # "not returned by triage" fallback verdict must not overwrite an existing confidence_score
    r = _resolve_triage_verdict("heuristic",
                                {"verdict": "needs_review", "severity": None, "confidence": None,
                                 "reason": "not returned by triage"})
    assert "confidence_score" not in r


def test_parse_probe_proposals_clean():
    text = ('{"probes":[{"finding_id":5,"server":"input-validation-testing","tool":"test_sqli",'
            '"args":{"url":"http://t","param":"q"},"hypothesis":"confirm sqli"}]}')
    out = _parse_probe_proposals(text)
    assert len(out) == 1
    assert out[0]["finding_id"] == 5 and out[0]["tool"] == "test_sqli"
    assert out[0]["args"]["param"] == "q"


def test_parse_probe_proposals_drops_incomplete_and_salvages():
    # first object complete, second cut off mid-string -> only the first survives
    text = ('{"probes":[{"finding_id":1,"server":"s","tool":"t","args":{},"hypothesis":"h"},'
            '{"finding_id":2,"server":"s","tool":')
    out = _parse_probe_proposals(text)
    assert [p["finding_id"] for p in out] == [1]


def test_parse_probe_proposals_garbage_returns_empty():
    assert _parse_probe_proposals("not json") == []
    # missing server/tool -> dropped
    assert _parse_probe_proposals('{"probes":[{"finding_id":9,"hypothesis":"x"}]}') == []


def test_propose_probes_surfaces_probe_and_validates_id(monkeypatch):
    client = SimpleLLMClient()
    seen = {"catalog": False, "fewshot": False}

    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        sys = messages[0]["content"]
        if "Example probe" in sys:
            seen["fewshot"] = True
        if "input-validation-testing" in messages[1]["content"]:
            seen["catalog"] = True
        # one valid candidate (id 5) and one hallucinated id (999) -> 999 must be dropped
        return ('{"probes":[{"finding_id":5,"server":"input-validation-testing","tool":"test_sqli",'
                '"args":{"url":"http://t","param":"q"},"hypothesis":"confirm"},'
                '{"finding_id":999,"server":"input-validation-testing","tool":"test_sqli",'
                '"args":{},"hypothesis":"hallucinated"}]}')

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    candidates = [{"id": 5, "category": "WSTG-INPV-05", "title": "f", "source": "heuristic",
                   "agent": "InputValidationAgent", "evidence": "e"}]
    catalog = {"input-validation-testing": ["test_sqli", "test_xss_reflected"]}
    out = asyncio.get_event_loop().run_until_complete(
        client.propose_probes(candidates, catalog, {"target": "t"}, max_probes=4))
    assert seen["fewshot"] is True and seen["catalog"] is True
    assert [p["finding_id"] for p in out] == [5]          # hallucinated 999 dropped


def test_propose_probes_empty_when_no_candidates_or_catalog():
    client = SimpleLLMClient()
    run = asyncio.get_event_loop().run_until_complete
    assert run(client.propose_probes([], {"s": ["t"]}, {"target": "t"})) == []
    assert run(client.propose_probes([{"id": 1}], {}, {"target": "t"})) == []


def test_propose_probes_repairs_server_and_drops_unknown_tool(monkeypatch):
    client = SimpleLLMClient()

    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        # 1st: bad server (target host) but valid tool -> server must be repaired from the catalog
        # 2nd: unknown tool -> must be dropped
        return ('{"probes":[{"finding_id":5,"server":"juice-shop:3000","tool":"test_sqli",'
                '"args":{"url":"http://t","param":"q"},"hypothesis":"h"},'
                '{"finding_id":5,"server":"input-validation-testing","tool":"no_such_tool",'
                '"args":{},"hypothesis":"x"}]}')

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    candidates = [{"id": 5, "category": "C", "title": "f", "source": "heuristic",
                   "agent": "InputValidationAgent", "evidence": "e"}]
    catalog = {"input-validation-testing": ["test_sqli", "test_xss_reflected"]}
    out = asyncio.get_event_loop().run_until_complete(
        client.propose_probes(candidates, catalog, {"target": "t"}, max_probes=4))
    assert len(out) == 1                                    # unknown-tool probe dropped
    assert out[0]["tool"] == "test_sqli"
    assert out[0]["server"] == "input-validation-testing"  # repaired from "juice-shop:3000"


def test_propose_probes_constrains_tool_to_catalog_enum(monkeypatch):
    # the json_schema must constrain `tool` to the catalog tools so the grammar can't let
    # the local model hallucinate a tool name (e.g. "dirsearch")
    client = SimpleLLMClient()
    captured = {}

    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        captured["schema"] = response_schema
        return '{"probes":[]}'

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    candidates = [{"id": 5, "category": "C", "title": "f", "source": "heuristic",
                   "agent": "InputValidationAgent", "evidence": "e"}]
    catalog = {"input-validation-testing": ["test_sqli", "test_xss_reflected"]}
    asyncio.get_event_loop().run_until_complete(
        client.propose_probes(candidates, catalog, {"target": "t"}, max_probes=4))
    tool_prop = captured["schema"]["properties"]["probes"]["items"]["properties"]["tool"]
    assert tool_prop.get("enum") == ["test_sqli", "test_xss_reflected"]


def test_propose_probes_backfills_url_from_evidence_or_target(monkeypatch):
    # the local model often omits args entirely; backfill url from the finding evidence,
    # else the scan target, so the tool call has its required url
    client = SimpleLLMClient()

    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        return ('{"probes":[{"finding_id":5,"server":"x","tool":"test_sqli","hypothesis":"h"},'
                '{"finding_id":6,"server":"x","tool":"test_sqli","hypothesis":"h"}]}')

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    candidates = [
        {"id": 5, "category": "C", "title": "f", "source": "heuristic", "agent": "InputValidationAgent",
         "evidence": "found at http://juice-shop:3000/rest/user/login via boolean"},
        {"id": 6, "category": "C", "title": "f", "source": "heuristic", "agent": "InputValidationAgent",
         "evidence": "no url here"},
    ]
    catalog = {"input-validation-testing": ["test_sqli"]}
    out = asyncio.get_event_loop().run_until_complete(
        client.propose_probes(candidates, catalog, {"target": "http://juice-shop:3000"}, max_probes=4))
    by_id = {p["finding_id"]: p for p in out}
    assert by_id[5]["args"]["url"] == "http://juice-shop:3000/rest/user/login"   # from evidence
    assert by_id[6]["args"]["url"] == "http://juice-shop:3000"                    # fallback target


def test_propose_probes_tool_collision_uses_first_server(monkeypatch):
    # same tool name under two servers -> enum and server-repair must agree (first wins)
    client = SimpleLLMClient()

    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        return ('{"probes":[{"finding_id":5,"server":"x","tool":"test_sqli",'
                '"args":{"url":"http://t"},"hypothesis":"h"}]}')

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    candidates = [{"id": 5, "category": "C", "title": "f", "source": "heuristic",
                   "agent": "A", "evidence": "e"}]
    catalog = {"server-a": ["test_sqli"], "server-b": ["test_sqli"]}
    out = asyncio.get_event_loop().run_until_complete(
        client.propose_probes(candidates, catalog, {"target": "http://t"}, max_probes=4))
    assert out[0]["server"] == "server-a"          # first occurrence wins


def test_propose_probes_strips_trailing_punctuation_from_evidence_url(monkeypatch):
    client = SimpleLLMClient()

    async def fake_chat(messages, max_tokens=2000, temperature=0.0, response_schema=None):
        return '{"probes":[{"finding_id":5,"server":"x","tool":"test_sqli","hypothesis":"h"}]}'

    monkeypatch.setattr(client, "chat_completion", fake_chat)
    candidates = [{"id": 5, "category": "C", "title": "f", "source": "heuristic", "agent": "A",
                   "evidence": "confirmed at http://juice-shop:3000/rest/user/login."}]
    catalog = {"input-validation-testing": ["test_sqli"]}
    out = asyncio.get_event_loop().run_until_complete(
        client.propose_probes(candidates, catalog, {"target": "http://t"}, max_probes=4))
    assert out[0]["args"]["url"] == "http://juice-shop:3000/rest/user/login"   # trailing "." stripped
