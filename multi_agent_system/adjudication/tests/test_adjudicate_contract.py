import asyncio, json
from multi_agent_system.utils.simple_llm_client import SimpleLLMClient

def test_adjudicate_parses_schema_response(monkeypatch):
    c = SimpleLLMClient()
    canned = json.dumps({"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04",
                         "evidence_span": "owner:1", "reason": "cross-user data", "confidence": 0.9})
    async def fake_chat(messages, max_tokens=600, temperature=0.0, response_schema=None):
        assert response_schema and response_schema["title"] == "adjudication"
        assert temperature == 0.0
        return canned
    monkeypatch.setattr(c, "chat_completion", fake_chat)
    art = {"wstg": "WSTG-ATHZ-04", "role": "user:2", "method": "GET", "url": "http://t/api/user/1",
           "status": 200, "baseline_status": 200, "headers_subset": {}, "body": '{"owner:1"}'}
    out = asyncio.get_event_loop().run_until_complete(c.adjudicate_response(art))
    assert out["verdict"] == "vulnerable" and out["evidence_span"] == "owner:1"

def test_adjudicate_returns_empty_on_error(monkeypatch):
    c = SimpleLLMClient()
    async def boom(*a, **k):
        raise RuntimeError("llm down")
    monkeypatch.setattr(c, "chat_completion", boom)
    out = asyncio.get_event_loop().run_until_complete(c.adjudicate_response({"wstg": "x", "body": ""}))
    assert out == {}
