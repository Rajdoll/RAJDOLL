import sqlite3
from pathlib import Path

import pytest

from multi_agent_system.framework.payload_synthesizer import PayloadSynthesizer
from multi_agent_system.framework.types import EndpointSpec, Payload


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "patterns.db"
    return db


def test_cache_key_is_target_agnostic(tmp_db):
    synth = PayloadSynthesizer(llm_client=None, pattern_db_path=tmp_db, enabled=True)
    key_a = synth._cache_key("ssti", {"framework": "express", "server": "nginx"})
    key_b = synth._cache_key("ssti", {"framework": "express", "server": "nginx"})
    key_c = synth._cache_key("ssti", {"framework": "spring", "server": "tomcat"})
    assert key_a == key_b
    assert key_a != key_c
    # No target hostname leaks into key
    assert "example.com" not in key_a
    assert "juice-shop" not in key_a


def test_cache_round_trip(tmp_db):
    synth = PayloadSynthesizer(llm_client=None, pattern_db_path=tmp_db, enabled=True)
    payloads = [Payload(value="{{7*7}}", encoding="raw",
                        expected_signal="49", category="ssti")]
    synth._cache_write("ssti", {"framework": "express"}, payloads)
    cached = synth._cache_read("ssti", {"framework": "express"})
    assert len(cached) == 1
    assert cached[0].value == "{{7*7}}"


def test_cache_miss_returns_empty(tmp_db):
    synth = PayloadSynthesizer(llm_client=None, pattern_db_path=tmp_db, enabled=True)
    cached = synth._cache_read("ssti", {"framework": "express"})
    assert cached == []


class _FakeLLM:
    """Mock LLM that returns canned JSON."""
    def __init__(self, response_json: dict):
        self.response = response_json
        self.calls = []

    def chat_with_schema(self, prompt: str, schema: dict, timeout: int = 60) -> dict:
        self.calls.append({"prompt": prompt, "schema": schema})
        return self.response


def test_llm_synthesis_parses_payloads(tmp_db):
    fake = _FakeLLM({
        "payloads": [
            {"value": "{{7*7}}", "encoding": "raw",
             "expected_signal": "49", "category": "ssti",
             "engine_hypothesis": "jinja2"},
            {"value": "${7*7}", "encoding": "raw",
             "expected_signal": "49", "category": "ssti",
             "engine_hypothesis": "freemarker"},
        ]
    })
    synth = PayloadSynthesizer(llm_client=fake, pattern_db_path=tmp_db, enabled=True)
    payloads = synth._llm_synthesize("ssti", {"framework": "flask"}, n=2)
    assert len(payloads) == 2
    assert payloads[0].value == "{{7*7}}"
    assert payloads[0].engine_hypothesis == "jinja2"
    assert len(fake.calls) == 1
    # Prompt must mention attack class and framework hint, but not target name
    assert "ssti" in fake.calls[0]["prompt"].lower()
    assert "flask" in fake.calls[0]["prompt"].lower()


def test_llm_synthesis_handles_invalid_response(tmp_db):
    fake = _FakeLLM({"not_payloads": []})
    synth = PayloadSynthesizer(llm_client=fake, pattern_db_path=tmp_db, enabled=True)
    payloads = synth._llm_synthesize("ssti", {"framework": "flask"}, n=2)
    assert payloads == []


def test_wordlist_fallback_returns_generic_payloads(tmp_path, tmp_db):
    wordlist = tmp_path / "ssti.txt"
    wordlist.write_text("{{7*7}}\n${7*7}\n<%=7*7%>\n#{7*7}\n")
    synth = PayloadSynthesizer(llm_client=None, pattern_db_path=tmp_db, enabled=True)
    payloads = synth._wordlist_fallback("ssti", wordlist_path=wordlist, n=3)
    assert len(payloads) == 3
    assert all(p.category == "ssti" for p in payloads)
    assert all(p.encoding == "raw" for p in payloads)
    assert all(p.expected_signal == "49" for p in payloads)


def test_wordlist_fallback_missing_file_returns_empty(tmp_db):
    synth = PayloadSynthesizer(llm_client=None, pattern_db_path=tmp_db, enabled=True)
    payloads = synth._wordlist_fallback("ssti", wordlist_path="/nonexistent", n=3)
    assert payloads == []
