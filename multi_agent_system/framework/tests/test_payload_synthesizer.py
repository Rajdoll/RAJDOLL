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
