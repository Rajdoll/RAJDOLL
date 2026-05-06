# multi_agent_system/tests/test_endpoint_classifier.py
"""Tests for LLMEndpointClassifier (batching, cache, schema validation)."""
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from multi_agent_system.utils.endpoint_classifier import (
    LLMEndpointClassifier,
    cache_key,
)


def make_endpoint(id_: str, path: str = "/x", method: str = "GET") -> dict:
    return {
        "id": id_,
        "path": path,
        "method": method,
        "auth_required": False,
        "discovered_by": "R1_passive",
        "response_signature": {"status": 200, "content_type": "application/json", "sample_keys": []},
    }


def test_cache_key_is_stable_per_host_path_method():
    ep = make_endpoint("ep_001", "/api/users/{id}", "GET")
    k1 = cache_key("example.com", ep)
    k2 = cache_key("example.com", ep)
    assert k1 == k2
    # Different host -> different key (no cross-target leakage)
    assert cache_key("other.com", ep) != k1


@pytest.mark.asyncio
async def test_classifier_calls_llm_in_batches_of_30(tmp_path):
    llm = AsyncMock()
    llm.chat_completion = AsyncMock(return_value=json.dumps({
        "classifications": [
            {"id": f"ep_{i}", "tags": ["api_generic"], "confidence": {"api_generic": 0.9}}
            for i in range(30)
        ],
    }))
    classifier = LLMEndpointClassifier(
        llm_client=llm,
        cache_path=tmp_path / "cache.json",
        batch_size=30,
        max_batches=3,
    )
    endpoints = [make_endpoint(f"ep_{i}") for i in range(30)]
    out = await classifier.classify("example.com", endpoints)
    assert len(out) == 30
    assert out[0]["tags"] == ["api_generic"]
    assert llm.chat_completion.await_count == 1


@pytest.mark.asyncio
async def test_classifier_respects_max_batches(tmp_path):
    """If endpoints > batch_size * max_batches, prioritize auth_required first then drop the rest."""
    llm = AsyncMock()
    # First batch: 30 auth-required endpoints
    llm.chat_completion = AsyncMock(side_effect=[
        json.dumps({"classifications": [
            {"id": f"ep_{i}", "tags": ["user_profile"], "confidence": {"user_profile": 0.9}}
            for i in range(30)
        ]}),
    ])
    classifier = LLMEndpointClassifier(
        llm_client=llm, cache_path=tmp_path / "cache.json", batch_size=30, max_batches=1,
    )
    endpoints = [make_endpoint(f"ep_{i}") for i in range(40)]
    # Mark first 30 as auth_required so they get priority
    for ep in endpoints[:30]:
        ep["auth_required"] = True
    out = await classifier.classify("h", endpoints)
    classified_ids = {ep["id"] for ep in out if ep.get("tags")}
    # The 30 auth-required got tagged; the 10 unauth got tags=[] (not classified)
    assert all(ep["id"] in classified_ids for ep in endpoints[:30])
    assert all(ep["tags"] == [] for ep in endpoints[30:])


@pytest.mark.asyncio
async def test_classifier_uses_cache_on_second_call(tmp_path):
    llm = AsyncMock()
    llm.chat_completion = AsyncMock(return_value=json.dumps({
        "classifications": [{"id": "ep_001", "tags": ["api_generic"], "confidence": {"api_generic": 0.9}}],
    }))
    classifier = LLMEndpointClassifier(
        llm_client=llm, cache_path=tmp_path / "cache.json", batch_size=30, max_batches=3,
    )
    eps = [make_endpoint("ep_001")]
    await classifier.classify("h", eps)
    await classifier.classify("h", eps)  # second call: pure cache hit
    assert llm.chat_completion.await_count == 1


@pytest.mark.asyncio
async def test_classifier_drops_unknown_tags_from_llm(tmp_path):
    llm = AsyncMock()
    llm.chat_completion = AsyncMock(return_value=json.dumps({
        "classifications": [
            {"id": "ep_001", "tags": ["api_generic", "made_up_tag"], "confidence": {"api_generic": 0.9, "made_up_tag": 0.9}},
        ],
    }))
    classifier = LLMEndpointClassifier(
        llm_client=llm, cache_path=tmp_path / "cache.json", batch_size=30, max_batches=3,
    )
    out = await classifier.classify("h", [make_endpoint("ep_001")])
    assert out[0]["tags"] == ["api_generic"]


@pytest.mark.asyncio
async def test_classifier_drops_low_confidence_tags(tmp_path):
    llm = AsyncMock()
    llm.chat_completion = AsyncMock(return_value=json.dumps({
        "classifications": [
            {"id": "ep_001", "tags": ["api_generic"], "confidence": {"api_generic": 0.4}},
        ],
    }))
    classifier = LLMEndpointClassifier(
        llm_client=llm, cache_path=tmp_path / "cache.json", batch_size=30, max_batches=3,
    )
    out = await classifier.classify("h", [make_endpoint("ep_001")])
    assert out[0]["tags"] == []
