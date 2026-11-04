from unittest.mock import AsyncMock

import pytest

from multi_agent_system.agents.modules.param_miner import (
    score_endpoint,
    confirm_param,
    mine_params,
)


def test_score_endpoint_prefers_auth_json_200():
    assert score_endpoint({
        "auth_required": True,
        "response_signature": {"status": 200, "content_type": "application/json"},
    }) > score_endpoint({
        "auth_required": False,
        "response_signature": {"status": 200, "content_type": "text/html"},
    })


@pytest.mark.asyncio
async def test_confirm_param_requires_3_consistent_trials():
    http = AsyncMock()
    http.get = AsyncMock(side_effect=[
        AsyncMock(status_code=200, text="A", headers={}),
        AsyncMock(status_code=200, text="B", headers={}),
        AsyncMock(status_code=200, text="B", headers={}),
        AsyncMock(status_code=200, text="B", headers={}),
    ])
    confirmed = await confirm_param(http, url="https://x/y", param="hidden")
    assert confirmed is True


@pytest.mark.asyncio
async def test_confirm_param_rejects_inconsistent_trials():
    http = AsyncMock()
    http.get = AsyncMock(side_effect=[
        AsyncMock(status_code=200, text="A", headers={}),
        AsyncMock(status_code=200, text="B", headers={}),
        AsyncMock(status_code=200, text="C", headers={}),
        AsyncMock(status_code=200, text="B", headers={}),
    ])
    confirmed = await confirm_param(http, url="https://x/y", param="noisy")
    assert confirmed is False


@pytest.mark.asyncio
async def test_mine_params_attaches_discovered_params(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("foo\nbar\n")
    http = AsyncMock()
    seq = [
        AsyncMock(status_code=200, text="X", headers={}),  # baseline foo
        AsyncMock(status_code=200, text="Y", headers={}),
        AsyncMock(status_code=200, text="Y", headers={}),
        AsyncMock(status_code=200, text="Y", headers={}),
        AsyncMock(status_code=200, text="X", headers={}),  # baseline bar
        AsyncMock(status_code=200, text="X", headers={}),  # bar same as baseline -> not confirmed
    ]
    http.get = AsyncMock(side_effect=seq)
    eps = [{"id": "ep_1", "path": "https://x/api/x", "method": "GET", "auth_required": True,
            "response_signature": {"status": 200, "content_type": "application/json"}}]
    out = await mine_params(http, eps, wordlist=wordlist, top_n=1, rate_per_sec=100)
    assert out[0]["discovered_params"] == ["foo"]
