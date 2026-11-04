# multi_agent_system/tests/test_endpoint_classification.py
"""Recon endpoint inventory builder test (post-LLM-classification)."""
from unittest.mock import AsyncMock

import pytest

from multi_agent_system.agents.reconnaissance_agent import build_endpoint_inventory


@pytest.mark.asyncio
async def test_build_endpoint_inventory_assigns_ids_and_calls_classifier():
    classifier = AsyncMock()
    classifier.classify = AsyncMock(side_effect=lambda host, eps: [
        {**ep, "tags": ["api_generic"], "tag_confidence": {"api_generic": 0.9}} for ep in eps
    ])
    raw_eps = [
        {"path": "/api/x", "method": "GET", "discovered_by": "R1_passive"},
        {"path": "/api/y", "method": "POST", "discovered_by": "R3_ffuf"},
    ]
    inv = await build_endpoint_inventory(
        hostname="example.com",
        endpoints=raw_eps,
        classifier=classifier,
        captured_ids={},
        phase_stats={"R1": 1, "R3": 1},
    )
    assert inv["version"] == 2
    assert inv["stats"]["total_endpoints"] == 2
    assert all(ep["id"].startswith("ep_") for ep in inv["endpoints"])
    assert inv["by_tag"]["api_generic"] == [ep["id"] for ep in inv["endpoints"]]
    classifier.classify.assert_awaited_once()
