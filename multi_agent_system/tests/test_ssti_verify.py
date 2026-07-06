import httpx
import pytest

from multi_agent_system.utils.ssti_verify import (
    build_ssti_payloads,
    product_from_payload,
    ssti_candidates,
    verify_ssti_evaluation,
    run_ssti_probe,
)


def test_build_ssti_payloads_pairs_product_and_raw():
    payloads = build_ssti_payloads(2, 3)
    raws = {raw for _, _, raw in payloads}
    products = {prod for _, prod, _ in payloads}
    assert raws == {"2*3"}
    assert products == {"6"}
    assert "{{2*3}}" in {p for p, _, _ in payloads}
    assert "${2*3}" in {p for p, _, _ in payloads}
    assert "<%= 2*3 %>" in {p for p, _, _ in payloads}


def test_product_from_payload_parses_expression():
    assert product_from_payload("{{7919*6997}}") == ("55409243", "7919*6997")
    assert product_from_payload("${7919 * 6997}") == ("55409243", "7919*6997")


def test_product_from_payload_returns_none_without_math():
    assert product_from_payload("{{config.items()}}") is None
    assert product_from_payload("plain") is None


def test_ssti_candidates_skips_wildcards_and_paramless():
    endpoints = [
        {"url": "https://x/a?id=1", "params": ["id"]},
        {"url": "https://x/*/b?*", "params": ["q"]},
        {"url": "https://x/c", "params": []},
        {"url": "https://x/d?q=1", "query_parameters": {"q": "1"}},
    ]
    assert ssti_candidates(endpoints) == [
        ("https://x/a?id=1", "id"),
        ("https://x/d?q=1", "q"),
    ]


def test_ssti_candidates_never_fabricates_q():
    assert ssti_candidates([{"url": "https://x/c"}]) == []


def test_ssti_candidates_respects_cap():
    endpoints = [{"url": f"https://x/a{i}?id=1", "params": ["id"]} for i in range(20)]
    assert len(ssti_candidates(endpoints, cap=15)) == 15


def test_verify_confirms_evaluated_expression():
    assert verify_ssti_evaluation(
        "baseline body no marker", "result is 55409243 here", "55409243", "7919*6997"
    ) is True


def test_verify_rejects_when_product_absent():
    assert verify_ssti_evaluation("base", "nothing here", "55409243", "7919*6997") is False


def test_verify_rejects_baseline_collision():
    assert verify_ssti_evaluation(
        "id 55409243 already", "id 55409243 already", "55409243", "7919*6997"
    ) is False


def test_verify_rejects_reflected_raw_expression():
    assert verify_ssti_evaluation(
        "base", "7919*6997 = 55409243", "55409243", "7919*6997"
    ) is False


def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_run_ssti_probe_confirms_on_evaluation():
    def handler(request):
        val = request.url.params.get("id", "")
        if "*" in val:  # payload contains the expression
            return httpx.Response(200, text="output 55409243 done")
        return httpx.Response(200, text="baseline output")

    payloads = build_ssti_payloads(7919, 6997)
    async with _mock_client(handler) as client:
        confirmed = await run_ssti_probe(
            client, [("https://x/a?id=1", "id")], payloads, marker="rajabc123"
        )
    assert len(confirmed) == 1
    assert confirmed[0]["product"] == "55409243"


async def test_run_ssti_probe_rejects_reflection():
    def handler(request):
        val = request.url.params.get("id", "")
        return httpx.Response(200, text=f"you searched for {val}")

    payloads = build_ssti_payloads(7919, 6997)
    async with _mock_client(handler) as client:
        confirmed = await run_ssti_probe(
            client, [("https://x/a?id=1", "id")], payloads, marker="rajabc123"
        )
    assert confirmed == []


def test_job164_wildcard_inventory_yields_no_candidates():
    # Exact shape of the agoda job-164 route inventory: all wildcard patterns.
    endpoints = [
        {"url": "https://www.agoda.com/*/activities/detail?*", "params": ["q"]},
        {"url": "https://www.agoda.com/*/trips?", "params": ["q"]},
        {"url": "https://www.agoda.com/*/home?", "params": ["q"]},
        {"url": "https://www.agoda.com/*-*/place/*?", "params": ["q"]},
        {"url": "https://www.agoda.com/activities/detail?*", "params": ["q"]},
    ]
    assert ssti_candidates(endpoints) == []
