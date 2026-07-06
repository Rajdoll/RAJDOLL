import httpx
import pytest

from multi_agent_system.utils.differential_verify import (
    _with_param,
    verify_differential,
    run_differential_probe,
)


def test_with_param_replaces_existing_query_value():
    assert _with_param("https://x/a?id=1", "id", "PAYLOAD") == "https://x/a?id=PAYLOAD"


def test_with_param_adds_missing_param():
    assert _with_param("https://x/a", "id", "PAYLOAD") == "https://x/a?id=PAYLOAD"


def test_verify_differential_confirms_when_signal_only_in_test():
    assert verify_differential("baseline body", "test body with SIGNAL123", "SIGNAL123") is True


def test_verify_differential_rejects_when_signal_in_baseline_too():
    assert verify_differential("body has SIGNAL123", "body has SIGNAL123", "SIGNAL123") is False


def test_verify_differential_rejects_when_raw_payload_reflected():
    assert verify_differential("baseline", "echo: RAWPAYLOAD -> SIGNAL123", "SIGNAL123", "RAWPAYLOAD") is False


def test_verify_differential_rejects_when_signal_absent():
    assert verify_differential("baseline", "nothing relevant here", "SIGNAL123") is False


def test_verify_differential_confirms_without_raw_payload_arg():
    assert verify_differential("baseline", "SIGNAL123 present", "SIGNAL123") is True


def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_run_differential_probe_confirms_on_real_signal():
    def handler(request):
        val = request.url.params.get("q", "")
        if val == "PAYLOAD":
            return httpx.Response(200, text="result: SIGNAL123")
        return httpx.Response(200, text="baseline response")

    async with _mock_client(handler) as client:
        confirmed = await run_differential_probe(
            client, [("https://x/a?q=1", "q")], [("PAYLOAD", "SIGNAL123", None)], marker="rajmark1"
        )
    assert confirmed == [{"url": "https://x/a?q=1", "parameter": "q", "payload": "PAYLOAD", "signal": "SIGNAL123"}]


async def test_run_differential_probe_rejects_reflection_only():
    def handler(request):
        val = request.url.params.get("q", "")
        return httpx.Response(200, text=f"you sent: {val}")

    async with _mock_client(handler) as client:
        confirmed = await run_differential_probe(
            client, [("https://x/a?q=1", "q")], [("PAYLOAD", "PAYLOAD", "PAYLOAD")], marker="rajmark1"
        )
    assert confirmed == []


async def test_run_differential_probe_rejects_baseline_collision():
    def handler(request):
        return httpx.Response(200, text="SIGNAL123 always present, even in baseline")

    async with _mock_client(handler) as client:
        confirmed = await run_differential_probe(
            client, [("https://x/a?q=1", "q")], [("PAYLOAD", "SIGNAL123", None)], marker="rajmark1"
        )
    assert confirmed == []
