import importlib.util
from pathlib import Path

from multi_agent_system.agents.weak_crypto_agent import WeakCryptographyAgent


def _load_weak_crypto_tool():
    path = Path(__file__).resolve().parents[2] / "weak-cryptography-testing" / "weak-cryptography.py"
    spec = importlib.util.spec_from_file_location("weak_cryptography_tool", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


LOW_ENTROPY_TOKENS = ["AAAAAAAAAA"] * 10


async def test_tool_reports_is_low_entropy_not_weak_randomness():
    # Documents the tool's real contract: it returns "is_low_entropy", never "weak_randomness".
    module = _load_weak_crypto_tool()
    result = await module.analyze_token_randomness(LOW_ENTROPY_TOKENS)
    data = result["data"]

    assert data["is_low_entropy"] is True
    assert "weak_randomness" not in data


def _agent():
    a = WeakCryptographyAgent.__new__(WeakCryptographyAgent)
    a.log = lambda *args, **kw: None
    a.log_tool_execution_plan = lambda: None
    a.get_auth_session = lambda: None
    a._get_target = lambda: "https://example.com"
    a._shared_context_snapshot = {"session_tokens": LOW_ENTROPY_TOKENS, "endpoint_inventory": {}}
    a.should_run_tool = lambda name: name == "analyze_token_randomness"
    a.findings = []
    a.add_finding = lambda *args, **kw: a.findings.append((args, kw))
    return a


async def test_weak_token_randomness_finding_fires_on_low_entropy_tokens():
    agent = _agent()

    await agent.run()

    assert any(
        args and args[0] == "WSTG-CRYP"
        for args, kw in agent.findings
    ), f"expected a WSTG-CRYP weak-randomness finding, got: {agent.findings}"
