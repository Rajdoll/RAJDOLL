from unittest.mock import MagicMock

from multi_agent_system.framework.payload_synthesizer import PayloadSynthesizer
from multi_agent_system.framework.types import EndpointSpec, Payload


def test_base_agent_generate_payloads_uses_synthesizer(tmp_path):
    """When payload_synth is provided, BaseAgent.generate_payloads delegates to it."""
    from multi_agent_system.agents.base_agent import BaseAgent

    fake_synth = MagicMock(spec=PayloadSynthesizer)
    fake_synth.enabled = True
    fake_synth.synthesize.return_value = [
        Payload(value="P1", encoding="raw", expected_signal="x", category="ssti")
    ]
    agent = BaseAgent.__new__(BaseAgent)  # bypass full __init__; framework-only test
    agent.payload_synth = fake_synth
    agent._shared_context_snapshot = {"tech_stack": {"framework": "express"}, "recon_summary": {}}

    ep = EndpointSpec(url="http://x/api", method="POST")
    result = agent.generate_payloads("ssti", ep, n=1)
    assert len(result) == 1
    assert result[0].value == "P1"
    fake_synth.synthesize.assert_called_once()


def test_base_agent_generate_payloads_falls_back_when_disabled():
    from multi_agent_system.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.payload_synth = None
    agent._shared_context_snapshot = {}

    ep = EndpointSpec(url="http://x/api", method="POST")
    result = agent.generate_payloads("ssti", ep, n=1)
    # Without synth, returns legacy/empty list — caller must use existing hardcoded path
    assert result == []
