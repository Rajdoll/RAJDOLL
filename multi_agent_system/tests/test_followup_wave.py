from multi_agent_system.core.config import Settings


def test_adaptive_reorder_defaults_off(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_REORDER", raising=False)
    assert Settings().adaptive_reorder is False


def test_adaptive_reorder_reads_env(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_REORDER", "true")
    assert Settings().adaptive_reorder is True


def test_max_followup_probes_default(monkeypatch):
    monkeypatch.delenv("MAX_FOLLOWUP_PROBES", raising=False)
    assert Settings().max_followup_probes == 4


import asyncio
from unittest.mock import AsyncMock
from multi_agent_system.utils.simple_llm_client import SimpleLLMClient


def _bare_client():
    return SimpleLLMClient.__new__(SimpleLLMClient)


def test_followup_probes_parses_and_filters():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value=(
        '{"probes": ['
        '{"agent": "ClientSideAgent", "focus": "test XSS on /rest/products q=", "reason": "sqli surface"},'
        '{"agent": "UnknownAgent", "focus": "x", "reason": "y"}'
        ']}'
    ))
    out = asyncio.run(c.propose_followup_probes(
        analysis="SQLi confirmed at /rest/products",
        findings_summary="...",
        available_agents=["ClientSideAgent", "InputValidationAgent"]))
    assert out == [{"agent": "ClientSideAgent",
                    "focus": "test XSS on /rest/products q=",
                    "reason": "sqli surface"}]


def test_followup_probes_empty_on_unparseable():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value="no json here")
    out = asyncio.run(c.propose_followup_probes(
        analysis="x", findings_summary="y", available_agents=["A"]))
    assert out == []


def test_followup_probes_empty_when_no_available_agents():
    c = _bare_client()
    c.chat_completion = AsyncMock(return_value='{"probes": [{"agent": "A", "focus": "f", "reason": "r"}]}')
    out = asyncio.run(c.propose_followup_probes(
        analysis="x", findings_summary="y", available_agents=[]))
    assert out == []


from unittest.mock import MagicMock, AsyncMock, patch
from multi_agent_system.orchestrator import Orchestrator


def _wave_orch(probes):
    orch = Orchestrator.__new__(Orchestrator)
    orch.cumulative_summary = "SQLi at /rest/products"
    orch.context_manager = MagicMock()
    orch.context_manager.read.return_value = "final analysis text"
    from multi_agent_system.utils.orchestrator_directive import OrchestratorDirective
    orch._accumulated_directive = OrchestratorDirective()
    summarizer = MagicMock()
    summarizer.propose_followup_probes = AsyncMock(return_value=probes)
    return orch, summarizer


def test_wave_noop_when_flag_off():
    orch, summarizer = _wave_orch([{"agent": "ClientSideAgent", "focus": "f", "reason": "r"}])
    ran = MagicMock()
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_run_agent_sync", ran), \
         patch.object(Orchestrator, "_run_final_analysis", MagicMock()):
        s.adaptive_replan = False
        orch._run_followup_wave()
    ran.assert_not_called()


def test_wave_runs_each_probe_then_reanalyzes():
    import asyncio
    probes = [
        {"agent": "ClientSideAgent", "focus": "xss on q", "reason": "sqli surface"},
        {"agent": "InputValidationAgent", "focus": "ssti on q", "reason": "sqli surface"},
    ]
    orch, summarizer = _wave_orch(probes)
    ran = MagicMock()
    final = MagicMock()
    loop = asyncio.new_event_loop()
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_followup_available_agents",
                      return_value=["ClientSideAgent", "InputValidationAgent"]), \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop", return_value=loop), \
         patch.object(Orchestrator, "_run_agent_sync", ran), \
         patch.object(Orchestrator, "_run_final_analysis", final):
        s.adaptive_replan = True
        s.max_followup_probes = 4
        orch._run_followup_wave()
    loop.close()
    assert [c.args[0] for c in ran.call_args_list] == ["ClientSideAgent", "InputValidationAgent"]
    final.assert_called_once()


def test_wave_caps_probe_count():
    import asyncio
    probes = [{"agent": "ClientSideAgent", "focus": f"f{i}", "reason": "r"} for i in range(5)]
    orch, summarizer = _wave_orch(probes)
    ran = MagicMock()
    loop = asyncio.new_event_loop()
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_followup_available_agents",
                      return_value=["ClientSideAgent"]), \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop", return_value=loop), \
         patch.object(Orchestrator, "_run_agent_sync", ran), \
         patch.object(Orchestrator, "_run_final_analysis", MagicMock()):
        s.adaptive_replan = True
        s.max_followup_probes = 2
        orch._run_followup_wave()
    loop.close()
    assert ran.call_count == 2


def test_wave_one_probe_failure_does_not_stop_others():
    import asyncio
    probes = [
        {"agent": "ClientSideAgent", "focus": "a", "reason": "r"},
        {"agent": "InputValidationAgent", "focus": "b", "reason": "r"},
    ]
    orch, summarizer = _wave_orch(probes)
    final = MagicMock()
    def run_side(agent, *a, **k):
        if agent == "ClientSideAgent":
            raise RuntimeError("boom")
    loop = asyncio.new_event_loop()
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_followup_available_agents",
                      return_value=["ClientSideAgent", "InputValidationAgent"]), \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop", return_value=loop), \
         patch.object(Orchestrator, "_run_agent_sync", side_effect=run_side) as ran, \
         patch.object(Orchestrator, "_run_final_analysis", final):
        s.adaptive_replan = True
        s.max_followup_probes = 4
        orch._run_followup_wave()
    loop.close()
    assert ran.call_count == 2
    final.assert_called_once()


def test_followup_available_agents_excludes_recon_report():
    orch = Orchestrator.__new__(Orchestrator)
    orch.job_id = 1
    rows = [MagicMock(agent_name=n) for n in
            ["ClientSideAgent", "InputValidationAgent", "ReconnaissanceAgent", "ReportGenerationAgent"]]
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = rows
    cm = MagicMock()
    cm.__enter__.return_value = db
    cm.__exit__.return_value = False
    with patch("multi_agent_system.orchestrator.get_db", return_value=cm):
        out = orch._followup_available_agents()
    assert out == ["ClientSideAgent", "InputValidationAgent"]


def test_wave_skips_agent_not_completed_this_scan():
    import asyncio
    probes = [
        {"agent": "ClientSideAgent", "focus": "xss", "reason": "r"},
        {"agent": "FileUploadAgent", "focus": "upload", "reason": "r"},  # never completed this scan
    ]
    orch, summarizer = _wave_orch(probes)
    ran = MagicMock()
    loop = asyncio.new_event_loop()
    with patch("multi_agent_system.orchestrator.settings") as s, \
         patch.object(Orchestrator, "_followup_available_agents",
                      return_value=["ClientSideAgent"]), \
         patch.object(Orchestrator, "_get_llm_summarizer", return_value=summarizer), \
         patch.object(Orchestrator, "_ensure_event_loop", return_value=loop), \
         patch.object(Orchestrator, "_run_agent_sync", ran), \
         patch.object(Orchestrator, "_run_final_analysis", MagicMock()):
        s.adaptive_replan = True
        s.max_followup_probes = 4
        orch._run_followup_wave()
    loop.close()
    assert [c.args[0] for c in ran.call_args_list] == ["ClientSideAgent"]
