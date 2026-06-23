import asyncio
from multi_agent_system.core.config import settings
from multi_agent_system.adjudication.runner import run_adjudication

class _Stub:
    def __init__(self, verdict):
        self._verdict = verdict
        self.findings = []
        outer = self
        class _C:
            async def adjudicate_response(self, art): return outer._verdict
        self._llm_client = _C()
    def add_finding(self, category, title, severity="info", evidence=None, details=None):
        self.findings.append({"category": category, "evidence": evidence or {}})
    def log(self, *a, **k): pass

_ATHZ = dict(tool="authz", wstg="WSTG-ATHZ-04", method="GET", url="http://t/api/user/1",
             role="user:2", status=200, headers_subset={}, body='{"owner:1"}', baseline_status=200)

def _run(coro): return asyncio.get_event_loop().run_until_complete(coro)

def test_emits_finding_when_flag_on_and_guards_pass(monkeypatch):
    monkeypatch.setattr(settings, "enable_llm_adjudication", True, raising=False)
    monkeypatch.setattr(settings, "adjudication_max_per_agent", 15, raising=False)
    monkeypatch.setattr(settings, "adjudication_min_confidence", 0.7, raising=False)
    agent = _Stub({"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04",
                   "evidence_span": "owner:1", "reason": "cross-user", "confidence": 0.9})
    n = _run(run_adjudication(agent, [dict(_ATHZ)]))
    assert n == 1
    assert agent.findings[0]["evidence"]["source"] == "llm-adjudicated"

def test_no_op_when_flag_off(monkeypatch):
    monkeypatch.setattr(settings, "enable_llm_adjudication", False, raising=False)
    agent = _Stub({"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04",
                   "evidence_span": "owner:1", "reason": "x", "confidence": 0.9})
    assert _run(run_adjudication(agent, [dict(_ATHZ)])) == 0
    assert agent.findings == []

def test_drops_when_guard_fails(monkeypatch):
    monkeypatch.setattr(settings, "enable_llm_adjudication", True, raising=False)
    monkeypatch.setattr(settings, "adjudication_max_per_agent", 15, raising=False)
    monkeypatch.setattr(settings, "adjudication_min_confidence", 0.7, raising=False)
    agent = _Stub({"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04",
                   "evidence_span": "NOT-IN-BODY", "reason": "x", "confidence": 0.9})
    assert _run(run_adjudication(agent, [dict(_ATHZ)])) == 0

def test_respects_per_agent_cap(monkeypatch):
    monkeypatch.setattr(settings, "enable_llm_adjudication", True, raising=False)
    monkeypatch.setattr(settings, "adjudication_max_per_agent", 1, raising=False)
    monkeypatch.setattr(settings, "adjudication_min_confidence", 0.7, raising=False)
    agent = _Stub({"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04",
                   "evidence_span": "owner:1", "reason": "x", "confidence": 0.9})
    n = _run(run_adjudication(agent, [dict(_ATHZ), dict(_ATHZ), dict(_ATHZ)]))
    assert n == 1
