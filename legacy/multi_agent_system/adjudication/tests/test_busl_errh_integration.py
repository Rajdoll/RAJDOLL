import asyncio
from multi_agent_system.core.config import settings
from multi_agent_system.adjudication.runner import run_adjudication

class _Agent:
    def __init__(self, verdict):
        self.findings = []
        class _C:
            async def adjudicate_response(self, art): return verdict
        self._llm_client = _C()
    def add_finding(self, category, title, severity="info", evidence=None, details=None):
        self.findings.append({"category": category, "evidence": evidence or {}})
    def log(self, *a, **k): pass

def _on(monkeypatch):
    monkeypatch.setattr(settings, "enable_llm_adjudication", True, raising=False)
    monkeypatch.setattr(settings, "adjudication_max_per_agent", 15, raising=False)
    monkeypatch.setattr(settings, "adjudication_min_confidence", 0.7, raising=False)

def test_errh_stacktrace_yields_info_leak(monkeypatch):
    _on(monkeypatch)
    art = dict(tool="errh", wstg="WSTG-ERRH-01", method="GET", url="http://t/x",
               role="anonymous", status=500, headers_subset={}, body="Traceback: /home/app/db.py line 42",
               baseline_status=200)
    agent = _Agent({"verdict": "vulnerable", "vuln_class": "WSTG-ERRH-01",
                    "evidence_span": "/home/app/db.py", "reason": "path leak", "confidence": 0.8})
    n = asyncio.get_event_loop().run_until_complete(run_adjudication(agent, [art]))
    assert n == 1 and agent.findings[0]["category"] == "WSTG-ERRH-01"

def test_busl_clean_response_no_finding(monkeypatch):
    _on(monkeypatch)
    art = dict(tool="biz", wstg="WSTG-BUSL-07", method="POST", url="http://t/order",
               role="user:2", status=200, headers_subset={}, body="ok", baseline_status=200)
    agent = _Agent({"verdict": "not_vulnerable", "vuln_class": "WSTG-BUSL-07",
                    "evidence_span": "", "reason": "nothing", "confidence": 0.2})
    n = asyncio.get_event_loop().run_until_complete(run_adjudication(agent, [art]))
    assert n == 0
