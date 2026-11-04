import asyncio
from multi_agent_system.core.config import settings
from multi_agent_system.adjudication.runner import run_adjudication

class _Agent:
    def __init__(self, verdict):
        self.findings = []
        outer = self
        class _C:
            async def adjudicate_response(self, art): return verdict
        self._llm_client = _C()
    def add_finding(self, category, title, severity="info", evidence=None, details=None):
        self.findings.append({"category": category, "evidence": evidence or {}})
    def log(self, *a, **k): pass

def test_authz_artifact_list_yields_idor_finding(monkeypatch):
    monkeypatch.setattr(settings, "enable_llm_adjudication", True, raising=False)
    monkeypatch.setattr(settings, "adjudication_max_per_agent", 15, raising=False)
    monkeypatch.setattr(settings, "adjudication_min_confidence", 0.7, raising=False)
    # Two artifacts collected from authorization tool results: one IDOR, one benign 403
    artifacts = [
        dict(tool="authz", wstg="WSTG-ATHZ-04", method="GET", url="http://t/api/user/1",
             role="user:2", status=200, headers_subset={}, body='{"id":1,"owner":1,"email":"a@x"}',
             baseline_status=200),
        dict(tool="authz", wstg="WSTG-ATHZ-04", method="GET", url="http://t/api/user/9",
             role="user:2", status=403, headers_subset={}, body="forbidden", baseline_status=200),
    ]
    agent = _Agent({"verdict": "vulnerable", "vuln_class": "WSTG-ATHZ-04",
                    "evidence_span": '"owner":1', "reason": "user:2 received owner 1 data", "confidence": 0.88})
    n = asyncio.get_event_loop().run_until_complete(run_adjudication(agent, artifacts))
    assert n == 1
    assert agent.findings[0]["category"] == "WSTG-ATHZ-04"
    assert agent.findings[0]["evidence"]["source"] == "llm-adjudicated"
