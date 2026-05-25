from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_client(monkeypatch, fake_findings):
    import api.routes.scan_evaluation as se
    monkeypatch.setattr(se, "get_job_findings", lambda job_id: fake_findings)
    app = FastAPI()
    app.include_router(se.router, prefix="/api")
    return TestClient(app)


def test_evaluation_endpoint_returns_summary_and_rows(monkeypatch):
    fake = [
        {"category": "WSTG-INPV-05", "title": "SQLi", "severity": "critical", "agent_name": "A"},
    ]
    client = _make_client(monkeypatch, fake)
    resp = client.get("/api/scans/123/evaluation?target_profile=juiceshop")
    assert resp.status_code == 200
    body = resp.json()
    assert body["job_id"] == 123
    assert body["target_profile"] == "juiceshop"
    assert body["summary"]["total_gt"] == 57
    assert len(body["ground_truth_rows"]) == 57
    assert any(r["wstg"] == "WSTG-INPV-05" and r["status"] == "TP"
               for r in body["ground_truth_rows"])


def test_evaluation_endpoint_unknown_profile_404(monkeypatch):
    client = _make_client(monkeypatch, [])
    resp = client.get("/api/scans/1/evaluation?target_profile=nope")
    assert resp.status_code == 404
