import pytest
from fastapi.testclient import TestClient

from rajdoll import __version__
from rajdoll.api.app import app as api_app
from tools.runner.app import app as tools_app


def test_api_health() -> None:
    response = TestClient(api_app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "api", "version": __version__}


def test_api_does_not_expose_interactive_docs() -> None:
    client = TestClient(api_app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_tools_health_reports_proxy_state(monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.runner.app as runner

    monkeypatch.setattr(runner, "proxy_listening", lambda *_: True)
    ok = TestClient(tools_app).get("/health")
    assert ok.status_code == 200
    assert ok.json()["proxy"] == "listening"

    monkeypatch.setattr(runner, "proxy_listening", lambda *_: False)
    down = TestClient(tools_app).get("/health")
    assert down.status_code == 503  # unhealthy container keeps the worker from starting
    assert down.json()["proxy"] == "down"
