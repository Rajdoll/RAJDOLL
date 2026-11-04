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


def test_tools_health() -> None:
    response = TestClient(tools_app).get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "tools"
