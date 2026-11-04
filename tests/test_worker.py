"""Worker process wiring and the runner client (no database needed)."""

import json

import httpx
import pytest

from rajdoll.core.config import Settings
from rajdoll.core.db import listen_dsn
from rajdoll.modules.base import TransientTaskError
from rajdoll.worker.main import build_engine
from rajdoll.worker.tools_client import ToolsClient


def test_listen_dsn_drops_the_sqlalchemy_driver() -> None:
    url = "postgresql+psycopg://rajdoll_app:p%40ss@db:5432/rajdoll"
    assert listen_dsn(url) == "postgresql://rajdoll_app:p%40ss@db:5432/rajdoll"


def test_build_engine_uses_settings(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        secrets_dir=str(tmp_path),
        worker_lease_seconds=30,
        worker_max_parallel=3,
        session_check_seconds=120,
    )
    engine = build_engine(settings)
    try:
        assert engine.lease.total_seconds() == 30
        assert engine.max_parallel == 3
        assert engine.session_check_seconds == 120
        assert engine.check_account is not None
        assert engine.listen_dsn == "postgresql://rajdoll_app@db:5432/rajdoll"
        assert "information_gathering" in engine.modules
    finally:
        engine.shutdown(grace_seconds=0)


def _client(handler) -> ToolsClient:
    return ToolsClient("http://tools:9000", "s3cret", transport=httpx.MockTransport(handler))


def test_run_posts_the_runner_contract() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"run_id": "r" * 8, "status": "completed"})

    result = _client(handler).run(
        "r" * 8,
        task_id=7,
        scan_id=3,
        tool="httpx",
        params={"urls": ["https://app.test/"]},
        scope=["app.test"],
        timeout_s=300,
    )
    assert result["status"] == "completed"
    request = seen[0]
    assert request.url == "http://tools:9000/run"
    assert request.headers["Authorization"] == "Bearer s3cret"
    assert json.loads(request.content) == {
        "run_id": "r" * 8,
        "task_id": 7,
        "scan_id": 3,
        "tool": "httpx",
        "params": {"urls": ["https://app.test/"]},
        "scope": ["app.test"],
        "timeout_s": 300,
    }


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx.ConnectError("refused"), TransientTaskError),
        (httpx.Response(503, text="busy"), TransientTaskError),
        (httpx.Response(422, text="bad params"), RuntimeError),
    ],
)
def test_run_errors(response, error) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        if isinstance(response, Exception):
            raise response
        return response

    with pytest.raises(error):
        _client(handler).run(
            "r" * 8, task_id=1, scan_id=1, tool="httpx", params={}, scope=["a"], timeout_s=5
        )


@pytest.mark.parametrize(("status", "expected"), [(200, True), (404, False)])
def test_cancel(status: int, expected: bool) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/run/abcdefgh/cancel"
        return httpx.Response(status, json={})

    assert _client(handler).cancel("abcdefgh") is expected


def test_cancel_when_runner_is_unreachable() -> None:
    def unreachable(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    assert _client(unreachable).cancel("abcdefgh") is False


def test_client_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    client = ToolsClient("http://tools:9000", "t")
    assert client._client.trust_env is False
    client.close()
