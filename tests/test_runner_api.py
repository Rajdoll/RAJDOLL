"""Runner API with a fake adapter that runs small Python scripts (no security tools needed)."""

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi.testclient import TestClient
from pydantic import Field, field_validator

from tools.runner.adapters.base import Adapter, BaseParams, RunContext, http_url
from tools.runner.app import RunnerConfig, create_app

TOKEN = "runner-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

SCRIPTS = {
    "ok": "import json,os; print(json.dumps({'cwd': os.getcwd(), 'env': sorted(os.environ)}))",
    "fail": "import sys; print('bad'); sys.exit(3)",
    "sleep": "import time; time.sleep(30)",
    "spam": "import sys; sys.stdout.write('x' * 2_500_000)",
    "badjson": "print('not json')",
}


class FakeParams(BaseParams):
    urls: list[str] = Field(min_length=1)
    mode: str = "ok"

    @field_validator("urls")
    @classmethod
    def _urls(cls, value: list[str]) -> list[str]:
        return [http_url(u) for u in value]


class FakeAdapter(Adapter):
    name = "fake"
    binary = "python"
    Params = FakeParams
    contexts: ClassVar[list[RunContext]] = []

    def targets(self, params: FakeParams) -> list[str]:
        return params.urls

    def command(self, params: FakeParams, ctx: RunContext) -> list[str]:
        FakeAdapter.contexts.append(ctx)
        return [sys.executable, "-c", SCRIPTS[params.mode]]

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        return {"echo": json.loads(stdout)}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("HTTPS_PROXY", "http://should-not-leak:1")
    FakeAdapter.contexts.clear()
    config = RunnerConfig(
        token=TOKEN,
        proxy_port=8081,
        bin_dir=tmp_path / "bin",
        template_dir=tmp_path / "templates",
        tool_home=tmp_path / "home",
        work_root=tmp_path,
    )
    return TestClient(create_app(config, {"fake": FakeAdapter()}))


def _run(client: TestClient, mode: str = "ok", **overrides: Any) -> Any:
    body = {
        "run_id": f"run-{mode}-{time.monotonic_ns()}",
        "task_id": 7,
        "scan_id": 3,
        "tool": "fake",
        "timeout_s": 20,
        "scope": ["testapp"],
        "params": {"urls": ["http://testapp:8080/"], "mode": mode},
    }
    body.update(overrides)
    return client.post("/run", json=body, headers=AUTH)


def test_token_is_required(client: TestClient, tmp_path: Path) -> None:
    body = {"run_id": "run-12345678", "task_id": 1, "scan_id": 1, "tool": "fake", "scope": ["x"]}
    assert client.post("/run", json=body).status_code == 401
    assert client.post("/run", json=body, headers={"Authorization": "Bearer no"}).status_code == 401
    unconfigured = TestClient(create_app(RunnerConfig(token="", work_root=tmp_path), {}))
    assert unconfigured.post("/run", json=body, headers=AUTH).status_code == 503


def test_unknown_tool_and_bad_params(client: TestClient) -> None:
    assert _run(client, tool="nmap").status_code == 422
    bad = _run(client, params={"urls": ["file:///etc/passwd"]})
    assert bad.status_code == 422
    secret = _run(client, params={"urls": ["http://testapp/"], "headers": {"Cookie": "sid=\nX"}})
    assert secret.status_code == 422
    assert "sid=" not in secret.text  # rejected values are not echoed back


def test_scope_is_checked_before_running(client: TestClient) -> None:
    response = _run(client, params={"urls": ["http://testapp/", "http://evil.example/"]})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "scope_rejected"
    assert body["out_of_scope"] == ["evil.example"]
    assert FakeAdapter.contexts == []  # the adapter was never asked to build a command


def test_completed_run(client: TestClient, tmp_path: Path) -> None:
    body = _run(client).json()
    assert body["status"] == "completed"
    assert body["exit_code"] == 0
    echo = body["normalized"]["echo"]
    # Proxy settings from the parent environment are not inherited by tools.
    assert not any("proxy" in name.lower() for name in echo["env"])
    assert set(echo["env"]) <= {"PATH", "HOME", "LANG", "LC_CTYPE", "PWD"}
    ctx = FakeAdapter.contexts[-1]
    assert ctx.proxy_url == f"http://task.7.fake:{TOKEN}@127.0.0.1:8081"
    assert echo["cwd"] == str(ctx.workdir)
    assert not ctx.workdir.exists()  # cleaned up


def test_failed_run_keeps_output(client: TestClient) -> None:
    body = _run(client, "fail").json()
    assert (body["status"], body["exit_code"]) == ("failed", 3)
    assert body["parse_error"].startswith("JSONDecodeError")
    assert body["raw_output"].strip() == "bad"


def test_timeout_kills_the_process(client: TestClient) -> None:
    started = time.monotonic()
    body = _run(client, "sleep", timeout_s=1).json()
    assert body["status"] == "timeout"
    assert time.monotonic() - started < 10


def test_output_is_capped(client: TestClient) -> None:
    body = _run(client, "spam").json()
    assert body["raw_truncated"] is True
    assert len(body["raw_output"]) <= 200_000


def test_cancel_running_tool(client: TestClient) -> None:
    run_id = "run-cancel-123456"
    result: dict[str, Any] = {}

    def start() -> None:
        result["response"] = _run(client, "sleep", run_id=run_id, timeout_s=30)

    thread = threading.Thread(target=start)
    thread.start()
    executor = client.app.state.executor
    deadline = time.monotonic() + 10
    while not executor.is_running(run_id) and time.monotonic() < deadline:
        time.sleep(0.05)
    cancelled = client.post(f"/run/{run_id}/cancel", headers=AUTH)
    assert cancelled.status_code == 200
    thread.join(timeout=15)
    assert result["response"].json()["status"] == "cancelled"
    assert client.post(f"/run/{run_id}/cancel", headers=AUTH).status_code == 404


def test_health_lists_tools(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.runner.app as runner

    monkeypatch.setattr(runner, "proxy_listening", lambda *_: True)
    body = client.get("/health").json()
    assert body["proxy"] == "listening"
    assert body["tools"] == {"fake": "missing"}  # no binary in the temporary bin dir
