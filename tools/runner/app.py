"""Internal tool runner API for the `tools` service (BSD 11).

    GET  /health                 proxy status and tool versions (no authentication)
    POST /run                    run one tool for one task, wait for the result
    POST /run/{run_id}/cancel    stop a running tool (pause and cancel in the worker)

/run and /cancel require `Authorization: Bearer <TOOLS_TOKEN>`. Every target is checked against
the scope sent with the request before the tool starts, and the tool itself can only reach the
network through the egress proxy, which checks scope again.
"""

import asyncio
import os
import re
import secrets
import shutil
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from rajdoll.core.scope import in_scope
from tools.runner.adapters import Adapter, AdapterError, RunContext, default_adapters
from tools.runner.executor import Executor, tool_environment

RUNNER_VERSION = "1.0.0.dev0"
MAX_RAW_OUTPUT = 200_000
_VERSION = re.compile(r"v?(\d+\.\d+\.\d+)")


@dataclass
class RunnerConfig:
    token: str = field(default_factory=lambda: os.environ.get("RAJDOLL_TOOLS_TOKEN", ""))
    proxy_port: int = field(
        default_factory=lambda: int(os.environ.get("RAJDOLL_PROXY_PORT", "8081"))
    )
    bin_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("RAJDOLL_TOOL_BIN_DIR", "/opt/tools/bin"))
    )
    template_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("RAJDOLL_TEMPLATE_DIR", "/opt/rajdoll-templates")
        )
    )
    tool_home: Path = field(
        default_factory=lambda: Path(os.environ.get("RAJDOLL_TOOL_HOME", "/data/home"))
    )
    work_root: Path | None = None


class RunRequest(BaseModel):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")
    task_id: int = Field(ge=1)
    scan_id: int = Field(ge=1)
    tool: str = Field(pattern=r"^[a-z0-9_-]{1,40}$")
    timeout_s: int = Field(default=600, ge=1, le=7200)
    scope: list[str] = Field(min_length=1)
    params: dict[str, Any] = {}


def proxy_listening(port: int | None = None, timeout: float = 1.0) -> bool:
    port = port or int(os.environ.get("RAJDOLL_PROXY_PORT", "8081"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def create_app(
    config: RunnerConfig | None = None, adapters: dict[str, Adapter] | None = None
) -> FastAPI:
    cfg = config or RunnerConfig()
    tools = adapters if adapters is not None else default_adapters()
    executor = Executor()
    versions: dict[str, str] = {}
    app = FastAPI(
        title="RAJDOLL tools runner",
        version=RUNNER_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.executor = executor

    def authorize(authorization: str | None) -> None:
        if not cfg.token:
            raise HTTPException(503, "runner token not configured")
        expected = f"Bearer {cfg.token}"
        if not authorization or not secrets.compare_digest(authorization, expected):
            raise HTTPException(401, "invalid runner token")

    async def tool_versions() -> dict[str, str]:
        if versions:
            return versions
        for name, adapter in tools.items():
            argv = adapter.version_command(cfg.bin_dir)
            if not Path(argv[0]).exists():
                versions[name] = "missing"
                continue
            cfg.tool_home.mkdir(parents=True, exist_ok=True)
            result = await executor.run(
                f"version-{name}",
                argv,
                cwd=cfg.tool_home,
                env=tool_environment(cfg.bin_dir, cfg.tool_home),
                timeout_s=30,
            )
            match = _VERSION.search(result.stdout + result.stderr_tail)
            versions[name] = match.group(1) if match else "unknown"
        return versions

    @app.get("/health")
    async def health() -> JSONResponse:
        proxy_ok = proxy_listening(cfg.proxy_port)
        body = {
            "status": "ok" if proxy_ok else "degraded",
            "service": "tools",
            "version": RUNNER_VERSION,
            "proxy": "listening" if proxy_ok else "down",
            "tools": await tool_versions(),
        }
        return JSONResponse(body, status_code=200 if proxy_ok else 503)

    @app.post("/run")
    async def run(
        request: RunRequest, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        authorize(authorization)
        adapter = tools.get(request.tool)
        if adapter is None:
            raise HTTPException(422, f"unknown tool {request.tool!r}")
        try:
            params = adapter.Params.model_validate(request.params)
        except ValidationError as exc:
            # No input or context in the errors: header values may carry session cookies.
            errors = exc.errors(include_url=False, include_context=False, include_input=False)
            return JSONResponse({"detail": errors}, status_code=422)

        outside = sorted(
            {
                urlsplit(url).hostname or url
                for url in adapter.targets(params)
                if not in_scope(request.scope, urlsplit(url).hostname)
            }
        )
        base = {"run_id": request.run_id, "tool": request.tool}
        if outside:
            return JSONResponse({**base, "status": "scope_rejected", "out_of_scope": outside})

        cfg.tool_home.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="run-", dir=cfg.work_root))
        username = f"task.{request.task_id}.{request.tool}"
        ctx = RunContext(
            proxy_url=f"http://{username}:{quote(cfg.token, safe='')}@127.0.0.1:{cfg.proxy_port}",
            workdir=workdir,
            bin_dir=cfg.bin_dir,
            template_dir=cfg.template_dir,
        )
        try:
            try:
                argv = adapter.command(params, ctx)
            except AdapterError as exc:
                return JSONResponse({"detail": str(exc)}, status_code=422)
            result = await executor.run(
                request.run_id,
                argv,
                cwd=workdir,
                env=tool_environment(cfg.bin_dir, cfg.tool_home),
                timeout_s=request.timeout_s,
            )
            try:
                normalized = await asyncio.to_thread(adapter.parse, ctx, result.stdout)
                parse_error = None
            except Exception as exc:  # noqa: BLE001 (a parser bug must not lose the raw output)
                normalized, parse_error = {}, f"{type(exc).__name__}: {exc}"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        raw = result.stdout
        return JSONResponse(
            {
                **base,
                "status": result.status,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "normalized": normalized,
                "parse_error": parse_error,
                "raw_output": raw[:MAX_RAW_OUTPUT],
                "raw_truncated": result.stdout_truncated or len(raw) > MAX_RAW_OUTPUT,
                "stderr_tail": result.stderr_tail[-4000:],
            }
        )

    @app.post("/run/{run_id}/cancel")
    async def cancel(run_id: str, authorization: str | None = Header(default=None)) -> dict:
        authorize(authorization)
        if not executor.cancel(run_id):
            raise HTTPException(404, "no such running tool")
        return {"run_id": run_id, "cancelled": True}

    return app


app = create_app()
