"""dalfox: reflected XSS detection on named parameters of one request (TRD 4.3).

Parameter mining, BAV checks, remote wordlists and payloads, headless verification, and the
`--found-action` hook are never enabled: RAJDOLL verifies XSS in its own Chromium (xss_check).
"""

from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field, model_validator

from tools.runner.adapters.base import Adapter, BaseParams, RunContext, read_jsonl
from tools.runner.adapters.request import RequestSpec, build, check_parameter

MAX_RAW = 65_536


class DalfoxParams(BaseParams):
    request: RequestSpec
    parameters: list[str] = Field(min_length=1, max_length=20)
    location: Literal["query", "body"] = "query"
    workers: int = Field(default=10, ge=1, le=50)
    delay_ms: int = Field(default=0, ge=0, le=5000)
    timeout_s: int = Field(default=10, ge=1, le=60)

    @model_validator(mode="after")
    def _parameters(self) -> "DalfoxParams":
        if self.request.body_encoding == "json" and self.location == "body":
            raise ValueError("dalfox tests query and form parameters only")
        for name in self.parameters:
            check_parameter(self.request, name, self.location)
        return self


class DalfoxAdapter(Adapter):
    name = "dalfox"
    binary = "dalfox"
    Params = DalfoxParams

    def targets(self, params: DalfoxParams) -> list[str]:  # type: ignore[override]
        return [params.request.url]

    def command(self, params: DalfoxParams, ctx: RunContext) -> list[str]:  # type: ignore[override]
        url, data = build(params.request)
        argv = [
            str(ctx.bin_dir / self.binary), "url", url,
            "--skip-discovery", "--skip-bav", "--skip-mining-all", "--skip-headless",
            "--no-color", "--silence", "--format", "jsonl",
            "--output-request", "--output-response",
            "-o", str(ctx.workdir / "out.jsonl"),
            "-w", str(params.workers),
            "--delay", str(params.delay_ms),
            "--timeout", str(params.timeout_s),
            "--proxy", ctx.proxy_url,
            "-X", params.request.method,
        ]  # fmt: skip
        if data is not None:
            argv += ["-d", data]
        for name in params.parameters:
            argv += ["-p", name]
        for name, value in params.headers.items():
            argv += ["-H", f"{name}: {value}"]
        return argv

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:  # type: ignore[override]
        candidates = []
        for row in read_jsonl(Path(ctx.workdir) / "out.jsonl"):
            if row.get("type") not in ("V", "R"):  # verified DOM object or reflected payload
                continue
            candidates.append(
                {
                    "type": row["type"],
                    "parameter": row.get("param"),
                    "payload": row.get("payload"),
                    "value": _value(row.get("data") or "", row.get("param") or ""),
                    "inject_type": row.get("inject_type"),
                    "message": row.get("message_str"),
                    "cwe": row.get("cwe"),
                    "request": (row.get("raw_request") or "")[:MAX_RAW],
                    "response": (row.get("raw_response") or "")[:MAX_RAW],
                }
            )
        return {"candidates": candidates}

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "version"]


def _value(poc_url: str, parameter: str) -> str | None:
    """The parameter's value in dalfox's PoC URL (GET), if it is there."""
    for name, value in parse_qsl(urlsplit(poc_url).query, keep_blank_values=True):
        if name == parameter:
            return value
    return None
