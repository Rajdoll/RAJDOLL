"""commix: OS command injection detection on one parameter (TRD 4.3, 6.3).

Only the classic (results-based) and eval-based techniques are offered by default; time-based is
opt-in because it is slow, and the file-based techniques are never offered because they write
files on the target. The pseudo-terminal shell commix offers after a hit is always declined.

Proxy: commix's own `--proxy` option sends its first request directly and drops credentials, so
the adapter gives the egress proxy through `http_proxy`/`https_proxy` instead, which every
request commix makes through urllib honours (credentials included). commix bypasses proxies for
`localhost` and `127.0.0.1` targets, so those are refused.
"""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import Field, model_validator

from tools.runner.adapters.base import Adapter, BaseParams, RunContext
from tools.runner.adapters.request import InjectionParams, injected_value, mark

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


class CommixParams(InjectionParams, BaseParams):
    # c = classic results-based, e = eval-based, t = time-based. File-based (f) is never offered.
    techniques: str = Field(default="ce", pattern=r"^[cet]{1,3}$")
    level: int = Field(default=1, ge=1, le=3)
    timeout_s: int = Field(default=15, ge=1, le=60)
    time_sec: int = Field(default=1, ge=1, le=10)

    @model_validator(mode="after")
    def _not_loopback(self) -> "CommixParams":
        if (urlsplit(self.request.url).hostname or "").lower() in LOOPBACK:
            raise ValueError("commix bypasses the proxy for loopback targets")
        return self


def parse_logs(text: str) -> list[dict[str, Any]]:
    """Injection points from commix's `logs.txt`."""
    points: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in _ANSI.sub("", text).splitlines():
        stripped = line.strip()
        if stripped.startswith("[info] Type:"):
            current = {"type": stripped.split(":", 1)[1].strip()}
        elif stripped.startswith("[info] Technique:") and current:
            current["technique"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("[info] Parameter:") and current:
            current["place"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("[info] Used payload:") and current:
            current["payload"] = unquote(line.split("Used payload:", 1)[1].strip())
            points.append(current)
            current = {}
    return points


class CommixAdapter(Adapter):
    name = "commix"
    binary = "commix"
    Params = CommixParams

    def targets(self, params: CommixParams) -> list[str]:  # type: ignore[override]
        return [params.request.url]

    def command(self, params: CommixParams, ctx: RunContext) -> list[str]:  # type: ignore[override]
        marked = mark(params.request, params.parameter, params.location, "*")
        (ctx.workdir / "marked.json").write_text(marked.model_dump_json(), encoding="utf-8")
        argv = [
            str(ctx.bin_dir / self.binary),
            "--url", marked.url,
            "--batch", "--disable-coloring", "--ignore-stdin", "--skip-waf",
            "--answers", "pseudo-terminal=N,non-custom=N",
            "--technique", params.techniques,
            "--level", str(params.level),
            "--timeout", str(params.timeout_s),
            "--time-sec", str(params.time_sec),
            "--retries", "1",
            "--output-dir", str(ctx.workdir / "out"),
        ]  # fmt: skip
        if params.headers:
            argv += ["--headers", "\n".join(f"{k}: {v}" for k, v in params.headers.items())]
        if params.request.method != "GET" or marked.data is not None:
            argv += ["--method", params.request.method]
        if marked.data is not None:
            argv += ["--data", marked.data]
        return argv

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:  # type: ignore[override]
        marked_path = Path(ctx.workdir) / "marked.json"
        marked = json.loads(marked_path.read_text()) if marked_path.exists() else {}
        logs = sorted((Path(ctx.workdir) / "out").glob("*/logs.txt"))
        points = parse_logs(logs[0].read_text(errors="replace")) if logs else []
        for point in points:
            # commix logs only the parameter's value, not the whole marked string.
            point["value"] = point["payload"]
            if marked and injected_value(marked, point["payload"]) is not None:
                point["value"] = injected_value(marked, point["payload"])
        return {"candidates": points}

    def environment(self, params: CommixParams, ctx: RunContext) -> dict[str, str]:  # type: ignore[override]
        return {"http_proxy": ctx.proxy_url, "https_proxy": ctx.proxy_url, "no_proxy": ""}

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "--version", "--ignore-stdin"]
