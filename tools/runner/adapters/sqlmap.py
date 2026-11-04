"""sqlmap: SQL injection detection on one parameter (TRD 4.3, 6.3).

Detection only: no enumeration, dumping, file or OS access options are exposed. The parameter is
marked with sqlmap's custom injection marker (`*`) instead of `-p`, because `-p` reads a
parameter named like an HTTP header (`host`, `referer`) as that header.
"""

import json
import re
from pathlib import Path
from typing import Any

from pydantic import Field

from tools.runner.adapters.base import Adapter, BaseParams, RunContext
from tools.runner.adapters.browser import proxy_settings
from tools.runner.adapters.request import InjectionParams, injected_value, mark

_TECHNIQUES = r"^[BEUST]{1,5}$"


class SqlmapParams(InjectionParams, BaseParams):
    level: int = Field(default=1, ge=1, le=3)
    # Risk 3 adds OR-based payloads that can change data in UPDATE statements: never offered.
    risk: int = Field(default=1, ge=1, le=2)
    techniques: str = Field(default="BEUST", pattern=_TECHNIQUES)
    time_sec: int = Field(default=5, ge=1, le=15)
    timeout_s: int = Field(default=15, ge=1, le=60)
    # Only run the full test set when sqlmap's heuristics are positive (much faster).
    smart: bool = True


def parse_log(text: str) -> list[dict[str, Any]]:
    """Injection points from sqlmap's `log` file (the block it also prints at the end)."""
    points: list[dict[str, Any]] = []
    dbms = None
    match = re.search(r"^back-end DBMS: (.+)$", text, re.M)
    if match:
        dbms = match.group(1).strip()
    place = None
    current: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Parameter:"):
            place = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Type:"):
            current = {"place": place, "technique": stripped.split(":", 1)[1].strip()}
        elif stripped.startswith("Title:") and current:
            current["title"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Payload:") and current:
            current["payload"] = line.split("Payload:", 1)[1].strip()
            current["dbms"] = dbms
            points.append(current)
            current = {}
    return points


class SqlmapAdapter(Adapter):
    name = "sqlmap"
    binary = "sqlmap"
    Params = SqlmapParams

    def targets(self, params: SqlmapParams) -> list[str]:  # type: ignore[override]
        return [params.request.url]

    def command(self, params: SqlmapParams, ctx: RunContext) -> list[str]:  # type: ignore[override]
        marked = mark(params.request, params.parameter, params.location, "*")
        (ctx.workdir / "marked.json").write_text(marked.model_dump_json(), encoding="utf-8")
        proxy = proxy_settings(ctx.proxy_url)
        argv = [
            str(ctx.bin_dir / self.binary),
            "-u", marked.url,
            "--method", params.request.method,
            "--batch", "--disable-coloring", "--skip-waf",
            "--level", str(params.level),
            "--risk", str(params.risk),
            "--technique", params.techniques,
            "--time-sec", str(params.time_sec),
            "--timeout", str(params.timeout_s),
            "--retries", "1",
            "--threads", "1",
            "--output-dir", str(ctx.workdir / "out"),
            "--proxy", proxy["server"],
            "--proxy-cred", f"{proxy['username']}:{proxy['password']}",
        ]  # fmt: skip
        if marked.data is not None:
            argv += ["--data", marked.data]
        if params.smart:
            argv.append("--smart")
        if params.headers:
            argv += ["--headers", "\n".join(f"{k}: {v}" for k, v in params.headers.items())]
        return argv

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:  # type: ignore[override]
        marked_path = Path(ctx.workdir) / "marked.json"
        marked = json.loads(marked_path.read_text()) if marked_path.exists() else {}
        logs = sorted((Path(ctx.workdir) / "out").glob("*/log"))
        points = parse_log(logs[0].read_text(errors="replace")) if logs else []
        for point in points:
            point["value"] = injected_value(marked, point["payload"]) if marked else None
        return {"candidates": points}

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "--version"]
