"""nuclei: template-based checks, including DAST (fuzzing) templates (TRD 4.3)."""

import json
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from tools.runner.adapters.base import (
    Adapter,
    AdapterError,
    BaseParams,
    RunContext,
    header_args,
    http_url,
    read_jsonl,
    write_lines,
)
from tools.runner.adapters.request import RequestSpec, build

_TEMPLATE = re.compile(r"^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_EVIDENCE_CHARS = 65_536

Severity = Literal["info", "low", "medium", "high", "critical"]


class NucleiParams(BaseParams):
    targets: list[str] = Field(default=[], max_length=500)
    # DAST input as whole requests (GET or with a body) instead of URLs; exclusive with targets.
    requests: list[RequestSpec] = Field(default=[], max_length=500)
    templates: list[str] = Field(default=["rajdoll"], min_length=1, max_length=100)
    tags: list[str] = Field(default=[], max_length=50)
    severities: list[Severity] = []
    rate_limit: int = Field(default=50, ge=1, le=500)
    concurrency: int = Field(default=10, ge=1, le=50)
    timeout_s: int = Field(default=10, ge=1, le=60)
    follow_redirects: bool = False
    dast: bool = False
    oob: bool = False  # interactsh sends data to a public server; off by default (TRD D-08)

    @field_validator("targets")
    @classmethod
    def _targets(cls, value: list[str]) -> list[str]:
        return [http_url(url) for url in value]

    @model_validator(mode="after")
    def _input(self) -> "NucleiParams":
        if bool(self.targets) == bool(self.requests):
            raise ValueError("give either targets or requests")
        return self

    @field_validator("templates")
    @classmethod
    def _templates(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _TEMPLATE.match(item) or ".." in item:
                raise ValueError(f"invalid template path {item!r}")
        return value

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _TAG.match(item):
                raise ValueError(f"invalid tag {item!r}")
        return value


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_EVIDENCE_CHARS:
        return value[:MAX_EVIDENCE_CHARS]
    return value


def _proxify(request: RequestSpec) -> dict[str, Any]:
    """A request in the jsonl input format nuclei reads with `-im jsonl` (proxify)."""
    url, data = build(request)
    parts = urlsplit(url)
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    lines = [f"{request.method} {target} HTTP/1.1", f"Host: {parts.netloc}"]
    if data is not None:
        kind = (
            "application/json"
            if request.body_encoding == "json"
            else ("application/x-www-form-urlencoded")
        )
        lines += [f"Content-Type: {kind}", f"Content-Length: {len(data.encode())}"]
    return {"url": url, "request": {"raw": "\r\n".join(lines) + "\r\n\r\n" + (data or "")}}


def _relative(path: str | None, root: Path) -> str | None:
    """A template's path relative to the template directory (as the `templates` param names it)."""
    if not path:
        return None
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return path


class NucleiAdapter(Adapter):
    name = "nuclei"
    binary = "nuclei"
    Params = NucleiParams

    def targets(self, params: NucleiParams) -> list[str]:
        return list(params.targets) or [request.url for request in params.requests]

    def _template_paths(self, params: NucleiParams, root: Path) -> list[str]:
        paths = []
        resolved_root = root.resolve()
        for item in params.templates:
            path = (root / item).resolve()
            if resolved_root not in (path, *path.parents) or not path.exists():
                raise AdapterError(f"template not found: {item}")
            paths.append(str(path))
        return paths

    def command(self, params: NucleiParams, ctx: RunContext) -> list[str]:
        if params.requests:
            source = ctx.workdir / "requests.jsonl"
            source.write_text(
                "".join(json.dumps(_proxify(r)) + "\n" for r in params.requests), encoding="utf-8"
            )
            inputs = ["-l", str(source), "-im", "jsonl"]
        else:
            inputs = ["-l", str(write_lines(ctx.workdir / "targets.txt", params.targets))]
        argv = [
            str(ctx.bin_dir / self.binary),
            *inputs,
            "-jsonl",
            "-o", str(ctx.workdir / "out.jsonl"),
            "-silent", "-nc", "-duc", "-ot",
            "-timeout", str(params.timeout_s),
            "-retries", "1",
            "-rl", str(params.rate_limit),
            "-c", str(params.concurrency),
            "-proxy", ctx.proxy_url,
        ]  # fmt: skip
        for path in self._template_paths(params, ctx.template_dir):
            argv += ["-t", path]
        if params.tags:
            argv += ["-tags", ",".join(params.tags)]
        if params.severities:
            argv += ["-s", ",".join(params.severities)]
        if not params.oob:
            argv.append("-ni")
        if params.dast:
            # nuclei skips a parameter after 10 templates found nothing in it, so which template
            # sees it depends on scheduling; an assessment must try every template on every one.
            argv += ["-dast", "-fuzz-param-frequency", "1000000"]
        if params.follow_redirects:
            argv.append("-fr")
        return argv + header_args(params.headers)

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        candidates = []
        for row in read_jsonl(Path(ctx.workdir) / "out.jsonl"):
            info = row.get("info") or {}
            classification = info.get("classification") or {}
            candidates.append(
                {
                    "template_id": row.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "tags": info.get("tags") or [],
                    "description": info.get("description"),
                    "remediation": info.get("remediation"),
                    "cwe_ids": [c.upper() for c in classification.get("cwe-id") or []],
                    "references": info.get("reference") or [],
                    "type": row.get("type"),
                    "url": row.get("url"),
                    "matched_at": row.get("matched-at"),
                    "host": row.get("host"),
                    "matcher_name": row.get("matcher-name"),
                    "extracted": row.get("extracted-results") or [],
                    "fuzzing_parameter": row.get("fuzzing_parameter"),
                    "fuzzing_position": row.get("fuzzing_position"),
                    "fuzzing_method": row.get("fuzzing_method"),
                    "template_path": _relative(row.get("template-path"), ctx.template_dir),
                    "request": _truncate(row.get("request")),
                    "response": _truncate(row.get("response")),
                    "curl": row.get("curl-command"),
                }
            )
        return {"candidates": candidates}
