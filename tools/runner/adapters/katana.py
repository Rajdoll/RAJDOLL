"""katana: crawling with JavaScript parsing, form extraction, and known files (TRD 4.3).

Standard (non-headless) mode only. Headless katana hands the proxy URL to Chrome with
`--proxy-server`, and Chrome ignores proxy credentials there, so every request would be refused
by the egress proxy. SPA rendering is done by the `browser` adapter (Playwright) instead.
"""

import re
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from tools.runner.adapters.base import (
    Adapter,
    BaseParams,
    RunContext,
    header_args,
    http_url,
    read_jsonl,
    write_lines,
)

# Exclusions become one regex for katana's -crawl-out-scope; keep them to safe characters.
_EXCLUDE = re.compile(r"^[A-Za-z0-9_./-]{1,64}$")


class KatanaParams(BaseParams):
    urls: list[str] = Field(min_length=1, max_length=50)
    depth: int = Field(default=3, ge=1, le=6)
    max_duration_s: int = Field(default=600, ge=10, le=3600)
    concurrency: int = Field(default=5, ge=1, le=20)
    rate_limit: int = Field(default=10, ge=1, le=500)
    timeout_s: int = Field(default=10, ge=1, le=60)
    js_crawl: bool = True
    known_files: bool = True
    # Path fragments never requested (logout and other state-destroying links).
    exclude: list[str] = Field(default=[], max_length=50)

    @field_validator("urls")
    @classmethod
    def _urls(cls, value: list[str]) -> list[str]:
        return [http_url(url) for url in value]

    @field_validator("exclude")
    @classmethod
    def _exclude(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _EXCLUDE.match(item):
                raise ValueError(f"invalid exclusion {item!r}")
        return value


class KatanaAdapter(Adapter):
    name = "katana"
    binary = "katana"
    Params = KatanaParams

    def targets(self, params: KatanaParams) -> list[str]:
        return list(params.urls)

    def command(self, params: KatanaParams, ctx: RunContext) -> list[str]:
        targets = write_lines(ctx.workdir / "targets.txt", params.urls)
        argv = [
            str(ctx.bin_dir / self.binary),
            "-list", str(targets),
            "-jsonl",
            "-o", str(ctx.workdir / "out.jsonl"),
            "-silent", "-nc", "-duc",
            "-or", "-ob",  # omit raw requests/responses and bodies from the output
            "-fx",  # form extraction
            "-fs", "fqdn",  # stay on the given hosts; the proxy enforces scope anyway
            "-d", str(params.depth),
            "-ct", str(params.max_duration_s),
            "-c", str(params.concurrency),
            "-rl", str(params.rate_limit),
            "-timeout", str(params.timeout_s),
            "-retry", "1",
            "-proxy", ctx.proxy_url,
        ]  # fmt: skip
        if params.js_crawl:
            argv.append("-jc")
        if params.known_files and params.depth >= 3:
            argv += ["-kf", "all"]
        if params.exclude:
            argv += ["-cos", "(?i)(" + "|".join(re.escape(e) for e in params.exclude) + ")"]
        return argv + header_args(params.headers)

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        endpoints: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        seen_forms: set[tuple[str, str]] = set()
        for row in read_jsonl(ctx.workdir / "out.jsonl"):
            request = row.get("request") or {}
            response = row.get("response") or {}
            url = request.get("endpoint")
            if not url or not urlsplit(url).hostname:
                continue
            headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
            endpoints.append(
                {
                    "method": (request.get("method") or "GET").upper(),
                    "url": url,
                    "status": response.get("status_code"),
                    "content_type": headers.get("content-type"),
                    "source": request.get("source"),
                    "tag": request.get("tag"),
                }
            )
            for form in response.get("forms") or []:
                action = form.get("action") or url
                method = (form.get("method") or "GET").upper()
                if (method, action) in seen_forms:
                    continue
                seen_forms.add((method, action))
                forms.append(
                    {
                        "method": method,
                        "url": action,
                        "enctype": form.get("enctype"),
                        "params": [p for p in form.get("parameters") or [] if p],
                        "page": url,
                    }
                )
        return {"endpoints": endpoints, "forms": forms}
