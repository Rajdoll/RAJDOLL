"""Headless Chromium (Playwright) rendering for single-page applications (TRD 4.3).

Records every request the rendered pages make (including fetch/XHR calls that exist only in
JavaScript), links, and forms. Traffic goes through the egress proxy with credentials, which
headless katana cannot do.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import Field, field_validator

from tools.runner.adapters.base import Adapter, BaseParams, RunContext, http_url, read_jsonl

SCRIPT = Path(__file__).resolve().parent.parent / "browser_crawl.py"
_EXCLUDE = re.compile(r"^[A-Za-z0-9_./-]{1,64}$")


class BrowserParams(BaseParams):
    urls: list[str] = Field(min_length=1, max_length=20)
    max_pages: int = Field(default=25, ge=1, le=200)
    max_depth: int = Field(default=2, ge=0, le=5)
    page_timeout_s: int = Field(default=15, ge=1, le=120)
    settle_ms: int = Field(default=1500, ge=0, le=10000)
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


def proxy_settings(proxy_url: str) -> dict[str, str]:
    parts = urlsplit(proxy_url)
    return {
        "server": f"{parts.scheme}://{parts.hostname}:{parts.port}",
        "username": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
    }


class BrowserAdapter(Adapter):
    name = "browser"
    binary = "python"
    Params = BrowserParams

    def targets(self, params: BrowserParams) -> list[str]:
        return list(params.urls)

    def command(self, params: BrowserParams, ctx: RunContext) -> list[str]:
        config = {
            "start_urls": params.urls,
            "proxy": proxy_settings(ctx.proxy_url),
            "headers": params.headers,
            "max_pages": params.max_pages,
            "max_depth": params.max_depth,
            "page_timeout_ms": params.page_timeout_s * 1000,
            "settle_ms": params.settle_ms,
            "exclude": params.exclude,
            "out": str(ctx.workdir / "out.jsonl"),
        }
        path = ctx.workdir / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)  # holds the proxy token and the session
        return [sys.executable, str(SCRIPT), str(path)]

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        requests: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        pages, links, forms = [], [], []
        for row in read_jsonl(ctx.workdir / "out.jsonl"):
            kind = row.pop("type", None)
            if kind == "request":
                key = (row.get("method") or "GET", row.get("url") or "")
                if key not in seen:
                    seen.add(key)
                    requests.append(row)
            elif kind == "page":
                pages.append(row)
            elif kind == "link":
                links.append(row)
            elif kind == "form":
                forms.append(row)
        return {"pages": pages, "requests": requests, "links": links, "forms": forms}

    def version_command(self, bin_dir: Path) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import importlib.metadata as m; print('playwright ' + m.version('playwright'))",
        ]


_MARKER = re.compile(r"^[A-Za-z0-9_-]{4,40}$")


class XssAttempt(BaseParams):
    method: str = Field(default="GET", pattern="^(GET|POST)$")
    url: str
    form: dict[str, str] = {}

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return http_url(value)


class XssCheckParams(BaseParams):
    attempts: list[XssAttempt] = Field(min_length=1, max_length=10)
    marker: str
    page_timeout_s: int = Field(default=15, ge=1, le=60)

    @field_validator("marker")
    @classmethod
    def _marker(cls, value: str) -> str:
        if not _MARKER.match(value):
            raise ValueError("marker must be 4-40 letters, digits, - or _")
        return value


class XssCheckAdapter(BrowserAdapter):
    """XSS validator: run payloads in Chromium and watch for alert(marker) (TRD 6.3)."""

    name = "xss_check"
    Params = XssCheckParams

    def targets(self, params: XssCheckParams) -> list[str]:  # type: ignore[override]
        return [attempt.url for attempt in params.attempts]

    def command(self, params: XssCheckParams, ctx: RunContext) -> list[str]:  # type: ignore[override]
        config = {
            "mode": "xss",
            "attempts": [a.model_dump(include={"method", "url", "form"}) for a in params.attempts],
            "marker": params.marker,
            "proxy": proxy_settings(ctx.proxy_url),
            "headers": params.headers,
            "page_timeout_ms": params.page_timeout_s * 1000,
            "out": str(ctx.workdir / "out.jsonl"),
        }
        path = ctx.workdir / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        return [sys.executable, str(SCRIPT), str(path)]

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:  # type: ignore[override]
        attempts = [r for r in read_jsonl(ctx.workdir / "out.jsonl") if r.get("type") == "xss"]
        executed = next((a for a in attempts if a.get("executed")), None)
        return {
            "executed": executed is not None,
            "attempt": executed["attempt"] if executed else None,
            "dialogs": executed["dialogs"] if executed else [],
            "attempts": attempts,
        }
