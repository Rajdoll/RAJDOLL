"""ProjectDiscovery httpx: HTTP probing and technology fingerprinting."""

from pathlib import Path
from typing import Any

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


class HttpxParams(BaseParams):
    urls: list[str] = Field(min_length=1, max_length=1000)
    follow_redirects: bool = True
    threads: int = Field(default=10, ge=1, le=50)
    timeout_s: int = Field(default=10, ge=1, le=60)

    @field_validator("urls")
    @classmethod
    def _urls(cls, value: list[str]) -> list[str]:
        return [http_url(url) for url in value]


class HttpxAdapter(Adapter):
    name = "httpx"
    binary = "httpx"
    Params = HttpxParams

    def targets(self, params: HttpxParams) -> list[str]:
        return list(params.urls)

    def command(self, params: HttpxParams, ctx: RunContext) -> list[str]:
        targets = write_lines(ctx.workdir / "targets.txt", params.urls)
        argv = [
            str(ctx.bin_dir / self.binary),
            "-l", str(targets),
            "-json",
            "-o", str(ctx.workdir / "out.jsonl"),
            "-silent", "-nc", "-duc",
            "-nfs",  # use the scheme given in the input; never probe the other one
            "-sc", "-title", "-server", "-td", "-ct", "-cl", "-location",
            "-timeout", str(params.timeout_s),
            "-retries", "1",
            "-t", str(params.threads),
            "-proxy", ctx.proxy_url,
        ]  # fmt: skip
        if params.follow_redirects:
            argv.append("-fr")
        return argv + header_args(params.headers)

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        endpoints: list[dict[str, Any]] = []
        technologies: dict[str, dict[str, Any]] = {}
        for row in read_jsonl(Path(ctx.workdir) / "out.jsonl"):
            if row.get("failed"):
                continue
            url = row.get("url") or row.get("input")
            endpoints.append(
                {
                    "url": url,
                    "input": row.get("input"),
                    "status": row.get("status_code"),
                    "title": row.get("title"),
                    "server": row.get("webserver"),
                    "content_type": row.get("content_type"),
                    "content_length": row.get("content_length"),
                    "location": row.get("location"),
                    "final_url": row.get("final_url"),
                    "redirect_chain": row.get("chain_status_codes") or [],
                }
            )
            for tech in row.get("tech") or []:
                name, _, version = str(tech).partition(":")
                key = f"{name}:{version}"
                technologies.setdefault(
                    key, {"name": name, "version": version or None, "urls": []}
                )["urls"].append(url)
        return {"endpoints": endpoints, "technologies": list(technologies.values())}
