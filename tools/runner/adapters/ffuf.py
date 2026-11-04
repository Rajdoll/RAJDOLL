"""ffuf: directory fuzzing and parameter discovery with bundled wordlists (TRD 4.3)."""

import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field, field_validator

from tools.runner.adapters.base import (
    Adapter,
    AdapterError,
    BaseParams,
    RunContext,
    header_args,
    http_url,
    write_lines,
)

_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,8}$")
_WORD = re.compile(r"^[A-Za-z0-9_./-]{1,64}$")
WORDLISTS = {"directories": "directories.txt", "parameters": "parameters.txt"}
# A value unlikely to exist in the application, sent for every candidate parameter.
PARAM_VALUE = "rajdoll1"


class FfufParams(BaseParams):
    url: str
    mode: Literal["directory", "parameter"] = "directory"
    wordlist: Literal["directories", "parameters"] = "directories"
    extensions: list[str] = Field(default=[], max_length=10)
    match_codes: list[int] = Field(
        default=[200, 204, 301, 302, 307, 308, 401, 403, 405], min_length=1, max_length=20
    )
    threads: int = Field(default=5, ge=1, le=40)
    rate_limit: int = Field(default=10, ge=1, le=500)
    timeout_s: int = Field(default=10, ge=1, le=60)
    max_time_s: int = Field(default=600, ge=10, le=3600)
    # Words containing these fragments are never requested (logout and other state changes).
    exclude: list[str] = Field(default=[], max_length=50)

    @field_validator("exclude")
    @classmethod
    def _exclude(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _WORD.match(item):
                raise ValueError(f"invalid exclusion {item!r}")
        return [item.lower() for item in value]

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        value = http_url(value)
        if "FUZZ" in value:
            raise ValueError("the adapter places FUZZ itself")
        return value

    @field_validator("extensions")
    @classmethod
    def _extensions(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _EXTENSION.match(item):
                raise ValueError(f"invalid extension {item!r}")
        return value

    @field_validator("match_codes")
    @classmethod
    def _codes(cls, value: list[int]) -> list[int]:
        if any(not 100 <= code <= 599 for code in value):
            raise ValueError("status codes must be between 100 and 599")
        return value


def fuzz_url(params: FfufParams) -> str:
    if params.mode == "directory":
        parts = urlsplit(params.url)
        return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}/FUZZ"
    separator = "&" if "?" in params.url else "?"
    return f"{params.url}{separator}FUZZ={PARAM_VALUE}"


class FfufAdapter(Adapter):
    name = "ffuf"
    binary = "ffuf"
    Params = FfufParams

    def targets(self, params: FfufParams) -> list[str]:
        return [params.url]

    def command(self, params: FfufParams, ctx: RunContext) -> list[str]:
        wordlist = ctx.wordlist_dir / WORDLISTS[params.wordlist]
        if not wordlist.is_file():
            raise AdapterError(f"wordlist {params.wordlist} is not installed")
        if params.exclude:
            words = wordlist.read_text(encoding="utf-8").splitlines()
            kept = [w for w in words if not any(e in w.lower() for e in params.exclude)]
            wordlist = write_lines(ctx.workdir / "wordlist.txt", kept)
        argv = [
            str(ctx.bin_dir / self.binary),
            "-u", fuzz_url(params),
            "-w", str(wordlist),
            "-of", "json",
            "-o", str(ctx.workdir / "out.json"),
            "-s", "-noninteractive",
            "-ac",  # auto-calibration filters the application's own "not found" answers
            "-mc", ",".join(str(code) for code in params.match_codes),
            "-t", str(params.threads),
            "-rate", str(params.rate_limit),
            "-timeout", str(params.timeout_s),
            "-maxtime", str(params.max_time_s),
            "-x", ctx.proxy_url,
        ]  # fmt: skip
        if params.extensions and params.mode == "directory":
            argv += ["-e", ",".join(params.extensions)]
        return argv + header_args(params.headers)

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        import json

        path = ctx.workdir / "out.json"
        if not path.exists():
            return {"results": []}
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace") or "{}")
        except json.JSONDecodeError:
            return {"results": []}
        results = []
        for row in data.get("results") or []:
            # Use `url`, not `input.FUZZ`: with auto-calibration ffuf 2.2.1 can report a
            # calibration string as the input of a real result.
            url = row.get("url")
            if not url:
                continue
            item = {
                "url": url,
                "status": row.get("status"),
                "length": row.get("length"),
                "words": row.get("words"),
                "lines": row.get("lines"),
                "content_type": row.get("content-type") or None,
                "redirect": row.get("redirectlocation") or None,
            }
            query = dict(parse_qsl(urlsplit(url).query))
            param = next((k for k, v in query.items() if v == PARAM_VALUE), None)
            if param:
                item["param"] = param
            results.append(item)
        return {"results": results}

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "-V"]
