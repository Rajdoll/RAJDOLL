"""Adapter contract: typed parameters in, argv out, normalized results back (TRD 4.1).

Adapters never build shell strings. Every value that reaches argv has been validated by the
adapter's pydantic model, and targets are scope-checked by the runner before anything runs.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
MAX_HEADER_VALUE = 8192


class AdapterError(ValueError):
    """Invalid input that the pydantic model could not express (for example a missing template)."""


@dataclass(frozen=True)
class RunContext:
    proxy_url: str
    workdir: Path
    bin_dir: Path
    template_dir: Path
    wordlist_dir: Path = Path("/opt/rajdoll-wordlists")


def http_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http(s) URL with a host")
    if any(ord(ch) < 0x21 for ch in value):
        raise ValueError("must not contain whitespace or control characters")
    return value


class BaseParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    headers: dict[str, str] = {}

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header_value in value.items():
            if not _HEADER_NAME.match(name):
                raise ValueError(f"invalid header name {name!r}")
            if len(header_value) > MAX_HEADER_VALUE or any(
                ord(ch) < 0x20 or ord(ch) == 0x7F for ch in header_value
            ):
                raise ValueError(f"invalid value for header {name}")
        return value


def header_args(headers: dict[str, str]) -> list[str]:
    args: list[str] = []
    for name, value in headers.items():
        args += ["-H", f"{name}: {value}"]
    return args


def write_lines(path: Path, lines: list[str]) -> Path:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    import json

    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


class Adapter(ABC):
    name: ClassVar[str]
    binary: ClassVar[str]
    Params: ClassVar[type[BaseParams]]
    # Non-HTTP tools bypass the egress proxy; the runner then writes one audit row per run.
    audit_exec: ClassVar[bool] = False
    # How to find the version in the version command's output (default: first x.y.z).
    version_pattern: ClassVar["re.Pattern[str] | None"] = None

    def audit_summary(self, params: Any) -> str:
        """What the audit row records as `url` for a non-HTTP run."""
        return self.name

    @abstractmethod
    def targets(self, params: Any) -> list[str]:
        """URLs the run will contact; the runner checks each host against the scope."""

    @abstractmethod
    def command(self, params: Any, ctx: RunContext) -> list[str]:
        """Write input files into ctx.workdir and return argv (no shell)."""

    @abstractmethod
    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        """Turn the tool's output into the normalized shape of BSD 11."""

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "-version"]
