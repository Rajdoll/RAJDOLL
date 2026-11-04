"""The VA report in Markdown (TRD 11, PRD F-32/F-33): accepted findings only.

Target content (evidence) is placed inside fenced code blocks whose fence is longer than any
backtick run in the content, so a response cannot close the block and inject Markdown; table
cells escape `|` and line breaks. The HTML preview renders with raw HTML disabled.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markdown_it import MarkdownIt

TEMPLATES = Path(__file__).parent / "templates"
EVIDENCE_CHARS = 3000
SEVERITY_NAMES = {
    "critical": "Kritis",
    "high": "Tinggi",
    "medium": "Sedang",
    "low": "Rendah",
    "info": "Info",
}
WIB = timezone(timedelta(hours=7), "WIB")  # reports show WIB (BSD 1); no daylight saving


def wib(moment: datetime, fmt: str) -> str:
    return moment.astimezone(WIB).strftime(fmt)


def cell(value: Any) -> str:
    """Text safe inside a Markdown table cell."""
    return re.sub(r"\s*[\r\n]+\s*", " ", str(value)).replace("|", "\\|")


def fenced(text: str, language: str = "") -> str:
    """`text` in a code fence longer than any backtick run inside it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    body = text.replace("\r\n", "\n").rstrip("\n")
    return f"{fence}{language}\n{body}\n{fence}"


def clip(text: str | None, limit: int = EVIDENCE_CHARS) -> tuple[str | None, bool]:
    if text is None or len(text) <= limit:
        return text, False
    return text[:limit], True


# Markdown, not HTML: no autoescaping. The preview renders with raw HTML disabled.
_env = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=False,  # noqa: S701
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)
_env.filters["cell"] = cell
_env.filters["fenced"] = fenced

_markdown = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


def render(context: dict[str, Any]) -> str:
    text = _env.get_template("va.md.j2").render(context)
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def to_html(markdown: str) -> str:
    """Preview HTML; raw HTML in the Markdown is escaped, not rendered."""
    return _markdown.render(markdown)
