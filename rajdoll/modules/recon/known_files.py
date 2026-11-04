"""robots.txt and sitemap.xml: paths the site lists about itself."""

from __future__ import annotations

import re
from urllib.parse import urljoin

MAX_TEXT = 1_000_000
MAX_URLS = 500
_RULE = re.compile(r"^\s*(?:dis)?allow\s*:\s*(\S+)", re.I | re.M)
_SITEMAP = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.I | re.M)
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def robots_paths(text: str) -> tuple[list[str], list[str]]:
    """(paths from Allow/Disallow without wildcards, sitemap URLs)."""
    text = text[:MAX_TEXT]
    paths = []
    for path in _RULE.findall(text):
        path = path.split("#")[0].rstrip("$")
        if path.startswith("/") and path != "/" and "*" not in path and path not in paths:
            paths.append(path)
    return paths[:MAX_URLS], _SITEMAP.findall(text)[:20]


def sitemap_urls(text: str, base: str) -> list[str]:
    return [urljoin(base, loc) for loc in _LOC.findall(text[:MAX_TEXT])][:MAX_URLS]
