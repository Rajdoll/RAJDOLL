"""Extract API URLs from JS source maps (.js.map)."""
from __future__ import annotations

import re

URL_RE = re.compile(r"['\"](/(?:api|rest|v\d+)/[A-Za-z0-9/_\-{}.]+)['\"]")


def extract_urls_from_sourcemap(sourcemap: dict) -> list[str]:
    urls: set[str] = set()
    contents = sourcemap.get("sourcesContent") or []
    for src in contents:
        if not isinstance(src, str):
            continue
        for m in URL_RE.finditer(src):
            urls.add(m.group(1))
    return sorted(urls)
