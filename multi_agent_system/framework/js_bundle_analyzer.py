from __future__ import annotations

import re
from typing import Optional

import httpx


class JSBundleAnalyzer:
    """Extract SPA routes from JavaScript bundles.

    Target-agnostic: pattern matching is per framework (Angular/React/Vue).
    """

    _ROUTE_PATTERN = re.compile(
        r"""['"]?path['"]?\s*:\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    _SCRIPT_SRC_PATTERN = re.compile(
        r"""<script[^>]+src=['"]([^'"]+\.js)['"]""", re.IGNORECASE,
    )

    def __init__(self, cache_path: Optional[object] = None):
        pass  # cache_path kept for backward compat with injection code

    def _extract_routes(self, js_source: str, source_file: str) -> list[dict]:
        matches = self._ROUTE_PATTERN.findall(js_source)
        routes: list[dict] = []
        for raw_path in matches:
            normalized = raw_path if raw_path.startswith("/") else "/" + raw_path
            if "RouterModule.forRoot" in js_source or "provideRouter" in js_source:
                framework = "angular"
            elif "createBrowserRouter" in js_source or "<Route " in js_source:
                framework = "react"
            elif "createRouter" in js_source and "vue-router" in js_source:
                framework = "vue"
            else:
                framework = "unknown"
            routes.append({"path": normalized, "framework": framework,
                           "source_file": source_file})
        seen = set()
        unique: list[dict] = []
        for r in routes:
            if r["path"] in seen:
                continue
            seen.add(r["path"])
            unique.append(r)
        return unique

    async def analyze(self, target: str, http_client: httpx.AsyncClient) -> dict:
        """Fetch homepage, extract JS bundles, find SPA routes.

        Returns {"routes": [...]}. Empty for non-SPA targets.
        """
        from urllib.parse import urljoin
        try:
            resp = await http_client.get(target, timeout=10)
            html = resp.text
        except (httpx.RequestError, httpx.HTTPStatusError):
            return {"routes": []}

        all_routes: list[dict] = []
        for raw in self._SCRIPT_SRC_PATTERN.findall(html):
            src_url = urljoin(target, raw)
            try:
                js_resp = await http_client.get(src_url, timeout=15)
                all_routes.extend(self._extract_routes(js_resp.text, source_file=src_url))
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue

        return {"routes": all_routes}
