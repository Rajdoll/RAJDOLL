from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Optional

import httpx


class JSBundleAnalyzer:
    """Extract SPA routes and JS dependencies from JavaScript bundles.

    Target-agnostic: pattern matching is per framework (Angular/React/Vue),
    not per application. Dependency CVE check uses OSV.dev API.
    """

    CACHE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS osv_cache (
        package TEXT NOT NULL,
        version TEXT NOT NULL,
        advisories_json TEXT NOT NULL,
        fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (package, version)
    );
    """

    def __init__(self, cache_path: Optional[Path] = None):
        default_path = Path("multi_agent_system/data/osv_cache.db")
        self.cache_path = Path(cache_path) if cache_path else default_path
        self._init_db()

    _ROUTE_PATTERN = re.compile(
        r"""['"]?path['"]?\s*:\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    # ES module imports: import X from 'lib'; import { Y } from 'lib';
    _IMPORT_PATTERN = re.compile(
        r"""import\s+(?:[\w*${}\s,]+\s+from\s+)?['"]([@\w/-]+)['"]""",
    )
    # Webpack chunk paths: ./node_modules/<lib>/...
    _WEBPACK_PATTERN = re.compile(r"node_modules/([@\w-]+)(?:/|/[\w-]+/)")

    def _init_db(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.cache_path) as conn:
            conn.executescript(self.CACHE_SCHEMA)

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

    def _extract_dependencies(self, js_source: str) -> list[dict]:
        names: set[str] = set()
        for m in self._IMPORT_PATTERN.findall(js_source):
            if m.startswith("."):
                continue   # relative import, not a dep
            names.add(m.split("/")[0] if not m.startswith("@") else "/".join(m.split("/")[:2]))
        for m in self._WEBPACK_PATTERN.findall(js_source):
            names.add(m)
        return [{"name": n, "version": None, "advisories": []} for n in sorted(names)]
