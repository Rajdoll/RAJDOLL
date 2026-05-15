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

    def _init_db(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.cache_path) as conn:
            conn.executescript(self.CACHE_SCHEMA)
