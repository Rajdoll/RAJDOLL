from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .types import EndpointSpec, Payload


class PayloadSynthesizer:
    """Generate attack payloads from cache, LLM, or wordlist fallback.

    Target-agnostic: cache key is (attack_class, tech_stack) hash — never the
    target hostname.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS payload_cache (
        cache_key TEXT PRIMARY KEY,
        attack_class TEXT NOT NULL,
        tech_stack_json TEXT NOT NULL,
        payloads_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """

    def __init__(self, llm_client: Any, pattern_db_path: Path, enabled: bool = True):
        self.llm_client = llm_client
        self.pattern_db_path = Path(pattern_db_path)
        self.enabled = enabled
        self._init_db()

    def _init_db(self) -> None:
        self.pattern_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.pattern_db_path) as conn:
            conn.executescript(self.SCHEMA)

    def _cache_key(self, attack_class: str, tech_stack: dict) -> str:
        canonical_stack = json.dumps(tech_stack, sort_keys=True)
        material = f"{attack_class}||{canonical_stack}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _cache_read(self, attack_class: str, tech_stack: dict) -> list[Payload]:
        key = self._cache_key(attack_class, tech_stack)
        with sqlite3.connect(self.pattern_db_path) as conn:
            row = conn.execute(
                "SELECT payloads_json FROM payload_cache WHERE cache_key = ?", (key,)
            ).fetchone()
        if row is None:
            return []
        return [Payload(**p) for p in json.loads(row[0])]

    def _cache_write(self, attack_class: str, tech_stack: dict, payloads: list[Payload]) -> None:
        key = self._cache_key(attack_class, tech_stack)
        payloads_json = json.dumps([p.__dict__ for p in payloads])
        with sqlite3.connect(self.pattern_db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO payload_cache "
                "(cache_key, attack_class, tech_stack_json, payloads_json) "
                "VALUES (?, ?, ?, ?)",
                (key, attack_class, json.dumps(tech_stack, sort_keys=True), payloads_json),
            )
