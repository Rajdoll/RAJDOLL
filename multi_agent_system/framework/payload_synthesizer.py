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

    GENERIC_SIGNALS = {
        "ssti": "49",          # template evaluation of 7*7
        "sql_injection": "(SQL syntax|ORA-|mysql_|SQLite)",
        "ssrf": "(127\\.0\\.0\\.1|localhost|metadata)",
        "xss_dom": "<script",
        "xss_reflected": "<script",
        "jwt_manipulation": "(token|jwt)",
        "command_injection": "(uid=|root:|/bin/)",
    }

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
        try:
            return [Payload(**p) for p in json.loads(row[0])]
        except (json.JSONDecodeError, TypeError, KeyError):
            return []

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
            conn.commit()

    PROMPT_TEMPLATE = """You are a generic web security payload generator. Generate {n}
payloads for attack class "{attack_class}". The target uses these characteristics:
{tech_stack_summary}

Output strict JSON only, no commentary. Schema:
{{"payloads": [{{"value": "...", "encoding": "raw|url|base64|json|xml",
                 "expected_signal": "string or regex to look for in response body",
                 "category": "{attack_class}",
                 "engine_hypothesis": "framework/engine name or null"}}, ...]}}

Make payloads diverse (different engines/encodings). Do NOT reference any specific
application or company name."""

    OUTPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "payloads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                        "encoding": {"type": "string"},
                        "expected_signal": {"type": "string"},
                        "category": {"type": "string"},
                        "engine_hypothesis": {"type": ["string", "null"]},
                    },
                    "required": ["value", "encoding", "expected_signal", "category"],
                },
            }
        },
        "required": ["payloads"],
    }

    def _llm_synthesize(self, attack_class: str, tech_stack: dict, n: int) -> list[Payload]:
        if self.llm_client is None:
            return []
        tech_summary = ", ".join(f"{k}={v}" for k, v in sorted(tech_stack.items()))
        prompt = self.PROMPT_TEMPLATE.format(
            n=n, attack_class=attack_class, tech_stack_summary=tech_summary or "unknown"
        )
        try:
            response = self.llm_client.chat_with_schema(
                prompt=prompt, schema=self.OUTPUT_SCHEMA, timeout=60
            )
        except Exception:
            return []
        items = response.get("payloads") if isinstance(response, dict) else None
        if not isinstance(items, list):
            return []
        out: list[Payload] = []
        for item in items:
            try:
                out.append(Payload(
                    value=item["value"],
                    encoding=item["encoding"],
                    expected_signal=item["expected_signal"],
                    category=item.get("category", attack_class),
                    engine_hypothesis=item.get("engine_hypothesis"),
                ))
            except (KeyError, TypeError):
                continue
        return out

    def _wordlist_fallback(self, attack_class: str, wordlist_path, n: int) -> list[Payload]:
        from pathlib import Path as _P
        wl = _P(wordlist_path)
        if not wl.exists():
            return []
        signal = self.GENERIC_SIGNALS.get(attack_class, "")
        lines = [ln.strip() for ln in wl.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
        return [Payload(value=ln, encoding="raw", expected_signal=signal, category=attack_class)
                for ln in lines[:n]]
