# multi_agent_system/utils/endpoint_classifier.py
"""LLM-driven endpoint classifier.

Sends endpoints in batches to LM Studio (Qwen 3-4B), validates output
against the taxonomy, and caches per (hostname, path, method,
response_signature_hash) on disk.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from multi_agent_system.core.endpoint_inventory import TAXONOMY

log = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 7 * 24 * 3600
CONFIDENCE_THRESHOLD = 0.5

PROMPT_PATH = Path(__file__).parent / "prompts" / "endpoint_classification.txt"


def _signature_hash(ep: dict) -> str:
    sig = ep.get("response_signature") or {}
    blob = json.dumps(
        {
            "status": sig.get("status"),
            "content_type": sig.get("content_type"),
            "sample_keys": sorted(sig.get("sample_keys") or []),
        },
        sort_keys=True,
    )
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def cache_key(hostname: str, ep: dict) -> str:
    blob = f"{hostname}|{ep.get('path', '')}|{ep.get('method', '')}|{_signature_hash(ep)}"
    return hashlib.sha256(blob.encode()).hexdigest()


class LLMEndpointClassifier:
    def __init__(
        self,
        llm_client,
        cache_path: Path | str,
        batch_size: int = 30,
        max_batches: int = 3,
        per_batch_timeout: float = 60.0,
    ):
        self.llm = llm_client
        self.cache_path = Path(cache_path)
        self.batch_size = batch_size
        self.max_batches = max_batches
        self.timeout = per_batch_timeout
        self._cache: dict[str, dict] = self._load_cache()

    def _load_cache(self) -> dict[str, dict]:
        if not self.cache_path.exists():
            return {}
        try:
            data = json.loads(self.cache_path.read_text())
            now = time.time()
            return {
                k: v for k, v in data.items()
                if now - v.get("cached_at", 0) <= CACHE_TTL_SECONDS
            }
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self._cache))

    async def classify(self, hostname: str, endpoints: list[dict]) -> list[dict]:
        prompt_template = PROMPT_PATH.read_text()
        results: dict[str, dict] = {}
        to_classify: list[tuple] = []

        # Apply cache
        for ep in endpoints:
            key = cache_key(hostname, ep)
            cached = self._cache.get(key)
            if cached:
                results[ep["id"]] = {"tags": cached["tags"], "confidence": cached.get("confidence", {})}
            else:
                to_classify.append((key, ep))

        # Priority: auth_required first, fresh first
        to_classify.sort(key=lambda kv: (not kv[1].get("auth_required"), kv[1].get("id")))
        budget = self.max_batches * self.batch_size
        if len(to_classify) > budget:
            log.info("classifier: %d endpoints exceed budget %d, dropping %d",
                     len(to_classify), budget, len(to_classify) - budget)
            to_classify = to_classify[:budget]

        # Batch
        for batch_start in range(0, len(to_classify), self.batch_size):
            batch = to_classify[batch_start: batch_start + self.batch_size]
            keys = [k for k, _ in batch]
            eps = [e for _, e in batch]
            try:
                tagged = await self._classify_batch(prompt_template, eps)
            except Exception as exc:  # batch isolation
                log.warning("classifier: batch failed (%s), retrying with size %d",
                            exc, max(1, self.batch_size // 2))
                try:
                    half = max(1, len(eps) // 2)
                    a = await self._classify_batch(prompt_template, eps[:half])
                    b = await self._classify_batch(prompt_template, eps[half:])
                    tagged = {**a, **b}
                except Exception as exc2:
                    log.error("classifier: batch retry failed (%s); skipping", exc2)
                    tagged = {}

            now = time.time()
            for key, ep in zip(keys, eps):
                tags_data = tagged.get(ep["id"], {"tags": [], "confidence": {}})
                results[ep["id"]] = tags_data
                self._cache[key] = {**tags_data, "cached_at": now}

        self._save_cache()

        # Apply tags back to endpoint records, preserving order
        out: list[dict] = []
        for ep in endpoints:
            tags_data = results.get(ep["id"], {"tags": [], "confidence": {}})
            new_ep = dict(ep)
            new_ep["tags"] = tags_data["tags"]
            new_ep["tag_confidence"] = tags_data["confidence"]
            # Also write back to original so callers checking original dicts see tags
            ep["tags"] = new_ep["tags"]
            ep["tag_confidence"] = new_ep["tag_confidence"]
            out.append(new_ep)
        return out

    async def _classify_batch(self, prompt_template: str, eps: list[dict]) -> dict[str, dict]:
        endpoint_payload = json.dumps([
            {k: ep.get(k) for k in ("id", "path", "method", "auth_required", "discovered_by", "response_signature")}
            for ep in eps
        ])
        prompt = prompt_template.replace("{endpoints_json}", endpoint_payload)
        messages = [{"role": "user", "content": prompt}]

        schema = {
            "name": "endpoint_classifications",
            "schema": {
                "type": "object",
                "properties": {
                    "classifications": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "tags": {"type": "array", "items": {"type": "string"}},
                                "confidence": {"type": "object", "additionalProperties": {"type": "number"}},
                            },
                            "required": ["id", "tags", "confidence"],
                        },
                    },
                },
                "required": ["classifications"],
            },
        }

        raw = await asyncio.wait_for(
            self.llm.chat_completion(
                messages,
                max_tokens=2000,
                temperature=0.1,
                response_format={"type": "json_schema", "json_schema": schema},
            ),
            timeout=self.timeout,
        )
        data = json.loads(raw)

        out: dict[str, dict] = {}
        for entry in data.get("classifications", []):
            ep_id = entry.get("id")
            if not ep_id:
                continue
            tags_in = entry.get("tags") or []
            conf = entry.get("confidence") or {}
            kept_tags: list[str] = []
            kept_conf: dict[str, float] = {}
            for t in tags_in:
                if t not in TAXONOMY:
                    continue
                c = float(conf.get(t, 0.0))
                if c < CONFIDENCE_THRESHOLD:
                    continue
                kept_tags.append(t)
                kept_conf[t] = c
            out[ep_id] = {"tags": kept_tags, "confidence": kept_conf}
        return out
