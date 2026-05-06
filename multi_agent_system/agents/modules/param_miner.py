"""Arjun-style parameter mining for Phase R4."""
from __future__ import annotations

import asyncio
import logging
import secrets
from pathlib import Path

log = logging.getLogger(__name__)

TRIALS = 3


def score_endpoint(ep: dict) -> int:
    s = 0
    if ep.get("auth_required"):
        s += 2
    sig = ep.get("response_signature") or {}
    if sig.get("status") == 200:
        s += 1
    if "json" in (sig.get("content_type") or ""):
        s += 2
    return s


def _response_fingerprint(resp) -> str:
    return f"{resp.status_code}|{getattr(resp, 'text', '') or ''}"


async def confirm_param(http_client, url: str, param: str) -> bool:
    """Baseline + TRIALS variant probes. Confirmed if all variants differ from baseline
    consistently (same as each other, different from baseline)."""
    baseline = await http_client.get(url)
    base_fp = _response_fingerprint(baseline)
    variant_fps: list[str] = []
    for _ in range(TRIALS):
        nonce = secrets.token_hex(4)
        r = await http_client.get(f"{url}?{param}={nonce}")
        fp = _response_fingerprint(r)
        if fp == base_fp:
            # Param has no effect — stop early
            return False
        variant_fps.append(fp)
    if not variant_fps:
        return False
    # All variants must be identical (consistent change) and different from baseline
    return len(set(variant_fps)) == 1


async def mine_params(
    http_client,
    endpoints: list[dict],
    wordlist: Path,
    top_n: int = 20,
    rate_per_sec: int = 5,
) -> list[dict]:
    words = [w.strip() for w in Path(wordlist).read_text().splitlines() if w.strip()]
    ranked = sorted(endpoints, key=score_endpoint, reverse=True)[:top_n]
    delay = 1.0 / max(1, rate_per_sec)

    out = list(endpoints)
    by_id = {ep.get("id"): ep for ep in out if ep.get("id")}

    for ep in ranked:
        url = ep.get("path", "")
        target_ep = by_id.get(ep.get("id")) or ep
        if not url.startswith("http"):
            target_ep.setdefault("discovered_params", [])
            continue
        confirmed: list[str] = []
        for word in words:
            try:
                ok = await confirm_param(http_client, url, word)
                if ok:
                    confirmed.append(word)
            except Exception as exc:
                log.debug("param probe failed: %s", exc)
            await asyncio.sleep(delay)
        target_ep["discovered_params"] = confirmed
    return out
