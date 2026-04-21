"""Redis-backed pause flag for cooperative between-agent pause/resume.

Key format: `pause_requested:{job_id}` = "1" (no TTL).
Key is cleared either by the orchestrator after consuming, or by the resume API.

All functions are fail-safe: if Redis is unreachable, they log and return a
safe default (pause treated as not-requested). A failed pause simply means the
scan continues — the user can retry.
"""
from __future__ import annotations

import logging
import redis

from ..core.config import settings

logger = logging.getLogger(__name__)

_PREFIX = "pause_requested:"
_client: redis.Redis | None = None


def _get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(settings.redis_url, decode_responses=True)
    return _client


def _key(job_id: int) -> str:
    return f"{_PREFIX}{job_id}"


def set_pause_requested(job_id: int) -> None:
    try:
        _get_client().set(_key(job_id), "1")
    except Exception as e:
        logger.error(f"[pause_manager] Redis SET failed for job {job_id}: {e}")


def is_pause_requested(job_id: int) -> bool:
    try:
        return bool(_get_client().exists(_key(job_id)))
    except Exception as e:
        logger.error(f"[pause_manager] Redis EXISTS failed for job {job_id}: {e}")
        return False


def clear_pause_flag(job_id: int) -> None:
    try:
        _get_client().delete(_key(job_id))
    except Exception as e:
        logger.error(f"[pause_manager] Redis DEL failed for job {job_id}: {e}")
