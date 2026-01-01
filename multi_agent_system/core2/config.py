from __future__ import annotations

import os
from dataclasses import dataclass


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


@dataclass
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://rajdoll:rajdoll@db:5432/rajdoll",
    )
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY")

    celery_soft_time_limit: int = _get_env_int("CELERY_SOFT_TIME_LIMIT", 900)
    celery_hard_time_limit: int = _get_env_int("CELERY_HARD_TIME_LIMIT", 960)

    job_total_timeout: int = _get_env_int("JOB_TOTAL_TIMEOUT", 3600)
    agent_timeout: int = _get_env_int("AGENT_TIMEOUT", 900)
    tool_timeout: int = _get_env_int("TOOL_TIMEOUT", 300)

    circuit_breaker_failures: int = _get_env_int("CIRCUIT_BREAKER_FAILURES", 5)


settings = Settings()
