"""
Central configuration for the multi-agent system.

Environment variables (with reasonable defaults for local dev):
- DATABASE_URL: SQLAlchemy URL, default: postgresql+psycopg://user:pass@localhost:5432/rajdoll
- REDIS_URL: Redis URL for Celery broker/result backend, default: redis://localhost:6379/0
- LLM_PROVIDER: LLM provider to use (openai, anthropic, or gemini), default: openai
- LLM_API_KEY: API key for LLM provider (OpenAI, Anthropic, or Gemini)
- LLM_BASE_URL: Base URL for LLM API (e.g., https://agentrouter.org/)
- LLM_MODEL: Model name (e.g., gpt-5, claude-3-5-sonnet-20241022, gemini-1.5-flash)
- CELERY_SOFT_TIME_LIMIT: default per-task soft time limit in seconds
- CELERY_HARD_TIME_LIMIT: default per-task hard time limit in seconds
- JOB_TOTAL_TIMEOUT: total timeout per job in seconds (default 3600 = 1 hour)
- AGENT_TIMEOUT: per-agent max runtime in seconds (default 900 = 15 minutes)
- TOOL_TIMEOUT: per-tool max runtime in seconds (default 300 = 5 minutes)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        value = "true" if default else "false"
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv(value: str | None) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://rajdoll:rajdoll@localhost:5432/rajdoll",
    )
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # LLM Configuration (unified for OpenAI/Anthropic/Gemini)
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai")  # openai, anthropic, gemini
    llm_api_key: str | None = (
        os.getenv("LLM_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("GOOGLE_API_KEY")
    )
    llm_base_url: str | None = os.getenv("LLM_BASE_URL") or (os.getenv("ANTHROPIC_BASE_URL") if os.getenv("LLM_PROVIDER", "openai") == "anthropic" else None)
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o-mini")  # gpt-4o-mini, gpt-4, claude-3-5-sonnet-20241022, etc
    
    # Legacy support (untuk backward compatibility)
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY")
    anthropic_base_url: str | None = os.getenv("ANTHROPIC_BASE_URL", "https://agentrouter.org/")

    celery_soft_time_limit: int = _get_env_int("CELERY_SOFT_TIME_LIMIT", 900)
    celery_hard_time_limit: int = _get_env_int("CELERY_HARD_TIME_LIMIT", 960)

    # Timeouts: 4-hour budget for 14 sequential agents with LLM summarisation
    job_total_timeout: int = _get_env_int("JOB_TOTAL_TIMEOUT", 14400)   # 4 hours
    agent_timeout: int = _get_env_int("AGENT_TIMEOUT", 2700)            # 45 min per agent
    tool_timeout: int = _get_env_int("TOOL_TIMEOUT", 420)               # 7 min per tool

    # Circuit breaker
    circuit_breaker_failures: int = _get_env_int("CIRCUIT_BREAKER_FAILURES", 5)

    # Environment / HITL controls
    lab_mode: bool = field(default_factory=lambda: _env_flag("LAB_MODE", False))
    hitl_enabled: bool = field(init=False)
    enable_tool_hitl: bool = field(init=False)
    hitl_mode: str = field(default_factory=lambda: os.getenv("HITL_MODE", "off"))  # off | agent | tool
    tool_hitl_timeout: int = _get_env_int("TOOL_APPROVAL_TIMEOUT", 600)
    auto_approve_tool_agents: List[str] = field(default_factory=list)
    scan_profile: str = field(default_factory=lambda: os.getenv("SCAN_PROFILE", "lab"))

    def __post_init__(self):
        base_hitl = _env_flag("HITL_ENABLED", True)
        self.hitl_enabled = base_hitl and not self.lab_mode

        base_tool_hitl = _env_flag("ENABLE_TOOL_APPROVALS", True)
        self.enable_tool_hitl = base_tool_hitl and self.hitl_enabled and not self.lab_mode

        # Validate hitl_mode
        if self.hitl_mode not in ("off", "agent", "tool"):
            self.hitl_mode = "off"

        agents_env = os.getenv("AUTO_APPROVE_TOOL_AGENTS")
        if agents_env is None and self.lab_mode:
            agents_env = "InputValidationAgent,APITestingAgent"
        self.auto_approve_tool_agents = _parse_csv(agents_env)


settings = Settings()

# Tools that require Director approval before execution (when hitl_mode == "agent")
HIGH_RISK_TOOLS: frozenset[str] = frozenset({
    "run_sqlmap",
    "test_xss_dalfox",
    "run_nikto",
    "run_nmap",
    "test_tls_configuration",
})

# Scan profile defaults — determines safe defaults when not explicitly set per-scan
# "lab"  → HITL=off, ADAPTIVE=aggressive (Juice Shop / CI)
# "vdp"  → HITL=agent, ADAPTIVE=balanced (real target VDP)
SCAN_PROFILE_DEFAULTS: dict[str, dict[str, str]] = {
    "lab": {"hitl_mode": "off", "adaptive_mode": "aggressive"},
    "vdp": {"hitl_mode": "agent", "adaptive_mode": "balanced"},
}

# Tools that violate single-target scope by design.
# Hard-disabled regardless of LLM planner choice or Director directive.
SCOPE_VIOLATION_TOOLS: frozenset[str] = frozenset({
    "enumerate_active_subdomains",       # amass/subfinder/DNS brute
    "test_subdomain_takeover",            # CNAME takeover check
    "comprehensive_domain_recon",         # umbrella: DNS + WHOIS + subdomain
    "enumerate_applications",             # vhost/application enumeration
})
