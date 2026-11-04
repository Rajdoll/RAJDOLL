"""What the navigation shows about the LLM: local, API (data leaves the laptop), or off."""

from __future__ import annotations

from typing import Any

from rajdoll.services import settings as app_settings


def indicator(settings: app_settings.AppSettings) -> dict[str, Any]:
    from rajdoll.services.scans import is_local_llm

    if not settings.llm.enabled:
        return {"state": "off", "label": "mati", "model": settings.llm.model}
    local = is_local_llm(str(settings.llm.base_url))
    return {
        "state": "local" if local else "api",
        "label": "lokal" if local else "API",
        "model": settings.llm.model,
    }
