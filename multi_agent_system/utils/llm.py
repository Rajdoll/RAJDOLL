from __future__ import annotations

import os
from typing import Any, Dict

from ..core.config import settings


class LLM:
    """
    Thin wrapper for Anthropic Claude Sonnet 4.5. We avoid importing the SDK if the key is missing
    to keep local dev flexible. Callers should handle NotConfiguredError.
    """

    class NotConfiguredError(RuntimeError):
        pass

    def __init__(self):
        if not settings.anthropic_api_key:
            raise LLM.NotConfiguredError("ANTHROPIC_API_KEY is not set")
        try:
            from anthropic import Anthropic
        except Exception as e:  # pragma: no cover
            raise RuntimeError("anthropic package not installed") from e
        
        # Use AgentRouter proxy for API access
        self._client = Anthropic(
            api_key=settings.anthropic_api_key,
            base_url=settings.anthropic_base_url
        )

    def analyze_recon_and_plan(self, recon_summary: str) -> Dict[str, Any]:
        """
        Return a JSON-like dict describing which agents to run, in which order and which in parallel.
        Keep token usage small by concise instruction.
        """
        prompt = (
            "You are an orchestrator for a web security multi-agent system following OWASP WSTG 4.2. "
            "Given this reconnaissance summary, output a minimal JSON plan with: "
            "{ sequence: [ 'ReconnaissanceAgent', { parallel: ['InputValidationAgent','ClientSideAgent'] }, 'AuthorizationAgent', 'AuthenticationAgent', 'SessionManagementAgent', 'ConfigurationAgent', 'ErrorHandlingAgent', 'CryptographyAgent', 'BusinessLogicAgent', 'APITestingAgent' ], reasons: '...' } "
            f"Recon summary:\n{recon_summary[:4000]}"
        )
        msg = self._client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=600,
            temperature=0.1,
            system="Return only valid JSON. Be concise.",
            messages=[{"role": "user", "content": prompt}],
        )
        # Depending on SDK, extract text
        text = getattr(msg, "content", "")
        if isinstance(text, list) and text:
            text = text[0].text  # type: ignore[attr-defined]
        import json
        try:
            return json.loads(text)
        except Exception:
            return {"sequence": ["ReconnaissanceAgent", {"parallel": ["InputValidationAgent", "ClientSideAgent"]}, "AuthorizationAgent"], "reasons": "Fallback static plan"}
