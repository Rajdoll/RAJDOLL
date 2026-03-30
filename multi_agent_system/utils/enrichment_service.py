"""
Hybrid finding enrichment: static knowledge base (90%) + LLM fallback (10%).
All methods are synchronous — called from add_finding() in Celery worker context.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# KB loaded once at module import
_KB_PATH = Path(__file__).parent.parent / "data" / "enrichment_kb.json"
_KB_ENTRIES: list[dict] = []

def _load_kb() -> list[dict]:
    try:
        with open(_KB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[EnrichmentService] WARNING: Could not load KB from {_KB_PATH}: {e}", file=sys.stderr)
        return []

_KB_ENTRIES = _load_kb()


@dataclass
class EnrichmentResult:
    explanation: str
    remediation: str
    cwe_id: str
    wstg_id: str
    cvss_score_v4: float
    references: list[str]
    source: str  # "static_kb" | "llm" | "fallback"


class StaticKBMatcher:
    """Match findings against the static JSON knowledge base."""

    @staticmethod
    def match(category: str, title: str) -> Optional[EnrichmentResult]:
        """Return EnrichmentResult if KB has a matching entry, else None."""
        category_lower = (category or "").lower()
        title_lower = (title or "").lower()

        for entry in _KB_ENTRIES:
            cat_pat = entry.get("category_pattern", "").lower()
            keywords = [k.lower() for k in entry.get("title_keywords", [])]
            if cat_pat and cat_pat not in category_lower:
                continue
            if not any(kw in title_lower for kw in keywords):
                continue
            return EnrichmentResult(
                explanation=entry.get("explanation", ""),
                remediation=entry.get("remediation", ""),
                cwe_id=entry.get("cwe_id", ""),
                wstg_id=entry.get("wstg_id", ""),
                cvss_score_v4=float(entry.get("cvss_score_v4", 0.0)),
                references=entry.get("references", []),
                source="static_kb",
            )
        return None


class LLMEnricher:
    """LLM fallback enrichment using sync httpx. Called only on KB miss."""

    _PROMPT_PATH = Path(__file__).parent.parent / "templates" / "enrichment_prompt.j2"

    @staticmethod
    def enrich(category: str, title: str, severity: str, evidence: dict) -> EnrichmentResult:
        """Call local LLM synchronously to generate enrichment data."""
        import httpx
        from jinja2 import Template

        llm_base_url = os.getenv("LLM_BASE_URL", "http://localhost:1234/v1")
        llm_api_key = os.getenv("LLM_API_KEY", "lm-studio")
        llm_model = os.getenv("LLM_MODEL", "qwen3-4b")

        # Render prompt template
        try:
            prompt_template = LLMEnricher._PROMPT_PATH.read_text(encoding="utf-8")
            template = Template(prompt_template)
        except Exception:
            template = Template(
                "You are a security expert. Analyze: Category={{ category }}, Title={{ title }}, "
                "Severity={{ severity }}, Evidence={{ evidence_summary }}. "
                "Return JSON: explanation, remediation, cwe_id, wstg_id, cvss_score_v4, references."
            )

        evidence_summary = str(evidence)[:300] if evidence else "No evidence available"
        prompt = template.render(
            category=category, title=title,
            severity=severity, evidence_summary=evidence_summary
        )

        schema = {
            "title": "finding_enrichment",
            "type": "object",
            "properties": {
                "explanation": {"type": "string"},
                "remediation": {"type": "string"},
                "cwe_id": {"type": "string"},
                "wstg_id": {"type": "string"},
                "cvss_score_v4": {"type": "number"},
                "references": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["explanation", "remediation", "cwe_id", "wstg_id", "cvss_score_v4", "references"],
            "additionalProperties": False,
        }

        payload = {
            "model": llm_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 800,
            "temperature": 0.3,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "finding_enrichment", "strict": True, "schema": schema},
            },
        }

        with httpx.Client(timeout=60.0) as client:
            response = client.post(
                f"{llm_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {llm_api_key}", "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]
        # Strip <think> tags if any (thinking model safeguard)
        if "<think>" in content:
            import re
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        data = json.loads(content)
        return EnrichmentResult(
            explanation=data.get("explanation", ""),
            remediation=data.get("remediation", ""),
            cwe_id=data.get("cwe_id", ""),
            wstg_id=data.get("wstg_id", ""),
            cvss_score_v4=float(data.get("cvss_score_v4", 0.0)),
            references=data.get("references", []),
            source="llm",
        )


class EnrichmentService:
    """Orchestrates KB lookup -> LLM fallback -> safe fallback. Never raises."""

    _SEVERITY_IMPACT = {
        "critical": "This vulnerability poses an immediate risk of complete system compromise or mass data breach.",
        "high": "This vulnerability poses a significant risk of unauthorized access or sensitive data exposure.",
        "medium": "This vulnerability poses a moderate risk that could lead to information disclosure or limited unauthorized access.",
        "low": "This vulnerability poses a minor security risk with limited exploitability.",
        "info": "This is an informational finding requiring no immediate remediation.",
    }

    @staticmethod
    def enrich(category: str, title: str, severity: str, evidence: dict) -> EnrichmentResult:
        """Main entry point — try KB, then LLM, then safe fallback. Never raises."""
        # 1. Try static KB
        kb_result = StaticKBMatcher.match(category, title)
        if kb_result is not None:
            return kb_result

        # 2. Try LLM
        try:
            return LLMEnricher.enrich(category, title, severity, evidence)
        except Exception as e:
            print(f"[EnrichmentService] LLM enrichment failed ({e}), using fallback", file=sys.stderr)

        # 3. Safe fallback
        return EnrichmentService._safe_fallback(severity)

    @staticmethod
    def _safe_fallback(severity: str) -> EnrichmentResult:
        sev_lower = (severity or "info").lower()
        impact = EnrichmentService._SEVERITY_IMPACT.get(
            sev_lower, EnrichmentService._SEVERITY_IMPACT["info"]
        )
        return EnrichmentResult(
            explanation=f"{impact} Manual review is recommended to confirm exploitability and scope.",
            remediation=(
                "1. Review the finding evidence carefully.\n"
                "2. Apply defense-in-depth controls relevant to the vulnerability category.\n"
                "3. Consult OWASP WSTG 4.2 for category-specific remediation guidance.\n"
                "4. Re-test after applying fixes."
            ),
            cwe_id="",
            wstg_id="",
            cvss_score_v4=0.0,
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            source="fallback",
        )
