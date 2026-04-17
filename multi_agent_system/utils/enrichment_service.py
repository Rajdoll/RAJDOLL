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

# WSTG code prefix → friendly category name used in KB entries
_WSTG_PREFIX_MAP: dict[str, str] = {
    "WSTG-INFO":   "Information Gathering",
    "WSTG-CONF":   "Configuration",
    "WSTG-CONFIG": "Configuration",
    "WSTG-ATHN":   "Authentication",
    "WSTG-ATHZ":   "Authorization",
    "WSTG-SESS":   "Session",
    "WSTG-INPV":   "Input Validation",
    "WSTG-ERRH":   "Error Handling",
    "WSTG-CRYP":   "Cryptography",
    "WSTG-CLNT":   "Client",
    "WSTG-BUSL":   "Business Logic",
    "WSTG-IDMG":   "Identity Management",
    "WSTG-IDNT":   "Identity Management",
}


def _category_candidates(category: str) -> list[str]:
    """Expand a category value into all forms that could match a KB category_pattern.

    Handles both friendly names ('Authentication') and WSTG codes ('WSTG-ATHN-06').
    For WSTG codes, adds progressively shorter prefixes + mapped friendly name so that
    KB entries using either notation will match.

    Examples:
        'WSTG-ATHN-06' → ['wstg-athn-06', 'wstg-athn', 'authentication']
        'WSTG-INPV-05' → ['wstg-inpv-05', 'wstg-inpv', 'input validation']
        'Authentication' → ['authentication']
    """
    cat = (category or "").strip()
    candidates: list[str] = [cat.lower()]
    upper = cat.upper()
    if upper.startswith("WSTG-"):
        parts = upper.split("-")
        # Walk from longest prefix to shortest, collect unique entries
        seen: set[str] = set()
        for n in range(len(parts), 1, -1):
            prefix = "-".join(parts[:n])
            if prefix not in seen:
                seen.add(prefix)
                candidates.append(prefix.lower())
                friendly = _WSTG_PREFIX_MAP.get(prefix)
                if friendly and friendly.lower() not in candidates:
                    candidates.append(friendly.lower())
    return candidates


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
        candidates = _category_candidates(category)
        title_lower = (title or "").lower()

        for entry in _KB_ENTRIES:
            cat_pat = entry.get("category_pattern", "").lower()
            keywords = [k.lower() for k in entry.get("title_keywords", [])]
            # cat_pat must appear as a substring in at least one candidate string
            if cat_pat and not any(cat_pat in cand for cand in candidates):
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
        """Main entry point — try KB, then LLM (if enabled), then safe fallback. Never raises.

        LLM enrichment is disabled by default (ENRICHMENT_LLM_ENABLED=false) because the local
        LLM is already busy with agent planning/summarization during scans, causing timeouts and
        slowing down all agents. The static KB covers 39 vulnerability types (~90% of findings).
        Enable only for post-scan enrichment or when the LLM has dedicated capacity.
        """
        # 1. Try static KB
        kb_result = StaticKBMatcher.match(category, title)
        if kb_result is not None:
            return kb_result

        # 2. Try LLM only if explicitly enabled
        llm_enabled = os.getenv("ENRICHMENT_LLM_ENABLED", "false").lower() in ("1", "true", "yes")
        if llm_enabled:
            try:
                return LLMEnricher.enrich(category, title, severity, evidence)
            except Exception as e:
                print(f"[EnrichmentService] LLM enrichment failed ({e}), using fallback", file=sys.stderr)

        # 3. Category-aware fallback
        return EnrichmentService._category_fallback(category, severity)

    # Per-WSTG-prefix remediation guidance used when the KB has no keyword match.
    _CATEGORY_REMEDIATION: dict[str, tuple[str, str, str]] = {
        # (wstg_id_prefix, cwe_id, remediation_text)
        "WSTG-ATHN": (
            "WSTG-ATHN",
            "CWE-287",
            "1. Enforce HTTPS on every authentication endpoint — redirect HTTP to HTTPS and add HSTS.\n"
            "2. Apply rate limiting (≤5 attempts/min per IP) on all auth channels: web, mobile API, and alternative paths.\n"
            "3. Add CSRF tokens to all authentication and password-management forms.\n"
            "4. Require email verification for password reset and expire reset tokens within 15 minutes.\n"
            "5. Set Cache-Control: no-store on authentication responses to prevent credential caching.",
        ),
        "WSTG-ATHZ": (
            "WSTG-ATHZ",
            "CWE-285",
            "1. Enforce authorization checks server-side for every request — never trust client-supplied role or ownership claims.\n"
            "2. Implement object-level authorization: validate that the authenticated user owns or is permitted to access the requested resource.\n"
            "3. Use unpredictable UUIDs rather than sequential IDs for resource references to limit IDOR exposure.\n"
            "4. Apply least-privilege: every role should have only the minimum permissions required.\n"
            "5. Write automated tests that attempt cross-user and cross-role resource access for all sensitive endpoints.",
        ),
        "WSTG-SESS": (
            "WSTG-SESS",
            "CWE-384",
            "1. Regenerate the session ID on login, privilege change, and logout.\n"
            "2. Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.\n"
            "3. Implement idle session timeout (15–30 min) and absolute session timeout (8 hours).\n"
            "4. Invalidate sessions server-side on logout — do not rely solely on clearing the client cookie.\n"
            "5. Store session state exclusively server-side; never encode sensitive data in client-visible cookies.",
        ),
        "WSTG-INPV": (
            "WSTG-INPV",
            "CWE-20",
            "1. Validate all input server-side against a strict allowlist — client-side validation is not a security control.\n"
            "2. Use parameterized queries or prepared statements for all database operations.\n"
            "3. Encode output contextually (HTML, JavaScript, URL) before rendering user-controlled data.\n"
            "4. Enforce strict Content-Type validation and reject unexpected request formats.\n"
            "5. Apply a Web Application Firewall (WAF) rule set for common injection patterns as a defence-in-depth layer.",
        ),
        "WSTG-ERRH": (
            "WSTG-ERRH",
            "CWE-209",
            "1. Disable debug mode and verbose error output in all production environments.\n"
            "2. Return generic error messages to users (e.g., 'An error occurred') — log detailed errors server-side only.\n"
            "3. Implement centralized error handling middleware to prevent unhandled exceptions from leaking stack traces.\n"
            "4. Configure custom 404 and 500 error pages that reveal no framework or path details.\n"
            "5. Audit application logs to ensure no credentials, tokens, or PII are written to log files.",
        ),
        "WSTG-CRYP": (
            "WSTG-CRYP",
            "CWE-311",
            "1. Enforce HTTPS with TLS 1.2+ on all endpoints; disable TLS 1.0/1.1 and SSLv3.\n"
            "2. Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.\n"
            "3. Hash passwords with bcrypt, Argon2, or PBKDF2 (≥10,000 iterations) — never use MD5 or SHA-1.\n"
            "4. Use cryptographically secure random number generation (os.urandom / crypto.randomBytes) for tokens and session IDs.\n"
            "5. Verify JWT signatures server-side with an explicit algorithm allowlist; reject alg:none tokens.",
        ),
        "WSTG-CLNT": (
            "WSTG-CLNT",
            "CWE-79",
            "1. Implement a strict Content Security Policy (CSP) with nonces — avoid unsafe-inline and unsafe-eval.\n"
            "2. Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.\n"
            "3. Validate all URL redirect targets against an allowlist — never redirect to user-supplied arbitrary URLs.\n"
            "4. Set SameSite=Strict on session cookies to prevent cross-site request forgery.\n"
            "5. Avoid eval(), innerHTML, and document.write() when processing user-supplied data.",
        ),
        "WSTG-BUSL": (
            "WSTG-BUSL",
            "CWE-840",
            "1. Validate all business logic constraints server-side — prices, quantities, and discounts cannot be trusted from the client.\n"
            "2. Implement rate limiting on all user-facing actions (login, registration, search, order placement).\n"
            "3. Enforce multi-step workflow ordering server-side; reject requests that arrive out of sequence.\n"
            "4. Sign business-critical values (coupon codes, order totals) with an HMAC to detect tampering.\n"
            "5. Log all business-critical actions and alert on statistical outliers (negative prices, unusually large discounts).",
        ),
        "WSTG-IDNT": (
            "WSTG-IDNT",
            "CWE-915",
            "1. Use an explicit allowlist for all registration fields — strip or reject unexpected properties (mass assignment prevention).\n"
            "2. Return identical error responses for valid and invalid usernames to prevent account enumeration.\n"
            "3. Enforce minimum complexity requirements for usernames and email addresses server-side.\n"
            "4. Require email verification before activating accounts to prevent bulk fake registrations.\n"
            "5. Log all account provisioning and role-assignment events for audit purposes.",
        ),
        "WSTG-IDMG": (
            "WSTG-IDMG",
            "CWE-915",
            "1. Use an explicit allowlist for all registration fields — strip or reject unexpected properties (mass assignment prevention).\n"
            "2. Return identical error responses for valid and invalid usernames to prevent account enumeration.\n"
            "3. Enforce minimum complexity requirements for usernames and email addresses server-side.\n"
            "4. Require email verification before activating accounts to prevent bulk fake registrations.\n"
            "5. Log all account provisioning and role-assignment events for audit purposes.",
        ),
        "WSTG-CONF": (
            "WSTG-CONF",
            "CWE-16",
            "1. Remove sensitive files from the web root: .git, .env, *.bak, *.key, configuration files.\n"
            "2. Set security response headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.\n"
            "3. Disable directory listing on the web server — return 403, not a file listing.\n"
            "4. Restrict dangerous upload file extensions (PHP, ASP, JSP, EXE) at the web server level.\n"
            "5. Regularly audit server configurations against CIS Benchmarks or OWASP's hardening guide.",
        ),
        "WSTG-INFO": (
            "WSTG-INFO",
            "CWE-200",
            "1. Suppress or genericize Server, X-Powered-By, and X-AspNet-Version response headers.\n"
            "2. Remove HTML comments, debug annotations, and developer notes from production builds.\n"
            "3. Restrict access to discovered hidden paths using authentication or IP allowlisting.\n"
            "4. Configure error pages to return generic messages without framework, path, or version details.\n"
            "5. Review the application's information disclosure surface regularly using automated scanners.",
        ),
        "WSTG-APIT": (
            "WSTG-APIT",
            "CWE-285",
            "1. Authenticate all API endpoints — require valid tokens for every operation, including read-only ones.\n"
            "2. Validate API input strictly: enforce schema validation and reject unexpected fields.\n"
            "3. Implement API rate limiting and per-consumer quotas.\n"
            "4. Return 401/403 rather than 404 for unauthorized access to avoid endpoint enumeration.\n"
            "5. Document and version all API endpoints; deprecate older versions with known vulnerabilities.",
        ),
    }

    @staticmethod
    def _category_fallback(category: str, severity: str) -> EnrichmentResult:
        sev_lower = (severity or "info").lower()
        impact = EnrichmentService._SEVERITY_IMPACT.get(
            sev_lower, EnrichmentService._SEVERITY_IMPACT["info"]
        )

        # Try to match on WSTG prefix (longest match first: WSTG-ATHN-03 → WSTG-ATHN → fallback)
        cat_upper = (category or "").upper().strip()
        matched_wstg_id = ""
        matched_cwe_id = ""
        matched_remediation = None

        for prefix, (wstg_id, cwe_id, remediation) in EnrichmentService._CATEGORY_REMEDIATION.items():
            if cat_upper.startswith(prefix):
                matched_wstg_id = wstg_id
                matched_cwe_id = cwe_id
                matched_remediation = remediation
                break  # first (longest matching) prefix wins since dict is insertion-ordered

        if matched_remediation is None:
            matched_remediation = (
                "1. Review the finding evidence carefully.\n"
                "2. Apply defense-in-depth controls relevant to the vulnerability category.\n"
                "3. Consult OWASP WSTG 4.2 for category-specific remediation guidance.\n"
                "4. Re-test after applying fixes."
            )

        return EnrichmentResult(
            explanation=f"{impact} Manual review is recommended to confirm exploitability and scope.",
            remediation=matched_remediation,
            cwe_id=matched_cwe_id,
            wstg_id=matched_wstg_id or cat_upper,
            cvss_score_v4=0.0,
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            source="fallback",
        )
