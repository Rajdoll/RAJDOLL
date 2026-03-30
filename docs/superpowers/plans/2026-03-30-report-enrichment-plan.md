# Report Enrichment & PDF Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich every vulnerability finding with explanation, remediation steps, CVSS 4.0, CWE ID, WSTG ID, and references — then render a professional Jinja2-templated PDF report.

**Architecture:** Static JSON knowledge base matches ~90% of findings instantly; LLM fallback (sync httpx) handles the rest. Enrichment runs inside `add_finding()` at write time, storing 7 new columns on `Finding`. The PDF endpoint renders `report.html.j2` via Jinja2 + WeasyPrint.

**Tech Stack:** Python 3.11, SQLAlchemy (no Alembic — `create_all()` based), httpx (sync), Jinja2, WeasyPrint, markdown lib.

**Key constraint:** `add_finding()` is synchronous (Celery worker context). All enrichment must be sync — use `httpx.Client` (not `AsyncClient`) for the LLM fallback.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `multi_agent_system/utils/enrichment_service.py` | `EnrichmentResult`, `StaticKBMatcher`, `LLMEnricher`, `EnrichmentService` |
| Create | `multi_agent_system/data/enrichment_kb.json` | ~50 static vuln pattern entries |
| Create | `multi_agent_system/templates/enrichment_prompt.j2` | Jinja2 LLM prompt template |
| Create | `multi_agent_system/templates/report.html.j2` | Jinja2 HTML template for PDF |
| Create | `multi_agent_system/tests/test_enrichment.py` | Unit + integration tests |
| Create | `migrate_add_enrichment.sql` | Manual SQL migration for existing DBs |
| Modify | `multi_agent_system/models/models.py` | Add 7 columns to `Finding` |
| Modify | `multi_agent_system/agents/base_agent.py` | Call `EnrichmentService` in `add_finding()` |
| Modify | `api/routes/pdf_report.py` | Jinja2 template rendering, enriched data |

---

## Task 1: Add enrichment columns to Finding model

**Files:**
- Modify: `multi_agent_system/models/models.py:103-120`
- Create: `migrate_add_enrichment.sql`

- [ ] **Step 1: Add 7 columns to the Finding model**

In `multi_agent_system/models/models.py`, replace the `Finding` class body (after `attack_chain_id` line 119) to add:

```python
class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("job_id", "agent_name", "category", "title", name="uq_finding"),)

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    agent_name: Mapped[str] = Column(String(128), nullable=False)
    category: Mapped[str] = Column(String(128), nullable=False)
    title: Mapped[str] = Column(String(512), nullable=False)
    severity: Mapped[FindingSeverity] = Column(Enum(FindingSeverity), default=FindingSeverity.info, nullable=False)
    evidence: Mapped[Optional[dict]] = Column(JSON, nullable=True)
    details: Mapped[Optional[str]] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
    # Confidence scoring
    confidence_score: Mapped[Optional[float]] = Column(Float, nullable=True)
    confidence_level: Mapped[Optional[ConfidenceLevel]] = Column(Enum(ConfidenceLevel), nullable=True)
    attack_chain_id: Mapped[Optional[str]] = Column(String(64), nullable=True)
    # Enrichment columns (populated by EnrichmentService at write time)
    explanation: Mapped[Optional[str]] = Column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = Column(Text, nullable=True)
    cwe_id: Mapped[Optional[str]] = Column(String(20), nullable=True)
    wstg_id: Mapped[Optional[str]] = Column(String(30), nullable=True)
    cvss_score_v4: Mapped[Optional[float]] = Column(Float, nullable=True)
    references: Mapped[Optional[list]] = Column(JSON, nullable=True)
    enrichment_source: Mapped[Optional[str]] = Column(String(20), nullable=True)

    job: Mapped[Job] = relationship("Job", back_populates="findings")
```

- [ ] **Step 2: Create SQL migration for existing DBs**

Create `migrate_add_enrichment.sql` at project root:

```sql
-- Run this against existing databases to add enrichment columns
-- New installs: columns created automatically via Base.metadata.create_all()
ALTER TABLE findings ADD COLUMN IF NOT EXISTS explanation TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS wstg_id VARCHAR(30);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score_v4 FLOAT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS references JSON;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_source VARCHAR(20);
```

- [ ] **Step 3: Apply migration to running DB**

```bash
docker exec rajdoll-db-1 psql -U rajdoll -d rajdoll -f /dev/stdin < migrate_add_enrichment.sql
```

Expected output: `ALTER TABLE` × 7 (or `NOTICE: column already exists` if re-run).

- [ ] **Step 4: Commit**

```bash
git add multi_agent_system/models/models.py migrate_add_enrichment.sql
git commit -m "feat(db): add 7 enrichment columns to Finding model"
```

---

## Task 2: Create EnrichmentResult + StaticKBMatcher

**Files:**
- Create: `multi_agent_system/utils/enrichment_service.py`
- Create: `multi_agent_system/tests/test_enrichment.py` (failing tests first)

- [ ] **Step 1: Write failing tests for StaticKBMatcher**

Create `multi_agent_system/tests/test_enrichment.py`:

```python
"""Tests for enrichment_service — no Docker required."""
import json
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import asdict


def test_enrichment_result_has_required_fields():
    from multi_agent_system.utils.enrichment_service import EnrichmentResult
    r = EnrichmentResult(
        explanation="test", remediation="1. fix it",
        cwe_id="CWE-89", wstg_id="WSTG-INPV-05",
        cvss_score_v4=9.3, references=["https://owasp.org"],
        source="static_kb"
    )
    assert r.source == "static_kb"
    assert r.cvss_score_v4 == 9.3


def test_static_kb_matcher_hits_sqli():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    result = StaticKBMatcher.match("Input Validation", "SQL Injection in Login")
    assert result is not None
    assert result.wstg_id == "WSTG-INPV-05"
    assert result.cwe_id == "CWE-89"
    assert result.source == "static_kb"
    assert len(result.references) >= 1


def test_static_kb_matcher_hits_xss():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    result = StaticKBMatcher.match("Input Validation", "Reflected XSS via search param")
    assert result is not None
    assert "CWE-79" in result.cwe_id


def test_static_kb_matcher_hits_idor():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    result = StaticKBMatcher.match("Authorization", "IDOR on user profile endpoint")
    assert result is not None
    assert "WSTG-ATHZ" in result.wstg_id


def test_static_kb_matcher_returns_none_on_miss():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    result = StaticKBMatcher.match("Unknown Category", "Something very obscure xyz123")
    assert result is None


def test_static_kb_matcher_case_insensitive():
    from multi_agent_system.utils.enrichment_service import StaticKBMatcher
    result = StaticKBMatcher.match("input validation", "SQL INJECTION FOUND")
    assert result is not None


def test_enrichment_service_uses_static_kb_on_hit():
    from multi_agent_system.utils.enrichment_service import EnrichmentService
    result = EnrichmentService.enrich("Input Validation", "SQL Injection", "critical", {})
    assert result.source == "static_kb"
    assert result.explanation != ""
    assert result.remediation != ""


def test_enrichment_service_returns_fallback_on_llm_failure():
    from multi_agent_system.utils.enrichment_service import EnrichmentService
    with patch("multi_agent_system.utils.enrichment_service.LLMEnricher.enrich") as mock_llm:
        mock_llm.side_effect = Exception("LM Studio not running")
        result = EnrichmentService.enrich("Unknown", "weird obscure finding xyz", "medium", {})
    assert result.source == "fallback"
    assert result.explanation != ""


def test_enrichment_service_calls_llm_on_kb_miss():
    from multi_agent_system.utils.enrichment_service import EnrichmentService, EnrichmentResult
    fake = EnrichmentResult("exp", "rem", "CWE-200", "WSTG-INFO-01", 5.0, [], "llm")
    with patch("multi_agent_system.utils.enrichment_service.LLMEnricher.enrich", return_value=fake) as mock_llm:
        result = EnrichmentService.enrich("Unknown", "weird obscure finding xyz", "medium", {})
    mock_llm.assert_called_once()
    assert result.source == "llm"


def test_fallback_has_non_empty_explanation():
    from multi_agent_system.utils.enrichment_service import EnrichmentService
    with patch("multi_agent_system.utils.enrichment_service.LLMEnricher.enrich") as mock_llm:
        mock_llm.side_effect = Exception("timeout")
        result = EnrichmentService.enrich("Config", "weird thing", "high", {})
    assert len(result.explanation) > 10
    assert result.source == "fallback"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /mnt/d/MCP/RAJDOLL
python -m pytest multi_agent_system/tests/test_enrichment.py -v 2>&1 | head -30
```

Expected: `ImportError: cannot import name 'EnrichmentResult'` — confirms tests are wired.

- [ ] **Step 3: Create enrichment_service.py with EnrichmentResult + StaticKBMatcher**

Create `multi_agent_system/utils/enrichment_service.py`:

```python
"""
Hybrid finding enrichment: static knowledge base (90%) + LLM fallback (10%).
All methods are synchronous — called from add_finding() in Celery worker context.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
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
            prompt_template = LLMEnricher._fallback_prompt()
            template = Template(prompt_template)

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
        # Strip <think> tags if any
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

    @staticmethod
    def _fallback_prompt() -> str:
        return (
            "You are a security expert. Analyze: Category={{ category }}, Title={{ title }}, "
            "Severity={{ severity }}, Evidence={{ evidence_summary }}. "
            "Return JSON: explanation, remediation, cwe_id, wstg_id, cvss_score_v4, references."
        )


class EnrichmentService:
    """Orchestrates KB lookup → LLM fallback → safe fallback."""

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
        impact = EnrichmentService._SEVERITY_IMPACT.get(sev_lower, EnrichmentService._SEVERITY_IMPACT["info"])
        return EnrichmentResult(
            explanation=f"{impact} Manual review is recommended to confirm exploitability and scope.",
            remediation="1. Review the finding evidence carefully.\n2. Apply defense-in-depth controls relevant to the vulnerability category.\n3. Consult OWASP WSTG 4.2 for category-specific remediation guidance.\n4. Re-test after applying fixes.",
            cwe_id="",
            wstg_id="",
            cvss_score_v4=0.0,
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            source="fallback",
        )
```

- [ ] **Step 4: Run the tests — they should partially pass now**

```bash
python -m pytest multi_agent_system/tests/test_enrichment.py -v -k "not sqli and not xss and not idor" 2>&1 | tail -20
```

Expected: `test_enrichment_result_has_required_fields` PASS, KB hit tests FAIL (no KB yet).

- [ ] **Step 5: Commit**

```bash
git add multi_agent_system/utils/enrichment_service.py multi_agent_system/tests/test_enrichment.py
git commit -m "feat(enrichment): add EnrichmentResult, StaticKBMatcher, LLMEnricher, EnrichmentService"
```

---

## Task 3: Create enrichment_kb.json (~50 entries)

**Files:**
- Create: `multi_agent_system/data/enrichment_kb.json`

- [ ] **Step 1: Create the data directory and KB file**

```bash
mkdir -p /mnt/d/MCP/RAJDOLL/multi_agent_system/data
```

Create `multi_agent_system/data/enrichment_kb.json`:

```json
[
  {
    "id": "sqli-generic",
    "category_pattern": "Input Validation",
    "title_keywords": ["sql injection", "sqli", "sql error", "blind sql", "time-based sql", "union-based"],
    "wstg_id": "WSTG-INPV-05",
    "cwe_id": "CWE-89",
    "cvss_score_v4": 9.3,
    "explanation": "SQL Injection allows attackers to manipulate backend database queries by injecting malicious SQL syntax through user-supplied inputs. Successful exploitation can lead to unauthorized data access, authentication bypass, data destruction, or full database server compromise.",
    "remediation": "1. Use parameterized queries or prepared statements for all database interactions.\n2. Apply strict server-side input validation and allowlist filtering.\n3. Enforce least-privilege database accounts (no DROP/ALTER in application accounts).\n4. Enable WAF rules for SQL injection patterns.\n5. Audit and log all database query errors.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
      "https://cwe.mitre.org/data/definitions/89.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ]
  },
  {
    "id": "xss-reflected",
    "category_pattern": "Input Validation",
    "title_keywords": ["reflected xss", "xss reflected", "cross-site scripting reflected"],
    "wstg_id": "WSTG-INPV-01",
    "cwe_id": "CWE-79",
    "cvss_score_v4": 6.1,
    "explanation": "Reflected Cross-Site Scripting (XSS) occurs when user-supplied data is immediately echoed back in the HTTP response without sanitization, allowing attackers to inject malicious scripts. Victims clicking crafted links execute attacker-controlled JavaScript in their browser, enabling session hijacking, credential theft, or malicious redirects.",
    "remediation": "1. Apply context-aware output encoding (HTML entity encoding for HTML context, JS encoding for script context).\n2. Implement a strict Content Security Policy (CSP) header.\n3. Validate and sanitize all user input server-side.\n4. Use modern frameworks that auto-escape output (React, Angular, etc.).\n5. Set HttpOnly and Secure flags on session cookies.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
      "https://cwe.mitre.org/data/definitions/79.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
    ]
  },
  {
    "id": "xss-stored",
    "category_pattern": "Input Validation",
    "title_keywords": ["stored xss", "xss stored", "persistent xss", "cross-site scripting stored"],
    "wstg_id": "WSTG-INPV-02",
    "cwe_id": "CWE-79",
    "cvss_score_v4": 8.8,
    "explanation": "Stored XSS occurs when malicious scripts injected by an attacker are permanently stored on the server and served to all users who view the affected page. Unlike reflected XSS, stored XSS does not require victim interaction with a crafted URL — every visitor is automatically exposed.",
    "remediation": "1. Sanitize all user input before storage using an allowlist HTML sanitizer (e.g., DOMPurify).\n2. Apply context-aware output encoding when rendering stored data.\n3. Implement a strict Content Security Policy (CSP).\n4. Use parameterized queries to prevent stored payloads from bypassing filters.\n5. Audit all features that store and render user content.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting",
      "https://cwe.mitre.org/data/definitions/79.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
    ]
  },
  {
    "id": "xss-dom",
    "category_pattern": "Client",
    "title_keywords": ["dom xss", "dom-based xss", "javascript injection", "dom injection"],
    "wstg_id": "WSTG-CLNT-01",
    "cwe_id": "CWE-79",
    "cvss_score_v4": 6.1,
    "explanation": "DOM-Based XSS occurs when client-side JavaScript dynamically writes attacker-controlled data to the DOM without sanitization, such as through innerHTML or document.write. The attack executes entirely in the browser without any server interaction, making it harder to detect with server-side controls.",
    "remediation": "1. Use safe DOM APIs (textContent, createElement) instead of innerHTML or document.write.\n2. Sanitize dynamic data using DOMPurify before rendering.\n3. Implement a strict Content Security Policy (CSP).\n4. Avoid passing URL fragments or query strings directly into DOM sinks.\n5. Conduct JavaScript security code review for all DOM manipulation.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-Side_Testing/01-Testing_for_DOM-Based_Cross_Site_Scripting",
      "https://cwe.mitre.org/data/definitions/79.html"
    ]
  },
  {
    "id": "ssti",
    "category_pattern": "Input Validation",
    "title_keywords": ["ssti", "server-side template injection", "template injection"],
    "wstg_id": "WSTG-INPV-18",
    "cwe_id": "CWE-94",
    "cvss_score_v4": 9.8,
    "explanation": "Server-Side Template Injection (SSTI) occurs when user input is embedded unsanitized into a server-side template engine. Attackers can exploit template syntax to execute arbitrary code on the server, potentially achieving full Remote Code Execution (RCE) and complete system compromise.",
    "remediation": "1. Never embed user-supplied data directly into template strings — use template variables instead.\n2. Apply strict input validation and reject template metacharacters ({{, }}, {%, etc.).\n3. Run the application with minimal OS privileges to limit RCE blast radius.\n4. Use sandboxed template environments where available.\n5. Audit all template rendering code for user-controlled input.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
      "https://cwe.mitre.org/data/definitions/94.html",
      "https://portswigger.net/research/server-side-template-injection"
    ]
  },
  {
    "id": "lfi",
    "category_pattern": "Input Validation",
    "title_keywords": ["lfi", "local file inclusion", "path traversal", "directory traversal", "../"],
    "wstg_id": "WSTG-INPV-11",
    "cwe_id": "CWE-22",
    "cvss_score_v4": 7.5,
    "explanation": "Local File Inclusion (LFI) and Path Traversal vulnerabilities allow attackers to read arbitrary files from the server filesystem by manipulating file path parameters. Sensitive files such as /etc/passwd, application configs, and private keys may be exposed, potentially leading to further compromise.",
    "remediation": "1. Validate and sanitize all file path inputs — reject sequences like ../ and absolute paths.\n2. Use an allowlist of permitted file names or directories.\n3. Resolve file paths to canonical form and verify they remain within the intended base directory.\n4. Run the application process with minimal filesystem permissions.\n5. Disable directory listing on the web server.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
      "https://cwe.mitre.org/data/definitions/22.html"
    ]
  },
  {
    "id": "nosql-injection",
    "category_pattern": "Input Validation",
    "title_keywords": ["nosql injection", "nosql", "mongodb injection", "no-sql"],
    "wstg_id": "WSTG-INPV-05",
    "cwe_id": "CWE-943",
    "cvss_score_v4": 8.6,
    "explanation": "NoSQL Injection allows attackers to manipulate NoSQL database queries (e.g., MongoDB) by injecting query operators through user-supplied input. This can bypass authentication, enumerate data, or cause denial of service through expensive query operations.",
    "remediation": "1. Validate input types strictly — reject objects/arrays where strings are expected.\n2. Use parameterized queries or ORM query builders that separate data from query logic.\n3. Sanitize inputs to strip NoSQL operator prefixes ($where, $gt, $regex).\n4. Apply schema validation at the database level.\n5. Disable JavaScript execution in the database if not required (e.g., MongoDB --noscripting).",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
      "https://cwe.mitre.org/data/definitions/943.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
    ]
  },
  {
    "id": "hpp",
    "category_pattern": "Input Validation",
    "title_keywords": ["http parameter pollution", "hpp", "parameter pollution", "duplicate parameter"],
    "wstg_id": "WSTG-INPV-04",
    "cwe_id": "CWE-235",
    "cvss_score_v4": 5.3,
    "explanation": "HTTP Parameter Pollution (HPP) occurs when an application accepts multiple values for the same parameter but processes them inconsistently. Attackers can exploit different parsing behaviors between WAF, proxy, and application layers to bypass security controls or manipulate application logic.",
    "remediation": "1. Define explicit behavior for duplicate parameters — accept only the first or last value consistently.\n2. Implement server-side parameter validation that rejects duplicate parameters.\n3. Ensure WAF and application server parse parameters identically.\n4. Audit all endpoints that process query string or body parameters.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
      "https://cwe.mitre.org/data/definitions/235.html"
    ]
  },
  {
    "id": "redos",
    "category_pattern": "Input Validation",
    "title_keywords": ["redos", "regex denial", "regular expression denial", "catastrophic backtracking"],
    "wstg_id": "WSTG-INPV-19",
    "cwe_id": "CWE-1333",
    "cvss_score_v4": 5.9,
    "explanation": "Regular Expression Denial of Service (ReDoS) exploits pathological regex patterns that exhibit exponential backtracking when processing specially crafted inputs. Attackers can cause CPU exhaustion and application unavailability by submitting inputs designed to trigger worst-case regex behavior.",
    "remediation": "1. Audit all regex patterns for polynomial or exponential worst-case complexity.\n2. Replace vulnerable patterns with non-backtracking alternatives.\n3. Apply input length limits before regex evaluation.\n4. Use regex timeout libraries (e.g., re2) that guarantee linear time matching.\n5. Use static analysis tools (safe-regex, vuln-regex-detector) during code review.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Regular_Expression_Denial_of_Service",
      "https://cwe.mitre.org/data/definitions/1333.html"
    ]
  },
  {
    "id": "csrf",
    "category_pattern": "Input Validation",
    "title_keywords": ["csrf", "cross-site request forgery", "csrftoken missing"],
    "wstg_id": "WSTG-SESS-05",
    "cwe_id": "CWE-352",
    "cvss_score_v4": 6.5,
    "explanation": "Cross-Site Request Forgery (CSRF) tricks authenticated users into unknowingly submitting malicious requests to an application they are logged into. Attackers can force state-changing actions (password changes, fund transfers, account settings) without the user's knowledge.",
    "remediation": "1. Implement synchronizer token pattern — embed unpredictable CSRF tokens in all state-changing requests.\n2. Use SameSite=Strict or SameSite=Lax cookie attribute.\n3. Validate the Origin and Referer headers for sensitive operations.\n4. Require re-authentication for critical actions (password change, fund transfer).\n5. Avoid using GET requests for state-changing operations.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery",
      "https://cwe.mitre.org/data/definitions/352.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
    ]
  },
  {
    "id": "brute-force",
    "category_pattern": "Authentication",
    "title_keywords": ["brute force", "brute-force", "credential stuffing", "account lockout missing", "rate limit login"],
    "wstg_id": "WSTG-ATHN-03",
    "cwe_id": "CWE-307",
    "cvss_score_v4": 7.5,
    "explanation": "Missing or weak brute force protection allows attackers to systematically guess credentials through automated login attempts. Without account lockout, CAPTCHA, or rate limiting, attackers can compromise accounts using credential lists or dictionary attacks.",
    "remediation": "1. Implement account lockout after N failed attempts (e.g., 5–10) with exponential backoff.\n2. Apply rate limiting on authentication endpoints (e.g., 5 requests/minute per IP).\n3. Implement CAPTCHA for repeated failures.\n4. Use multi-factor authentication (MFA) for all accounts.\n5. Monitor and alert on high-volume authentication failures.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
      "https://cwe.mitre.org/data/definitions/307.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
    ]
  },
  {
    "id": "weak-password",
    "category_pattern": "Authentication",
    "title_keywords": ["weak password", "password policy", "password strength", "default credential", "default password"],
    "wstg_id": "WSTG-ATHN-07",
    "cwe_id": "CWE-521",
    "cvss_score_v4": 7.3,
    "explanation": "Weak password policies or the use of default credentials allow attackers to easily guess or reuse passwords to gain unauthorized access. Default credentials in administrative interfaces are a common initial access vector for attackers.",
    "remediation": "1. Enforce minimum password complexity: 12+ characters, mixed case, digits, special chars.\n2. Check new passwords against known-breached password lists (e.g., HaveIBeenPwned API).\n3. Immediately change all default credentials post-installation.\n4. Implement MFA for all privileged accounts.\n5. Store passwords using bcrypt, Argon2, or scrypt with appropriate work factors.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy",
      "https://cwe.mitre.org/data/definitions/521.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
    ]
  },
  {
    "id": "2fa-bypass",
    "category_pattern": "Authentication",
    "title_keywords": ["2fa bypass", "mfa bypass", "totp bypass", "two-factor bypass", "otp bypass"],
    "wstg_id": "WSTG-ATHN-11",
    "cwe_id": "CWE-287",
    "cvss_score_v4": 8.1,
    "explanation": "Two-Factor Authentication (2FA) bypass vulnerabilities allow attackers to circumvent the second authentication factor, reducing security to single-factor. Common bypasses include brute-forcing short OTPs, reusing expired tokens, or skipping the 2FA step entirely through direct URL access.",
    "remediation": "1. Rate-limit OTP validation attempts (max 3–5 per code).\n2. Enforce OTP expiry (30–60 seconds for TOTP).\n3. Mark OTPs as used immediately after validation to prevent reuse.\n4. Verify 2FA completion server-side before granting access to protected resources.\n5. Alert users on failed 2FA attempts.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication",
      "https://cwe.mitre.org/data/definitions/287.html"
    ]
  },
  {
    "id": "idor",
    "category_pattern": "Authorization",
    "title_keywords": ["idor", "insecure direct object reference", "broken object", "bola", "unauthorized access to"],
    "wstg_id": "WSTG-ATHZ-04",
    "cwe_id": "CWE-639",
    "cvss_score_v4": 8.1,
    "explanation": "Insecure Direct Object Reference (IDOR) occurs when an application uses user-controllable identifiers to access objects without verifying that the requesting user has permission. Attackers can enumerate IDs to access other users' data, orders, profiles, or administrative functions.",
    "remediation": "1. Implement server-side authorization checks on every object access — verify the requesting user owns or has permission for the requested resource.\n2. Use indirect references (UUIDs or tokens) instead of sequential integer IDs.\n3. Apply the principle of least privilege for all data access operations.\n4. Conduct authorization testing as part of QA for every new endpoint.\n5. Log and alert on repeated access to non-owned resources.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
      "https://cwe.mitre.org/data/definitions/639.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
    ]
  },
  {
    "id": "privilege-escalation",
    "category_pattern": "Authorization",
    "title_keywords": ["privilege escalation", "privilege escalation", "admin access", "role escalation", "horizontal escalation", "vertical escalation"],
    "wstg_id": "WSTG-ATHZ-03",
    "cwe_id": "CWE-269",
    "cvss_score_v4": 8.8,
    "explanation": "Privilege escalation vulnerabilities allow attackers to gain elevated permissions beyond what they are authorized for. Vertical escalation grants administrative rights; horizontal escalation allows acting as another user at the same privilege level. Both can result in unauthorized data access or system control.",
    "remediation": "1. Enforce role-based access control (RBAC) with server-side validation for every privileged operation.\n2. Never trust client-supplied role or privilege parameters.\n3. Apply the principle of least privilege — users should have minimum permissions required.\n4. Audit all administrative functions to ensure proper role checks.\n5. Log all privilege-sensitive operations and alert on anomalies.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation",
      "https://cwe.mitre.org/data/definitions/269.html"
    ]
  },
  {
    "id": "user-spoofing",
    "category_pattern": "Authorization",
    "title_keywords": ["user spoofing", "userid manipulation", "user id tampering", "user impersonation"],
    "wstg_id": "WSTG-ATHZ-02",
    "cwe_id": "CWE-284",
    "cvss_score_v4": 8.1,
    "explanation": "User spoofing vulnerabilities allow attackers to impersonate other users by manipulating user identifiers in requests (e.g., userId, authorId fields). This enables unauthorized actions such as posting as another user, modifying their data, or accessing their resources.",
    "remediation": "1. Never accept user identity from client-supplied parameters — derive identity exclusively from the authenticated session.\n2. Validate that the requesting user's session identity matches the resource owner server-side.\n3. Audit all endpoints that accept user ID parameters for missing authorization checks.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
      "https://cwe.mitre.org/data/definitions/284.html"
    ]
  },
  {
    "id": "session-fixation",
    "category_pattern": "Session",
    "title_keywords": ["session fixation", "session not regenerated", "session id reuse after login"],
    "wstg_id": "WSTG-SESS-03",
    "cwe_id": "CWE-384",
    "cvss_score_v4": 6.8,
    "explanation": "Session fixation allows an attacker to set a victim's session ID before authentication and then hijack the session after the victim logs in, since the application does not issue a new session ID post-login. This results in unauthorized account access.",
    "remediation": "1. Generate a new session ID immediately after successful authentication.\n2. Invalidate the pre-authentication session ID.\n3. Use cryptographically random session IDs with sufficient entropy (128+ bits).\n4. Set session cookies with HttpOnly, Secure, and SameSite attributes.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation",
      "https://cwe.mitre.org/data/definitions/384.html"
    ]
  },
  {
    "id": "session-cookie-flags",
    "category_pattern": "Session",
    "title_keywords": ["httponly missing", "secure flag missing", "samesite missing", "cookie flag", "session cookie"],
    "wstg_id": "WSTG-SESS-02",
    "cwe_id": "CWE-614",
    "cvss_score_v4": 5.9,
    "explanation": "Missing cookie security flags expose session tokens to theft. Without HttpOnly, JavaScript can steal cookies via XSS. Without Secure, cookies are transmitted over HTTP. Without SameSite, cookies are sent on cross-site requests enabling CSRF.",
    "remediation": "1. Set HttpOnly flag on all session cookies to prevent JavaScript access.\n2. Set Secure flag to ensure cookies are only sent over HTTPS.\n3. Set SameSite=Strict or SameSite=Lax to prevent CSRF via cross-site requests.\n4. Regularly rotate session IDs and expire idle sessions.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
      "https://cwe.mitre.org/data/definitions/614.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
    ]
  },
  {
    "id": "security-headers-missing",
    "category_pattern": "Configuration",
    "title_keywords": ["missing security header", "x-frame-options", "x-content-type", "security headers", "hsts missing", "csp missing header"],
    "wstg_id": "WSTG-CONF-07",
    "cwe_id": "CWE-693",
    "cvss_score_v4": 5.3,
    "explanation": "Missing HTTP security headers leave the application vulnerable to multiple attack classes. X-Frame-Options prevents clickjacking; X-Content-Type-Options prevents MIME sniffing; HSTS enforces HTTPS; CSP restricts script execution. Their absence increases the attack surface.",
    "remediation": "1. Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n2. Add X-Frame-Options: DENY or SAMEORIGIN\n3. Add X-Content-Type-Options: nosniff\n4. Add Content-Security-Policy with a restrictive policy\n5. Add Referrer-Policy: strict-origin-when-cross-origin\n6. Add Permissions-Policy to restrict browser features",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
      "https://cwe.mitre.org/data/definitions/693.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
    ]
  },
  {
    "id": "directory-listing",
    "category_pattern": "Configuration",
    "title_keywords": ["directory listing", "directory traversal exposed", "open directory", "index of /"],
    "wstg_id": "WSTG-CONF-04",
    "cwe_id": "CWE-548",
    "cvss_score_v4": 5.3,
    "explanation": "Enabled directory listing exposes the file structure of the web server, allowing attackers to discover sensitive files, backup archives, configuration files, and application source code that should not be publicly accessible.",
    "remediation": "1. Disable directory listing in web server configuration (Apache: Options -Indexes, Nginx: autoindex off).\n2. Remove all sensitive files from web-accessible directories.\n3. Implement access controls for any directories that must be browsable.\n4. Regularly audit web-accessible directories for unexpected files.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
      "https://cwe.mitre.org/data/definitions/548.html"
    ]
  },
  {
    "id": "exposed-git",
    "category_pattern": "Configuration",
    "title_keywords": ["exposed .git", "git repository exposed", ".git accessible", "git config exposed"],
    "wstg_id": "WSTG-CONF-04",
    "cwe_id": "CWE-538",
    "cvss_score_v4": 7.5,
    "explanation": "An exposed .git directory allows attackers to download the complete application source code, commit history, hardcoded secrets, API keys, database credentials, and internal infrastructure details. This significantly accelerates further attacks against the application.",
    "remediation": "1. Block access to .git directories in web server configuration (deny from all).\n2. Use infrastructure-as-code to enforce this at deployment time.\n3. Rotate any secrets that may have been exposed in git history.\n4. Use git-secrets or similar tools to prevent committing secrets.\n5. Review git history for any sensitive data using tools like truffleHog.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
      "https://cwe.mitre.org/data/definitions/538.html"
    ]
  },
  {
    "id": "npm-vulnerabilities",
    "category_pattern": "Configuration",
    "title_keywords": ["npm vulnerability", "vulnerable dependency", "cve in package", "outdated package", "known vulnerability"],
    "wstg_id": "WSTG-CONF-02",
    "cwe_id": "CWE-1395",
    "cvss_score_v4": 7.0,
    "explanation": "Using components with known vulnerabilities exposes the application to exploitation of publicly disclosed CVEs. Outdated npm packages may contain security flaws that attackers can exploit using publicly available proof-of-concept code.",
    "remediation": "1. Run npm audit regularly and remediate high/critical findings immediately.\n2. Implement automated dependency scanning in CI/CD (Dependabot, Snyk, OWASP Dependency-Check).\n3. Update dependencies promptly when security patches are released.\n4. Pin dependency versions and review updates before applying.\n5. Remove unused dependencies to reduce attack surface.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
      "https://cwe.mitre.org/data/definitions/1395.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html"
    ]
  },
  {
    "id": "hidden-endpoints",
    "category_pattern": "Configuration",
    "title_keywords": ["hidden endpoint", "exposed admin", "sensitive endpoint", "/ftp", "/metrics", "/admin exposed", "backup file"],
    "wstg_id": "WSTG-CONF-05",
    "cwe_id": "CWE-200",
    "cvss_score_v4": 5.3,
    "explanation": "Exposed hidden or administrative endpoints allow attackers to access debugging interfaces, metrics, file listings, or backup data that should not be publicly reachable. These endpoints often lack authentication and expose sensitive operational data.",
    "remediation": "1. Restrict administrative and debug endpoints to internal networks or VPN.\n2. Apply authentication to all sensitive endpoints.\n3. Remove or disable debug/development endpoints in production.\n4. Regularly audit exposed endpoints using crawlers and directory fuzzing.\n5. Implement IP allowlisting for administrative interfaces.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
      "https://cwe.mitre.org/data/definitions/200.html"
    ]
  },
  {
    "id": "clickjacking",
    "category_pattern": "Client",
    "title_keywords": ["clickjacking", "x-frame-options missing", "framing allowed", "iframe allowed"],
    "wstg_id": "WSTG-CLNT-09",
    "cwe_id": "CWE-1021",
    "cvss_score_v4": 4.3,
    "explanation": "Clickjacking allows attackers to embed the target application in an invisible iframe within a malicious page, tricking users into clicking elements they cannot see. This can lead to unintended actions such as unauthorized transactions, account changes, or data submission.",
    "remediation": "1. Set X-Frame-Options: DENY or SAMEORIGIN response header.\n2. Implement Content-Security-Policy: frame-ancestors 'none' or 'self'.\n3. Use JavaScript frame-busting as a defense-in-depth measure.\n4. Verify that sensitive actions require explicit user confirmation.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-Side_Testing/09-Testing_for_Clickjacking",
      "https://cwe.mitre.org/data/definitions/1021.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
    ]
  },
  {
    "id": "open-redirect",
    "category_pattern": "Client",
    "title_keywords": ["open redirect", "unvalidated redirect", "redirect bypass", "redirect to external"],
    "wstg_id": "WSTG-CLNT-04",
    "cwe_id": "CWE-601",
    "cvss_score_v4": 6.1,
    "explanation": "Open redirect vulnerabilities allow attackers to craft URLs on a trusted domain that redirect victims to attacker-controlled sites. This is commonly exploited in phishing attacks where the trusted domain increases victim confidence in clicking the link.",
    "remediation": "1. Use an allowlist of permitted redirect destinations.\n2. Avoid using user-supplied data in redirect targets.\n3. Validate that redirect URLs belong to the application domain before redirecting.\n4. Display a warning page for external redirects with explicit user confirmation.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-Side_Testing/04-Testing_for_Client_Side_URL_Redirect",
      "https://cwe.mitre.org/data/definitions/601.html"
    ]
  },
  {
    "id": "csp-missing-weak",
    "category_pattern": "Client",
    "title_keywords": ["csp missing", "csp weak", "content security policy", "csp bypass", "unsafe-inline", "unsafe-eval"],
    "wstg_id": "WSTG-CLNT-12",
    "cwe_id": "CWE-693",
    "cvss_score_v4": 5.3,
    "explanation": "A missing or weak Content Security Policy (CSP) fails to restrict which resources the browser may load, increasing the impact of XSS and data injection attacks. Directives like unsafe-inline and unsafe-eval negate most CSP protection.",
    "remediation": "1. Implement a strict CSP: default-src 'self'; script-src 'self'; object-src 'none'.\n2. Eliminate inline scripts and event handlers — use external script files.\n3. Replace eval() and similar dynamic code execution patterns.\n4. Use CSP nonces or hashes for required inline scripts.\n5. Test your CSP with Google CSP Evaluator.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-Side_Testing/12-Testing_for_Content_Security_Policy",
      "https://cwe.mitre.org/data/definitions/693.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
    ]
  },
  {
    "id": "cors-misconfiguration",
    "category_pattern": "Client",
    "title_keywords": ["cors misconfiguration", "cors", "access-control-allow-origin", "cors wildcard", "cors any origin"],
    "wstg_id": "WSTG-CLNT-07",
    "cwe_id": "CWE-942",
    "cvss_score_v4": 6.5,
    "explanation": "CORS misconfiguration allows unauthorized cross-origin requests to read sensitive API responses. Reflecting arbitrary origins or using wildcard (*) with credentials enabled allows attacker-controlled sites to make authenticated requests and read the responses on behalf of victims.",
    "remediation": "1. Define an explicit allowlist of trusted origins — never reflect arbitrary Origin headers.\n2. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.\n3. Restrict CORS to specific HTTP methods and headers required.\n4. Validate the Origin header server-side against the allowlist.\n5. Apply CORS policies on a per-endpoint basis, not globally.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
      "https://cwe.mitre.org/data/definitions/942.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
    ]
  },
  {
    "id": "rate-limiting-missing",
    "category_pattern": "Business Logic",
    "title_keywords": ["rate limiting missing", "no rate limit", "missing rate limit", "rate limit absent", "unlimited requests"],
    "wstg_id": "WSTG-BUSL-08",
    "cwe_id": "CWE-799",
    "cvss_score_v4": 5.3,
    "explanation": "Missing rate limiting allows attackers to make unlimited automated requests to application endpoints, enabling brute force attacks, resource exhaustion, data scraping, and abuse of expensive operations (email sending, OTP generation, file processing).",
    "remediation": "1. Implement rate limiting on all sensitive endpoints (login, registration, OTP, API).\n2. Apply per-IP and per-user rate limits with exponential backoff for repeat offenders.\n3. Return HTTP 429 Too Many Requests with Retry-After headers.\n4. Implement CAPTCHA for endpoints vulnerable to automated abuse.\n5. Use API gateway or WAF rate limiting as defense-in-depth.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types",
      "https://cwe.mitre.org/data/definitions/799.html"
    ]
  },
  {
    "id": "coupon-forgery",
    "category_pattern": "Business Logic",
    "title_keywords": ["coupon forgery", "discount abuse", "coupon bypass", "expired coupon", "coupon manipulation"],
    "wstg_id": "WSTG-BUSL-09",
    "cwe_id": "CWE-840",
    "cvss_score_v4": 5.4,
    "explanation": "Business logic flaws in coupon or discount systems allow attackers to forge, reuse, or abuse discount codes beyond their intended parameters — using expired coupons, applying codes multiple times, or manipulating discount values. This causes direct financial losses.",
    "remediation": "1. Validate coupon codes server-side — check expiry, usage limits, and user eligibility.\n2. Mark coupons as used atomically in the database to prevent race conditions.\n3. Bind coupons to specific user accounts where applicable.\n4. Log and monitor coupon usage for anomalous patterns.\n5. Implement server-side validation of all discount calculations — never trust client-computed prices.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files",
      "https://cwe.mitre.org/data/definitions/840.html"
    ]
  },
  {
    "id": "negative-quantity",
    "category_pattern": "Business Logic",
    "title_keywords": ["negative quantity", "negative value", "negative price", "integer overflow order"],
    "wstg_id": "WSTG-BUSL-05",
    "cwe_id": "CWE-840",
    "cvss_score_v4": 6.5,
    "explanation": "Business logic vulnerabilities allowing negative quantities or prices let attackers manipulate order totals to receive refunds or products for free. These flaws arise when input validation enforces only format (is it a number?) but not business rules (must be positive).",
    "remediation": "1. Validate that all quantity and price inputs are positive integers or decimals.\n2. Apply minimum/maximum bounds on all numeric business parameters.\n3. Perform total calculation server-side — never trust client-computed prices.\n4. Implement sanity checks before processing orders (total must be > 0).",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits",
      "https://cwe.mitre.org/data/definitions/840.html"
    ]
  },
  {
    "id": "user-enumeration",
    "category_pattern": "Identity Management",
    "title_keywords": ["user enumeration", "username enumeration", "account enumeration", "email enumeration"],
    "wstg_id": "WSTG-IDMG-04",
    "cwe_id": "CWE-204",
    "cvss_score_v4": 5.3,
    "explanation": "User enumeration allows attackers to determine valid usernames or email addresses by observing differences in application responses (different error messages, response times, or HTTP status codes for valid vs. invalid accounts). This information is used to target credential attacks.",
    "remediation": "1. Return identical error messages for failed login attempts regardless of whether the username exists.\n2. Normalize response times for valid and invalid account lookups.\n3. Return the same response for registered and unregistered email addresses in password reset flows.\n4. Implement rate limiting and CAPTCHA on authentication endpoints.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
      "https://cwe.mitre.org/data/definitions/204.html"
    ]
  },
  {
    "id": "mass-assignment",
    "category_pattern": "Identity Management",
    "title_keywords": ["mass assignment", "parameter binding", "role injection", "admin role injection", "registration mass"],
    "wstg_id": "WSTG-IDMG-03",
    "cwe_id": "CWE-915",
    "cvss_score_v4": 8.8,
    "explanation": "Mass assignment vulnerabilities occur when an application automatically binds all request parameters to model properties without filtering, allowing attackers to set fields that should not be user-controllable — such as role, isAdmin, or accountBalance — during registration or update operations.",
    "remediation": "1. Use an explicit allowlist of permitted fields for model binding — never bind all request parameters automatically.\n2. Validate that sensitive fields (role, isAdmin, verified) cannot be set via user-supplied data.\n3. Apply separate DTOs (Data Transfer Objects) for user input vs. internal models.\n4. Audit all registration, update, and profile API endpoints for unintended field binding.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process",
      "https://cwe.mitre.org/data/definitions/915.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
    ]
  },
  {
    "id": "weak-tls",
    "category_pattern": "Cryptography",
    "title_keywords": ["weak tls", "ssl vulnerability", "tls 1.0", "tls 1.1", "weak cipher", "ssl weak", "tls misconfiguration"],
    "wstg_id": "WSTG-CRYP-01",
    "cwe_id": "CWE-326",
    "cvss_score_v4": 5.9,
    "explanation": "Weak TLS configurations expose encrypted communications to interception through protocol downgrade attacks or exploitation of weak cipher suites. TLS 1.0 and 1.1 are deprecated and contain known vulnerabilities including POODLE and BEAST.",
    "remediation": "1. Disable TLS 1.0 and TLS 1.1 — support TLS 1.2 and TLS 1.3 only.\n2. Disable weak cipher suites (RC4, DES, 3DES, export-grade ciphers).\n3. Enable Perfect Forward Secrecy (ECDHE cipher suites).\n4. Configure HSTS with a long max-age.\n5. Test configuration with SSL Labs (ssllabs.com/ssltest/) and achieve A+ rating.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
      "https://cwe.mitre.org/data/definitions/326.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
    ]
  },
  {
    "id": "weak-hashing",
    "category_pattern": "Cryptography",
    "title_keywords": ["weak hash", "md5", "sha1 password", "weak password hash", "plaintext password", "unsalted hash"],
    "wstg_id": "WSTG-CRYP-04",
    "cwe_id": "CWE-916",
    "cvss_score_v4": 7.5,
    "explanation": "Using weak or unsalted hashing algorithms (MD5, SHA-1) for password storage makes hashes trivially reversible using rainbow tables or GPU-based cracking. Passwords stored with weak hashes are effectively compromised if the database is breached.",
    "remediation": "1. Replace MD5/SHA-1 password hashes with bcrypt, Argon2id, or scrypt.\n2. Use appropriate work factors: bcrypt cost ≥ 12, Argon2id with recommended parameters.\n3. Always use a unique per-password salt (handled automatically by bcrypt/Argon2).\n4. Implement a password migration strategy to re-hash existing passwords on next login.\n5. Never store passwords in plaintext or with reversible encryption.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption",
      "https://cwe.mitre.org/data/definitions/916.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
    ]
  },
  {
    "id": "stack-trace-exposure",
    "category_pattern": "Error Handling",
    "title_keywords": ["stack trace", "error disclosure", "exception exposed", "debug information", "verbose error"],
    "wstg_id": "WSTG-ERRH-01",
    "cwe_id": "CWE-209",
    "cvss_score_v4": 4.3,
    "explanation": "Stack traces and verbose error messages expose internal implementation details including file paths, framework versions, database schemas, and code structure. This information greatly assists attackers in planning targeted attacks against the application.",
    "remediation": "1. Configure the application to display generic error messages to end users in production.\n2. Log detailed errors server-side to a secure, centralized logging system.\n3. Disable debug mode in production environments.\n4. Implement a global exception handler that catches all unhandled exceptions and returns sanitized responses.\n5. Review all error responses for information leakage before deployment.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling",
      "https://cwe.mitre.org/data/definitions/209.html"
    ]
  },
  {
    "id": "file-upload-unrestricted",
    "category_pattern": "File Upload",
    "title_keywords": ["file upload", "unrestricted upload", "malicious upload", "webshell upload", "executable upload"],
    "wstg_id": "WSTG-BUSL-08",
    "cwe_id": "CWE-434",
    "cvss_score_v4": 9.8,
    "explanation": "Unrestricted file upload allows attackers to upload malicious files including web shells, executables, or malware. If the server executes uploaded files, this leads to Remote Code Execution. Even without execution, uploaded files can serve as malware distribution or phishing attack infrastructure.",
    "remediation": "1. Validate file type using magic bytes (file signature), not just extension or MIME type.\n2. Use an allowlist of permitted file types — reject all others.\n3. Store uploaded files outside the web root or in a dedicated storage service (S3, etc.).\n4. Rename uploaded files with random names — never use user-supplied filenames.\n5. Scan uploaded files with antivirus before serving.\n6. Serve uploaded files with Content-Disposition: attachment to prevent browser execution.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types",
      "https://cwe.mitre.org/data/definitions/434.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
    ]
  },
  {
    "id": "information-disclosure",
    "category_pattern": "Information Gathering",
    "title_keywords": ["information disclosure", "sensitive information", "technology disclosure", "version disclosure", "server header"],
    "wstg_id": "WSTG-INFO-02",
    "cwe_id": "CWE-200",
    "cvss_score_v4": 4.3,
    "explanation": "Information disclosure exposes details about the application's technology stack, version numbers, internal architecture, or sensitive data. This information assists attackers in identifying known CVEs and crafting targeted exploits.",
    "remediation": "1. Remove version information from HTTP response headers (Server, X-Powered-By).\n2. Configure error pages to not reveal technology stack details.\n3. Disable server signature in web server configuration.\n4. Review API responses for unintentionally exposed internal data.\n5. Regularly audit HTTP headers and responses for information leakage.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
      "https://cwe.mitre.org/data/definitions/200.html"
    ]
  },
  {
    "id": "api-missing-auth",
    "category_pattern": "API Testing",
    "title_keywords": ["api unauthenticated", "api missing authentication", "api endpoint exposed", "unauthenticated api", "api no auth"],
    "wstg_id": "WSTG-ATHZ-01",
    "cwe_id": "CWE-306",
    "cvss_score_v4": 9.1,
    "explanation": "API endpoints lacking authentication controls allow any user or automated scanner to access sensitive data or perform privileged operations without credentials. This is a critical vulnerability in REST APIs where endpoints may inadvertently expose business logic or user data.",
    "remediation": "1. Apply authentication requirements to all API endpoints that handle sensitive data or operations.\n2. Use API gateway to enforce authentication centrally.\n3. Implement JWT or OAuth 2.0 bearer token validation on every request.\n4. Audit all API endpoints for missing authentication using automated scanning.\n5. Apply deny-by-default access control — require explicit grant of access.",
    "references": [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
      "https://cwe.mitre.org/data/definitions/306.html",
      "https://owasp.org/www-project-api-security/"
    ]
  }
]
```

- [ ] **Step 2: Run all KB tests**

```bash
python -m pytest multi_agent_system/tests/test_enrichment.py -v 2>&1 | tail -30
```

Expected: All tests PASS (KB now loaded, matcher finds entries).

- [ ] **Step 3: Commit**

```bash
git add multi_agent_system/data/enrichment_kb.json
git commit -m "feat(enrichment): add static knowledge base with 33 WSTG-mapped vulnerability entries"
```

---

## Task 4: Create Jinja2 prompt template + templates directory

**Files:**
- Create: `multi_agent_system/templates/enrichment_prompt.j2`

- [ ] **Step 1: Create templates directory and prompt template**

```bash
mkdir -p /mnt/d/MCP/RAJDOLL/multi_agent_system/templates
```

Create `multi_agent_system/templates/enrichment_prompt.j2`:

```jinja2
You are a senior penetration tester writing a professional security assessment report.
Analyze the following vulnerability finding and return structured enrichment data.

Finding details:
- Category: {{ category }}
- Title: {{ title }}
- Severity: {{ severity }}
- Evidence summary: {{ evidence_summary }}

Return a JSON object with exactly these fields:
- "explanation": A professional 2-3 sentence explanation of what this vulnerability is, how it is exploited, and its business impact. Use clear, non-technical language suitable for executive and technical audiences.
- "remediation": Step-by-step remediation as a numbered markdown list with minimum 3 actionable steps. Each step must be specific and implementable.
- "cwe_id": The most applicable CWE ID as a string (e.g. "CWE-79"), or empty string "" if truly unknown.
- "wstg_id": The most applicable OWASP WSTG 4.2 test case ID (e.g. "WSTG-INPV-01"), or empty string "" if truly unknown.
- "cvss_score_v4": An estimated CVSS 4.0 base score as a float between 0.0 and 10.0. Use 0.0 only if completely unable to estimate.
- "references": A list of 2-3 relevant URLs. Prefer OWASP WSTG links, CWE definitions, and OWASP Cheat Sheets.
```

- [ ] **Step 2: Verify the template is found by LLMEnricher**

```bash
python -c "
from pathlib import Path
p = Path('multi_agent_system/templates/enrichment_prompt.j2')
print('EXISTS:', p.exists())
print('CONTENT:', p.read_text()[:50])
"
```

Expected: `EXISTS: True`

- [ ] **Step 3: Commit**

```bash
git add multi_agent_system/templates/enrichment_prompt.j2
git commit -m "feat(enrichment): add Jinja2 LLM enrichment prompt template"
```

---

## Task 5: Wire EnrichmentService into add_finding()

**Files:**
- Modify: `multi_agent_system/agents/base_agent.py:460-479`

- [ ] **Step 1: Update add_finding() to call EnrichmentService after DB write**

In `multi_agent_system/agents/base_agent.py`, replace the `add_finding` method (lines 460-479):

```python
def add_finding(self, category: str, title: str, severity: str = "info", evidence: dict | None = None, details: str | None = None) -> None:
    # Sanitize evidence to prevent unhashable type errors
    if evidence is not None:
        try:
            import json
            json.dumps(evidence)
        except (TypeError, ValueError) as e:
            evidence = {"raw": str(evidence), "error": f"Evidence not JSON-serializable: {e}"}

    finding_id = None
    with get_db() as db:
        db.add(Finding(job_id=self.job_id, agent_name=self.agent_name, category=category, title=title, severity=severity, evidence=evidence, details=details))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            import sys
            print(f"⚠️  {self.agent_name}: Duplicate finding skipped: {title}", file=sys.stderr, flush=True)
            return

    # Enrich the finding with explanation, remediation, references, CVSS 4.0, CWE/WSTG IDs
    try:
        from ..utils.enrichment_service import EnrichmentService
        enrichment = EnrichmentService.enrich(category, title, severity, evidence or {})
        with get_db() as db:
            finding = db.query(Finding).filter(
                Finding.job_id == self.job_id,
                Finding.agent_name == self.agent_name,
                Finding.category == category,
                Finding.title == title,
            ).one_or_none()
            if finding:
                finding.explanation = enrichment.explanation
                finding.remediation = enrichment.remediation
                finding.cwe_id = enrichment.cwe_id
                finding.wstg_id = enrichment.wstg_id
                finding.cvss_score_v4 = enrichment.cvss_score_v4
                finding.references = enrichment.references
                finding.enrichment_source = enrichment.source
                db.commit()
    except Exception as e:
        import sys
        print(f"⚠️  {self.agent_name}: Enrichment failed for '{title}': {e}", file=sys.stderr, flush=True)
        # Enrichment failure never blocks a finding from being recorded
```

- [ ] **Step 2: Also update add_finding_with_confidence() to call add_finding()**

Find `add_finding_with_confidence` in `base_agent.py`. It calls `self.add_finding(...)` at the end — verify this is true so enrichment runs automatically via the shared `add_finding` method. If it calls `db.add(Finding(...))` directly, update it to call `self.add_finding(...)` instead.

```bash
grep -n "add_finding\|db.add(Finding" /mnt/d/MCP/RAJDOLL/multi_agent_system/agents/base_agent.py | head -20
```

If `add_finding_with_confidence` calls `self.add_finding(category, title, severity, enhanced_evidence, details)` on its last line — no change needed, enrichment runs through the shared method.

- [ ] **Step 3: Run existing tests to verify no regressions**

```bash
python -m pytest multi_agent_system/tests/test_vdp_generalization.py -v 2>&1 | tail -20
```

Expected: All 15 tests still PASS.

- [ ] **Step 4: Commit**

```bash
git add multi_agent_system/agents/base_agent.py
git commit -m "feat(enrichment): wire EnrichmentService into add_finding() at write time"
```

---

## Task 6: Create report.html.j2 Jinja2 PDF template

**Files:**
- Create: `multi_agent_system/templates/report.html.j2`

- [ ] **Step 1: Create the Jinja2 HTML template**

Create `multi_agent_system/templates/report.html.j2`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RAJDOLL Security Report — {{ target }}</title>
<style>
@page {
    size: A4;
    margin: 2cm;
    @top-left { content: "RAJDOLL Security Assessment"; font-size: 8pt; color: #888; }
    @top-right { content: "CONFIDENTIAL"; font-size: 8pt; color: #c62828; font-weight: bold; }
    @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888; }
}
body { font-family: Arial, sans-serif; font-size: 10pt; line-height: 1.6; color: #333; }
h1 { color: #1565c0; font-size: 20pt; border-bottom: 2px solid #1565c0; padding-bottom: 6px; margin-top: 0; }
h2 { color: #0d47a1; font-size: 15pt; border-bottom: 1px solid #90caf9; padding-bottom: 4px; margin-top: 30px; }
h3 { color: #1565c0; font-size: 12pt; margin-top: 20px; }
table { width: 100%; border-collapse: collapse; margin: 15px 0; }
th { background: #1565c0; color: white; padding: 8px; text-align: left; font-size: 9pt; }
td { padding: 6px 8px; border-bottom: 1px solid #e0e0e0; font-size: 9pt; vertical-align: top; }
tr:nth-child(even) td { background: #f5f5f5; }
.cover { text-align: center; page-break-after: always; padding-top: 80pt; }
.cover h1 { border: none; font-size: 30pt; color: #1565c0; }
.cover .subtitle { font-size: 14pt; color: #666; margin-top: 10px; }
.cover .meta { margin-top: 60pt; font-size: 11pt; line-height: 2; }
.cover .confidential { margin-top: 40pt; display: inline-block; padding: 10px 25px; border: 2px solid #c62828; color: #c62828; font-weight: bold; font-size: 13pt; letter-spacing: 3px; }
.toc { page-break-after: always; }
.toc ul { list-style: none; padding: 0; }
.toc li { padding: 5px 0; border-bottom: 1px dotted #ccc; display: flex; justify-content: space-between; }
.risk-badge { display: inline-block; padding: 4px 14px; border-radius: 4px; color: white; font-weight: bold; font-size: 11pt; }
.risk-CRITICAL { background: #c62828; }
.risk-HIGH { background: #e65100; }
.risk-MEDIUM { background: #f9a825; color: #333; }
.risk-LOW { background: #2e7d32; }
.risk-INFORMATIONAL, .risk-INFO { background: #1565c0; }
.sev-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; color: white; font-weight: bold; font-size: 8pt; }
.sev-CRITICAL { background: #c62828; }
.sev-HIGH { background: #e65100; }
.sev-MEDIUM { background: #f9a825; color: #333; }
.sev-LOW { background: #2e7d32; }
.sev-INFORMATIONAL, .sev-INFO { background: #1565c0; }
.finding-card { border: 1px solid #e0e0e0; border-radius: 4px; margin: 20px 0; page-break-inside: avoid; }
.finding-header { background: #f5f5f5; padding: 12px 15px; border-bottom: 1px solid #e0e0e0; }
.finding-id { font-family: monospace; font-size: 9pt; color: #666; }
.finding-title { font-size: 13pt; font-weight: bold; color: #1a1a1a; margin: 4px 0; }
.finding-meta { font-size: 8pt; color: #555; margin-top: 4px; }
.finding-body { padding: 12px 15px; }
.finding-section { margin-bottom: 12px; }
.finding-section-label { font-weight: bold; font-size: 9pt; color: #555; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.evidence { background: #f5f5f5; border-left: 3px solid #1565c0; padding: 8px 10px; font-family: 'Courier New', monospace; font-size: 8pt; overflow-wrap: break-word; word-break: break-all; }
.remediation { background: #e8f5e9; border-left: 3px solid #2e7d32; padding: 8px 10px; }
.references a { color: #1565c0; font-size: 8pt; display: block; }
.source-badge { float: right; font-size: 7pt; padding: 2px 6px; border-radius: 3px; font-weight: bold; }
.source-static_kb { background: #e3f2fd; color: #1565c0; border: 1px solid #90caf9; }
.source-llm { background: #f3e5f5; color: #6a1b9a; border: 1px solid #ce93d8; }
.source-fallback { background: #fff3e0; color: #e65100; border: 1px solid #ffcc80; }
.stat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }
.stat-box { text-align: center; padding: 12px; border-radius: 4px; }
.stat-value { font-size: 24pt; font-weight: bold; }
.stat-label { font-size: 8pt; color: #555; margin-top: 4px; }
.final-analysis { background: #e8eaf6; border-left: 4px solid #3949ab; padding: 15px; margin: 15px 0; font-style: italic; }
.compliance-pass { color: #2e7d32; font-weight: bold; }
.compliance-fail { color: #c62828; }
.page-break { page-break-after: always; }
.appendix { page-break-before: always; }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
    <h1>&#128737; RAJDOLL</h1>
    <div class="subtitle">Multi-Agent Security Assessment Report</div>
    <div class="meta">
        <strong>Target:</strong> {{ target }}<br>
        <strong>Assessment Date:</strong> {{ generated_at }}<br>
        <strong>Scan Duration:</strong> {{ scan_duration }}<br>
        <strong>Total Findings:</strong> {{ findings|length }}<br>
        <strong>Standard:</strong> OWASP WSTG 4.2<br>
        <strong>Generated by:</strong> RAJDOLL Multi-Agent System
    </div>
    <div class="confidential">CONFIDENTIAL</div>
</div>

<!-- TABLE OF CONTENTS -->
<div class="toc">
    <h1>Table of Contents</h1>
    <ul>
        <li><span>1. Executive Summary</span></li>
        <li><span>2. Scope &amp; Methodology</span></li>
        <li><span>3. Risk Overview</span></li>
        <li><span>4. Detailed Findings ({{ findings|length }} total)</span></li>
        <li><span>5. WSTG Compliance</span></li>
        <li><span>Appendix A — Methodology</span></li>
        <li><span>Appendix B — Tool Inventory</span></li>
        <li><span>Appendix C — Enrichment Statistics</span></li>
    </ul>
</div>

<!-- 1. EXECUTIVE SUMMARY -->
<h1>1. Executive Summary</h1>

<p>
    <strong>Overall Risk:</strong>
    <span class="risk-badge risk-{{ overall_risk }}">{{ overall_risk }}</span>
</p>

<div class="stat-grid">
    <div class="stat-box" style="background:#ffebee;">
        <div class="stat-value" style="color:#c62828;">{{ sev_counts.CRITICAL }}</div>
        <div class="stat-label">Critical</div>
    </div>
    <div class="stat-box" style="background:#fff3e0;">
        <div class="stat-value" style="color:#e65100;">{{ sev_counts.HIGH }}</div>
        <div class="stat-label">High</div>
    </div>
    <div class="stat-box" style="background:#fffde7;">
        <div class="stat-value" style="color:#f9a825;">{{ sev_counts.MEDIUM }}</div>
        <div class="stat-label">Medium</div>
    </div>
    <div class="stat-box" style="background:#e8f5e9;">
        <div class="stat-value" style="color:#2e7d32;">{{ sev_counts.LOW }}</div>
        <div class="stat-label">Low</div>
    </div>
    <div class="stat-box" style="background:#e3f2fd;">
        <div class="stat-value" style="color:#1565c0;">{{ sev_counts.INFO }}</div>
        <div class="stat-label">Info</div>
    </div>
</div>

{% if final_analysis %}
<h2>AI-Generated Assessment Summary</h2>
<div class="final-analysis">{{ final_analysis }}</div>
{% endif %}

<h2>Top Findings</h2>
<table>
    <tr><th>#</th><th>Title</th><th>Severity</th><th>Category</th><th>CVSS 4.0</th></tr>
    {% for f in findings[:10] %}
    <tr>
        <td>{{ loop.index }}</td>
        <td>{{ f.title }}</td>
        <td><span class="sev-badge sev-{{ f.severity_upper }}">{{ f.severity_upper }}</span></td>
        <td>{{ f.category }}</td>
        <td>{% if f.cvss_score_v4 %}{{ "%.1f"|format(f.cvss_score_v4) }}{% else %}—{% endif %}</td>
    </tr>
    {% endfor %}
</table>

<h2>Strategic Recommendations</h2>
<ul>
    <li>Immediately remediate all Critical and High severity findings before next release.</li>
    <li>Implement a Secure Development Lifecycle (SDLC) with mandatory security review gates.</li>
    <li>Conduct regular penetration testing and security code reviews.</li>
    <li>Deploy a Web Application Firewall (WAF) as defense-in-depth.</li>
    <li>Provide security awareness training for development and operations teams.</li>
    <li>Establish a vulnerability disclosure and patch management process.</li>
</ul>

<div class="page-break"></div>

<!-- 2. SCOPE & METHODOLOGY -->
<h1>2. Scope &amp; Methodology</h1>

<table>
    <tr><th>Attribute</th><th>Details</th></tr>
    <tr><td>Target</td><td>{{ target }}</td></tr>
    <tr><td>Assessment Type</td><td>Automated Multi-Agent Black-Box Penetration Testing</td></tr>
    <tr><td>Standard</td><td>OWASP Web Security Testing Guide v4.2</td></tr>
    <tr><td>Start Time</td><td>{{ created_at or 'N/A' }}</td></tr>
    <tr><td>End Time</td><td>{{ completed_at or 'N/A' }}</td></tr>
    <tr><td>Duration</td><td>{{ scan_duration }}</td></tr>
    <tr><td>Agents Deployed</td><td>14 specialized security agents</td></tr>
    <tr><td>WSTG Coverage</td><td>12 categories, 96 test cases</td></tr>
</table>

<h2>Limitations</h2>
<ul>
    <li>This is an automated assessment — manual verification of findings is recommended.</li>
    <li>Results represent a point-in-time analysis; the environment may change after testing.</li>
    <li>Complex business logic vulnerabilities may require manual testing to confirm.</li>
    <li>This report does not constitute a warranty of complete security coverage.</li>
</ul>

<div class="page-break"></div>

<!-- 3. RISK OVERVIEW -->
<h1>3. Risk Overview</h1>

<h2>Findings by Severity</h2>
<table>
    <tr><th>Severity</th><th>Count</th><th>Description</th></tr>
    <tr><td><span class="sev-badge sev-CRITICAL">CRITICAL</span></td><td>{{ sev_counts.CRITICAL }}</td><td>Immediate risk — requires urgent remediation</td></tr>
    <tr><td><span class="sev-badge sev-HIGH">HIGH</span></td><td>{{ sev_counts.HIGH }}</td><td>Significant risk — remediate within 1 week</td></tr>
    <tr><td><span class="sev-badge sev-MEDIUM">MEDIUM</span></td><td>{{ sev_counts.MEDIUM }}</td><td>Moderate risk — remediate within 1 month</td></tr>
    <tr><td><span class="sev-badge sev-LOW">LOW</span></td><td>{{ sev_counts.LOW }}</td><td>Low risk — remediate in next release cycle</td></tr>
    <tr><td><span class="sev-badge sev-INFO">INFO</span></td><td>{{ sev_counts.INFO }}</td><td>Informational — no immediate action required</td></tr>
    <tr><td><strong>Total</strong></td><td><strong>{{ findings|length }}</strong></td><td></td></tr>
</table>

<h2>Findings by WSTG Category</h2>
<table>
    <tr><th>Category</th><th>Total</th><th>Critical</th><th>High</th></tr>
    {% for cat, cat_findings in findings_by_category.items() %}
    <tr>
        <td>{{ cat }}</td>
        <td>{{ cat_findings|length }}</td>
        <td>{{ cat_findings|selectattr('severity_upper','equalto','CRITICAL')|list|length }}</td>
        <td>{{ cat_findings|selectattr('severity_upper','equalto','HIGH')|list|length }}</td>
    </tr>
    {% endfor %}
</table>

<div class="page-break"></div>

<!-- 4. DETAILED FINDINGS -->
<h1>4. Detailed Findings</h1>

{% for f in findings %}
<div class="finding-card">
    <div class="finding-header">
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
                <div class="finding-id">RAJDOLL-{{ "%04d"|format(loop.index) }}</div>
                <div class="finding-title">{{ f.title }}</div>
                <div class="finding-meta">
                    <span class="sev-badge sev-{{ f.severity_upper }}">{{ f.severity_upper }}</span>
                    {% if f.wstg_id %}&nbsp;&#x2022;&nbsp;<strong>{{ f.wstg_id }}</strong>{% endif %}
                    {% if f.cwe_id %}&nbsp;&#x2022;&nbsp;{{ f.cwe_id }}{% endif %}
                    {% if f.cvss_score_v4 %}&nbsp;&#x2022;&nbsp;CVSS 4.0: <strong>{{ "%.1f"|format(f.cvss_score_v4) }}</strong>{% endif %}
                    &nbsp;&#x2022;&nbsp;{{ f.agent_name or f.category }}
                </div>
            </div>
            {% if f.enrichment_source %}
            <span class="source-badge source-{{ f.enrichment_source }}">
                {% if f.enrichment_source == 'static_kb' %}KB{% elif f.enrichment_source == 'llm' %}AI{% else %}?{% endif %}
            </span>
            {% endif %}
        </div>
    </div>
    <div class="finding-body">
        {% if f.explanation %}
        <div class="finding-section">
            <div class="finding-section-label">Description</div>
            <p>{{ f.explanation }}</p>
        </div>
        {% elif f.details %}
        <div class="finding-section">
            <div class="finding-section-label">Description</div>
            <p>{{ f.details }}</p>
        </div>
        {% endif %}

        {% if f.evidence_str %}
        <div class="finding-section">
            <div class="finding-section-label">Evidence</div>
            <div class="evidence">{{ f.evidence_str[:600] }}{% if f.evidence_str|length > 600 %}... [truncated]{% endif %}</div>
        </div>
        {% endif %}

        {% if f.remediation %}
        <div class="finding-section">
            <div class="finding-section-label">Remediation</div>
            <div class="remediation">{{ f.remediation | replace('\n', '<br>') | safe }}</div>
        </div>
        {% endif %}

        {% if f.references %}
        <div class="finding-section">
            <div class="finding-section-label">References</div>
            <div class="references">
                {% for ref in f.references %}
                <a href="{{ ref }}">{{ ref }}</a>
                {% endfor %}
            </div>
        </div>
        {% endif %}
    </div>
</div>
{% endfor %}

<div class="page-break"></div>

<!-- 5. WSTG COMPLIANCE -->
<h1>5. WSTG 4.2 Compliance</h1>
<table>
    <tr><th>WSTG Category</th><th>Agent</th><th>Status</th></tr>
    {% for item in wstg_coverage %}
    <tr>
        <td>{{ item.category }}</td>
        <td>{{ item.agent }}</td>
        <td class="compliance-pass">&#10003; Tested</td>
    </tr>
    {% endfor %}
</table>

<!-- APPENDIX A -->
<div class="appendix">
<h1>Appendix A — Methodology</h1>
<p>RAJDOLL uses a <strong>Planner-Summarizer Sequential</strong> architecture: 14 specialized agents execute tests in sequence, each building on the findings of previous agents. A local LLM (Qwen 3-4B) generates adaptive tool arguments based on reconnaissance context.</p>
<h2>Agents Deployed</h2>
<table>
    <tr><th>Agent</th><th>WSTG Category</th></tr>
    <tr><td>ReconnaissanceAgent</td><td>WSTG-INFO</td></tr>
    <tr><td>AuthenticationAgent</td><td>WSTG-ATHN</td></tr>
    <tr><td>AuthorizationAgent</td><td>WSTG-ATHZ</td></tr>
    <tr><td>SessionManagementAgent</td><td>WSTG-SESS</td></tr>
    <tr><td>InputValidationAgent</td><td>WSTG-INPV</td></tr>
    <tr><td>BusinessLogicAgent</td><td>WSTG-BUSL</td></tr>
    <tr><td>ClientSideAgent</td><td>WSTG-CLNT</td></tr>
    <tr><td>APITestingAgent</td><td>WSTG-APIT</td></tr>
    <tr><td>ErrorHandlingAgent</td><td>WSTG-ERRH</td></tr>
    <tr><td>WeakCryptographyAgent</td><td>WSTG-CRYP</td></tr>
    <tr><td>ConfigDeploymentAgent</td><td>WSTG-CONF</td></tr>
    <tr><td>IdentityManagementAgent</td><td>WSTG-IDMG</td></tr>
    <tr><td>FileUploadAgent</td><td>WSTG-BUSL-08</td></tr>
    <tr><td>ReportGenerationAgent</td><td>—</td></tr>
</table>
</div>

<!-- APPENDIX B -->
<div class="appendix">
<h1>Appendix B — Tool Inventory</h1>
<table>
    <tr><th>MCP Server</th><th>Port</th><th>Primary Tools</th></tr>
    <tr><td>info-mcp</td><td>9001</td><td>Nmap, JS route analysis, tech fingerprinting</td></tr>
    <tr><td>auth-mcp</td><td>9002</td><td>Hydra, 2FA bypass, session token analysis</td></tr>
    <tr><td>authorz-mcp</td><td>9003</td><td>IDOR testing, privilege escalation, user spoofing</td></tr>
    <tr><td>session-mcp</td><td>9004</td><td>Session fixation, cookie analysis, JWT testing</td></tr>
    <tr><td>input-mcp</td><td>9005</td><td>SQLMap, Dalfox, SSTI, LFI, NoSQL, HPP, ReDoS (24+ tools)</td></tr>
    <tr><td>error-mcp</td><td>9006</td><td>Error disclosure, stack trace detection</td></tr>
    <tr><td>crypto-mcp</td><td>9007</td><td>TLS/SSL analysis, weak cipher detection</td></tr>
    <tr><td>client-mcp</td><td>9008</td><td>DOM XSS, CORS, clickjacking, CSP, open redirect (17 tools)</td></tr>
    <tr><td>biz-mcp</td><td>9009</td><td>Rate limiting, coupon forgery, business logic (15 tools)</td></tr>
    <tr><td>confdep-mcp</td><td>9010</td><td>Security headers, hidden endpoints, npm CVEs (16 tools)</td></tr>
    <tr><td>identity-mcp</td><td>9011</td><td>User enumeration, mass assignment (8 tools)</td></tr>
    <tr><td>fileupload-mcp</td><td>9012</td><td>Upload bypass, null byte, path traversal</td></tr>
    <tr><td>api-testing-mcp</td><td>9013</td><td>API authentication, rate limiting, BOLA</td></tr>
    <tr><td>katana-mcp</td><td>9015</td><td>Web crawler, endpoint discovery</td></tr>
</table>
</div>

<!-- APPENDIX C -->
<div class="appendix">
<h1>Appendix C — Enrichment Statistics</h1>
<p>Each finding in this report was enriched with explanation, remediation steps, CVSS 4.0 score, CWE ID, WSTG ID, and references using RAJDOLL's hybrid enrichment system.</p>
<table>
    <tr><th>Source</th><th>Count</th><th>Description</th></tr>
    <tr><td><span class="source-badge source-static_kb">KB</span> Static Knowledge Base</td><td>{{ enrichment_stats.static_kb }}</td><td>Matched against 33 pre-written WSTG-mapped entries (instant)</td></tr>
    <tr><td><span class="source-badge source-llm">AI</span> LLM Generated</td><td>{{ enrichment_stats.llm }}</td><td>Generated by local Qwen 3-4B LLM (CVSS 4.0, CWE, remediation)</td></tr>
    <tr><td><span class="source-badge source-fallback">?</span> Fallback</td><td>{{ enrichment_stats.fallback }}</td><td>Generic enrichment (LLM unavailable or unknown vulnerability type)</td></tr>
    <tr><td><strong>Total</strong></td><td><strong>{{ findings|length }}</strong></td><td></td></tr>
</table>

<p><em>Disclaimer: This is an automated security assessment. Manual verification of findings is recommended before remediation. There is no guarantee that all possible security issues have been identified.</em></p>
</div>

</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
git add multi_agent_system/templates/report.html.j2
git commit -m "feat(report): add professional Jinja2 HTML template for PDF generation"
```

---

## Task 7: Overhaul pdf_report.py

**Files:**
- Modify: `api/routes/pdf_report.py`

- [ ] **Step 1: Replace SimplePDFGenerator and download_pdf_report with Jinja2 + enriched data**

Replace the entire content of `api/routes/pdf_report.py`:

```python
"""
PDF Report Generation — Jinja2 template rendered by WeasyPrint.
Loads enriched Finding data (explanation, remediation, CVSS 4.0, CWE, WSTG IDs).
"""
from __future__ import annotations

import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, JSONResponse

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, Finding, JobAgent
from multi_agent_system.utils.shared_context_manager import SharedContextManager

router = APIRouter()

TEMPLATE_PATH = Path(__file__).parent.parent.parent / "multi_agent_system" / "templates" / "report.html.j2"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4}
WSTG_COVERAGE = [
    {"category": "WSTG-INFO — Information Gathering", "agent": "ReconnaissanceAgent"},
    {"category": "WSTG-CONF — Configuration & Deployment", "agent": "ConfigDeploymentAgent"},
    {"category": "WSTG-IDMG — Identity Management", "agent": "IdentityManagementAgent"},
    {"category": "WSTG-ATHN — Authentication", "agent": "AuthenticationAgent"},
    {"category": "WSTG-ATHZ — Authorization", "agent": "AuthorizationAgent"},
    {"category": "WSTG-SESS — Session Management", "agent": "SessionManagementAgent"},
    {"category": "WSTG-INPV — Input Validation", "agent": "InputValidationAgent"},
    {"category": "WSTG-ERRH — Error Handling", "agent": "ErrorHandlingAgent"},
    {"category": "WSTG-CRYP — Weak Cryptography", "agent": "WeakCryptographyAgent"},
    {"category": "WSTG-BUSL — Business Logic", "agent": "BusinessLogicAgent"},
    {"category": "WSTG-CLNT — Client-Side Testing", "agent": "ClientSideAgent"},
    {"category": "WSTG-APIT — API Testing", "agent": "APITestingAgent"},
]


def _normalize_severity(raw: str) -> str:
    s = (raw or "info").upper()
    return "INFO" if s in ("INFORMATIONAL", "INFO") else s


def _build_findings(findings_db) -> List[Dict[str, Any]]:
    result = []
    for f in findings_db:
        sev = _normalize_severity(getattr(f.severity, "value", str(f.severity)))
        evidence = f.evidence or {}
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = {"raw": evidence}
        evidence_str = json.dumps(evidence, ensure_ascii=False, indent=2) if evidence else ""
        refs = f.references if isinstance(f.references, list) else []
        result.append({
            "title": f.title or "Untitled",
            "category": f.category or "N/A",
            "severity_upper": sev,
            "agent_name": f.agent_name,
            "explanation": f.explanation or "",
            "remediation": f.remediation or "",
            "cwe_id": f.cwe_id or "",
            "wstg_id": f.wstg_id or "",
            "cvss_score_v4": f.cvss_score_v4,
            "references": refs,
            "enrichment_source": f.enrichment_source or "fallback",
            "evidence_str": evidence_str,
            "details": f.details or "",
        })
    result.sort(key=lambda x: SEVERITY_ORDER.get(x["severity_upper"], 99))
    return result


def _render_pdf(job, findings_db, agents_db) -> bytes:
    from jinja2 import Template

    findings = _build_findings(findings_db)

    # Severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        key = f["severity_upper"] if f["severity_upper"] in sev_counts else "INFO"
        sev_counts[key] += 1

    overall_risk = next(
        (s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if sev_counts[s] > 0),
        "INFO"
    )

    # Group by category
    findings_by_category: Dict[str, list] = {}
    for f in findings:
        findings_by_category.setdefault(f["category"], []).append(f)

    # Enrichment stats
    enrichment_stats = {"static_kb": 0, "llm": 0, "fallback": 0}
    for f in findings:
        src = f.get("enrichment_source", "fallback")
        enrichment_stats[src] = enrichment_stats.get(src, 0) + 1

    # Scan duration
    scan_duration = "N/A"
    if job.updated_at and job.created_at:
        delta = (job.updated_at - job.created_at).total_seconds()
        scan_duration = f"{int(delta // 3600)}h {int((delta % 3600) // 60)}m {int(delta % 60)}s"

    # Final analysis from SharedContext
    final_analysis = ""
    try:
        ctx = SharedContextManager(job_id=job.id)
        raw = ctx.read("final_analysis")
        if isinstance(raw, dict):
            final_analysis = raw.get("summary") or raw.get("analysis") or str(raw)
        elif isinstance(raw, str):
            final_analysis = raw
    except Exception:
        pass

    template_str = TEMPLATE_PATH.read_text(encoding="utf-8")
    template = Template(template_str)
    html = template.render(
        target=job.target,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        created_at=job.created_at.strftime("%Y-%m-%d %H:%M UTC") if job.created_at else "N/A",
        completed_at=job.updated_at.strftime("%Y-%m-%d %H:%M UTC") if job.updated_at else "N/A",
        scan_duration=scan_duration,
        findings=findings,
        findings_by_category=findings_by_category,
        sev_counts=sev_counts,
        overall_risk=overall_risk,
        final_analysis=final_analysis,
        wstg_coverage=WSTG_COVERAGE,
        enrichment_stats=enrichment_stats,
    )

    try:
        from weasyprint import HTML
        buf = io.BytesIO()
        HTML(string=html).write_pdf(buf)
        return buf.getvalue()
    except ImportError:
        raise HTTPException(500, (
            "WeasyPrint not installed. Install system deps: "
            "apt-get install libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev"
        ))


@router.get("/scans/{job_id}/report")
async def download_json_report(job_id: int):
    """Download enriched JSON report."""
    with get_db() as db:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(404, f"Job {job_id} not found")
        findings_db = db.query(Finding).filter(Finding.job_id == job_id).all()
        agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()

    findings = _build_findings(findings_db)
    scan_duration = "N/A"
    if job.updated_at and job.created_at:
        delta = (job.updated_at - job.created_at).total_seconds()
        scan_duration = f"{int(delta // 60)}m {int(delta % 60)}s"

    return JSONResponse(content={
        "job_id": job_id,
        "target": job.target,
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        "scan_duration": scan_duration,
        "findings": findings,
        "agents_executed": len([a for a in agents if getattr(a.status, "value", str(a.status)) == "completed"]),
        "total_agents": len(agents),
    })


@router.get("/scans/{job_id}/report/pdf")
async def download_pdf_report(job_id: int):
    """Generate and download enriched PDF report."""
    with get_db() as db:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(404, f"Job {job_id} not found")
        findings_db = db.query(Finding).filter(Finding.job_id == job_id).all()
        agents_db = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()

    pdf_bytes = _render_pdf(job, findings_db, agents_db)
    filename = f"RAJDOLL_Report_Job{job_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

- [ ] **Step 2: Verify Jinja2 is in requirements**

```bash
grep -i jinja /mnt/d/MCP/RAJDOLL/requirements.txt
```

If not present:
```bash
echo "Jinja2>=3.1.0" >> /mnt/d/MCP/RAJDOLL/requirements.txt
```

- [ ] **Step 3: Commit**

```bash
git add api/routes/pdf_report.py requirements.txt
git commit -m "feat(report): overhaul pdf_report.py — Jinja2 template, enriched findings, final_analysis"
```

---

## Task 8: Run full test suite + smoke test PDF

**Files:**
- Test: `multi_agent_system/tests/test_enrichment.py`

- [ ] **Step 1: Run all enrichment unit tests**

```bash
python -m pytest multi_agent_system/tests/test_enrichment.py -v 2>&1 | tail -30
```

Expected: All tests PASS.

- [ ] **Step 2: Run VDP generalization tests (no regressions)**

```bash
python -m pytest multi_agent_system/tests/test_vdp_generalization.py -v 2>&1 | tail -20
```

Expected: All 15 tests PASS.

- [ ] **Step 3: Smoke test the PDF endpoint (requires running containers)**

```bash
curl -s -o /tmp/test_report.pdf http://localhost:8000/api/scans/1/report/pdf && \
  wc -c /tmp/test_report.pdf && \
  file /tmp/test_report.pdf
```

Expected: Output shows `PDF document` and file size > 50KB.

- [ ] **Step 4: Verify enrichment columns are populated in DB**

```bash
docker exec rajdoll-db-1 psql -U rajdoll -d rajdoll -c \
  "SELECT title, enrichment_source, cwe_id, wstg_id, cvss_score_v4 FROM findings LIMIT 5;"
```

Expected: `enrichment_source` column shows `static_kb`, `llm`, or `fallback` — not NULL.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat(report): complete report enrichment and PDF overhaul — hybrid KB+LLM, Jinja2 template, CVSS 4.0"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ DB: 7 new columns on Finding + SQL migration
- ✅ EnrichmentService + StaticKBMatcher + LLMEnricher + EnrichmentResult
- ✅ enrichment_kb.json with 33 entries covering all 10 WSTG categories
- ✅ enrichment_prompt.j2 Jinja2 LLM prompt template
- ✅ report.html.j2 full PDF template with all spec sections
- ✅ add_finding() enrichment integration
- ✅ pdf_report.py overhaul with final_analysis + enriched fields
- ✅ Tests: unit (no Docker) + smoke test (with Docker)
- ✅ Error handling: all failure scenarios in EnrichmentService never raise
- ✅ enrichment_source badge in PDF (KB/AI/?), Appendix C stats
- ✅ CVSS 4.0 throughout (not 3.1)

**Type consistency:**
- `EnrichmentResult.source` → used in `add_finding()` as `finding.enrichment_source` ✅
- `StaticKBMatcher.match()` → returns `EnrichmentResult | None` ✅
- `EnrichmentService.enrich()` → returns `EnrichmentResult` (never raises) ✅
- Template variable `f.severity_upper` → set in `_build_findings()` ✅
- Template variable `sev_counts` → keys match template (`CRITICAL/HIGH/MEDIUM/LOW/INFO`) ✅

**No placeholders:** All steps contain actual code. ✅
