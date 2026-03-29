# RAJDOLL Source Code Security Audit Report

**Date:** 2026-03-29
**Auditor:** Martua Raja Doli Pangaribuan (assisted by Claude Sonnet 4.6)
**Scope:** All Python files in RAJDOLL codebase, excluding tests/ and __pycache__
**Purpose:** Verify system readiness for real-world VDP target scanning (BSSN VVIP Program)

---

## Executive Summary

Pre-audit, RAJDOLL contained 2 critical and 4 medium hardcoding issues that would prevent safe and correct operation against arbitrary targets. All issues have been remediated. Post-fix, the system is confirmed generic: any target can be scanned by providing `target`, `whitelist_domain`, and `credentials` in `POST /api/scans`.

---

## Findings

### CRITICAL

| ID | File | Line | Issue | Fix Commit |
|----|------|------|-------|------------|
| C1 | `multi_agent_system/core/security_guards.py` | 263 | `admin_token_placeholder` hardcoded — anyone knowing this string can add any domain to whitelist | 2d40580 |
| C2 | `api/routes/logs.py` | 181 | `container_name` from URL param inserted into subprocess args without validation — container name injection | d26543b |

### MEDIUM

| ID | File | Line | Issue | Fix Commit |
|----|------|------|-------|------------|
| M1 | `multi_agent_system/utils/session_service.py` | 54 | `admin@juice-sh.op/admin123` in DEFAULT_CREDENTIALS — app-specific credentials in source code | 5cec001 |
| M2 | `multi_agent_system/core/security_guards.py` | 94 | Whitelist defaults included `juice-shop`, `dvwa`, `localhost` — risk for cloud/production deployment | 4f250b9 |
| M3 | `multi_agent_system/agents/base_agent.py` | 964 | Silent fallback to `http://juice-shop:3000` if `_target` unset — agent could silently scan wrong target | cd88730 |
| M4 | `multi_agent_system/utils/knowledge_graph.py` | 159 | `name="http://juice-shop:3000"` hardcoded as default entity name — incorrect audit trail for non-Juice-Shop scans | e8f316f |

### LOW

| ID | File | Issue | Status |
|----|------|-------|--------|
| L1 | `api/main.py` | No CORSMiddleware configured | Accepted risk — Docker-internal deployment only |
| L2 | `requirements.txt` | `openai>=1.40.0` unpinned | Accepted risk — stable range for thesis scope |

---

## Clean Areas (No Issues Found)

- Subprocess calls: No `shell=True` (all use list args) ✓
- Deserialization: No `pickle.load` / `yaml.load` unsafe ✓
- Code execution: `eval()`/`exec()` only in payload test-data strings ✓
- Path traversal: File operations use container-internal paths ✓
- SQL injection: SQLAlchemy ORM used consistently ✓
- Dependencies: No known critical CVEs in pinned versions ✓

---

## Remediation Summary

All critical and medium findings were fixed before first VDP scan attempt.

| Finding | Remediation |
|---------|-------------|
| C1 — Hardcoded admin token | `ADMIN_TOKEN` env var, no default. Warning logged if unset. |
| C2 — Container name injection | `KNOWN_CONTAINERS` allowlist, HTTPException(400) on unknown name |
| M1 — Juice Shop creds in source | Removed; credentials now passed via `POST /api/scans` body |
| M2 — Hardcoded whitelist | Default empty; loaded from `ALLOWED_DOMAINS` env var |
| M3 — Fallback URL | `raise ValueError` when `_target` not set |
| M4 — KG default entity | `target` param added to `KnowledgeGraph.__init__`, default `""` |

## Extended Scan API

New `ScanCredentials` model added to `api/schemas/schemas.py`. VDP targets can now be scanned:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://target.bssn.go.id",
    "whitelist_domain": "target.bssn.go.id",
    "credentials": {"username": "myuser@email.com", "password": "mypassword"}
  }'
```
