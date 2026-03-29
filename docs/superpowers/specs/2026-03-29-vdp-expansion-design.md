# RAJDOLL VDP Expansion & Source Code Audit Design

**Date:** 2026-03-29
**Author:** Martua Raja Doli Pangaribuan
**Context:** Thesis research — Politeknik Siber dan Sandi Negara
**Scope:** Expand RAJDOLL from Juice Shop-only to real-world government VDP targets (BSSN VVIP Program)

---

## 1. Goals & Scope

### What is being built
Two sub-phases:
1. **Source Code Audit** — Systematic documentation of all hardcoding per category (credentials, URLs, domain whitelist, Juice Shop references) → produces audit report for thesis
2. **Infrastructure Generalization** — Fix all audit findings, extend scan API with `credentials` and `whitelist_domain` fields

### What is NOT changing
- All 16 Juice Shop-specific tools → remain untouched
- All WSTG 4.2 tool coverage → not modified
- Evaluation module (juice_shop_coverage_matrix.py) → not modified
- Scan results & recall metrics → identical when credentials passed via request

### Success Criteria
- Audit report documented (findings + fix evidence with commit hashes)
- RAJDOLL successfully scans ≥1 BSSN VVIP Program in-scope target
- Juice Shop scan with `credentials` in request body retains ≥ 98% recall
- Zero Juice Shop-specific strings remain in core infrastructure files

---

## 2. Source Code Audit Findings

### 🔴 CRITICAL (2 found)

| # | File | Line | Issue | Risk | Fix |
|---|------|------|-------|------|-----|
| C1 | `multi_agent_system/core/security_guards.py` | 263 | `admin_tokens = ["admin_token_placeholder"]` hardcoded | Anyone knowing this string can add any domain to whitelist | Read from `ADMIN_TOKEN` env var, no default |
| C2 | `api/routes/logs.py` | 181 | `container_name` from URL param inserted into subprocess args `f"rajdoll-{container_name}-1"` | Container name injection; invalid input can crash or leak info | Validate against allowlist of known container names |

### 🟡 MEDIUM (4 found)

| # | File | Line | Issue | Risk | Fix |
|---|------|------|-------|------|-----|
| M1 | `multi_agent_system/utils/session_service.py` | 54 | `("admin@juice-sh.op", "admin123")` in DEFAULT_CREDENTIALS | App-specific credentials in source code | Remove; pass via `POST /api/scans` credentials field |
| M2 | `multi_agent_system/core/security_guards.py` | 80-98 | Whitelist defaults include `juice-shop`, `dvwa`, `localhost`, `127.0.0.1` | Production deployment would allow internal scanning without explicit approval | Default whitelist = `[]`; require explicit addition |
| M3 | `multi_agent_system/agents/base_agent.py` | 964 | `self._target or "http://juice-shop:3000"` silent fallback | Agent silently scans wrong target if `_target` unset | `raise ValueError("Target not set for agent")` |
| M4 | `multi_agent_system/utils/knowledge_graph.py` | 159 | `name="http://juice-shop:3000"` hardcoded default entity | Incorrect audit trail for all non-Juice-Shop scans | Inject actual target as constructor parameter |

### 🟢 LOW (2 found)

| # | File | Issue | Fix |
|---|------|-------|-----|
| L1 | `api/main.py` | No CORSMiddleware configured | Add `CORSMiddleware(allow_origins=["http://localhost:*"])` for local deployment |
| L2 | `requirements.txt` | `openai>=1.40.0` unpinned | Pin to tested exact version |

### ✅ No Issues Found
- Subprocess calls: No `shell=True` (all use list args)
- Deserialization: No `pickle.load` / `yaml.load` unsafe
- Code execution: `eval()`/`exec()` only in payload strings (test data), not Python runtime
- Path traversal: File ops use container-internal paths, not user input
- SQL injection: SQLAlchemy ORM used consistently, no raw SQL
- Dependencies: No known critical CVEs in pinned versions

---

## 3. Architecture & Components

### Component 1 — Infrastructure Generalization

Fix all 6 audit findings in-place (no new files, no abstractions):

| File | Change |
|------|--------|
| `security_guards.py:263` | `ADMIN_TOKEN` from env var, no default, log warning if unset |
| `security_guards.py:80-98` | Default whitelist = `[]` |
| `session_service.py:54` | Remove `admin@juice-sh.op/admin123` from DEFAULT_CREDENTIALS |
| `base_agent.py:964` | `raise ValueError("Target not set")` instead of fallback |
| `knowledge_graph.py:159` | Accept `target` as constructor param |
| `api/routes/logs.py:181` | Validate container_name against `KNOWN_CONTAINERS` allowlist |

### Component 2 — Extended Scan API

Add to `api/schemas/schemas.py`:

```python
class ScanCredentials(BaseModel):
    username: str
    password: str
    auth_type: str = "form"  # form | bearer | basic | cookie

class CreateScanRequest(BaseModel):
    # ... existing fields unchanged ...
    credentials: Optional[ScanCredentials] = None
    whitelist_domain: Optional[str] = None  # auto-add to whitelist at scan time
```

Update `api/routes/scans.py` to:
1. If `whitelist_domain` provided → auto-add to security_guard whitelist
2. If `credentials` provided → store in Job record or SharedContext
3. `session_service.auto_login()` checks SharedContext for provided credentials first

### Component 3 — Audit Report Document

`docs/audit/source_code_audit_report.md` — static document with findings table + commit hash of each fix. Referenced in thesis Chapter on System Validation.

---

## 4. Data Flow

```
POST /api/scans {target, credentials, whitelist_domain}
  → Pydantic validation (ScanCredentials type-checked)
  → security_guard.validate_target()
      → if whitelist_domain: auto-add to whitelist
  → Job created in DB
  → credentials saved to SharedContext["scan_credentials"]
  → Celery task → Orchestrator.run()
      → Phase 1: ReconnaissanceAgent
      → Phase 1.5: session_service.auto_login()
          → Try SharedContext["scan_credentials"] FIRST
          → Then try generic DEFAULT_CREDENTIALS wordlist
          → If all fail: log warning, continue unauthenticated
      → Phase 2-5: All agents normal (unchanged)
```

---

## 5. Error Handling

| Scenario | Behavior |
|----------|----------|
| Credentials wrong | auto_login fails → scan continues unauthenticated, warning logged |
| `ADMIN_TOKEN` env var not set | Startup warning logged; whitelist management via API disabled |
| `whitelist_domain` not in scope | Target still validated; if domain doesn't match target, 403 |
| `container_name` invalid in logs API | 400 Bad Request with list of valid container names |

---

## 6. Testing Plan

1. Juice Shop regression: `POST /api/scans {"target": "http://juice-shop:3000", "credentials": {"username": "admin@juice-sh.op", "password": "admin123"}}` → verify recall ≥ 98%
2. Unauthenticated path: Same scan without credentials → verify scan completes (lower recall expected, no crash)
3. VDP target: `POST /api/scans` with BSSN target + `whitelist_domain` + credentials → verify scan runs end-to-end
4. Security: Attempt `POST /api/whitelist` with wrong admin token → expect 401
5. Container injection: `GET /api/logs/recent/../../etc/passwd` → expect 400

---

## 7. Files Changed (Summary)

| File | Type of Change |
|------|---------------|
| `api/schemas/schemas.py` | Add `ScanCredentials` model, extend `CreateScanRequest` |
| `api/routes/scans.py` | Handle `whitelist_domain` auto-add, store credentials |
| `multi_agent_system/utils/session_service.py` | Remove hardcoded creds, check SharedContext first |
| `multi_agent_system/core/security_guards.py` | Env-var admin token, empty default whitelist |
| `multi_agent_system/agents/base_agent.py` | Replace fallback URL with ValueError |
| `multi_agent_system/utils/knowledge_graph.py` | Accept target param in constructor |
| `api/routes/logs.py` | Container name allowlist validation |
| `docs/audit/source_code_audit_report.md` | New: audit report document |

**Total: 8 files (7 edits + 1 new)**. No new abstractions. No architectural changes. Juice Shop tools untouched.
