# Real-Target Scope Enforcement — Design Spec
**Date:** 2026-04-11  
**Author:** Martua Raja Doli Pangaribuan  
**Status:** Approved for implementation

---

## 1. Overview

RAJDOLL has been validated exclusively against OWASP Juice Shop (7 scan jobs). Before testing against real VDP targets (e.g., BSSN), three gaps must be closed:

1. **Safe defaults** — HITL and ADAPTIVE_MODE must be pre-configured for cautious real-target operation.
2. **Subdomain enumeration** — Active subdomain discovery tools exist in info-mcp but are out-of-scope for thesis research (focused website testing, not bug bounty).
3. **URL-level scope enforcement** — LLM-generated tool arguments can reference hosts outside the declared scan scope.

This design introduces a **3-layer defense-in-depth** architecture that ensures all tool activity stays within the explicitly declared whitelist, while preserving passive OSINT capability with clear scope separation in the report.

**Non-goals:** Automated pre-scan checklists, rate limiting, authorization letter verification, multi-tenant access control.

---

## 2. Architecture

### 2.1 Three-Layer Defense

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1 — LLM Prompt Injection (Prevention)               │
│  _inject_planner_context() / _prepare_planning_context():   │
│    • Informs LLM of allowed hosts                           │
│    • Lists disabled tools (SCOPE_VIOLATION_TOOLS)           │
│    • Instructs: do NOT select disabled tools or OOS hosts   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 2 — Runtime Enforcement (Gate)                       │
│  2a. should_run_tool():                                     │
│      if tool_name in SCOPE_VIOLATION_TOOLS → skip           │
│  2b. _before_tool_execution():                              │
│      Extract hostname from URL args                         │
│      if not security_guard.is_host_allowed(host) → skip     │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 3 — Findings Filter (Post-processing)               │
│  _handle_osint():                                           │
│    Partition search_engine_reconnaissance results into       │
│    in-scope vs *_out_of_scope keys                          │
│    Report renders OOS items in a separate section            │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Scope Principles

1. **Scope must be declared before scan, not discovered mid-scan.** The user declares allowed hosts via `whitelist_domain` in the POST body or `ALLOWED_DOMAINS` env var.
2. **Passive OSINT is allowed** (crt.sh, Bing dorking, theHarvester, GitHub code search). These do not touch out-of-scope hosts — they read public data sources only.
3. **Out-of-scope findings are preserved but separated.** Tagged in JSON with `*_out_of_scope` keys, rendered in a dedicated report section. Not counted as vulnerabilities.
4. **No DB migration.** All changes use env vars, JSON fields, and template logic.

---

## 3. Scan Profiles

### 3.1 `SCAN_PROFILE` Env Var

Added to `multi_agent_system/core/config.py`:

```python
SCAN_PROFILE: str = os.getenv("SCAN_PROFILE", "lab")

SCAN_PROFILE_DEFAULTS = {
    "lab": {"hitl_mode": "off",    "adaptive_mode": "aggressive"},
    "vdp": {"hitl_mode": "agent",  "adaptive_mode": "balanced"},
}
```

| Profile | HITL_MODE | ADAPTIVE_MODE | Use Case |
|---------|-----------|---------------|----------|
| `lab`   | `off`     | `aggressive`  | Juice Shop, DVWA, CI regression |
| `vdp`   | `agent`   | `balanced`    | Real VDP target, authorized pentest |

### 3.2 Resolution Priority

In `api/routes/scans.py`:

```python
def _resolve_hitl_mode(request_hitl: Optional[str]) -> str:
    if request_hitl:
        return request_hitl                                   # 1. Per-scan explicit
    profile = settings.SCAN_PROFILE
    return SCAN_PROFILE_DEFAULTS.get(profile, {}).get(
        "hitl_mode", "off")                                   # 2. Profile default

def _resolve_adaptive_mode(request_adaptive: Optional[str]) -> str:
    if request_adaptive:
        return request_adaptive
    profile = settings.SCAN_PROFILE
    return SCAN_PROFILE_DEFAULTS.get(profile, {}).get(
        "adaptive_mode", "aggressive")                        # 3. Hardcoded fallback
```

Request body `hitl_mode` can still override (existing HITL v2 behavior). `adaptive_mode` resolved from profile — not exposed in request body to keep API simple.

---

## 4. SCOPE_VIOLATION_TOOLS

### 4.1 Definition

Added to `config.py` after `settings = Settings()` (same location as `HIGH_RISK_TOOLS`):

```python
SCOPE_VIOLATION_TOOLS: frozenset[str] = frozenset({
    "enumerate_active_subdomains",    # amass/subfinder/DNS brute
    "test_subdomain_takeover",         # CNAME takeover check
    "comprehensive_domain_recon",      # umbrella: DNS + WHOIS + subdomain
    "enumerate_applications",          # vhost/application enumeration
})
```

### 4.2 Enforcement in `should_run_tool()`

In `base_agent.py`, as the **first gate** (before circuit breaker, adaptive mode, HITL):

```python
def should_run_tool(self, tool_name: str, ...) -> tuple[bool, str]:
    if tool_name in settings.SCOPE_VIOLATION_TOOLS:
        logger.warning(f"[scope] tool '{tool_name}' rejected: in SCOPE_VIOLATION_TOOLS")
        return False, f"scope_violation:hard_disabled:{tool_name}"
    # ... existing checks ...
```

- **Not counted as failure** — does not increment circuit breaker counter.
- **Cannot be overridden** by Director INCLUDE directive or HITL approval.
- **Audit logged** via `job_agent.record_skip()`.

### 4.3 Tools NOT in SCOPE_VIOLATION_TOOLS

These info-mcp tools remain available because they are target-scoped:

| Tool | Why Kept |
|------|----------|
| `search_engine_reconnaissance` | Passive OSINT — reads public data, does not touch other hosts |
| `run_dig_lookup` | DNS lookup on target domain only |
| `run_whois_lookup` | WHOIS on target domain only |
| `check_email_security` | SPF/DKIM/DMARC on target domain only |

---

## 5. URL-Level Host Enforcement

### 5.1 `SecurityGuard.is_host_allowed()`

In `multi_agent_system/utils/security_guard.py`:

```python
import fnmatch

class SecurityGuard:
    def __init__(self, allowed_domains: Iterable[str]):
        self.allowed_domains: set[str] = {
            d.strip().lower() for d in allowed_domains if d and d.strip()
        }

    # Always allowed: internal loopback (MCP containers communicate via localhost)
    INTERNAL_HOSTS = frozenset({"localhost", "127.0.0.1"})

    def is_host_allowed(self, host: str) -> bool:
        if not host:
            return False
        host = host.lower().strip()
        if host in self.INTERNAL_HOSTS:
            return True
        for pattern in self.allowed_domains:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    def validate_target(self, target_url: str) -> bool:
        """Existing method — now delegates to is_host_allowed."""
        host = urlparse(target_url).hostname
        return self.is_host_allowed(host) if host else False
```

### 5.2 Wildcard Behavior

| `whitelist_domain` | Host | Match? | Why |
|---------------------|------|--------|-----|
| `target.bssn.go.id` | `target.bssn.go.id` | Yes | Exact |
| `target.bssn.go.id` | `api.target.bssn.go.id` | No | Subdomain != parent |
| `target.bssn.go.id` | `target.bssn.go.id.evil.com` | No | Different domain |
| `*.target.bssn.go.id` | `api.target.bssn.go.id` | Yes | Wildcard match |
| `*.target.bssn.go.id` | `target.bssn.go.id` | No | Root not matched by `*` |
| `["*.target.bssn.go.id", "target.bssn.go.id"]` | Both | Yes | Explicit root + wildcard |

### 5.3 Host Check in `_before_tool_execution()`

In `base_agent.py`:

```python
URL_ARG_NAMES = ("url", "target_url", "target", "base_url", "domain", "host")

def _extract_hostname(self, value: str) -> Optional[str]:
    if not value:
        return None
    try:
        parsed = urlparse(value if "://" in value else f"http://{value}")
        return (parsed.hostname or "").lower() or None
    except Exception:
        return None

async def _before_tool_execution(self, tool_name, args):
    # ... existing LLM args merge + HITL approval ...

    # Layer 2b: URL host enforcement
    for arg_name in URL_ARG_NAMES:
        if arg_name not in args:
            continue
        host = self._extract_hostname(str(args[arg_name]))
        if host is None:
            continue
        if not self.security_guard.is_host_allowed(host):
            logger.warning(
                f"[scope] tool '{tool_name}' rejected: "
                f"arg '{arg_name}'={host!r} not in whitelist"
            )
            return False, args, f"scope_violation:host_not_whitelisted:{host}"

    return True, args, ""
```

- **Not counted as circuit breaker failure.**
- **Skip result format:** `{"status": "skipped", "reason": "scope_violation:host_not_whitelisted:dev.target.bssn.go.id"}`

### 5.4 Whitelist Domain as List

In `api/routes/scans.py`, `ScanRequest`:

```python
class ScanRequest(BaseModel):
    target: str
    credentials: Optional[Dict[str, str]] = None
    whitelist_domain: Optional[Union[str, List[str]]] = None
    hitl_mode: Optional[Literal["off", "agent", "tool"]] = None

    def get_whitelist_list(self) -> List[str]:
        if self.whitelist_domain is None:
            return []
        if isinstance(self.whitelist_domain, str):
            return [self.whitelist_domain]
        return list(self.whitelist_domain)
```

Merge flow (Safe-Change Rule #6: append BEFORE validate_target):

```python
for entry in request.get_whitelist_list():
    security_guard.allowed_domains.add(entry.lower().strip())

if not security_guard.validate_target(request.target):
    raise HTTPException(403, ...)
```

**Backward compatible:** `"whitelist_domain": "juice-shop"` (string) still works.

---

## 6. LLM Scope Context Injection (Layer 1)

### 6.1 Scope Context Block

Built dynamically in orchestrator:

```python
def _build_scope_context_block(self) -> str:
    allowed = ", ".join(sorted(self.security_guard.allowed_domains))
    disabled = ", ".join(sorted(settings.SCOPE_VIOLATION_TOOLS))
    return f"""
## SCOPE CONSTRAINTS (MANDATORY)

**Allowed target hosts:** {allowed}
- All url/target_url/target/base_url/domain/host arguments MUST resolve
  to one of these hosts (exact match or glob pattern).
- Tool calls with hostnames outside this list will be rejected at runtime.

**Disabled tools (scope violation — do not select):**
{disabled}
- These tools perform subdomain/host discovery outside research scope.
- Selecting them has no effect; they are silently skipped.
"""
```

### 6.2 Injection Points

1. `LLMPlanner.plan_testing_strategy()` — Phase 2 global planner
2. `BaseAgent._prepare_planning_context()` — Phase 3 per-agent LLM planning

Appended after existing context blocks (cumulative_summary, director_directive). Dynamic — reads from `security_guard.allowed_domains` and `settings.SCOPE_VIOLATION_TOOLS` at call time.

---

## 7. Findings Post-Processing (Layer 3)

### 7.1 OSINT Partitioning

In `reconnaissance_agent.py:_handle_osint()`:

```python
def _handle_osint(self, result):
    findings = result.get("data", {}).get("findings", {})

    def _partition(items, host_extractor):
        in_scope, out_scope = [], []
        for item in items:
            h = host_extractor(item)
            (in_scope if h and self.security_guard.is_host_allowed(h) else out_scope).append(item)
        return in_scope, out_scope

    # Subdomains
    subs_in, subs_out = _partition(
        findings.get("subdomains_found", []), lambda s: s.lower())
    findings["subdomains_found"] = subs_in
    findings["subdomains_out_of_scope"] = subs_out

    # Emails
    emails_in, emails_out = _partition(
        findings.get("emails_found", []),
        lambda e: e.split("@")[-1] if "@" in e else None)
    findings["emails_found"] = emails_in
    findings["emails_out_of_scope"] = emails_out

    # URL fields
    for field in ("exposed_documents", "admin_panels", "directory_listings",
                  "backup_files", "pastebin_mentions"):
        urls_in, urls_out = _partition(
            findings.get(field, []), lambda u: self._extract_hostname(u))
        findings[field] = urls_in
        findings[f"{field}_out_of_scope"] = urls_out

    # Out-of-scope summary
    result["data"]["out_of_scope_summary"] = {
        "subdomain_count": len(subs_out),
        "email_count": len(emails_out),
        "url_count": sum(
            len(findings.get(f"{f}_out_of_scope", []))
            for f in ("exposed_documents", "admin_panels",
                      "directory_listings", "backup_files", "pastebin_mentions")
        ),
    }
    return result
```

### 7.2 Severity & Metrics

- Out-of-scope items are **not** stored as `Vulnerability` rows. They live in `SharedContext` JSON only.
- They do **not** affect `total_findings` count, severity distribution, or evaluation metrics (Precision/Recall/F1).
- Severity recalculation in `_handle_osint` uses only in-scope findings.

---

## 8. Report Template Changes

### 8.1 Cover Page — Scope Row

After `report.html.j2:151` (Framework row):

```html
<tr><td>Scope</td><td>{{ scope_whitelist | join(', ') }}</td></tr>
```

Context variable `scope_whitelist` set by `ReportGenerationAgent` from `sorted(security_guard.allowed_domains)`.

### 8.2 New Section: Out-of-Scope Discovery

Inserted after "4. Detailed Findings" (line 319), before "Appendix A":

```html
{% if oos_findings %}
<h1 class="section-break">5. Informational: Out-of-Scope Discovery</h1>
<p style="font-size:9pt;color:#546e7a">
  The following items were discovered through passive OSINT (certificate transparency,
  search engine dorking, theHarvester) but reference hosts <strong>outside the declared
  scan scope</strong>. No active testing was performed against these targets.
</p>

{% if oos_findings.subdomains %}
<h2>Subdomains (Certificate Transparency &amp; theHarvester)</h2>
<table>
  <tr><th>Subdomain</th><th>Source</th></tr>
  {% for sub in oos_findings.subdomains %}
  <tr><td>{{ sub }}</td><td>crt.sh / theHarvester</td></tr>
  {% endfor %}
</table>
{% endif %}

{% if oos_findings.emails %}
<h2>Email Addresses</h2>
<table>
  <tr><th>Email</th><th>Source</th></tr>
  {% for email in oos_findings.emails %}
  <tr><td>{{ email }}</td><td>theHarvester</td></tr>
  {% endfor %}
</table>
{% endif %}

{% if oos_findings.urls %}
<h2>URLs Referencing Out-of-Scope Hosts</h2>
<table>
  <tr><th>URL</th><th>Category</th></tr>
  {% for item in oos_findings.urls %}
  <tr><td><a href="{{ item.url }}">{{ item.url }}</a></td><td>{{ item.category }}</td></tr>
  {% endfor %}
</table>
{% endif %}

<p style="font-size:9pt;color:#78909c;margin-top:20px">
  <em>These items are provided for situational awareness only. To include them in
  active testing, add the relevant hostnames to <code>whitelist_domain</code>
  and re-scan.</em>
</p>
{% endif %}
```

### 8.3 Conditional Rendering

- `oos_findings` is `None` when no out-of-scope data exists → section not rendered.
- Juice Shop scans (single-host, no subdomains from crt.sh) → section absent → no visual change.
- Section numbering: "5" only appears conditionally. Appendix A/B numbering unchanged.

### 8.4 Context Variable Assembly

In `report_generation_agent.py`:

```python
oos_findings = {"subdomains": [], "emails": [], "urls": []}
osint_data = context_manager.load("reconnaissance_findings") or {}
osint = osint_data.get("search_engine_reconnaissance", {})

oos_findings["subdomains"] = osint.get("subdomains_out_of_scope", [])
oos_findings["emails"] = osint.get("emails_out_of_scope", [])

for field in ("exposed_documents", "admin_panels", "directory_listings",
              "backup_files", "pastebin_mentions"):
    for url in osint.get(f"{field}_out_of_scope", []):
        oos_findings["urls"].append({
            "url": url,
            "category": field.replace("_", " ").title()
        })

has_oos = any(oos_findings[k] for k in oos_findings)
report_context["oos_findings"] = oos_findings if has_oos else None
report_context["scope_whitelist"] = sorted(self.security_guard.allowed_domains)
```

---

## 9. Testing Strategy

### 9.1 Unit Tests (`test_scope_enforcement.py`, no Docker)

| Test Group | Cases | What It Validates |
|------------|-------|-------------------|
| `is_host_allowed()` | 8 | Exact match, wildcard, case insensitive, evil suffix, empty |
| `SCOPE_VIOLATION_TOOLS` | 2 | Frozenset contents, normal tools excluded |
| `_extract_hostname()` | 4 | Full URL, URL with port, bare hostname, None/empty |
| URL arg scope check | 3 | In-scope pass, out-of-scope reject, `base_url` checked |
| OSINT partitioning | 1 | Subdomains split correctly by whitelist |
| SCAN_PROFILE defaults | 2 | `lab` and `vdp` profile values |

**Total: ~20 test cases.**

### 9.2 Integration Test (Docker required)

Added to `test_new_architecture.py`:
- Start scan with `whitelist_domain: "juice-shop"` → verify `enumerate_active_subdomains` not in job_agent records.
- Verify `search_engine_reconnaissance` findings contain `*_out_of_scope` keys.

### 9.3 Regression Checklist

| # | Check | Command |
|---|---|---------|
| 1 | Unit tests | `pytest multi_agent_system/tests/test_scope_enforcement.py -v` |
| 2 | Existing tests | `pytest multi_agent_system/tests/test_vdp_generalization.py -v` |
| 3 | Juice Shop baseline | `SCAN_PROFILE=lab` → 14/14 agents, ~100 findings |
| 4 | Profile resolution | `SCAN_PROFILE=vdp` → HITL pauses + balanced mode |
| 5 | Scope violation log | `docker-compose logs -f worker` → `[scope]` entries |
| 6 | Report renders | PDF cover shows "Scope" row; no OOS section for Juice Shop |

---

## 10. Rollback

All changes are env-var and code-only. **Zero DB migration.**

| Scenario | Action |
|----------|--------|
| Scope too strict | Add host to `whitelist_domain` or remove from `SCOPE_VIOLATION_TOOLS` |
| Profile breaks Juice Shop | Set `SCAN_PROFILE=lab` in `.env`, restart worker |
| URL check false positive | Add `localhost`/`127.0.0.1` to default allowed list |
| LLM confused by scope prompt | Remove scope block from `_inject_planner_context()`, Layer 2 still enforces |
| Full revert needed | `git revert <commit>`, rebuild worker. No DB impact |

---

## 11. Files Modified

| File | Change |
|------|--------|
| `multi_agent_system/core/config.py` | `SCAN_PROFILE`, `SCAN_PROFILE_DEFAULTS`, `SCOPE_VIOLATION_TOOLS` |
| `multi_agent_system/utils/security_guard.py` | `is_host_allowed()` with fnmatch, refactor `validate_target()` |
| `multi_agent_system/agents/base_agent.py` | `should_run_tool()` scope gate, `_before_tool_execution()` host check, `_extract_hostname()`, `URL_ARG_NAMES` |
| `multi_agent_system/orchestrator.py` | `_build_scope_context_block()`, inject into `_inject_planner_context()` and `_prepare_planning_context()` |
| `multi_agent_system/agents/reconnaissance_agent.py` | `_handle_osint()` partition logic |
| `multi_agent_system/agents/report_generation_agent.py` | `oos_findings` + `scope_whitelist` context assembly |
| `multi_agent_system/templates/report.html.j2` | Cover "Scope" row, Section 5 OOS conditional block |
| `api/routes/scans.py` | `whitelist_domain: Union[str, List[str]]`, `_resolve_hitl_mode()`, `_resolve_adaptive_mode()` |
| `multi_agent_system/tests/test_scope_enforcement.py` | **NEW** — ~20 unit tests |
