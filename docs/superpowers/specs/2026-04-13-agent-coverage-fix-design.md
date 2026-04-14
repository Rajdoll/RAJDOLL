# Agent Tool Coverage Fix — Design Spec

**Date:** 2026-04-13
**Branch:** feat/scope-enforcement
**Status:** Approved

---

## Problem Summary

Four agents have bugs that silently prevent tools from running, reducing finding coverage:

| Type | Definition | Symptom |
|------|-----------|---------|
| **Type A** | `should_run_tool("name")` uses a different string than `_get_available_tools()` | Tool is SKIPPED in balanced mode because the name isn't found in the LLM plan |
| **Type B** | Tool is listed in `_get_available_tools()` but no `should_run_tool()` block exists in `execute()` | Tool never runs regardless of mode |

Root cause of Type A: the LLM plan and comprehensive coverage both use names from `_get_available_tools()`. If `execute()` checks a different name, the plan-check in `should_run_tool()` returns False → tool skipped.

Root cause of Type B: `_get_available_tools()` was updated to add new tools but the corresponding execute blocks were never written.

**Affected agents (10 agents unaffected and not touched):**

- `client_side_agent.py` — Type A (3 tools) + dead code removal + missing gate (1 tool)
- `identity_management_agent.py` — Type A (1 tool)
- `input_validation_agent.py` — Type A (7 tools missing from `_get_available_tools()`)
- `session_management_agent.py` — Type B (3 tools never called)

---

## Scope

| File | Change |
|------|--------|
| `multi_agent_system/agents/client_side_agent.py` | Fix 3 name mismatches, remove 2 dead blocks, add 1 gate |
| `multi_agent_system/agents/identity_management_agent.py` | Fix 1 name mismatch |
| `multi_agent_system/agents/input_validation_agent.py` | Add 7 tools to `_get_available_tools()` |
| `multi_agent_system/agents/session_management_agent.py` | Add 3 execute blocks |

No other files change. No DB migration. No orchestrator changes.

---

## Fix 1 — `client_side_agent.py`

### 1a. Name mismatch: `test_cors`

The MCP server (`client-side-testing`) exposes `test_cors_misconfiguration`, not `test_cors`.

**Change in `execute()`:**
```python
# BEFORE
if self.should_run_tool("test_cors"):
    ...
    client.call_tool(server="client-side-testing", tool="test_cors", ...)

# AFTER
if self.should_run_tool("test_cors_misconfiguration"):
    ...
    client.call_tool(server="client-side-testing", tool="test_cors_misconfiguration", ...)
```

### 1b. Name mismatch: `test_websocket`

MCP exposes `test_websockets` (with s), not `test_websocket`.

```python
# BEFORE
if self.should_run_tool("test_websocket"):
    ...
    client.call_tool(server="client-side-testing", tool="test_websocket", ...)

# AFTER
if self.should_run_tool("test_websockets"):
    ...
    client.call_tool(server="client-side-testing", tool="test_websockets", ...)
```

### 1c. Remove dead `test_csp` block

The block at `should_run_tool("test_csp")` calls `tool="test_csp"` which does not exist in the MCP server. `test_csp_bypass` is already correctly handled separately. Delete the entire block:

```python
# DELETE this entire block:
if self.should_run_tool("test_csp"):
    try:
        res = await self.run_tool_with_timeout(
            client.call_tool(server="client-side-testing", tool="test_csp", ...)
        ...
```

### 1d. Remove dead `analyze_csp` block

The unconditional block calling `tool="analyze_csp"` references a non-existent MCP tool. Delete it:

```python
# DELETE this entire block:
try:
    res = await self.run_tool_with_timeout(
        client.call_tool(server="client-side-testing", tool="analyze_csp", ...)
    ...
```

### 1e. Add gate to `test_browser_storage`

Currently called unconditionally. Add `should_run_tool` gate so it respects ADAPTIVE_MODE:

```python
# BEFORE (unconditional):
try:
    self.log("info", "Testing browser storage security")
    storage_res = await self.run_tool_with_timeout(
        client.call_tool(server="client-side-testing", tool="test_browser_storage", ...)

# AFTER (gated):
if self.should_run_tool("test_browser_storage"):
    try:
        self.log("info", "Testing browser storage security")
        storage_res = await self.run_tool_with_timeout(
            client.call_tool(server="client-side-testing", tool="test_browser_storage", ...)
```

Note: `_get_available_tools()` for `ClientSideAgent` already contains the correct canonical names and requires no changes.

---

## Fix 2 — `identity_management_agent.py`

### Name mismatch: `test_registration_process`

MCP server (`identity-management`) exposes `test_user_registration`, not `test_registration_process`.

```python
# BEFORE
if self.should_run_tool("test_registration_process"):
    ...
    client.call_tool(server="identity-management-testing", tool="test_registration_process", ...)

# AFTER
if self.should_run_tool("test_user_registration"):
    ...
    client.call_tool(server="identity-management-testing", tool="test_user_registration", ...)
```

`_get_available_tools()` already lists `test_user_registration` — no change needed there.

---

## Fix 3 — `input_validation_agent.py`

### 7 tools missing from `_get_available_tools()`

These tools are correctly called in `execute()` via `should_run_tool()`, and all exist in the input-validation MCP server, but are absent from `_get_available_tools()`. This means `set_tool_plan()` comprehensive coverage never includes them, and they can only run if the LLM happens to name them.

Add to the return list of `_get_available_tools()`:

```python
'test_nosql_injection',
'test_sqli_login',
'test_stored_xss',
'test_http_parameter_pollution',
'test_http_verb_tampering',
'test_http_incoming_requests',
'test_redos',
```

---

## Fix 4 — `session_management_agent.py`

### Three missing execute blocks

These tools are in `_get_available_tools()` and the MCP server, but `execute()` never calls them.

#### `test_csrf_protection` (WSTG-SESS-05)

The tool checks for CSRF token patterns in HTML and tests SameSite cookie attributes. `form_data={}` is valid — the tool checks the page even without form data.

```python
if self.should_run_tool("test_csrf_protection"):
    try:
        csrf_res = await self.run_tool_with_timeout(
            client.call_tool(
                server="session-management-testing",
                tool="test_csrf_protection",
                args={"url": target, "form_data": {}},
                auth_session=auth_data
            ),
            timeout=60
        )
        if isinstance(csrf_res, dict) and csrf_res.get("status") == "success":
            data = csrf_res.get("data", {})
            if data.get("csrf_vulnerable"):
                self.add_finding(
                    "WSTG-SESS-05",
                    "CSRF protection missing or bypassable",
                    severity="high",
                    evidence=data,
                    details="State-changing requests accepted without CSRF token"
                )
            elif not data.get("has_csrf_token_in_form"):
                cookies = data.get("cookies_samesite_check", [])
                missing_samesite = [c for c in cookies if c.get("samesite") == "Not Set"]
                if missing_samesite or not cookies:
                    self.add_finding(
                        "WSTG-SESS-05",
                        "CSRF: No token in forms and SameSite cookie not set",
                        severity="medium",
                        evidence=data,
                        details="No CSRF token detected; session cookies lack SameSite attribute"
                    )
    except Exception as e:
        self.log("warning", f"CSRF protection testing failed: {e}")
```

#### `test_session_puzzling` (WSTG-SESS-08)

Tests session variable overwriting via URL parameter pollution. `test_params={}` is valid — tool has built-in tests for common session variables.

```python
if self.should_run_tool("test_session_puzzling"):
    try:
        puzzling_res = await self.run_tool_with_timeout(
            client.call_tool(
                server="session-management-testing",
                tool="test_session_puzzling",
                args={"url": target, "test_params": {}},
                auth_session=auth_data
            ),
            timeout=60
        )
        if isinstance(puzzling_res, dict) and puzzling_res.get("status") == "success":
            data = puzzling_res.get("data", {})
            reflected = [
                t for t in data.get("parameter_pollution_tests", [])
                if t.get("reflected_in_response")
            ]
            if reflected or data.get("array_injection_vulnerable"):
                self.add_finding(
                    "WSTG-SESS-08",
                    "Session puzzling: session variables can be overwritten via URL parameters",
                    severity="medium",
                    evidence=data,
                    details=f"{len(reflected)} session variables reflected; array injection: {data.get('array_injection_vulnerable')}"
                )
    except Exception as e:
        self.log("warning", f"Session puzzling testing failed: {e}")
```

#### `test_session_hijacking` (WSTG-SESS-09)

Tests session hijacking resistance. Pass cookies from `auth_session` if available, otherwise empty dict (tool will still test for predictable session tokens).

```python
if self.should_run_tool("test_session_hijacking"):
    try:
        session_cookies = {}
        if auth_data and auth_data.get("cookies"):
            session_cookies = auth_data["cookies"]
        hijack_res = await self.run_tool_with_timeout(
            client.call_tool(
                server="session-management-testing",
                tool="test_session_hijacking",
                args={"url": target, "session_cookies": session_cookies},
                auth_session=auth_data
            ),
            timeout=60
        )
        if isinstance(hijack_res, dict) and hijack_res.get("status") == "success":
            data = hijack_res.get("data", {})
            if data.get("vulnerable"):
                self.add_finding(
                    "WSTG-SESS-09",
                    "Session hijacking risk detected",
                    severity="high",
                    evidence=data,
                    details=data.get("description", "Session tokens predictable or transmissible over insecure channel")
                )
    except Exception as e:
        self.log("warning", f"Session hijacking testing failed: {e}")
```

---

## Non-changes

- No changes to orchestrator, base_agent, models, or report template
- No DB migration required
- ADAPTIVE_MODE and HITL logic unchanged
- 10 other agents confirmed OK, not touched

---

## Testing

| Test | Method |
|------|--------|
| ClientSideAgent runs `test_cors_misconfiguration` | Check worker logs for APPROVED (not SKIPPED) |
| ClientSideAgent runs `test_websockets` | Check worker logs |
| `test_csp`/`analyze_csp` no longer appear | Grep worker logs — should be absent |
| IdentityManagementAgent runs `test_user_registration` | Worker logs APPROVED |
| InputValidationAgent tools in comprehensive plan | Worker logs show all 7 in tool_plan |
| SessionManagementAgent runs all 9 tools | Worker logs: 9 APPROVED (was 6) |
| SESS findings > 1 | DB query after scan: `SELECT COUNT(*) FROM findings WHERE agent_name='SessionManagementAgent'` |
