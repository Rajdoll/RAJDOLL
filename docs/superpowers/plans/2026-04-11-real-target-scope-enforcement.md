# Real-Target Scope Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 3-layer defense-in-depth scope enforcement (LLM prompt, runtime gate, findings filter) so RAJDOLL can safely test real VDP targets without out-of-scope activity.

**Architecture:** `SCAN_PROFILE` env var selects safe defaults (hitl + adaptive mode). `SCOPE_VIOLATION_TOOLS` frozenset hard-disables subdomain enumeration. `SecurityGuardRails.is_host_allowed()` with fnmatch wildcards gates every tool call at runtime. OSINT findings are partitioned in-scope vs out-of-scope and rendered in a separate report section.

**Tech Stack:** Python 3.11, FastAPI/Pydantic, Jinja2, pytest, fnmatch

**Spec:** `docs/superpowers/specs/2026-04-11-real-target-scope-enforcement-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `multi_agent_system/core/config.py` | Modify | `SCAN_PROFILE`, `SCAN_PROFILE_DEFAULTS`, `SCOPE_VIOLATION_TOOLS` |
| `multi_agent_system/core/security_guards.py` | Modify | `is_host_allowed()` with fnmatch, refactor `is_whitelisted()` |
| `api/schemas/schemas.py` | Modify | `whitelist_domain: Union[str, List[str]]`, `get_whitelist_list()` |
| `api/routes/scans.py` | Modify | List whitelist merge, `_resolve_hitl_mode()`, `_resolve_adaptive_mode()` |
| `multi_agent_system/agents/base_agent.py` | Modify | `should_run_tool()` scope gate, `_before_tool_execution()` host check |
| `multi_agent_system/orchestrator.py` | Modify | `_build_scope_context_block()`, inject into `_inject_planner_context()` |
| `multi_agent_system/agents/reconnaissance_agent.py` | Modify | `_handle_osint()` partition logic |
| `multi_agent_system/agents/report_generation_agent.py` | Modify | `oos_findings` + `scope_whitelist` context assembly |
| `multi_agent_system/templates/report.html.j2` | Modify | Cover "Scope" row, Section 5 OOS conditional block |
| `multi_agent_system/tests/test_scope_enforcement.py` | Create | ~20 unit tests for all scope enforcement logic |

---

### Task 1: Config — SCAN_PROFILE + SCOPE_VIOLATION_TOOLS

**Files:**
- Modify: `multi_agent_system/core/config.py:104-113`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing tests for config constants**

Create `multi_agent_system/tests/test_scope_enforcement.py`:

```python
"""Tests for real-target scope enforcement (no Docker required)."""
import os
import pytest
from unittest.mock import patch


# ── SCAN_PROFILE + SCOPE_VIOLATION_TOOLS ─────────────────

class TestScanProfile:
    def test_scan_profile_defaults_has_lab(self):
        from multi_agent_system.core.config import SCAN_PROFILE_DEFAULTS
        assert "lab" in SCAN_PROFILE_DEFAULTS
        assert SCAN_PROFILE_DEFAULTS["lab"]["hitl_mode"] == "off"
        assert SCAN_PROFILE_DEFAULTS["lab"]["adaptive_mode"] == "aggressive"

    def test_scan_profile_defaults_has_vdp(self):
        from multi_agent_system.core.config import SCAN_PROFILE_DEFAULTS
        assert "vdp" in SCAN_PROFILE_DEFAULTS
        assert SCAN_PROFILE_DEFAULTS["vdp"]["hitl_mode"] == "agent"
        assert SCAN_PROFILE_DEFAULTS["vdp"]["adaptive_mode"] == "balanced"


class TestScopeViolationTools:
    def test_contains_subdomain_tools(self):
        from multi_agent_system.core.config import SCOPE_VIOLATION_TOOLS
        assert "enumerate_active_subdomains" in SCOPE_VIOLATION_TOOLS
        assert "test_subdomain_takeover" in SCOPE_VIOLATION_TOOLS
        assert "comprehensive_domain_recon" in SCOPE_VIOLATION_TOOLS
        assert "enumerate_applications" in SCOPE_VIOLATION_TOOLS

    def test_excludes_normal_tools(self):
        from multi_agent_system.core.config import SCOPE_VIOLATION_TOOLS
        assert "feroxbuster_scan" not in SCOPE_VIOLATION_TOOLS
        assert "security_headers_analysis" not in SCOPE_VIOLATION_TOOLS
        assert "search_engine_reconnaissance" not in SCOPE_VIOLATION_TOOLS
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py -v`
Expected: FAIL — `ImportError: cannot import name 'SCAN_PROFILE_DEFAULTS'` and `'SCOPE_VIOLATION_TOOLS'`

- [ ] **Step 3: Add constants to config.py**

In `multi_agent_system/core/config.py`, after line 113 (after `HIGH_RISK_TOOLS` frozenset), add:

```python
# Scan profile — determines safe defaults when not explicitly set per-scan
# "lab"  → HITL=off, ADAPTIVE=aggressive (Juice Shop / CI)
# "vdp"  → HITL=agent, ADAPTIVE=balanced (real target VDP)
SCAN_PROFILE_DEFAULTS: dict[str, dict[str, str]] = {
    "lab": {"hitl_mode": "off", "adaptive_mode": "aggressive"},
    "vdp": {"hitl_mode": "agent", "adaptive_mode": "balanced"},
}

# Tools that violate single-target scope by design.
# Hard-disabled regardless of LLM planner choice or Director directive.
SCOPE_VIOLATION_TOOLS: frozenset[str] = frozenset({
    "enumerate_active_subdomains",       # amass/subfinder/DNS brute
    "test_subdomain_takeover",            # CNAME takeover check
    "comprehensive_domain_recon",         # umbrella: DNS + WHOIS + subdomain
    "enumerate_applications",             # vhost/application enumeration
})
```

Also add `SCAN_PROFILE` to the `Settings` dataclass (before `__post_init__`):

```python
    scan_profile: str = field(default_factory=lambda: os.getenv("SCAN_PROFILE", "lab"))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestScanProfile -v && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestScopeViolationTools -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run existing tests for regression**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_vdp_generalization.py -v`
Expected: All 15 tests PASS (no regression)

- [ ] **Step 6: Commit**

```bash
git add multi_agent_system/core/config.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): add SCAN_PROFILE, SCAN_PROFILE_DEFAULTS, and SCOPE_VIOLATION_TOOLS to config"
```

---

### Task 2: SecurityGuardRails — `is_host_allowed()` with fnmatch

**Files:**
- Modify: `multi_agent_system/core/security_guards.py:58-175`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing tests for is_host_allowed()**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
# ── SecurityGuardRails.is_host_allowed() ─────────────────

class TestIsHostAllowed:
    def _make_guard(self, domains):
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        guard.whitelist_domains = list(domains)
        return guard

    def test_exact_match(self):
        guard = self._make_guard(["target.bssn.go.id"])
        assert guard.is_host_allowed("target.bssn.go.id") is True

    def test_exact_mismatch_subdomain(self):
        guard = self._make_guard(["target.bssn.go.id"])
        assert guard.is_host_allowed("api.target.bssn.go.id") is False

    def test_wildcard_match(self):
        guard = self._make_guard(["*.target.bssn.go.id"])
        assert guard.is_host_allowed("api.target.bssn.go.id") is True
        assert guard.is_host_allowed("dev.target.bssn.go.id") is True

    def test_wildcard_no_root(self):
        """*.x.com does NOT match x.com — user must add root explicitly."""
        guard = self._make_guard(["*.target.bssn.go.id"])
        assert guard.is_host_allowed("target.bssn.go.id") is False

    def test_wildcard_plus_root(self):
        guard = self._make_guard(["*.target.bssn.go.id", "target.bssn.go.id"])
        assert guard.is_host_allowed("target.bssn.go.id") is True
        assert guard.is_host_allowed("api.target.bssn.go.id") is True

    def test_evil_suffix_rejected(self):
        guard = self._make_guard(["target.bssn.go.id"])
        assert guard.is_host_allowed("target.bssn.go.id.evil.com") is False

    def test_case_insensitive(self):
        guard = self._make_guard(["Target.BSSN.go.id"])
        assert guard.is_host_allowed("target.bssn.go.id") is True

    def test_empty_host_rejected(self):
        guard = self._make_guard(["target.bssn.go.id"])
        assert guard.is_host_allowed("") is False
        assert guard.is_host_allowed(None) is False

    def test_localhost_always_allowed(self):
        guard = self._make_guard(["target.bssn.go.id"])
        assert guard.is_host_allowed("localhost") is True
        assert guard.is_host_allowed("127.0.0.1") is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestIsHostAllowed -v`
Expected: FAIL — `AttributeError: 'SecurityGuardRails' object has no attribute 'is_host_allowed'`

- [ ] **Step 3: Implement is_host_allowed() on SecurityGuardRails**

In `multi_agent_system/core/security_guards.py`, add `import fnmatch` at top (after `import re`), then add a class constant and method to `SecurityGuardRails` (after line 84, before `_load_default_whitelist`):

```python
    # Internal hosts always allowed (MCP containers use loopback)
    INTERNAL_HOSTS: frozenset = frozenset({"localhost", "127.0.0.1"})

    def is_host_allowed(self, host: str | None) -> bool:
        """Check if hostname matches whitelist (exact or fnmatch glob).

        Supports:
        - Exact match: "target.bssn.go.id"
        - Wildcard: "*.target.bssn.go.id" (matches subdomains, NOT root)
        - Internal hosts (localhost, 127.0.0.1) always allowed.
        """
        if not host:
            return False
        host = host.lower().strip()
        if host in self.INTERNAL_HOSTS:
            return True
        for pattern in self.whitelist_domains:
            if fnmatch.fnmatch(host, pattern.lower().strip()):
                return True
        return False
```

- [ ] **Step 4: Refactor is_whitelisted() to use is_host_allowed()**

Replace the existing `is_whitelisted` method body (lines 157-175) with:

```python
    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is in whitelist. Delegates to is_host_allowed()."""
        domain = domain.split(':')[0]  # Remove port if present
        return self.is_host_allowed(domain)
```

This preserves the existing API (all callers use `is_whitelisted`) but centralizes matching logic.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestIsHostAllowed -v`
Expected: All 9 tests PASS

- [ ] **Step 6: Run existing tests for regression**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_vdp_generalization.py -v`
Expected: All 15 tests PASS

- [ ] **Step 7: Commit**

```bash
git add multi_agent_system/core/security_guards.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): add is_host_allowed() with fnmatch wildcard to SecurityGuardRails"
```

---

### Task 3: API Schema — whitelist_domain as list + profile resolution

**Files:**
- Modify: `api/schemas/schemas.py:14-24`
- Modify: `api/routes/scans.py:28-31, 86-97`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing tests for whitelist normalization and profile resolution**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
# ── Whitelist domain normalization ───────────────────────

class TestWhitelistNormalization:
    def test_string_to_list(self):
        from api.schemas.schemas import CreateScanRequest
        req = CreateScanRequest(target="http://example.com", whitelist_domain="example.com")
        assert req.get_whitelist_list() == ["example.com"]

    def test_list_passthrough(self):
        from api.schemas.schemas import CreateScanRequest
        req = CreateScanRequest(
            target="http://example.com",
            whitelist_domain=["a.com", "b.com"]
        )
        assert req.get_whitelist_list() == ["a.com", "b.com"]

    def test_none_returns_empty(self):
        from api.schemas.schemas import CreateScanRequest
        req = CreateScanRequest(target="http://example.com")
        assert req.get_whitelist_list() == []


# ── Profile resolution ───────────────────────────────────

class TestProfileResolution:
    def test_resolve_hitl_mode_explicit_wins(self):
        from api.routes.scans import _resolve_hitl_mode
        assert _resolve_hitl_mode("tool") == "tool"

    def test_resolve_hitl_mode_lab_default(self):
        from api.routes.scans import _resolve_hitl_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "lab"}):
            assert _resolve_hitl_mode(None) == "off"

    def test_resolve_hitl_mode_vdp_default(self):
        from api.routes.scans import _resolve_hitl_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "vdp"}):
            assert _resolve_hitl_mode(None) == "agent"

    def test_resolve_adaptive_mode_vdp_default(self):
        from api.routes.scans import _resolve_adaptive_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "vdp"}):
            assert _resolve_adaptive_mode(None) == "balanced"

    def test_resolve_adaptive_mode_fallback(self):
        from api.routes.scans import _resolve_adaptive_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "unknown"}):
            assert _resolve_adaptive_mode(None) == "aggressive"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestWhitelistNormalization -v && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestProfileResolution -v`
Expected: FAIL — `get_whitelist_list` not found, `_resolve_hitl_mode` not found

- [ ] **Step 3: Update CreateScanRequest schema**

In `api/schemas/schemas.py`, change the imports and `CreateScanRequest`:

Add `Union` to imports:
```python
from typing import Optional, List, Any, Union
```

Replace `whitelist_domain` field (line 24) and add method:
```python
    whitelist_domain: Optional[Union[str, List[str]]] = None

    def get_whitelist_list(self) -> List[str]:
        """Normalize whitelist_domain to always return a list."""
        if self.whitelist_domain is None:
            return []
        if isinstance(self.whitelist_domain, str):
            return [self.whitelist_domain]
        return list(self.whitelist_domain)
```

- [ ] **Step 4: Add profile resolution functions to scans.py**

In `api/routes/scans.py`, after the imports block (after line 21), add:

```python
from multi_agent_system.core.config import settings, SCAN_PROFILE_DEFAULTS
from typing import Optional


def _resolve_hitl_mode(request_hitl: Optional[str]) -> str:
    """Resolve HITL mode: per-scan explicit > SCAN_PROFILE > fallback."""
    if request_hitl:
        return request_hitl
    profile = settings.scan_profile
    return SCAN_PROFILE_DEFAULTS.get(profile, {}).get("hitl_mode", "off")


def _resolve_adaptive_mode(request_adaptive: Optional[str]) -> str:
    """Resolve adaptive mode: per-scan explicit > SCAN_PROFILE > fallback."""
    if request_adaptive:
        return request_adaptive
    profile = settings.scan_profile
    return SCAN_PROFILE_DEFAULTS.get(profile, {}).get("adaptive_mode", "aggressive")
```

- [ ] **Step 5: Update whitelist merge in create_scan()**

In `api/routes/scans.py`, replace lines 29-31:

```python
	# Auto-add whitelist_domain if provided (convenience for VDP scans)
	if req.whitelist_domain:
		security_guard.whitelist_domains.append(req.whitelist_domain)
```

With:

```python
	# Auto-add whitelist_domain(s) — supports single string or list
	# Safe-Change Rule #6: append BEFORE validate_target
	for domain in req.get_whitelist_list():
		d = domain.lower().strip()
		if d and d not in security_guard.whitelist_domains:
			security_guard.whitelist_domains.append(d)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestWhitelistNormalization -v && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestProfileResolution -v`
Expected: All 8 tests PASS

- [ ] **Step 7: Run existing tests for regression**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_vdp_generalization.py -v`
Expected: All 15 tests PASS

- [ ] **Step 8: Commit**

```bash
git add api/schemas/schemas.py api/routes/scans.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): whitelist_domain as list, add SCAN_PROFILE resolution"
```

---

### Task 4: Layer 2a — SCOPE_VIOLATION_TOOLS gate in should_run_tool()

**Files:**
- Modify: `multi_agent_system/agents/base_agent.py:889-942`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing test for scope gate**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
# ── should_run_tool scope gate ───────────────────────────

class TestShouldRunToolScopeGate:
    def test_scope_violation_tool_rejected(self):
        """should_run_tool must reject tools in SCOPE_VIOLATION_TOOLS."""
        from multi_agent_system.core.config import SCOPE_VIOLATION_TOOLS
        # We test by verifying the check exists in should_run_tool.
        # Import and read source to confirm the guard is present.
        import inspect
        from multi_agent_system.agents.base_agent import BaseAgent
        source = inspect.getsource(BaseAgent.should_run_tool)
        assert "SCOPE_VIOLATION_TOOLS" in source
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestShouldRunToolScopeGate -v`
Expected: FAIL — `SCOPE_VIOLATION_TOOLS` not in source

- [ ] **Step 3: Add scope gate to should_run_tool()**

In `multi_agent_system/agents/base_agent.py`, at line 891 (right after the docstring of `should_run_tool`, before the Director SKIP check), add:

```python
		# SCOPE ENFORCEMENT: hard-disable subdomain enumeration tools (Layer 2a)
		# Cannot be overridden by Director INCLUDE, LLM planner, or HITL approval.
		from ..core.config import SCOPE_VIOLATION_TOOLS
		if tool_name in SCOPE_VIOLATION_TOOLS:
			self.log("warning", f"[scope] tool '{tool_name}' rejected: in SCOPE_VIOLATION_TOOLS")
			print(f"🚫 {self.agent_name}: Tool {tool_name} BLOCKED — scope violation (subdomain enum disabled)", file=sys.stderr, flush=True)
			return False
```

This must be placed **before** the Director SKIP check (line 894) so it takes precedence.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestShouldRunToolScopeGate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add multi_agent_system/agents/base_agent.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): add SCOPE_VIOLATION_TOOLS gate as first check in should_run_tool()"
```

---

### Task 5: Layer 2b — URL host check in _before_tool_execution()

**Files:**
- Modify: `multi_agent_system/agents/base_agent.py:1083-1136`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing tests for _extract_hostname and URL host check**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
from urllib.parse import urlparse


# ── _extract_hostname utility ────────────────────────────

def _extract_hostname(value):
    """Standalone copy of the extraction logic for testing."""
    if not value:
        return None
    try:
        parsed = urlparse(value if "://" in str(value) else f"http://{value}")
        return (parsed.hostname or "").lower() or None
    except Exception:
        return None


class TestExtractHostname:
    def test_full_url(self):
        assert _extract_hostname("https://target.bssn.go.id/login") == "target.bssn.go.id"

    def test_url_with_port(self):
        assert _extract_hostname("https://target.bssn.go.id:8443/admin") == "target.bssn.go.id"

    def test_bare_hostname(self):
        assert _extract_hostname("target.bssn.go.id") == "target.bssn.go.id"

    def test_empty_returns_none(self):
        assert _extract_hostname("") is None
        assert _extract_hostname(None) is None


# ── URL arg scope check ─────────────────────────────────

class TestUrlArgScopeCheck:
    URL_ARG_NAMES = ("url", "target_url", "target", "base_url", "domain", "host")

    def _check_args_in_scope(self, guard, args):
        """Return True if all URL-like args are in scope."""
        for arg_name in self.URL_ARG_NAMES:
            if arg_name not in args:
                continue
            host = _extract_hostname(str(args[arg_name]))
            if host is None:
                continue
            if not guard.is_host_allowed(host):
                return False
        return True

    def test_in_scope_passes(self):
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        guard.whitelist_domains = ["target.bssn.go.id"]
        args = {"url": "https://target.bssn.go.id/search?q=test"}
        assert self._check_args_in_scope(guard, args) is True

    def test_out_of_scope_rejected(self):
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        guard.whitelist_domains = ["target.bssn.go.id"]
        args = {"url": "https://dev.target.bssn.go.id/api"}
        assert self._check_args_in_scope(guard, args) is False

    def test_base_url_checked(self):
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        guard.whitelist_domains = ["target.bssn.go.id"]
        args = {"base_url": "https://evil.com/"}
        assert self._check_args_in_scope(guard, args) is False

    def test_source_code_has_host_check(self):
        """_before_tool_execution must contain URL host enforcement."""
        import inspect
        from multi_agent_system.agents.base_agent import BaseAgent
        source = inspect.getsource(BaseAgent._before_tool_execution)
        assert "is_host_allowed" in source
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestUrlArgScopeCheck::test_source_code_has_host_check -v`
Expected: FAIL — `is_host_allowed` not in `_before_tool_execution` source

- [ ] **Step 3: Add URL host check to _before_tool_execution()**

In `multi_agent_system/agents/base_agent.py`, add a module-level constant and a helper method, then modify `_before_tool_execution`.

After the existing imports at the top of the file, add:

```python
URL_ARG_NAMES = ("url", "target_url", "target", "base_url", "domain", "host")
```

Add a helper method to `BaseAgent` (before `_before_tool_execution`):

```python
	@staticmethod
	def _extract_hostname(value: str | None) -> str | None:
		"""Extract hostname from URL or bare hostname string."""
		if not value:
			return None
		try:
			v = str(value)
			parsed = urlparse(v if "://" in v else f"http://{v}")
			return (parsed.hostname or "").lower() or None
		except Exception:
			return None
```

In `_before_tool_execution` (line 1083), insert the host check **at the very beginning**, before the LLM args merge (line 1088). The method's new opening lines become:

```python
	async def _before_tool_execution(self, server: str, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
		"""Hook invoked by MCPClient prior to executing a tool."""
		# SCOPE ENFORCEMENT: reject tool calls targeting out-of-scope hosts (Layer 2b)
		from ..core.security_guards import security_guard
		for arg_name in URL_ARG_NAMES:
			if arg_name not in args:
				continue
			host = self._extract_hostname(str(args[arg_name]))
			if host is None:
				continue
			if not security_guard.is_host_allowed(host):
				self.log("warning", f"[scope] tool '{tool_name}' rejected: arg '{arg_name}'={host!r} not in whitelist")
				import sys
				print(f"🚫 {self.agent_name}: Tool {tool_name} BLOCKED — host {host!r} not in whitelist", file=sys.stderr, flush=True)
				return {"approved": False, "arguments": args}

		args = self._merge_planned_arguments(tool_name, args)
		# ... rest of existing method unchanged ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestExtractHostname -v && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestUrlArgScopeCheck -v`
Expected: All 8 tests PASS

- [ ] **Step 5: Run existing tests for regression**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_vdp_generalization.py -v`
Expected: All 15 tests PASS

- [ ] **Step 6: Commit**

```bash
git add multi_agent_system/agents/base_agent.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): add URL host check in _before_tool_execution() (Layer 2b)"
```

---

### Task 6: Layer 1 — LLM scope context injection in orchestrator

**Files:**
- Modify: `multi_agent_system/orchestrator.py:719-733`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing test for scope context block**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
# ── LLM scope context injection ──────────────────────────

class TestScopeContextBlock:
    def test_inject_planner_context_has_scope_block(self):
        """_inject_planner_context must include scope constraints."""
        import inspect
        from multi_agent_system.orchestrator import Orchestrator
        source = inspect.getsource(Orchestrator._inject_planner_context)
        assert "SCOPE CONSTRAINTS" in source or "_build_scope_context_block" in source
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestScopeContextBlock -v`
Expected: FAIL

- [ ] **Step 3: Add _build_scope_context_block() and inject it**

In `multi_agent_system/orchestrator.py`, add a new method to the `Orchestrator` class (before `_inject_planner_context`, around line 718):

```python
	def _build_scope_context_block(self) -> str:
		"""Build scope constraints block for LLM planning context (Layer 1)."""
		from .core.config import SCOPE_VIOLATION_TOOLS
		from .core.security_guards import security_guard
		allowed = ", ".join(sorted(security_guard.whitelist_domains)) or "(none — all hosts allowed)"
		disabled = ", ".join(sorted(SCOPE_VIOLATION_TOOLS))
		return (
			"\n## SCOPE CONSTRAINTS (MANDATORY)\n\n"
			f"**Allowed target hosts:** {allowed}\n"
			"- All url/target_url/target/base_url/domain/host arguments MUST resolve\n"
			"  to one of these hosts (exact match or glob pattern).\n"
			"- Tool calls with hostnames outside this list will be rejected at runtime.\n\n"
			f"**Disabled tools (scope violation — do not select):**\n{disabled}\n"
			"- These tools perform subdomain/host discovery outside research scope.\n"
			"- Selecting them has no effect; they are silently skipped.\n"
		)
```

Then modify `_inject_planner_context` (line 719). After the `director_instructions_text` injection (line 732), add:

```python
		# Layer 1: Scope enforcement via LLM prompt
		ctx["scope_constraints"] = self._build_scope_context_block()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestScopeContextBlock -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add multi_agent_system/orchestrator.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): inject scope constraints into LLM planning context (Layer 1)"
```

---

### Task 7: Layer 3 — OSINT findings partition in reconnaissance_agent

**Files:**
- Modify: `multi_agent_system/agents/reconnaissance_agent.py:618-631`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing test for OSINT partitioning**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
# ── OSINT findings partition ─────────────────────────────

class TestOsintPartition:
    def test_subdomains_partitioned(self):
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        guard.whitelist_domains = ["target.bssn.go.id"]

        subs = ["target.bssn.go.id", "api.target.bssn.go.id", "dev.target.bssn.go.id"]
        in_scope = [s for s in subs if guard.is_host_allowed(s.lower())]
        out_scope = [s for s in subs if not guard.is_host_allowed(s.lower())]

        assert in_scope == ["target.bssn.go.id"]
        assert set(out_scope) == {"api.target.bssn.go.id", "dev.target.bssn.go.id"}

    def test_emails_partitioned_by_domain(self):
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        guard.whitelist_domains = ["target.bssn.go.id"]

        emails = ["admin@target.bssn.go.id", "user@other.bssn.go.id"]
        in_scope = [e for e in emails if guard.is_host_allowed(e.split("@")[-1])]
        out_scope = [e for e in emails if not guard.is_host_allowed(e.split("@")[-1])]

        assert in_scope == ["admin@target.bssn.go.id"]
        assert out_scope == ["user@other.bssn.go.id"]

    def test_handle_osint_has_partition_logic(self):
        """_handle_osint must contain out_of_scope partitioning."""
        import inspect
        from multi_agent_system.agents.reconnaissance_agent import ReconnaissanceAgent
        source = inspect.getsource(ReconnaissanceAgent._handle_osint)
        assert "out_of_scope" in source
```

- [ ] **Step 2: Run tests to verify the source check fails**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestOsintPartition::test_handle_osint_has_partition_logic -v`
Expected: FAIL — `out_of_scope` not in source

- [ ] **Step 3: Modify _handle_osint() to partition findings**

In `multi_agent_system/agents/reconnaissance_agent.py`, replace the `_handle_osint` method (lines 618-630) with:

```python
    def _handle_osint(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return

        findings = data.get("findings", {})

        # Layer 3: Partition findings by scope
        from ..core.security_guards import security_guard

        def _partition(items, host_extractor):
            in_scope, out_scope = [], []
            for item in items:
                h = host_extractor(item)
                if h and security_guard.is_host_allowed(h):
                    in_scope.append(item)
                else:
                    out_scope.append(item)
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
                findings.get(field, []),
                lambda u: self._extract_hostname_from_url(u))
            findings[field] = urls_in
            findings[f"{field}_out_of_scope"] = urls_out

        # Summary
        data["out_of_scope_summary"] = {
            "subdomain_count": len(subs_out),
            "email_count": len(emails_out),
            "url_count": sum(
                len(findings.get(f"{f}_out_of_scope", []))
                for f in ("exposed_documents", "admin_panels",
                          "directory_listings", "backup_files", "pastebin_mentions")
            ),
        }

        snapshot["osint"] = data
        self.write_context("osint", data)

        # Only create findings from in-scope admin panels
        if findings.get("admin_panels"):
            self.add_finding(
                "WSTG-INFO",
                "Public OSINT exposed potential admin panels",
                severity="medium",
                evidence={"samples": findings["admin_panels"][:5]}
            )
```

Also add a helper method to `ReconnaissanceAgent` (in the class, near other helpers):

```python
    @staticmethod
    def _extract_hostname_from_url(url: str) -> str | None:
        """Extract hostname from URL for scope partitioning."""
        if not url:
            return None
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            return (parsed.hostname or "").lower() or None
        except Exception:
            return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestOsintPartition -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add multi_agent_system/agents/reconnaissance_agent.py multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): partition OSINT findings in-scope vs out-of-scope (Layer 3)"
```

---

### Task 8: Report template — Scope row + OOS section

**Files:**
- Modify: `multi_agent_system/templates/report.html.j2:147-153, 319-321`
- Modify: `multi_agent_system/agents/report_generation_agent.py`
- Test: `multi_agent_system/tests/test_scope_enforcement.py`

- [ ] **Step 1: Write failing test for template rendering**

Append to `multi_agent_system/tests/test_scope_enforcement.py`:

```python
from pathlib import Path


# ── Report template scope rendering ──────────────────────

class TestReportTemplate:
    def test_template_has_scope_row(self):
        template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
        content = template_path.read_text()
        assert "scope_whitelist" in content

    def test_template_has_oos_section(self):
        template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
        content = template_path.read_text()
        assert "oos_findings" in content

    def test_template_renders_with_oos(self):
        """Template renders OOS section when oos_findings is provided."""
        from jinja2 import Environment, FileSystemLoader
        import markdown

        def _md(text):
            if not text:
                return text
            return markdown.markdown(str(text))

        template_dir = Path(__file__).resolve().parent.parent / "templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=False)
        env.filters["md"] = _md
        tmpl = env.get_template("report.html.j2")

        fake_finding = {
            "ref": "F-001", "title": "Test", "severity": "HIGH",
            "wstg_id": "WSTG-INPV-05", "cwe_id": "CWE-89",
            "evidence": "test", "explanation": "test", "remediation": "test",
            "cvss_score_v4": 9.3, "references": [], "agent_name": "Test",
            "enrichment_source": "fallback",
        }
        oos = {
            "subdomains": ["api.target.bssn.go.id", "dev.target.bssn.go.id"],
            "emails": ["user@other.bssn.go.id"],
            "urls": [{"url": "https://staging.target.bssn.go.id/admin", "category": "Admin Panels"}],
        }

        html = tmpl.render(
            job_id=1, target="https://target.bssn.go.id",
            scan_date="2026-04-11", scan_duration="1h",
            total_findings=1, final_analysis="Summary.",
            findings=[fake_finding], top_findings=[fake_finding],
            sev_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            wstg_categories={"WSTG-INPV": 1},
            enrichment_stats={"static_kb": 0, "llm": 0, "fallback": 1},
            agents=[{"agent_name": "TestAgent", "status": "completed", "duration": "5m"}],
            scope_whitelist=["target.bssn.go.id"],
            oos_findings=oos,
        )

        assert "target.bssn.go.id" in html
        assert "Out-of-Scope Discovery" in html
        assert "api.target.bssn.go.id" in html
        assert "user@other.bssn.go.id" in html

    def test_template_renders_without_oos(self):
        """Template does NOT render OOS section when oos_findings is None."""
        from jinja2 import Environment, FileSystemLoader
        import markdown

        def _md(text):
            if not text:
                return text
            return markdown.markdown(str(text))

        template_dir = Path(__file__).resolve().parent.parent / "templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=False)
        env.filters["md"] = _md
        tmpl = env.get_template("report.html.j2")

        fake_finding = {
            "ref": "F-001", "title": "Test", "severity": "HIGH",
            "wstg_id": "WSTG-INPV-05", "cwe_id": "CWE-89",
            "evidence": "test", "explanation": "test", "remediation": "test",
            "cvss_score_v4": 9.3, "references": [], "agent_name": "Test",
            "enrichment_source": "fallback",
        }

        html = tmpl.render(
            job_id=1, target="http://juice-shop:3000",
            scan_date="2026-04-11", scan_duration="1h",
            total_findings=1, final_analysis="Summary.",
            findings=[fake_finding], top_findings=[fake_finding],
            sev_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            wstg_categories={"WSTG-INPV": 1},
            enrichment_stats={"static_kb": 0, "llm": 0, "fallback": 1},
            agents=[{"agent_name": "TestAgent", "status": "completed", "duration": "5m"}],
            scope_whitelist=["juice-shop"],
            oos_findings=None,
        )

        assert "Out-of-Scope Discovery" not in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestReportTemplate::test_template_has_scope_row -v`
Expected: FAIL — `scope_whitelist` not in template

- [ ] **Step 3: Add Scope row to cover page**

In `multi_agent_system/templates/report.html.j2`, after line 151 (the Framework row), add:

```html
    {% if scope_whitelist %}<tr><td>Scope</td><td>{{ scope_whitelist | join(', ') }}</td></tr>{% endif %}
```

- [ ] **Step 4: Add OOS section to template**

In `multi_agent_system/templates/report.html.j2`, after line 319 (after `{% endfor %}` that closes the findings loop) and before `{# ══════════════════════════════════════════════════ APPENDICES` (line 321), add:

```html

{# ═══════════════════════════════ OUT-OF-SCOPE INFORMATIONAL ═══ #}
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

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py::TestReportTemplate -v`
Expected: All 4 tests PASS

- [ ] **Step 6: Run existing PDF report test for regression**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_pdf_report.py -v`
Expected: All tests PASS (existing test does not pass `scope_whitelist` or `oos_findings` — Jinja2 treats undefined vars as empty by default, so template still renders)

- [ ] **Step 7: Commit**

```bash
git add multi_agent_system/templates/report.html.j2 multi_agent_system/tests/test_scope_enforcement.py
git commit -m "feat(scope): add Scope row and OOS section to report template"
```

---

### Task 9: Report context assembly — oos_findings + scope_whitelist

**Files:**
- Modify: `multi_agent_system/agents/report_generation_agent.py`

- [ ] **Step 1: Find the report context assembly point**

Read `multi_agent_system/agents/report_generation_agent.py` and locate where `report_context` or equivalent dict is built and passed to template rendering. Look for where `target`, `scan_date`, `findings` are assembled.

- [ ] **Step 2: Add scope_whitelist and oos_findings to report context**

At the point where the report context dict is assembled (near where `target`, `scan_date`, `findings` etc. are set), add:

```python
		# Scope enforcement: whitelist and out-of-scope OSINT findings
		from ..core.security_guards import security_guard
		report_context["scope_whitelist"] = sorted(security_guard.whitelist_domains)

		# Build out-of-scope findings from recon OSINT data
		oos_findings = {"subdomains": [], "emails": [], "urls": []}
		osint_data = shared_context.get("osint", {})
		if isinstance(osint_data, dict):
			findings_data = osint_data.get("findings", osint_data)
			oos_findings["subdomains"] = findings_data.get("subdomains_out_of_scope", [])
			oos_findings["emails"] = findings_data.get("emails_out_of_scope", [])
			for field in ("exposed_documents", "admin_panels", "directory_listings",
			              "backup_files", "pastebin_mentions"):
				for url in findings_data.get(f"{field}_out_of_scope", []):
					oos_findings["urls"].append({
						"url": url,
						"category": field.replace("_", " ").title()
					})

		has_oos = any(oos_findings[k] for k in oos_findings)
		report_context["oos_findings"] = oos_findings if has_oos else None
```

The exact insertion point depends on reading the file in Step 1. Place it near where other context keys are set.

- [ ] **Step 3: Commit**

```bash
git add multi_agent_system/agents/report_generation_agent.py
git commit -m "feat(scope): assemble oos_findings and scope_whitelist for report template"
```

---

### Task 10: Final regression tests + cleanup

**Files:**
- Test: `multi_agent_system/tests/test_scope_enforcement.py`
- Test: `multi_agent_system/tests/test_vdp_generalization.py`
- Test: `multi_agent_system/tests/test_pdf_report.py`

- [ ] **Step 1: Run full test suite**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py multi_agent_system/tests/test_vdp_generalization.py multi_agent_system/tests/test_pdf_report.py -v`
Expected: All tests PASS

- [ ] **Step 2: Verify test count**

Run: `cd /mnt/d/MCP/RAJDOLL && python -m pytest multi_agent_system/tests/test_scope_enforcement.py -v --co`
Expected: ~20 test items collected

- [ ] **Step 3: Verify no import errors in modified files**

Run: `cd /mnt/d/MCP/RAJDOLL && python -c "from multi_agent_system.core.config import SCAN_PROFILE_DEFAULTS, SCOPE_VIOLATION_TOOLS; print('config OK')" && python -c "from multi_agent_system.core.security_guards import security_guard; print('is_host_allowed:', hasattr(security_guard, 'is_host_allowed'))" && python -c "from api.schemas.schemas import CreateScanRequest; r = CreateScanRequest(target='http://x.com', whitelist_domain=['a','b']); print('whitelist:', r.get_whitelist_list())" && python -c "from api.routes.scans import _resolve_hitl_mode, _resolve_adaptive_mode; print('resolvers OK')"```
Expected: All print OK with no errors

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "test(scope): final regression pass for real-target scope enforcement"
```
