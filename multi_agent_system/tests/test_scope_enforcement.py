"""Tests for real-target scope enforcement (no Docker required)."""
import os
import pytest
from unittest.mock import patch


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
            # Need to reimport settings to pick up new env
            from multi_agent_system.core import config
            config.settings = config.Settings()
            from api.routes.scans import _resolve_hitl_mode
            assert _resolve_hitl_mode(None) == "off"

    def test_resolve_hitl_mode_vdp_default(self):
        from api.routes.scans import _resolve_hitl_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "vdp"}):
            from multi_agent_system.core import config
            config.settings = config.Settings()
            from api.routes.scans import _resolve_hitl_mode
            assert _resolve_hitl_mode(None) == "agent"

    def test_resolve_adaptive_mode_vdp_default(self):
        from api.routes.scans import _resolve_adaptive_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "vdp"}):
            from multi_agent_system.core import config
            config.settings = config.Settings()
            from api.routes.scans import _resolve_adaptive_mode
            assert _resolve_adaptive_mode(None) == "balanced"

    def test_resolve_adaptive_mode_fallback(self):
        from api.routes.scans import _resolve_adaptive_mode
        with patch.dict(os.environ, {"SCAN_PROFILE": "unknown"}):
            from multi_agent_system.core import config
            config.settings = config.Settings()
            from api.routes.scans import _resolve_adaptive_mode
            assert _resolve_adaptive_mode(None) == "aggressive"


# ── should_run_tool scope gate ───────────────────────────

class TestShouldRunToolScopeGate:
    def test_scope_violation_tool_rejected(self):
        """should_run_tool must reject tools in SCOPE_VIOLATION_TOOLS."""
        import inspect
        from multi_agent_system.agents.base_agent import BaseAgent
        source = inspect.getsource(BaseAgent.should_run_tool)
        assert "SCOPE_VIOLATION_TOOLS" in source
