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
