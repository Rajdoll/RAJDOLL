# multi_agent_system/tests/test_vdp_generalization.py
import os
import pytest
from unittest.mock import patch


class TestAdminToken:
    def test_verify_admin_token_reads_from_env(self):
        """ADMIN_TOKEN must come from env var, not hardcode."""
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        with patch.dict(os.environ, {"ADMIN_TOKEN": "my_secret_token"}):
            assert guard.verify_admin_token("my_secret_token") is True

    def test_verify_admin_token_rejects_placeholder(self):
        """The old 'admin_token_placeholder' must no longer work."""
        from multi_agent_system.core.security_guards import SecurityGuardRails
        with patch.dict(os.environ, {"ADMIN_TOKEN": "real_secret"}):
            guard = SecurityGuardRails()
            assert guard.verify_admin_token("admin_token_placeholder") is False

    def test_verify_admin_token_empty_env_rejects_all(self):
        """If ADMIN_TOKEN env var is not set, all tokens rejected."""
        from multi_agent_system.core.security_guards import SecurityGuardRails
        env = {k: v for k, v in os.environ.items() if k != "ADMIN_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            guard = SecurityGuardRails()
            assert guard.verify_admin_token("anything") is False


class TestWhitelistDefaults:
    def test_default_whitelist_is_empty(self):
        """Default whitelist must not contain any domain — require explicit add."""
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        assert guard.whitelist_domains == []

    def test_juice_shop_not_in_whitelist(self):
        """juice-shop must not be in whitelist_domains after fix."""
        from multi_agent_system.core.security_guards import SecurityGuardRails
        guard = SecurityGuardRails()
        assert "juice-shop" not in guard.whitelist_domains
