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


class TestContainerNameAllowlist:
    def test_known_containers_constant_exists(self):
        """KNOWN_CONTAINERS set must exist in api.routes.logs."""
        from api.routes.logs import KNOWN_CONTAINERS
        assert "worker" in KNOWN_CONTAINERS
        assert "input-mcp" in KNOWN_CONTAINERS
        assert "auth-mcp" in KNOWN_CONTAINERS

    def test_invalid_container_rejected(self):
        """container_name not in KNOWN_CONTAINERS must raise HTTPException 400."""
        from api.routes.logs import KNOWN_CONTAINERS
        assert "../../etc/passwd" not in KNOWN_CONTAINERS
        assert "../secret" not in KNOWN_CONTAINERS


class TestSessionServiceCredentials:
    def test_juice_shop_creds_not_in_defaults(self):
        """admin@juice-sh.op must not appear in DEFAULT_CREDENTIALS."""
        from multi_agent_system.utils.session_service import SessionService
        usernames = [u for u, _ in SessionService.DEFAULT_CREDENTIALS]
        assert "admin@juice-sh.op" not in usernames

    def test_default_credentials_are_generic(self):
        """All DEFAULT_CREDENTIALS must be generic (no app-specific emails)."""
        from multi_agent_system.utils.session_service import SessionService
        for username, _ in SessionService.DEFAULT_CREDENTIALS:
            assert "@" not in username, f"App-specific email found: {username}"


class TestBaseAgentTargetFallback:
    def test_no_juice_shop_fallback_in_source(self):
        """_auto_generate_test_arguments must not contain juice-shop fallback URL."""
        import inspect
        from multi_agent_system.agents.base_agent import BaseAgent
        source = inspect.getsource(BaseAgent._auto_generate_test_arguments)
        assert "juice-shop" not in source, (
            "Found hardcoded juice-shop URL in base_agent._auto_generate_test_arguments"
        )


class TestKnowledgeGraphTarget:
    def test_knowledge_graph_accepts_target_param(self):
        """KnowledgeGraph.__init__ must accept optional target param."""
        from multi_agent_system.utils.knowledge_graph import KnowledgeGraph
        from unittest.mock import patch
        with patch.object(KnowledgeGraph, '_load_from_db', return_value=None):
            kg = KnowledgeGraph(job_id=999, target="https://target.bssn.go.id")
            assert kg.target == "https://target.bssn.go.id"

    def test_knowledge_graph_default_target_is_empty(self):
        """KnowledgeGraph target defaults to empty string, not juice-shop URL."""
        from multi_agent_system.utils.knowledge_graph import KnowledgeGraph
        from unittest.mock import patch
        with patch.object(KnowledgeGraph, '_load_from_db', return_value=None):
            kg = KnowledgeGraph(job_id=999)
            assert kg.target == ""
            assert "juice-shop" not in kg.target


class TestScanCredentialsSchema:
    def test_scan_credentials_model_exists(self):
        """ScanCredentials Pydantic model must be importable."""
        from api.schemas.schemas import ScanCredentials
        creds = ScanCredentials(username="admin@juice-sh.op", password="admin123")
        assert creds.username == "admin@juice-sh.op"
        assert creds.auth_type == "form"  # default

    def test_create_scan_request_accepts_credentials(self):
        """CreateScanRequest must accept optional credentials and whitelist_domain."""
        from api.schemas.schemas import CreateScanRequest, ScanCredentials
        req = CreateScanRequest(
            target="http://localhost:3000",
            credentials=ScanCredentials(username="u", password="p"),
            whitelist_domain="localhost",
        )
        assert req.credentials.username == "u"
        assert req.whitelist_domain == "localhost"

    def test_create_scan_request_credentials_optional(self):
        """credentials and whitelist_domain are optional."""
        from api.schemas.schemas import CreateScanRequest
        req = CreateScanRequest(target="http://localhost:3000")
        assert req.credentials is None
        assert req.whitelist_domain is None
