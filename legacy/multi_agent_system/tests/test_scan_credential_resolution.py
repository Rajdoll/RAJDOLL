"""Unit tests for resolving scan credentials from SharedContext secrets. No Docker."""
from multi_agent_system.orchestrator import _resolve_scan_credentials


class _FakeCtx:
    """Minimal stand-in for SharedContextManager."""
    def __init__(self, scan_credentials=None, secret=None):
        self._scan_credentials = scan_credentials
        self._secret = secret

    def read(self, key):
        if key == "scan_credentials":
            return self._scan_credentials
        return None

    def read_secret(self, ref):
        return self._secret if ref == "ref-123" else None


def test_returns_none_when_no_credentials():
    assert _resolve_scan_credentials(_FakeCtx(scan_credentials=None)) is None


def test_returns_none_when_no_credential_ref():
    ctx = _FakeCtx(scan_credentials={"provided": True})
    assert _resolve_scan_credentials(ctx) is None


def test_resolves_username_password_from_secret():
    ctx = _FakeCtx(
        scan_credentials={"credential_ref": "ref-123", "provided": True},
        secret={"username": "admin@juice-sh.op", "password": "admin123", "auth_type": "form"},
    )
    assert _resolve_scan_credentials(ctx) == [("admin@juice-sh.op", "admin123")]


def test_returns_none_when_secret_missing_fields():
    ctx = _FakeCtx(
        scan_credentials={"credential_ref": "ref-123"},
        secret={"username": "admin@juice-sh.op"},  # no password
    )
    assert _resolve_scan_credentials(ctx) is None
