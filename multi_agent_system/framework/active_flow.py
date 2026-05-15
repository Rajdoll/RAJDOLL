from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


@dataclass
class FlowResult:
    success: bool
    proof_type: str
    evidence: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"


@dataclass
class SessionRef:
    """Reference to an authenticated session for flow testing."""
    cookies: dict[str, str] = field(default_factory=dict)
    jwt_token: Optional[str] = None
    auth_headers: dict[str, str] = field(default_factory=dict)


class ActiveFlowTester:
    """Generic multi-step active flow tests (CSRF, password reset, JWT).

    Endpoint info passed in from caller (typically from endpoint_inventory).
    No hardcoded paths.
    """

    def __init__(self, jwt_wordlist_path: Optional[str] = None):
        self.jwt_wordlist_path = jwt_wordlist_path
