# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import httpx
import asyncio
import json
import base64
from typing import Dict, Any, List, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [authorization-testing] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


_BODY_LIMIT = 8192
_HEADER_KEYS = {"content-type", "content-length", "location", "server", "x-powered-by", "www-authenticate"}


def _emit_artifact(bucket, *, wstg, method, url, role, status, headers, body, baseline_status=None):
    if len(bucket) >= 12:
        return
    hs = {k: v for k, v in dict(headers or {}).items() if k.lower() in _HEADER_KEYS}
    bucket.append({"tool": "authz", "wstg": wstg, "method": method, "url": url,
                   "role": role or "anonymous", "status": int(status), "headers_subset": hs,
                   "body": (body or "")[:_BODY_LIMIT], "baseline_status": baseline_status})


# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"authorization-testing")

# --- Prompt ---
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domain: str, user_credentials: Dict[str, str], admin_credentials: Dict[str, str]) -> str:
    return f"""
You are an expert security tester specializing in **Authorization** flaws (OWASP WSTG 4.5). Your target is **{domain}**.

You will operate with two identities to compare behavior:
- **Low-Privilege User:** username `{user_credentials.get('username')}`
- **High-Privilege Admin:** username `{admin_credentials.get('username')}`

**Your Primary Objectives:**
1.  **Test for Vertical Privilege Escalation (4.5.1):** Can the low-privilege user access admin functions or pages? Use the `test_vertical_privilege_escalation` tool.
2.  **Test for Horizontal Privilege Escalation / IDOR (4.5.2, 4.5.4):** Can the user access resources belonging to other users by manipulating IDs? Use the `test_idor_vulnerability` tool on endpoints like `/api/users/{{ID}}` or `/profile?id={{ID}}`.
3.  **Test for Method Tampering (4.5.3):** Can changing an HTTP method (e.g., GET to DELETE) on a URL bypass access controls? Use `test_http_method_tampering`.
4.  **Check for User-Controllable Keys (4.5.5):** Analyze JWTs or cookies for roles or privileges that can be tampered with.

**Your Workflow:**
1.  **Login as both users** using a browser controller (Puppeteer) and capture their session cookies or JWTs. Store them securely.
2.  **Discover** functionality available to the normal user and URLs that seem restricted to admins.
3.  **Execute** the tools provided in this script using the captured sessions to test for vulnerabilities. For example, provide the low-privilege user's cookies and a list of admin URLs to the vertical escalation tool.
4.  **Analyze** the JSON results from each tool. A successful vertical escalation or an IDOR finding is a critical vulnerability.
5.  **Report** all findings with clear evidence and mitigation steps.
"""

# --- Tools ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_vertical_privilege_escalation(
    admin_urls: List[str],
    low_priv_session: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Attempts to access a list of admin-only URLs using a low-privilege user's session.
    A session can be {'cookies': {...}} or {'headers': {'Authorization': 'Bearer ...'}}.
    """
    logger.info("🔍 Executing test_vertical_privilege_escalation")
    findings = []
    artifacts = []
    try:
        async with httpx.AsyncClient(verify=False) as client:
            for url in admin_urls:
                try:
                    # Menyiapkan request dengan sesi pengguna biasa
                    req_kwargs = {
                        "cookies": low_priv_session.get("cookies"),
                        "headers": low_priv_session.get("headers"),
                        "follow_redirects": False,
                        "timeout": 10
                    }
                    resp = await client.get(url, **req_kwargs)

                    # Kerentanan ada jika server merespons dengan 2xx (Success)
                    if 200 <= resp.status_code < 300:
                        # A bare 2xx is not proof by itself. Confirm the URL is
                        # actually gated by re-requesting it with no session at
                        # all: if anonymous access is rejected but the
                        # low-privilege session gets real content back, that is
                        # genuine cross-role access proof.
                        try:
                            anon_resp = await client.get(url, follow_redirects=False, timeout=10)
                        except Exception:
                            anon_resp = None
                        anon_blocked = anon_resp is None or not (200 <= anon_resp.status_code < 300)
                        has_content = bool(resp.text and resp.text.strip())
                        confirmed = anon_blocked and has_content
                        findings.append({
                            "url": url,
                            "status": "VULNERABLE" if confirmed else "POTENTIALLY VULNERABLE",
                            "status_code": resp.status_code,
                            "description": "Low-privilege user successfully accessed a high-privilege URL.",
                            **({"evidence": {
                                "data_extracted": True,
                                "anonymous_status_code": anon_resp.status_code if anon_resp else None,
                                "low_priv_status_code": resp.status_code,
                            }} if confirmed else {}),
                        })
                        _emit_artifact(artifacts, wstg="WSTG-ATHZ-04", method="GET", url=url,
                                       role=(low_priv_session.get("username") if isinstance(low_priv_session, dict) else low_priv_session) or "anonymous",
                                       status=resp.status_code, headers=dict(resp.headers), body=resp.text,
                                       baseline_status=None)
                    else:
                        findings.append({
                            "url": url,
                            "status": "Likely Not Vulnerable",
                            "status_code": resp.status_code
                        })
                except Exception as e:
                    findings.append({"url": url, "status": "ERROR", "message": str(e)})

        return {"status": "success", "data": {"results": findings}, "artifacts": artifacts}
    except Exception as e:
        return {"status": "error", "message": f"An unexpected error occurred: {e}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_idor_vulnerability(
    base_url_with_placeholder: str,
    session: Dict[str, Any],
    start_id: int,
    count: int = 10
) -> Dict[str, Any]:
    """
    Tests for Insecure Direct Object References (IDOR) by iterating through numeric IDs.
    Example base_url: "https://example.com/api/users/{ID}/profile"
    """
    logger.info("🔍 Executing test_idor_vulnerability")
    findings = []
    artifacts = []
    placeholder = "{ID}"
    if placeholder not in base_url_with_placeholder:
        return {"status": "error", "message": f"base_url_with_placeholder must contain '{{ID}}'."}

    seen_bodies = {}
    try:
        async with httpx.AsyncClient(verify=False) as client:
            for i in range(start_id, start_id + count):
                url = base_url_with_placeholder.replace(placeholder, str(i))
                try:
                    req_kwargs = {
                        "cookies": session.get("cookies"),
                        "headers": session.get("headers"),
                        "timeout": 10
                    }
                    resp = await client.get(url, **req_kwargs)

                    # Kerentanan ada jika server merespons dengan 200 OK untuk ID yang berbeda
                    if resp.status_code == 200:
                        # A bare 200 does not prove a different user's object was
                        # reached. If a later ID's body genuinely differs from an
                        # earlier ID's body, that proves each ID maps to a real,
                        # distinct object (not a static/cached page) -- strong
                        # cross-object access proof.
                        distinct = any(resp.text != prior for prior in seen_bodies.values())
                        seen_bodies[i] = resp.text
                        finding = {
                            "id_tested": i,
                            "url": url,
                            "status": "VULNERABLE" if distinct else "POTENTIALLY VULNERABLE",
                            "status_code": resp.status_code,
                            "response_size": len(resp.content)
                        }
                        if distinct:
                            finding["evidence"] = {"data_extracted": True, "distinct_from_other_ids": True}
                        findings.append(finding)
                        _emit_artifact(artifacts, wstg="WSTG-ATHZ-04", method="GET", url=url,
                                       role=(session.get("username") if isinstance(session, dict) else session) or "anonymous",
                                       status=resp.status_code, headers=dict(resp.headers), body=resp.text,
                                       baseline_status=None)
                except Exception:
                    # Mengabaikan error koneksi untuk ID individual
                    continue

        return {"status": "success", "data": {"results": findings, "instructions": "Review results to confirm if data from other users was accessed."}, "artifacts": artifacts}
    except Exception as e:
        return {"status": "error", "message": f"An unexpected error occurred: {e}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_http_method_tampering(
    url: str,
    session: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Checks if changing the HTTP method reveals authorization bypasses.
    Tries HEAD, POST, PUT, DELETE on a given URL.
    """
    logger.info("🔍 Executing test_http_method_tampering")
    findings = []
    artifacts = []
    methods_to_test = ["HEAD", "POST", "PUT", "DELETE", "PATCH"]
    state_changing_methods = {"PUT", "DELETE", "PATCH"}
    try:
        async with httpx.AsyncClient(verify=False) as client:
            req_kwargs = {
                "cookies": session.get("cookies"),
                "headers": session.get("headers"),
                "timeout": 10
            }
            # Ambil response dasar dengan GET
            base_resp = await client.get(url, **req_kwargs)

            for method in methods_to_test:
                try:
                    resp = await client.request(method, url, **req_kwargs)
                    if resp.status_code != base_resp.status_code and resp.status_code < 500:
                        finding = {
                            "method": method,
                            "status": "INTERESTING_RESPONSE",
                            "original_status": base_resp.status_code,
                            "new_status": resp.status_code,
                            "description": "The server responded differently to a tampered HTTP method."
                        }
                        # A status-code difference alone is not proof of impact.
                        # For state-changing methods that returned 2xx, re-read
                        # the resource and confirm the change actually took
                        # effect (e.g. DELETE -> now 404, PUT/PATCH -> body
                        # changed) before treating it as confirmed.
                        if method in state_changing_methods and 200 <= resp.status_code < 300:
                            try:
                                followup = await client.get(url, **req_kwargs)
                                if method == "DELETE":
                                    state_changed = followup.status_code in (404, 410)
                                else:
                                    state_changed = followup.text != base_resp.text
                            except Exception:
                                state_changed = False
                            if state_changed:
                                finding["status"] = "VULNERABLE"
                                finding["evidence"] = {
                                    "state_change_verified": True,
                                    "followup_status_code": followup.status_code,
                                }
                        findings.append(finding)
                        if 200 <= resp.status_code < 300:
                            _emit_artifact(artifacts, wstg="WSTG-ATHZ-04", method=method, url=url,
                                           role=(session.get("username") if isinstance(session, dict) else session) or "anonymous",
                                           status=resp.status_code, headers=dict(resp.headers), body=resp.text,
                                           baseline_status=base_resp.status_code)
                except Exception:
                    continue
        return {"status": "success", "data": {"results": findings}, "artifacts": artifacts}
    except Exception as e:
        return {"status": "error", "message": f"An unexpected error occurred: {e}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def get_manual_authorization_checklist() -> Dict[str, Any]:
    """
    Provides a checklist for complex authorization tests that require manual review.
    """
    checklist = {
        "User-controllable Keys": [
            "Decode any JWTs or session cookies. Do they contain role, user ID, or privilege claims (e.g., 'isAdmin: false')?",
            "If so, try to modify the claim (e.g., 'isAdmin: true'), re-sign/re-encode if necessary, and submit the modified token/cookie.",
            "Can you access resources of user B by substituting user B's ID into a cookie or token originally issued to user A?"
        ],
        "Business Logic Flaws": [
            "Can a user approve a transaction they are not authorized to approve by manipulating a hidden form field?",
            "Is it possible to perform actions in an incorrect order to bypass authorization checks (e.g., add item to cart after checkout)?",
            "If there is a multi-step wizard, can you skip steps to land on a privileged page?"
        ]
    }
    return {"status": "success", "data": checklist}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_idor_comprehensive(
    base_url: str,
    endpoint_patterns: Optional[List[str]] = None,
    session: Optional[Dict[str, Any]] = None,
    id_range_start: int = 1,
    id_range_end: int = 20
) -> Dict[str, Any]:
    """
    Comprehensive IDOR testing for any web application.

    LLM should provide endpoint_patterns based on reconnaissance findings.
    Discovers IDOR vulnerabilities by testing sequential ID access across endpoints.

    Args:
        base_url: Target application base URL
        endpoint_patterns: List of endpoint patterns with {id} placeholder, e.g., ["/api/users/{id}", "/api/orders/{id}"]
                          If None, uses common REST API patterns for discovery
        session: Optional authenticated session (cookies/headers)
        id_range_start: Starting ID to test (default: 1)
        id_range_end: Ending ID to test (default: 20)

    Returns:
        Dict with vulnerabilities_found count and detailed findings
    """
    logger.info("🔍 Executing test_idor_comprehensive (generic IDOR testing)")

    # If LLM doesn't provide patterns, use common REST API patterns for discovery
    if endpoint_patterns is None:
        idor_patterns = [
            "/api/users/{id}",  # User profiles
            "/api/user/{id}",
            "/api/orders/{id}",  # Orders
            "/api/order/{id}",
            "/api/documents/{id}",  # Documents
            "/api/files/{id}",  # Files
            "/api/invoices/{id}",  # Invoices
            "/api/tickets/{id}",  # Support tickets
            "/api/messages/{id}",  # Messages
            "/api/profiles/{id}",  # Profiles
            "/rest/users/{id}",  # REST patterns
            "/rest/items/{id}",
            "/users/{id}",  # Simple patterns
            "/items/{id}",
        ]
    else:
        idor_patterns = endpoint_patterns

    findings = []
    artifacts = []

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
            # Test each IDOR pattern with configurable ID range
            for pattern in idor_patterns:
                # Test IDs from id_range_start to id_range_end
                for test_id in range(id_range_start, id_range_end + 1):
                    url = base_url.rstrip('/') + pattern.format(id=test_id)

                    try:
                        req_kwargs = {}
                        if session:
                            req_kwargs["cookies"] = session.get("cookies", {})
                            req_kwargs["headers"] = session.get("headers", {})

                        resp = await client.get(url, **req_kwargs)

                        # IDOR detected if we get 200 OK
                        if resp.status_code == 200:
                            try:
                                data = resp.json() if 'json' in resp.headers.get('content-type', '') else {}
                            except:
                                data = {}

                            # A bare 200 is not proof of authorization bypass by
                            # itself. Real, non-empty JSON object data proves the
                            # endpoint actually returned a resource, not just a
                            # generic 200 wrapper (empty/binary/non-JSON body).
                            has_real_data = bool(data)
                            findings.append({
                                "endpoint": pattern,
                                "id_tested": test_id,
                                "url": url,
                                "severity": "High" if has_real_data else "Low",
                                "status": "VULNERABLE" if has_real_data else "POTENTIALLY VULNERABLE",
                                "status_code": resp.status_code,
                                "response_size": len(resp.content),
                                "description": f"Can access resource {test_id} without proper authorization check",
                                "evidence": {
                                    "data_extracted": has_real_data,
                                    "data_sample": str(data)[:200] if data else "Binary or non-JSON response"
                                }
                            })
                            _emit_artifact(artifacts, wstg="WSTG-ATHZ-04", method="GET", url=url,
                                           role=(session.get("username") if isinstance(session, dict) else session) or "anonymous",
                                           status=resp.status_code, headers=dict(resp.headers), body=resp.text,
                                           baseline_status=None)

                    except httpx.TimeoutException:
                        continue  # Skip timeout
                    except Exception as e:
                        continue  # Skip errors

        # Summary
        unique_endpoints = len(set(f["endpoint"] for f in findings))
        return {
            "status": "success",
            "data": {
                "vulnerabilities_found": len(findings),
                "unique_endpoints_affected": unique_endpoints,
                "tested_patterns": len(idor_patterns),
                "id_range_tested": f"{id_range_start}-{id_range_end}",
                "findings": findings,
                "description": f"Comprehensive IDOR testing complete. Tested {len(idor_patterns)} endpoint patterns across ID range {id_range_start}-{id_range_end}. High severity findings indicate authorization bypass vulnerabilities.",
                "remediation": "Implement proper authorization checks before serving sensitive resources. Verify user ownership/permissions for all resource access."
            },
            "artifacts": artifacts
        }

    except Exception as e:
        return {"status": "error", "message": f"IDOR testing failed: {e}"}


async def test_user_spoofing(url: str, auth_session: Optional[Dict[str, Any]] = None, endpoints: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Test for user spoofing vulnerabilities — posting content as another user.

    Tests each provided endpoint for:
    - POST with manipulated user ID fields (UserId, user_id, userId, author_id)
    - PATCH with NoSQL operator injection ($ne) for mass update
    - Repeated POST/like actions to detect missing rate limiting

    If no endpoints are provided, tests the url directly.

    OWASP Reference: WSTG-ATHZ-02, WSTG-ATHZ-03

    Args:
        url: Target URL (used as base URL to resolve relative endpoints, or tested directly if no endpoints given)
        auth_session: Optional authenticated session (cookies/headers/token)
        endpoints: Optional list of endpoint paths to test (e.g., ["/api/feedback", "/api/reviews"]).
                   Can be absolute URLs or relative paths (resolved against url's origin).
    """
    findings = []
    artifacts = []
    from urllib.parse import urlparse, urljoin
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    req_kwargs = {"timeout": 15, "verify": False, "follow_redirects": True}
    headers = {"Content-Type": "application/json"}
    if auth_session:
        if 'cookies' in auth_session:
            req_kwargs['cookies'] = auth_session['cookies']
        if 'headers' in auth_session:
            headers.update(auth_session.get('headers', {}))
        elif 'token' in auth_session:
            headers['Authorization'] = f"Bearer {auth_session['token']}"
    req_kwargs['headers'] = headers

    # Resolve endpoint list: use provided endpoints, or fall back to the url itself
    if endpoints:
        resolved_endpoints = []
        for ep in endpoints:
            if ep.startswith("http://") or ep.startswith("https://"):
                resolved_endpoints.append(ep)
            else:
                resolved_endpoints.append(base_url.rstrip('/') + '/' + ep.lstrip('/'))
    else:
        resolved_endpoints = [url]

    async with httpx.AsyncClient(**req_kwargs) as client:

        for endpoint_url in resolved_endpoints:
            # Test 1: POST with spoofed user ID fields
            spoofed_user_ids = [1, 2, 3]
            user_id_fields = ["UserId", "user_id", "userId", "author_id"]
            for uid in spoofed_user_ids:
                for id_field in user_id_fields:
                    try:
                        payload = {
                            id_field: uid,
                            "comment": "Spoofing test (automated security scan)",
                            "rating": 3,
                        }
                        resp = await client.post(endpoint_url, json=payload)
                        if resp.status_code in (200, 201):
                            resp_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                            data = resp_data.get("data", resp_data)
                            actual_uid = data.get(id_field) if isinstance(data, dict) else None
                            if actual_uid == uid:
                                findings.append({
                                    "type": "user_spoofing",
                                    "status": "VULNERABLE",
                                    "severity": "high",
                                    "description": f"Content posted as {id_field}={uid} (different from authenticated user)",
                                    "endpoint": endpoint_url,
                                    "evidence": {
                                        "owner_mismatch": True,
                                        "spoofed_id_field": id_field,
                                        "spoofed_uid": uid,
                                        "echoed_uid": actual_uid,
                                        "raw_response": str(resp_data)[:300],
                                    },
                                    "recommendation": f"Enforce server-side {id_field} from session, ignore client-sent value",
                                })
                                _emit_artifact(artifacts, wstg="WSTG-ATHZ-03", method="POST", url=endpoint_url,
                                               role=(auth_session.get("username") if isinstance(auth_session, dict) else auth_session) or "anonymous",
                                               status=resp.status_code, headers=dict(resp.headers), body=resp.text,
                                               baseline_status=None)
                                break  # One proof per uid is enough
                    except Exception:
                        continue

            # Test 2: PATCH with NoSQL operator injection for mass update
            try:
                resp = await client.patch(endpoint_url, json={
                    "id": {"$ne": -1},
                    "message": "NoSQL mass update test",
                })
                if resp.status_code == 200:
                    resp_data = {}
                    try:
                        resp_data = resp.json()
                    except Exception:
                        pass
                    modified = resp_data.get("modified", resp_data.get("modifiedCount", 0))
                    if isinstance(modified, int) and modified > 1:
                        findings.append({
                            "type": "nosql_mass_update",
                            "status": "VULNERABLE",
                            "severity": "critical",
                            "description": f"NoSQL injection: mass update affected {modified} records",
                            "endpoint": endpoint_url,
                            "evidence": {
                                "state_change_verified": True,
                                "modified_count": modified,
                                "raw_response": str(resp_data)[:300],
                            },
                        })
                    elif resp.status_code == 200:
                        # 200 alone does not prove the $ne operator was effective.
                        # Evidence = a multi-record response (operator matched many
                        # rows); otherwise report low/unconfirmed instead of high.
                        _many = False
                        try:
                            _d = resp.json()
                            _many = isinstance(_d, list) and len(_d) > 1
                        except Exception:
                            pass
                        findings.append({
                            "type": "nosql_operator_accepted",
                            "severity": "high" if _many else "low",
                            "description": (
                                "NoSQL $ne returned multiple records (operator effective)"
                                if _many else
                                "Endpoint accepted NoSQL operator ($ne) but effect unconfirmed (200 only)"
                            ),
                            "endpoint": endpoint_url,
                            "evidence": resp.text[:300],
                        })
            except Exception:
                pass

            # Test 3: Repeated action to detect missing rate limiting
            like_count = 0
            for _ in range(5):
                try:
                    resp = await client.post(endpoint_url)
                    if resp.status_code == 200:
                        like_count += 1
                except Exception:
                    break
            if like_count >= 3:
                findings.append({
                    "type": "missing_rate_limit",
                    "severity": "medium",
                    "description": f"Same action succeeded {like_count} times without rate limiting",
                    "endpoint": endpoint_url,
                    "recommendation": "Enforce rate limiting or one-action-per-user constraint",
                })

    return {
        "status": "success",
        "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "description": "User spoofing and unauthorized action testing",
        },
        "artifacts": artifacts
    }


# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter
#     mcp.run(transport="stdio")

