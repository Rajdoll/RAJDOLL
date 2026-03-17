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
                        findings.append({
                            "url": url,
                            "status": "VULNERABLE",
                            "status_code": resp.status_code,
                            "description": "Low-privilege user successfully accessed a high-privilege URL."
                        })
                    else:
                        findings.append({
                            "url": url,
                            "status": "Likely Not Vulnerable",
                            "status_code": resp.status_code
                        })
                except Exception as e:
                    findings.append({"url": url, "status": "ERROR", "message": str(e)})
        
        return {"status": "success", "data": {"results": findings}}
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
    placeholder = "{ID}"
    if placeholder not in base_url_with_placeholder:
        return {"status": "error", "message": f"base_url_with_placeholder must contain '{{ID}}'."}

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
                        findings.append({
                            "id_tested": i,
                            "url": url,
                            "status": "POTENTIALLY VULNERABLE",
                            "status_code": resp.status_code,
                            "response_size": len(resp.content)
                        })
                except Exception:
                    # Mengabaikan error koneksi untuk ID individual
                    continue
        
        return {"status": "success", "data": {"results": findings, "instructions": "Review results to confirm if data from other users was accessed."}}
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
    methods_to_test = ["HEAD", "POST", "PUT", "DELETE", "PATCH"]
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
                        findings.append({
                            "method": method,
                            "status": "INTERESTING_RESPONSE",
                            "original_status": base_resp.status_code,
                            "new_status": resp.status_code,
                            "description": "The server responded differently to a tampered HTTP method."
                        })
                except Exception:
                    continue
        return {"status": "success", "data": {"results": findings}}
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
            "/rest/basket/{id}",        # Shopping basket access
            "/api/BasketItems/{id}",    # Basket items
            "/api/Feedbacks/{id}",      # Feedback/reviews
            "/api/Complaints/{id}",     # Complaint records
            "/api/Recycles/{id}",       # Recycle data
            "/api/Addresss/{id}",       # Address records (note: typo-inclusive)
            "/api/Addresses/{id}",      # Address records
            "/api/Cards/{id}",          # Payment cards
            "/api/Products/{id}",       # Product details
            "/api/Quantitys/{id}",      # Quantity records
            "/api/SecurityQuestions/{id}", # Security questions
            "/rest/products/{id}/reviews", # Product reviews
            "/api/Deliverys/{id}",      # Delivery records
            "/api/Wallets/{id}",        # Wallet data
        ]
    else:
        idor_patterns = endpoint_patterns

    findings = []

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

                            findings.append({
                                "endpoint": pattern,
                                "id_tested": test_id,
                                "url": url,
                                "severity": "High",
                                "status": "VULNERABLE",
                                "status_code": resp.status_code,
                                "response_size": len(resp.content),
                                "description": f"Can access resource {test_id} without proper authorization check",
                                "evidence": {
                                    "accessible": True,
                                    "data_sample": str(data)[:200] if data else "Binary or non-JSON response"
                                }
                            })

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
            }
        }

    except Exception as e:
        return {"status": "error", "message": f"IDOR testing failed: {e}"}


# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter
#     mcp.run(transport="stdio")

