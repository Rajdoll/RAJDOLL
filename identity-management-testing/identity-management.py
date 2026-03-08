# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
from datetime import datetime
from pathlib import Path
import json
import base64
import httpx
import time
import asyncio
from typing import Dict, Any, List, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [identity-management-testing] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"identity-management-testing")

# Helper (tidak ada perubahan)
def _phase_dir(domain: str) -> Path:
    p = Path(f"/mnt/d/MCP/RAJDOLL/identity-testing/{domain}")
    p.mkdir(parents=True, exist_ok=True)
    return p

# [REVISI] Prompt diperbarui untuk menyertakan helper tools baru
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domain: str) -> str:
    return f"""
You are a highly skilled web-application tester specialising in **Identity-Management** flaws. Your target is **{domain}**. Follow OWASP WSTG v4.2 section 4.3, focusing on dynamic, browser-driven checks.

**Your Objectives:**
1.  **Role Definition (4.3.1):** Identify user roles and privilege boundaries.
2.  **Registration Process (4.3.2):** Test registration forms, email validation, and CAPTCHA.
3.  **Account Provisioning (4.3.3):** Inspect first-login, default passwords, and invitation links.
4.  **Account Enumeration (4.3.4):** Test for username enumeration vulnerabilities on login and password reset pages.
5.  **Username Policy (4.3.5):** Check for weaknesses in the username policy (length, special characters).

**Instructions:**
- Use the **Puppeteer MCP server** for all browser interactions (`Maps`, `fill_form`, `click`, `get_inner_text`, `screenshot`).
- Use the **helper tools provided in this script** (`test_account_enumeration`, `generate_test_usernames`) to create structured testing plans. These tools will give you a series of steps to execute using Puppeteer.
- Capture evidence (DOM text, screenshots) for each finding.
- Summarise results and recommended mitigations in a final report.
- Flag any manual follow-up needed (e.g., email link activation).

Start by exploring the site to find relevant pages like `/login`, `/register`, `/forgot-password`, then use the helper tools to build and execute a test plan.
"""

# --- HELPER TOOLS BARU ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def generate_test_usernames(strength: str = "medium") -> Dict[str, Any]:
    """
    [BARU] Generates a list of usernames for testing based on strength.
    Strength can be 'light', 'medium', or 'full'.
    """
    common_users = ["admin", "administrator", "root", "test", "guest", "user"]
    edge_cases = ["", "a", "a" * 100, "<script>alert(1)</script>", "test@test.com", "test' OR 1=1--"]
    unicode_users = ["用户", "пользователь", "مستخدم"]
    
    users = {
        "light": common_users[:3],
        "medium": common_users + edge_cases[:4],
        "full": common_users + edge_cases + unicode_users
    }
    
    selected_users = users.get(strength, users['medium'])
    
    return {
        "status": "success",
        "data": {
            "generated_usernames": selected_users
        }
    }

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_account_enumeration(
    url: str,
    form_selector: str,
    username_field_selector: str,
    submit_button_selector: str,
    error_message_selector: str,
    usernames_to_test: List[str]
) -> Dict[str, Any]:
    """
    [BARU] Creates a structured test plan for the agent to execute for account enumeration.
    The agent must execute these steps using the Puppeteer server and record the results.
    """
    logger.info("🔍 Executing test_account_enumeration")
    if not all([url, form_selector, username_field_selector, submit_button_selector, error_message_selector, usernames_to_test]):
        return {"status": "error", "message": "All parameters are required."}

    test_plan = []
    for i, username in enumerate(usernames_to_test):
        test_plan.extend([
            {"step": i * 4 + 1, "description": f"Navigate to login page for user '{username}'", "action": "navigate", "args": [url]},
            {"step": i * 4 + 2, "description": "Fill the form", "action": "fill_form", "args": [form_selector, {username_field_selector: username, "password": "DummyPassword123!"}]},
            {"step": i * 4 + 3, "description": "Click submit", "action": "click", "args": [submit_button_selector]},
            {"step": i * 4 + 4, "description": "Capture the error message", "action": "get_inner_text", "args": [error_message_selector]}
        ])

    return {
        "status": "success",
        "data": {
            "test_name": "Account Enumeration Test Plan",
            "instructions": "Execute each step using the Puppeteer server. Record the output of 'get_inner_text' for each username and compare the messages.",
            "plan": test_plan
        }
    }


# --- TOOL YANG DIREVISI ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def generate_identity_report(
    domain: str,
    findings: str,
    screenshots: Dict[str, str] | None = None
) -> Dict[str, Any]:
    """
    [REVISI] Writes a Markdown report and returns a JSON confirmation.
    Screenshots are expected as a dict of {name: base64_png_string}.
    The agent is responsible for saving the files first using Puppeteer's tools.
    """
    try:
        ts = datetime.now().strftime("%B %d, %Y")
        ddir = _phase_dir(domain)
        report_path = ddir / f"{domain}_identity_report_{datetime.now().strftime('%Y%m%d%H%M')}.md"

        report_lines = [
            f"# Identity-Management Report – {domain}",
            f"\n**Date:** {ts}\n",
            "## Findings & Observations",
            findings,
            "\n## Evidence (Screenshots)"
        ]

        if screenshots:
            for name, b64_data in screenshots.items():
                img_filename = f"{name.replace(' ', '_')}.png"
                img_path = ddir / img_filename
                try:
                    # Simpan screenshot dari base64 string
                    img_path.write_bytes(base64.b64decode(b64_data))
                    report_lines.append(f"![{name}]({img_filename})")
                except Exception as e:
                    report_lines.append(f"_{name} (Error saving image: {e})_")
        else:
            report_lines.append("_No screenshots provided._")

        report_path.write_text("\n".join(report_lines), encoding="utf-8")
        
        return {
            "status": "success",
            "data": {
                "message": "Report generated successfully.",
                "report_path": str(report_path)
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to generate report: {e}"}

# ========== OPSI B: 4 NEW IDENTITY MANAGEMENT TOOLS ==========

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_role_definitions(base_url: str, test_accounts: List[Dict[str, str]] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests role definitions and privilege boundaries.
    logger.info(f"🔍 Executing test_role_definitions")
    Checks if low-privilege users can access admin functions.
    WSTG-IDNT-01: Testing for Role Definitions
    """
    if test_accounts is None:
        test_accounts = [
            {"username": "admin", "password": "admin", "expected_role": "admin"},
            {"username": "user", "password": "user", "expected_role": "user"}
        ]
    
    try:
        findings = []
        
        # Admin-only endpoints to test
        admin_endpoints = [
            "/admin", "/administrator", "/admin/users", "/admin/settings",
            "/api/admin", "/administration", "/manage", "/dashboard/admin"
        ]
        
        # Build request kwargs with auth
        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            for account in test_accounts:
                # Login
                login_url = f"{base_url.rstrip('/')}/login"
                login_resp = await client.post(login_url, data=account)
                
                if login_resp.status_code not in [200, 302]:
                    continue
                
                # Test access to admin endpoints
                for endpoint in admin_endpoints:
                    url = f"{base_url.rstrip('/')}{endpoint}"
                    try:
                        resp = await client.get(url)
                        
                        # If low-privilege user can access admin area
                        if resp.status_code == 200 and account.get("expected_role") != "admin":
                            findings.append({
                                "account": account.get("username"),
                                "expected_role": account.get("expected_role"),
                                "accessible_endpoint": endpoint,
                                "status_code": resp.status_code,
                                "severity": "Critical",
                                "vulnerability": "Privilege escalation - low privilege user accessed admin function"
                            })
                        elif resp.status_code == 403 and account.get("expected_role") != "admin":
                            # Good - access denied
                            findings.append({
                                "account": account.get("username"),
                                "endpoint": endpoint,
                                "status": "Properly restricted",
                                "severity": "Info"
                            })
                    except Exception:
                        continue
        
        return {"status": "success", "data": {
            "accounts_tested": len(test_accounts),
            "admin_endpoints_tested": len(admin_endpoints),
            "privilege_escalations_found": len([f for f in findings if f.get("severity") == "Critical"]),
            "findings": findings,
            "description": "Role-based access control should prevent users from accessing functions above their privilege level"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_user_registration(register_url: str, validation_checks: Dict[str, Any] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests user registration process for weaknesses.
    logger.info(f"🔍 Executing test_user_registration")
    Checks for weak validation, email verification bypass, and duplicate accounts.
    WSTG-IDNT-02: Testing for User Registration Process
    """
    if validation_checks is None:
        validation_checks = {
            "weak_passwords": ["123", "pass", "a"],
            "invalid_emails": ["notanemail", "test@", "@domain.com"],
            "special_usernames": ["admin'--", "<script>alert(1)</script>", "../../etc/passwd"]
        }
    
    try:
        findings = []
        
        # Build request kwargs with auth
        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Weak password acceptance
            for weak_pass in validation_checks.get("weak_passwords", []):
                try:
                    resp = await client.post(register_url, data={
                        "username": f"test_{weak_pass}",
                        "email": f"test_{weak_pass}@test.com",
                        "password": weak_pass,
                        "password_confirm": weak_pass
                    })
                    
                    if resp.status_code in [200, 302] and "success" in resp.text.lower():
                        findings.append({
                            "type": "weak_password_accepted",
                            "password": weak_pass,
                            "severity": "Medium",
                            "description": f"Registration accepted weak password: {weak_pass}"
                        })
                except Exception:
                    continue
            
            # Test 2: Invalid email acceptance
            for invalid_email in validation_checks.get("invalid_emails", []):
                try:
                    resp = await client.post(register_url, data={
                        "username": f"test_{invalid_email.replace('@', '_')}",
                        "email": invalid_email,
                        "password": "ValidPassword123!",
                        "password_confirm": "ValidPassword123!"
                    })
                    
                    if resp.status_code in [200, 302] and "success" in resp.text.lower():
                        findings.append({
                            "type": "invalid_email_accepted",
                            "email": invalid_email,
                            "severity": "Medium",
                            "description": f"Registration accepted invalid email: {invalid_email}"
                        })
                except Exception:
                    continue
            
            # Test 3: XSS/Injection in username
            for special_user in validation_checks.get("special_usernames", []):
                try:
                    resp = await client.post(register_url, data={
                        "username": special_user,
                        "email": f"test_{hash(special_user)}@test.com",
                        "password": "ValidPassword123!",
                        "password_confirm": "ValidPassword123!"
                    })
                    
                    if resp.status_code in [200, 302]:
                        findings.append({
                            "type": "special_character_injection",
                            "username": special_user,
                            "severity": "High",
                            "description": "Registration accepted potentially malicious username"
                        })
                except Exception:
                    continue
            
            # Test 4: Duplicate username
            unique_user = f"duplicatetest_{int(time.time())}"
            try:
                # Register once
                resp1 = await client.post(register_url, data={
                    "username": unique_user,
                    "email": f"{unique_user}@test.com",
                    "password": "Test123!",
                    "password_confirm": "Test123!"
                })
                
                # Try to register again
                resp2 = await client.post(register_url, data={
                    "username": unique_user,
                    "email": f"{unique_user}_2@test.com",
                    "password": "Test123!",
                    "password_confirm": "Test123!"
                })
                
                if resp2.status_code in [200, 302] and "success" in resp2.text.lower():
                    findings.append({
                        "type": "duplicate_username_allowed",
                        "username": unique_user,
                        "severity": "Medium",
                        "description": "System allows duplicate usernames"
                    })
            except Exception:
                pass
        
        return {"status": "success", "data": {
            "checks_performed": sum(len(v) for v in validation_checks.values() if isinstance(v, list)),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "User registration should validate all inputs and prevent weak credentials"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_account_provisioning(base_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests account provisioning and lifecycle management.
    logger.info(f"🔍 Executing test_account_provisioning")
    Checks for insecure account creation and activation processes.
    WSTG-IDNT-03: Testing for Account Provisioning Process
    """
    try:
        findings = []
        
        # Build request kwargs with auth
        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Check if account is immediately active without verification
            test_email = f"provisiontest_{int(time.time())}@test.com"
            register_url = f"{base_url.rstrip('/')}/register"
            
            try:
                register_resp = await client.post(register_url, data={
                    "username": f"provtest_{int(time.time())}",
                    "email": test_email,
                    "password": "TestPass123!",
                    "password_confirm": "TestPass123!"
                })
                
                if register_resp.status_code in [200, 302]:
                    # Try to login immediately without email verification
                    login_url = f"{base_url.rstrip('/')}/login"
                    login_resp = await client.post(login_url, data={
                        "email": test_email,
                        "password": "TestPass123!"
                    })
                    
                    if login_resp.status_code in [200, 302] and "dashboard" in login_resp.text.lower():
                        findings.append({
                            "type": "no_email_verification",
                            "severity": "Medium",
                            "description": "Account is immediately active without email verification"
                        })
            except Exception:
                pass
            
            # Test 2: Check for predictable activation tokens
            for path in ["/activate", "/verify", "/confirm"]:
                try:
                    # Try common weak tokens
                    for token in ["123456", "test", "activate", "1"]:
                        verify_url = f"{base_url.rstrip('/')}{path}?token={token}"
                        resp = await client.get(verify_url)
                        
                        if resp.status_code == 200 and "success" in resp.text.lower():
                            findings.append({
                                "type": "predictable_activation_token",
                                "token": token,
                                "severity": "High",
                                "description": f"Weak activation token accepted: {token}"
                            })
                            break
                except Exception:
                    continue
            
            # Test 3: Mass account creation rate limiting
            rate_limit_found = False
            for i in range(10):
                try:
                    resp = await client.post(register_url, data={
                        "username": f"masstest_{int(time.time())}_{i}",
                        "email": f"mass_{int(time.time())}_{i}@test.com",
                        "password": "Test123!",
                        "password_confirm": "Test123!"
                    })
                    
                    if resp.status_code == 429 or "rate limit" in resp.text.lower():
                        rate_limit_found = True
                        break
                    
                    await asyncio.sleep(0.1)
                except Exception:
                    break
            
            if not rate_limit_found:
                findings.append({
                    "type": "no_rate_limiting",
                    "severity": "Medium",
                    "description": "No rate limiting on account creation - allows mass registration"
                })
        
        return {"status": "success", "data": {
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Account provisioning should include email verification and rate limiting"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_username_policy(base_url: str, test_usernames: List[str] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests username enumeration via registration/forgot password.
    logger.info(f"🔍 Executing test_username_policy")
    Checks if system reveals which usernames exist.
    WSTG-IDNT-04: Testing for Username Policy
    """
    if test_usernames is None:
        test_usernames = ["admin", "administrator", "root", "test", "user", "nonexistentuser123456"]
    
    try:
        findings = []
        
        # Build request kwargs with auth
        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Username enumeration via registration
            register_url = f"{base_url.rstrip('/')}/register"
            registration_responses = {}
            
            for username in test_usernames:
                try:
                    resp = await client.post(register_url, data={
                        "username": username,
                        "email": f"{username}@test.com",
                        "password": "Test123!",
                        "password_confirm": "Test123!"
                    })
                    
                    registration_responses[username] = {
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                        "contains_exists": "exists" in resp.text.lower() or "taken" in resp.text.lower()
                    }
                except Exception:
                    continue
            
            # Analyze for enumeration
            unique_responses = set((v["status_code"], v["response_length"]) for v in registration_responses.values())
            if len(unique_responses) > 1:
                findings.append({
                    "type": "username_enumeration_registration",
                    "method": "registration_response_difference",
                    "severity": "Medium",
                    "description": "Different responses for existing vs non-existing usernames",
                    "evidence": {k: v for k, v in list(registration_responses.items())[:3]}
                })
            
            # Test 2: Username enumeration via password reset
            reset_url = f"{base_url.rstrip('/')}/forgot-password"
            reset_responses = {}
            
            for username in test_usernames:
                try:
                    resp = await client.post(reset_url, data={"username": username})
                    reset_responses[username] = {
                        "status_code": resp.status_code,
                        "response_length": len(resp.text)
                    }
                except Exception:
                    continue
            
            unique_reset_responses = set((v["status_code"], v["response_length"]) for v in reset_responses.values())
            if len(unique_reset_responses) > 1:
                findings.append({
                    "type": "username_enumeration_reset",
                    "method": "password_reset_response_difference",
                    "severity": "Medium",
                    "description": "Password reset reveals which usernames exist",
                    "evidence": {k: v for k, v in list(reset_responses.items())[:3]}
                })
            
            # Test 3: Timing-based enumeration
            import time
            timing_results = {}
            for username in test_usernames[:3]:  # Limit to prevent slowdown
                try:
                    start = time.time()
                    await client.post(reset_url, data={"username": username})
                    elapsed = time.time() - start
                    timing_results[username] = elapsed
                except Exception:
                    continue
            
            if timing_results:
                avg_time = sum(timing_results.values()) / len(timing_results)
                suspicious_timing = [u for u, t in timing_results.items() if abs(t - avg_time) > 0.5]
                
                if suspicious_timing:
                    findings.append({
                        "type": "timing_based_enumeration",
                        "severity": "Low",
                        "description": "Significant timing differences may reveal username existence",
                        "evidence": {"timing_ms": {k: int(v*1000) for k, v in timing_results.items()}}
                    })
        
        return {"status": "success", "data": {
            "usernames_tested": len(test_usernames),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Username enumeration allows attackers to build valid username lists for attacks"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_weak_username_policy(base_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-IDNT-05: Test for Weak or Unenforced Username Policy.
    Checks if the application enforces minimum username requirements
    (length, character set, uniqueness, reserved names).
    """
    try:
        findings = []

        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        # Weak usernames to test policy enforcement
        weak_usernames = [
            ("a", "single_char", "Username too short (1 char)"),
            ("ab", "two_chars", "Username too short (2 chars)"),
            ("123", "numeric_only", "Numeric-only username"),
            ("   ", "whitespace_only", "Whitespace-only username"),
            ("admin", "reserved_name", "Reserved/privileged username"),
            ("root", "reserved_name", "Reserved/privileged username"),
            ("system", "reserved_name", "Reserved system username"),
            ("<script>", "special_chars", "Special characters in username"),
            ("user@evil", "injection", "Email-like injection in username"),
            ("a" * 256, "oversized", "Extremely long username (256 chars)"),
        ]

        register_endpoints = [
            f"{base_url.rstrip('/')}/api/Users/",
            f"{base_url.rstrip('/')}/register",
            f"{base_url.rstrip('/')}/api/register",
            f"{base_url.rstrip('/')}/signup",
        ]

        async with httpx.AsyncClient(**req_kwargs) as client:
            # Find registration endpoint
            reg_url = None
            for ep in register_endpoints:
                try:
                    resp = await client.get(ep)
                    if resp.status_code < 500:
                        reg_url = ep
                        break
                except Exception:
                    continue

            if not reg_url:
                # Try POST to first endpoint anyway
                reg_url = register_endpoints[0]

            accepted_weak = []
            for username, category, description in weak_usernames:
                try:
                    payloads = [
                        {"username": username, "email": f"test_{category}@test.com", "password": "Test12345!", "passwordRepeat": "Test12345!"},
                        {"email": f"{username}@test.com", "password": "Test12345!", "passwordRepeat": "Test12345!"},
                    ]
                    for payload in payloads:
                        resp = await client.post(reg_url, json=payload)
                        # If registration succeeded (2xx) or no validation error
                        if resp.status_code in (200, 201):
                            accepted_weak.append({
                                "username": username[:50],
                                "category": category,
                                "description": description,
                                "status_code": resp.status_code,
                            })
                            break
                        # Check if response body indicates success
                        try:
                            body = resp.json()
                            if body.get("status") == "success" or "id" in body:
                                accepted_weak.append({
                                    "username": username[:50],
                                    "category": category,
                                    "description": description,
                                    "status_code": resp.status_code,
                                })
                                break
                        except Exception:
                            pass
                except Exception:
                    continue

            if accepted_weak:
                findings.append({
                    "type": "weak_username_policy",
                    "severity": "Medium",
                    "description": "Application accepts weak or invalid usernames",
                    "evidence": accepted_weak[:5],
                    "recommendation": "Enforce minimum username length, character restrictions, and block reserved names"
                })

            # Test duplicate username handling
            try:
                dup_payload = {"username": "testdup123", "email": "testdup123@test.com", "password": "Test12345!", "passwordRepeat": "Test12345!"}
                resp1 = await client.post(reg_url, json=dup_payload)
                resp2 = await client.post(reg_url, json=dup_payload)
                if resp1.status_code in (200, 201) and resp2.status_code in (200, 201):
                    findings.append({
                        "type": "duplicate_username_allowed",
                        "severity": "High",
                        "description": "Application allows duplicate usernames",
                        "recommendation": "Enforce unique username constraint"
                    })
            except Exception:
                pass

        return {"status": "success", "data": {
            "weak_usernames_tested": len(weak_usernames),
            "weak_accepted": len(accepted_weak) if 'accepted_weak' in dir() else 0,
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Weak username policies allow account enumeration, impersonation, and confusion attacks"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Entrypoint (tidak ada perubahan)
# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter`n#     mcp.run(transport="stdio")

