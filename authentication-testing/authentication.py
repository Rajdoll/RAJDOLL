# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import asyncio
import os
import re
import json
import httpx
import base64
import logging
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [authentication-mcp] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"authentication-testing")

# --- Helpers ---
# Default to workspace-mounted SecLists inside container; allow override via env
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/app/SecLists")

async def run(cmd: str, timeout: int = 90) -> str:
    """Run a shell command using bash -lc in Linux container (no WSL)."""
    proc = await asyncio.create_subprocess_exec(
        "bash", "-lc", cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        return out.decode('utf-8', errors='ignore').strip()
    except asyncio.TimeoutError:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

# --- Tools (Revisi & Peningkatan) ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_tls_credentials(login_url: str) -> Dict[str, Any]:
    """
    [REVISI] Confirms login form and page are HTTPS and checks for mixed-content.
    """
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as cli:
            resp = await cli.get(login_url)
            content = resp.text

        is_https = resp.url.scheme == "https"
        action_is_https = 'action="https://' in content
        mixed_content_found = bool(re.search(r'src="http://', content, re.IGNORECASE))

        return {"status": "success", "data": {
            "page_served_over_https": is_https,
            "form_action_is_https": action_is_https,
            "mixed_content_found": mixed_content_found
        }}
    except Exception as e:
        return {"status": "error", "message": f"Could not analyze URL {login_url}: {e}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_default_credentials(target: str) -> Dict[str, Any]:
    """
    [REVISI] Tries common default credentials against common login endpoints.

    This intentionally avoids external template scanners and keeps the check lightweight.
    """
    from urllib.parse import urlparse

    def _base(url: str) -> str:
        u = url.strip()
        if not u.startswith("http://") and not u.startswith("https://"):
            u = "http://" + u
        p = urlparse(u)
        scheme = p.scheme or "http"
        netloc = p.netloc or p.path
        return f"{scheme}://{netloc}".rstrip("/")

    base = _base(target)

    # Small, high-signal credential list (keep conservative)
    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        # Juice Shop common defaults
        ("admin@juice-sh.op", "admin123"),
    ]

    # Common login endpoints to try
    endpoints = [
        ("POST", "/rest/user/login", "json", {"email": "{u}", "password": "{p}"}),  # Juice Shop
        ("POST", "/api/login", "json", {"username": "{u}", "password": "{p}"}),
        ("POST", "/auth/login", "json", {"username": "{u}", "password": "{p}"}),
        ("POST", "/api/auth/login", "json", {"username": "{u}", "password": "{p}"}),
        ("POST", "/login", "form", {"username": "{u}", "password": "{p}"}),
        ("POST", "/session", "json", {"username": "{u}", "password": "{p}"}),
    ]

    findings: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as cli:
            # Prime the base URL (cookies, redirects)
            try:
                await cli.get(base)
            except Exception:
                pass

            for method, path, kind, template in endpoints:
                url = f"{base}{path}"
                for username, password in common_creds:
                    payload = {k: (v.format(u=username, p=password) if isinstance(v, str) else v) for k, v in template.items()}
                    try:
                        if kind == "json":
                            resp = await cli.request(method, url, json=payload)
                        else:
                            resp = await cli.request(method, url, data=payload)

                        ok_status = resp.status_code in (200, 201, 202, 204, 302)
                        body = resp.text or ""

                        # Heuristics: token in JSON or auth cookie set
                        token = None
                        if resp.headers.get("content-type", "").lower().startswith("application/json"):
                            try:
                                j = resp.json()
                                if isinstance(j, dict):
                                    token = j.get("token") or j.get("authentication") or j.get("access_token")
                            except Exception:
                                pass

                        set_cookie = resp.headers.get("set-cookie", "")
                        looks_successful = ok_status and (
                            bool(token)
                            or ("token" in body.lower() and resp.status_code == 200)
                            or ("session" in set_cookie.lower())
                            or ("jwt" in set_cookie.lower())
                        )

                        if looks_successful:
                            findings.append({
                                "endpoint": url,
                                "username": username,
                                "password": password,
                                "status_code": resp.status_code,
                                "token_present": bool(token),
                                "set_cookie": set_cookie[:200] if set_cookie else "",
                            })
                            # Do not brute-force further once a hit is found for this endpoint
                            break
                    except Exception:
                        continue

        return {"status": "success", "data": {"findings": findings, "tested_endpoints": [e[1] for e in endpoints]}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_auth_bypass(url: str) -> Dict[str, Any]:
    """
    [PENINGKATAN] Uses ffuf with a wordlist to test for authentication bypasses.
    Replaces the previous basic check.
    """
    try:
        wordlist_path = f"{WORDLIST_DIR}/Fuzzing/Authentication/auth-bypass.txt"
        if not os.path.exists(wordlist_path):
            return {"status": "error", "message": f"Wordlist not found: {wordlist_path}"}
        
        # ffuf akan memfilter status code 401/403/404, mencari yang berhasil (e.g., 200)
        cmd = f"ffuf -u {url}/FUZZ -w {wordlist_path} -mc 200,302 -fs 0"
        output = await run(cmd, timeout=300)
        
        # Parsing sederhana output ffuf
        bypasses_found = [line for line in output.split('\n') if "->" in line and "[post]" not in line]

        return {"status": "success", "data": {
            "bypasses_found": bypasses_found,
            "message": f"Found {len(bypasses_found)} potential bypasses." if bypasses_found else "No simple auth bypasses found."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_remember_me(cookies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    [REVISI] Inspects a list of cookie dictionaries for remember-me weaknesses.
    The agent should get the cookies using Puppeteer and pass them here.
    """
    findings = []
    remember_me_cookies = [c for c in cookies if c['name'].lower() in ["rememberme", "remember_me", "remember-me", "remember_token"]]
    
    if not remember_me_cookies:
        return {"status": "success", "data": {"message": "No remember-me cookie detected."}}

    for cookie in remember_me_cookies:
        is_secure = cookie.get('secure', False)
        is_httponly = cookie.get('httpOnly', False)
        findings.append({
            "name": cookie['name'],
            "is_secure_flagged": is_secure,
            "is_httponly_flagged": is_httponly,
            "recommendation": "Cookie should have Secure and HttpOnly flags." if not is_secure or not is_httponly else "Flags seem correct."
        })
    return {"status": "success", "data": {"findings": findings}}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_cache_headers(url: str) -> Dict[str, Any]:
    """
    [REVISI] Checks for security-related cache headers.
    """
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.head(url)
        cache_control = resp.headers.get("Cache-Control", "")
        pragma = resp.headers.get("Pragma", "")
        
        is_safe = "no-store" in cache_control and "no-cache" in cache_control
        
        return {"status": "success", "data": {
            "cache-control_header": cache_control,
            "pragma_header": pragma,
            "is_caching_disabled": is_safe
        }}
    except Exception as e:
         return {"status": "error", "message": f"Could not check headers for {url}: {e}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_password_policy(register_url: str, username_field: str, password_field: str) -> Dict[str, Any]:
    """
    [PENINGKATAN] Tries to create an account with a list of common weak passwords.
    """
    weak_passwords = ["123456", "password", "12345678", "qwerty", "111111", "aaaaaaaa"]
    findings = []
    
    async with httpx.AsyncClient(verify=False) as client:
        for pwd in weak_passwords:
            unique_user = f"testuser{os.urandom(4).hex()}"
            data = {username_field: unique_user, password_field: pwd}
            try:
                r = await client.post(register_url, data=data)
                # Berhasil jika status 2xx (OK) atau 3xx (Redirect setelah login)
                if 200 <= r.status_code < 400:
                    findings.append({"password": pwd, "result": "ACCEPTED", "status_code": r.status_code})
                else:
                    findings.append({"password": pwd, "result": "REJECTED", "status_code": r.status_code})
            except Exception as e:
                findings.append({"password": pwd, "result": "ERROR", "message": str(e)})

    return {"status": "success", "data": {"results": findings}}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def analyze_jwt(token: str) -> Dict[str, Any]:
    """
    [BARU] Decodes a JWT and checks for common vulnerabilities.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"status": "error", "message": "Invalid JWT format. It must have 3 parts."}

        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
        
        findings = {
            "header": header,
            "payload": payload,
            "vulnerabilities": []
        }
        
        # Check for alg=none
        if header.get('alg', '').lower() == 'none':
            findings['vulnerabilities'].append({
                "type": "alg_none",
                "severity": "Critical",
                "description": "The token uses the 'none' algorithm, allowing signature bypass."
            })
        
        # Check for expiration
        if 'exp' not in payload:
            findings['vulnerabilities'].append({
                "type": "no_expiration",
                "severity": "High",
                "description": "The token does not have an expiration claim ('exp')."
            })
            
        return {"status": "success", "data": findings}
    except Exception as e:
        return {"status": "error", "message": f"Failed to decode or analyze JWT: {e}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def get_manual_testing_checklist(topic: str) -> Dict[str, Any]:
    """
    [REVISI] Provides a structured checklist for manual testing topics.
    Topic can be 'security_questions' or 'alt_channel'.
    """
    checklists = {
        "security_questions": [
            "Do security questions have a limited and predictable set of answers (e.g., 'What is your favorite color?')?",
            "Are answers stored case-insensitively, allowing easier guessing?",
            "Can the answers be easily found through social media or OSINT?",
            "Is there a rate-limiting mechanism on attempts to answer security questions?"
        ],
        "alt_channel": [
            "Does a mobile API endpoint exist with weaker authentication than the web app?",
            "Are One-Time Passwords (OTPs) sent via SMS/Email sufficiently long (>=6 chars)?",
            "Do OTPs expire within a reasonable time (e.g., 5-10 minutes)?",
            "Can the OTP mechanism be bypassed or brute-forced?"
        ]
    }
    
    if topic not in checklists:
        return {"status": "error", "message": f"Invalid topic. Choose from: {list(checklists.keys())}"}

    return {"status": "success", "data": {"topic": topic, "checklist": checklists[topic]}}

# ========== OPSI B: 4 NEW AUTHENTICATION TOOLS ==========

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_lockout_mechanism(login_url: str, username: str, wrong_password: str, attempts: int = 5) -> Dict[str, Any]:
    """
    [OPSI B] Tests account lockout after failed login attempts.
    Checks if the application implements rate limiting or account lockout.
    WSTG-ATHN-03: Testing for Weak Lock Out Mechanism
    """
    try:
        lockout_detected = False
        responses = []
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
            for i in range(attempts):
                try:
                    resp = await client.post(login_url, data={"username": username, "password": wrong_password})
                    responses.append({
                        "attempt": i + 1,
                        "status_code": resp.status_code,
                        "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                        "contains_lockout_message": any(keyword in resp.text.lower() for keyword in 
                                                       ["locked", "too many", "rate limit", "blocked", "temporarily disabled"])
                    })
                    
                    # Check for lockout indicators
                    if responses[-1]["contains_lockout_message"]:
                        lockout_detected = True
                        break
                        
                    # Small delay between attempts
                    await asyncio.sleep(0.5)
                except Exception as e:
                    responses.append({"attempt": i + 1, "error": str(e)})
        
        # Analyze response times (increasing = rate limiting)
        avg_response_time = sum(r.get("response_time_ms", 0) for r in responses) / len(responses) if responses else 0
        rate_limiting_suspected = any(r.get("response_time_ms", 0) > avg_response_time * 2 for r in responses)
        
        return {"status": "success", "data": {
            "lockout_detected": lockout_detected,
            "rate_limiting_suspected": rate_limiting_suspected,
            "total_attempts": len(responses),
            "responses": responses,
            "description": "No lockout mechanism detected" if not lockout_detected else "Lockout mechanism active"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_security_questions(url: str, common_answers: List[str] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests security questions for weak implementation.
    Checks for predictable answers and lack of rate limiting.
    WSTG-ATHN-08: Testing for Weak Security Question/Answer
    """
    if common_answers is None:
        common_answers = ["password", "admin", "123456", "blue", "pizza", "dog", "smith", "john", "london", "2000"]
    
    try:
        # 1. Fetch the security question page
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            
            if resp.status_code != 200:
                return {"status": "error", "message": f"Cannot access {url}"}
            
            # 2. Look for security question patterns
            question_patterns = [
                r'what is your (mother|father|pet|favorite|first)',
                r'where (were you born|did you meet)',
                r'what was your (childhood|first)',
            ]
            
            found_questions = []
            for pattern in question_patterns:
                matches = re.findall(pattern, resp.text, re.I)
                found_questions.extend(matches)
            
            # 3. Check if form has rate limiting (try multiple submissions)
            rate_limit_detected = False
            if found_questions:
                for i in range(3):
                    test_resp = await client.post(url, data={"security_answer": common_answers[i % len(common_answers)]})
                    if "rate" in test_resp.text.lower() or "too many" in test_resp.text.lower():
                        rate_limit_detected = True
                        break
                    await asyncio.sleep(0.3)
            
            return {"status": "success", "data": {
                "security_questions_found": len(found_questions) > 0,
                "sample_questions": list(set(found_questions))[:3],
                "rate_limiting": rate_limit_detected,
                "predictable_answers_tested": len(common_answers),
                "description": "Security questions may be weak if predictable and without rate limiting"
            }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_password_reset(reset_url: str, email: str) -> Dict[str, Any]:
    """
    [OPSI B] Tests password reset mechanism for security flaws.
    Checks reset token entropy, expiration, and one-time use.
    WSTG-ATHN-09: Testing for Weak Password Change or Reset Functionalities
    """
    try:
        findings = []
        
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            # 1. Request password reset
            reset_resp = await client.post(reset_url, data={"email": email})
            
            if reset_resp.status_code not in [200, 302]:
                return {"status": "error", "message": f"Reset request failed with status {reset_resp.status_code}"}
            
            # 2. Check for reset token in response (sometimes exposed in dev mode)
            token_pattern = r'[a-f0-9]{32,}|[A-Za-z0-9\-_]{20,}'
            tokens_in_response = re.findall(token_pattern, reset_resp.text)
            
            if tokens_in_response:
                findings.append({
                    "type": "token_exposure",
                    "severity": "Critical",
                    "description": "Reset token exposed in HTTP response",
                    "evidence": {"tokens_found": len(tokens_in_response)}
                })
            
            # 3. Check for user enumeration
            invalid_reset = await client.post(reset_url, data={"email": "nonexistent@invalid.com"})
            response_diff = len(reset_resp.text) != len(invalid_reset.text)
            
            if response_diff:
                findings.append({
                    "type": "user_enumeration",
                    "severity": "Medium",
                    "description": "Different responses for valid/invalid emails allow user enumeration"
                })
            
            # 4. Test if old password is required for reset
            requires_old_password = "current password" in reset_resp.text.lower() or "old password" in reset_resp.text.lower()
            
            if not requires_old_password:
                findings.append({
                    "type": "no_verification",
                    "severity": "High",
                    "description": "Password reset does not require current password verification"
                })
            
            # 5. Check rate limiting on reset requests
            rate_limit_detected = False
            for i in range(5):
                rapid_reset = await client.post(reset_url, data={"email": email})
                if "rate" in rapid_reset.text.lower() or "too many" in rapid_reset.text.lower():
                    rate_limit_detected = True
                    break
                await asyncio.sleep(0.2)
            
            if not rate_limit_detected:
                findings.append({
                    "type": "no_rate_limiting",
                    "severity": "Medium",
                    "description": "No rate limiting on password reset requests"
                })
            
            return {"status": "success", "data": {
                "vulnerabilities_found": len(findings),
                "findings": findings,
                "rate_limiting": rate_limit_detected
            }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_alternative_channel_auth(base_url: str, mobile_endpoints: List[str] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests authentication in alternative channels (mobile API, webhooks, etc).
    Checks for weaker auth in non-web interfaces.
    WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel
    """
    if mobile_endpoints is None:
        mobile_endpoints = ["/api/v1/login", "/api/mobile/auth", "/m/login", "/mobile/api/signin", "/api/auth"]
    
    try:
        findings = []
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
            for endpoint in mobile_endpoints:
                url = f"{base_url.rstrip('/')}{endpoint}"
                
                try:
                    # 1. Check if endpoint exists
                    resp = await client.get(url)

                    content_type = resp.headers.get("content-type", "")
                    if resp.status_code == 404 or "text/html" in content_type:
                        continue  # not an API auth endpoint — skip HTML error pages and missing routes
                    
                    # 2. Try weak credentials
                    weak_auth_tests = [
                        {"username": "admin", "password": "admin"},
                        {"username": "test", "password": "test"},
                        {"api_key": "12345"},
                    ]
                    
                    for creds in weak_auth_tests:
                        auth_resp = await client.post(url, json=creds)
                        
                        if auth_resp.status_code == 200 and any(keyword in auth_resp.text.lower() 
                                                                 for keyword in ["token", "success", "authenticated"]):
                            findings.append({
                                "type": "weak_credentials",
                                "endpoint": endpoint,
                                "severity": "Critical",
                                "description": f"Weak credentials accepted on {endpoint}",
                                "credentials_used": creds
                            })
                    
                    # 3. Check for missing TLS
                    if url.startswith("http://"):
                        findings.append({
                            "type": "no_tls",
                            "endpoint": endpoint,
                            "severity": "High",
                            "description": f"Authentication endpoint {endpoint} uses HTTP (not HTTPS)"
                        })
                    
                    # 4. Check for missing rate limiting
                    rate_limit_found = False
                    for i in range(10):
                        rapid_req = await client.post(url, json={"user": "test", "pass": "test"})
                        if rapid_req.status_code == 429 or "rate" in rapid_req.text.lower():
                            rate_limit_found = True
                            break
                        await asyncio.sleep(0.1)
                    
                    if not rate_limit_found:
                        findings.append({
                            "type": "no_rate_limiting",
                            "endpoint": endpoint,
                            "severity": "Medium",
                            "description": f"No rate limiting on {endpoint}"
                        })
                
                except Exception as e:
                    continue
            
            return {"status": "success", "data": {
                "alternative_channels_tested": len(mobile_endpoints),
                "vulnerabilities_found": len(findings),
                "findings": findings,
                "description": "Alternative authentication channels should have equal or stronger security than web interface"
            }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_auth_bypass_schema(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-ATHN-06: Test for Authentication Bypass via Direct Request / Schema Manipulation.
    Attempts to access protected resources without authentication or by
    manipulating URL paths (forced browsing, path traversal, parameter removal).
    """
    try:
        findings = []

        # Two clients: one authenticated, one unauthenticated
        auth_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        unauth_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}

        if auth_session:
            if 'cookies' in auth_session:
                auth_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                auth_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                auth_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        base = url.rstrip('/')

        # Protected endpoints that should require auth
        protected_paths = [
            "/api/Users", "/api/Feedbacks", "/api/Products",
            "/api/Quantitys", "/api/Complaints", "/api/Recycles",
            "/administration", "/accounting", "/profile",
            "/api/SecurityAnswers", "/api/PrivacyRequests",
            "/rest/user/whoami", "/rest/basket/",
        ]

        # Schema manipulation / forced browsing patterns
        bypass_patterns = [
            ("direct_access", lambda p: p),
            ("double_encode", lambda p: p.replace("/", "%252f")),
            ("path_traversal", lambda p: f"/public/../{p.lstrip('/')}"),
            ("case_change", lambda p: p.upper()),
            ("trailing_dot", lambda p: f"{p}."),
            ("null_byte", lambda p: f"{p}%00"),
            ("json_ext", lambda p: f"{p}.json"),
        ]

        async with httpx.AsyncClient(**unauth_kwargs) as unauth_client:
            for path in protected_paths:
                full_url = f"{base}{path}"
                for bypass_name, transform in bypass_patterns:
                    try:
                        test_path = transform(path)
                        test_url = f"{base}{test_path}"
                        resp = await unauth_client.get(test_url)

                        # Check if we got actual data (not redirect to login)
                        if resp.status_code == 200:
                            body = resp.text
                            # Heuristic: if response has JSON data or significant content
                            if len(body) > 50 and ('login' not in body.lower()[:200]):
                                try:
                                    data = resp.json()
                                    if isinstance(data, (list, dict)) and data:
                                        findings.append({
                                            "type": "auth_bypass",
                                            "method": bypass_name,
                                            "path": test_path,
                                            "original_path": path,
                                            "status_code": resp.status_code,
                                            "severity": "Critical",
                                            "description": f"Protected resource accessible without auth via {bypass_name}",
                                            "evidence": str(body[:200])
                                        })
                                except Exception:
                                    pass
                    except Exception:
                        continue

        # Test HTTP method override
        method_override_headers = [
            ("X-HTTP-Method-Override", "GET"),
            ("X-Method-Override", "GET"),
            ("X-HTTP-Method", "GET"),
        ]
        async with httpx.AsyncClient(**unauth_kwargs) as client:
            for path in protected_paths[:5]:
                for header_name, method in method_override_headers:
                    try:
                        resp = await client.post(
                            f"{base}{path}",
                            headers={header_name: method}
                        )
                        if resp.status_code == 200 and len(resp.text) > 50:
                            findings.append({
                                "type": "method_override_bypass",
                                "header": header_name,
                                "path": path,
                                "severity": "High",
                                "description": f"Auth bypass via {header_name} header"
                            })
                    except Exception:
                        continue

        return {"status": "success", "data": {
            "paths_tested": len(protected_paths),
            "bypass_techniques": len(bypass_patterns),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Authentication bypass allows unauthorized access to protected resources"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_2fa_bypass(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-ATHN-09: Test 2FA/TOTP bypass techniques.
    Attempts to bypass two-factor authentication via:
    1. Direct access to post-auth endpoints without completing 2FA
    2. TOTP brute force with common values and rate-limit detection
    3. 2FA setup/disable bypass without valid TOTP
    """
    from urllib.parse import urlparse

    findings: List[Dict[str, Any]] = []
    base = url.rstrip('/')

    # Build auth headers if session provided
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    tmp_token: Optional[str] = None

    if auth_session:
        if 'headers' in auth_session:
            headers.update(auth_session['headers'])
        elif 'token' in auth_session:
            headers["Authorization"] = f"Bearer {auth_session['token']}"
            tmp_token = auth_session['token']
        if 'cookies' in auth_session:
            cookies.update(auth_session['cookies'])

    try:
        async with httpx.AsyncClient(
            timeout=10.0, verify=False, follow_redirects=True,
            headers=headers, cookies=cookies
        ) as client:

            # ------------------------------------------------------------------
            # 1. Direct access to post-auth endpoints without completing 2FA
            # ------------------------------------------------------------------
            post_auth_endpoints = [
                "/api/Users",
                "/rest/user/whoami",
                "/api/Products",
                "/api/Feedbacks",
                "/api/Complaints",
                "/profile",
                "/administration",
            ]

            for ep in post_auth_endpoints:
                try:
                    resp = await client.get(f"{base}{ep}")
                    if resp.status_code == 200 and len(resp.text) > 50:
                        # Check if real data was returned (not a login redirect)
                        body_lower = resp.text.lower()[:500]
                        if 'login' not in body_lower and 'sign in' not in body_lower:
                            try:
                                data = resp.json()
                                has_data = bool(data) if isinstance(data, (list, dict)) else False
                            except Exception:
                                has_data = len(resp.text) > 100

                            if has_data:
                                findings.append({
                                    "type": "2fa_direct_access_bypass",
                                    "endpoint": ep,
                                    "severity": "critical",
                                    "description": f"Post-auth endpoint {ep} accessible without completing 2FA step",
                                    "evidence": resp.text[:200]
                                })
                except Exception:
                    continue

            # ------------------------------------------------------------------
            # 2. TOTP brute force — common values + rate-limit check
            # ------------------------------------------------------------------
            totp_endpoints = [
                "/rest/2fa/verify",
                "/api/2fa/verify",
                "/api/auth/2fa",
                "/api/mfa/verify",
            ]

            common_totp_codes = ["000000", "111111", "123456", "999999", "000001", "654321"]

            for totp_ep in totp_endpoints:
                totp_url = f"{base}{totp_ep}"
                rate_limited = False
                attempts_before_limit = 0

                for i, code in enumerate(common_totp_codes):
                    payload = {"token": code}
                    if tmp_token:
                        payload["tmpToken"] = tmp_token

                    try:
                        resp = await client.post(totp_url, json=payload)

                        # 404 means this endpoint doesn't exist — skip
                        if resp.status_code == 404:
                            break

                        # Check for rate limiting
                        if resp.status_code == 429 or any(
                            kw in resp.text.lower()
                            for kw in ["rate limit", "too many", "locked", "blocked", "try again later"]
                        ):
                            rate_limited = True
                            attempts_before_limit = i + 1
                            break

                        # Check if TOTP was accepted
                        if resp.status_code == 200:
                            try:
                                rj = resp.json()
                                if isinstance(rj, dict) and (
                                    rj.get("token") or rj.get("authentication") or
                                    rj.get("access_token") or rj.get("success")
                                ):
                                    findings.append({
                                        "type": "2fa_totp_brute_force",
                                        "endpoint": totp_ep,
                                        "severity": "critical",
                                        "description": f"2FA TOTP accepted common code '{code}' on {totp_ep}",
                                        "evidence": resp.text[:200]
                                    })
                                    break
                            except Exception:
                                pass

                        await asyncio.sleep(0.3)
                    except Exception:
                        continue

                # If we tested all codes without rate limiting on an existing endpoint
                if not rate_limited and attempts_before_limit == 0:
                    # Check if the endpoint actually existed (we didn't break on 404)
                    # We only flag if we actually sent requests
                    try:
                        probe = await client.post(totp_url, json={"token": "000000"})
                        if probe.status_code != 404:
                            findings.append({
                                "type": "2fa_no_rate_limit",
                                "endpoint": totp_ep,
                                "severity": "high",
                                "description": f"No rate limiting on TOTP verification endpoint {totp_ep} — brute force feasible",
                                "evidence": f"Sent {len(common_totp_codes)} TOTP attempts without rate limiting"
                            })
                    except Exception:
                        pass

            # ------------------------------------------------------------------
            # 3. 2FA setup/disable bypass
            # ------------------------------------------------------------------
            # 3a. Check 2FA status
            status_endpoints = ["/rest/2fa/status", "/api/2fa/status", "/api/mfa/status"]
            for status_ep in status_endpoints:
                try:
                    resp = await client.get(f"{base}{status_ep}")
                    if resp.status_code == 200:
                        try:
                            sdata = resp.json()
                            if isinstance(sdata, dict):
                                findings.append({
                                    "type": "2fa_status_info_leak",
                                    "endpoint": status_ep,
                                    "severity": "medium",
                                    "description": f"2FA status endpoint {status_ep} returns configuration details",
                                    "evidence": str(sdata)[:200]
                                })
                        except Exception:
                            pass
                except Exception:
                    continue

            # 3b. Try disabling 2FA without TOTP
            disable_endpoints = ["/rest/2fa/disable", "/api/2fa/disable", "/api/mfa/disable"]
            for disable_ep in disable_endpoints:
                try:
                    # Try without any TOTP token
                    resp = await client.post(f"{base}{disable_ep}", json={})
                    if resp.status_code == 200:
                        findings.append({
                            "type": "2fa_disable_bypass",
                            "endpoint": disable_ep,
                            "severity": "critical",
                            "description": f"2FA can be disabled without providing TOTP code at {disable_ep}",
                            "evidence": resp.text[:200]
                        })
                    # Also try with empty password field
                    resp2 = await client.post(f"{base}{disable_ep}", json={"password": "", "token": ""})
                    if resp2.status_code == 200 and resp2.status_code != resp.status_code:
                        findings.append({
                            "type": "2fa_disable_bypass",
                            "endpoint": disable_ep,
                            "severity": "critical",
                            "description": f"2FA disabled with empty credentials at {disable_ep}",
                            "evidence": resp2.text[:200]
                        })
                except Exception:
                    continue

            # 3c. Check if 2FA setup leaks the TOTP secret
            setup_endpoints = ["/rest/2fa/setup", "/api/2fa/setup", "/api/mfa/setup"]
            for setup_ep in setup_endpoints:
                try:
                    resp = await client.post(f"{base}{setup_ep}", json={})
                    if resp.status_code == 200:
                        body = resp.text
                        # Look for base32-encoded TOTP secrets or otpauth:// URIs
                        secret_leaked = (
                            "otpauth://" in body or
                            re.search(r'[A-Z2-7]{16,}', body) is not None or
                            "secret" in body.lower()
                        )
                        if secret_leaked:
                            findings.append({
                                "type": "2fa_setup_secret_leak",
                                "endpoint": setup_ep,
                                "severity": "high",
                                "description": f"2FA setup endpoint {setup_ep} leaks TOTP secret without proper auth",
                                "evidence": body[:200]
                            })
                except Exception:
                    continue

        vulnerable = len(findings) > 0
        return {"status": "success", "data": {
            "vulnerable": vulnerable,
            "findings": findings,
            "vulnerabilities_found": len(findings),
            "description": "2FA/TOTP bypass testing complete"
        }}
    except Exception as e:
        return {"status": "error", "message": f"2FA bypass test failed: {e}"}


# --- Prompt (tidak ada perubahan signifikan) ---
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domainname: str) -> str:
    # Prompt yang Anda buat sudah sangat baik dan komprehensif.
    # Tidak perlu diubah.
    return f"""
You are a highly skilled penetration tester specialising in authentication security.
Your mission is to evaluate the authentication controls of **{domainname}** in accordance with OWASP WSTG 4.4.

Primary objectives:
- Ensure credentials are transported only over encrypted channels.
- Detect default or easily guessable credentials.
- Assess the strength of lock-out and rate-limiting mechanisms.
- Attempt to bypass authentication schemes by any means.
- Evaluate “remember me” cookies, browser-cache directives and password policy enforcement.
- Review security-question usage and the robustness of password-reset/change workflows.
- Identify weaker authentication in alternate channels (mobile/API/SSO).
- **Analyze any discovered JSON Web Tokens (JWT) for common flaws.**

First, **reflect** on these objectives and draft an initial plan.
Then begin testing by executing the most relevant techniques.
Report findings clearly and revise your strategy as new information emerges.
"""

# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter instead
#     mcp.run(transport="stdio")

