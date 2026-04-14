# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import asyncio
import os
import re
import json
import httpx
import random
import string
import time
from typing import Dict, Any, List, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [session-managemenet-testing] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"session-management-testing")

# --- Helpers (Tidak ada perubahan signifikan) ---
async def quick_req(method: str, url: str, auth_session: Optional[Dict[str, Any]] = None, **kwargs) -> httpx.Response | None:
    try:
        # Build request kwargs with auth support
        req_kwargs = {"timeout": 8, "follow_redirects": False, "verify": False}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        # Merge any additional kwargs (they take precedence)
        req_kwargs.update(kwargs)
        async with httpx.AsyncClient(**req_kwargs) as cli:
            return await cli.request(method, url, **kwargs)
    except Exception:
        return None

def rand_id(n: int = 32) -> str: # Panjang default ditingkatkan untuk keamanan
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

# --- Tools (Revisi & Peningkatan) ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def analyze_cookies(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [PENINGKATAN & KONSOLIDASI] Fetches a page and provides a comprehensive analysis of all set cookies,
    including their attributes (Secure, HttpOnly, SameSite) and entropy heuristics.
    Replaces test_session_schema and test_cookie_attributes.
    """
    try:
        resp = await quick_req("GET", url, auth_session=auth_session)
        if not resp:
            return {"status": "error", "message": f"Cannot reach {url}"}
        
        cookie_analysis = []
        # Analisis dari Set-Cookie header untuk mendapatkan semua atribut
        set_cookie_headers = resp.headers.get_list('set-cookie')
        
        for header in set_cookie_headers:
            parts = [p.strip() for p in header.split(';')]
            name_value = parts[0].split('=', 1)
            name = name_value[0]
            value = name_value[1] if len(name_value) > 1 else ""
            
            # Heuristik entropi sederhana
            entropy_bits = len(value) * 4 

            analysis = {
                "name": name,
                "value_preview": value[:10] + "...",
                "length": len(value),
                "entropy_heuristic_bits": entropy_bits,
                "is_secure": "secure" in header.lower(),
                "is_httponly": "httponly" in header.lower(),
                "samesite": re.search(r'samesite=(strict|lax|none)', header, re.I).group(1) if re.search(r'samesite=', header, re.I) else "Not Set"
            }
            cookie_analysis.append(analysis)

        return {"status": "success", "data": {"cookies": cookie_analysis}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_session_fixation(login_url: str, login_data: Dict[str, str]) -> Dict[str, Any]:
    """
    [REVISI] Tests for session fixation by sending a preset session ID before authentication.
    logger.info(f"🔍 Executing test_session_fixation")
    """
    fixation_id = rand_id()
    # Mencoba beberapa nama cookie sesi yang umum
    cookie_names = ["sessionid", "PHPSESSID", "JSESSIONID", "ASPSESSIONID"]
    
    try:
        for cookie_name in cookie_names:
            headers = {"Cookie": f"{cookie_name}={fixation_id}"}
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, headers=headers, verify=False) as client:
                # 1. Kunjungi halaman untuk menanam cookie
                await client.get(login_url)
                
                # 2. Lakukan login
                await client.post(login_url, data=login_data)
                
                # 3. Periksa cookie baru setelah login
                post_login_id = client.cookies.get(cookie_name)

                if post_login_id == fixation_id:
                    return {"status": "success", "data": {
                        "vulnerable": True,
                        "cookie_name": cookie_name,
                        "initial_id": fixation_id,
                        "post_login_id": post_login_id,
                        "description": "Session ID was not regenerated after login. Vulnerable to session fixation."
                    }}
        
        return {"status": "success", "data": {"vulnerable": False, "description": "Session ID appears to be regenerated after login."}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_exposed_session_vars(url: str) -> Dict[str, Any]:
    """
    [REVISI] Scans page content and URL for exposed session variables.
    logger.info(f"🔍 Executing test_exposed_session_vars")
    """
    try:
        resp = await quick_req("GET", url)
        if not resp: return {"status": "error", "message": "GET request failed."}
        
        leaks_in_body = re.findall(r'(?:PHPSESSID|JSESSIONID|ASPSESSIONID|sid|session_id|token)=[A-Za-z0-9\-_]{16,}', resp.text, re.I)
        leaks_in_url = re.findall(r'(?:sid|session_id|token)=\w{16,}', url, re.I)
        
        all_leaks = list(set(leaks_in_body + leaks_in_url))
        
        return {"status": "success", "data": {"leaks_found": all_leaks}}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_logout_functionality(logout_url: str, protected_url: str, initial_session: Dict[str, Any]) -> Dict[str, Any]:
    """
    [REVISI] Tests if the session is properly invalidated after logout.
    logger.info(f"🔍 Executing test_logout_functionality")
    """
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False, cookies=initial_session.get("cookies")) as client:
            # Panggil logout
            await client.get(logout_url)
            
            # Coba akses halaman terproteksi lagi
            post_logout_resp = await client.get(protected_url)
            
            # Sesi valid jika status 200, tidak valid jika redirect (302) atau unauthenticated (401/403)
            session_invalidated = post_logout_resp.status_code in [302, 401, 403]
            
            return {"status": "success", "data": {
                "post_logout_status_code": post_logout_resp.status_code,
                "session_invalidated": session_invalidated,
                "description": "A status of 302, 401, or 403 is expected after logout."
            }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_session_timeout(url: str, session: Dict[str, Any], wait_seconds: int = 30) -> Dict[str, Any]:
    """
    [PENINGKATAN] Checks if a session remains valid after a specified wait time. Uses async sleep.
    logger.info(f"🔍 Executing test_session_timeout")
    """
    try:
        # Ganti time.sleep dengan asyncio.sleep
        await asyncio.sleep(wait_seconds)
        
        resp_after_wait = await quick_req("GET", url, cookies=session.get("cookies"))
        
        if not resp_after_wait:
            return {"status": "error", "message": "Request after wait failed."}
            
        session_still_valid = resp_after_wait.status_code == 200

        return {"status": "success", "data": {
            "wait_duration_seconds": wait_seconds,
            "session_still_valid": session_still_valid,
            "status_code_after_wait": resp_after_wait.status_code,
            "description": "If session is still valid, it may indicate a long or non-existent timeout."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_cors_misconfiguration(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [BARU] Checks for CORS misconfigurations that could leak session data to malicious origins.
    logger.info(f"🔍 Executing test_cors_misconfiguration")
    """
    try:
        malicious_origin = "https://evil-domain.com"
        headers = {"Origin": malicious_origin}
        resp = await quick_req("GET", url, auth_session=auth_session, headers=headers)
        
        if not resp:
            return {"status": "error", "message": "Request failed."}

        acao_header = resp.headers.get("access-control-allow-origin", "")
        acac_header = resp.headers.get("access-control-allow-credentials", "")
        
        is_vulnerable = (acao_header == malicious_origin or acao_header == "*") and acac_header.lower() == 'true'

        return {"status": "success", "data": {
            "vulnerable": is_vulnerable,
            "access_control_allow_origin": acao_header,
            "access_control_allow_credentials": acac_header,
            "description": "Vulnerable if 'allow-origin' reflects a malicious domain and 'allow-credentials' is true."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ========== OPSI B: 3 NEW SESSION MANAGEMENT TOOLS ==========

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_csrf_protection(url: str, form_data: Dict[str, str], auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests CSRF protection on state-changing operations.
    logger.info(f"🔍 Executing test_csrf_protection")
    Checks for CSRF tokens in forms and validates SameSite cookie attributes.
    WSTG-SESS-05: Testing for Cross-Site Request Forgery
    """
    try:
        # 1. GET page to check for CSRF token in form
        resp = await quick_req("GET", url, auth_session=auth_session)
        if not resp:
            return {"status": "error", "message": f"Cannot reach {url}"}
        
        # Check for CSRF token patterns in HTML
        csrf_patterns = [
            r'<input[^>]*name=["\']csrf[^"\']*["\'][^>]*>',
            r'<input[^>]*name=["\']_token["\'][^>]*>',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*>'
        ]
        has_csrf_token = any(re.search(pattern, resp.text, re.I) for pattern in csrf_patterns)
        
        # 2. Check SameSite attributes on session cookies
        cookies_analysis = []
        for header in resp.headers.get_list('set-cookie'):
            if 'session' in header.lower() or 'auth' in header.lower():
                samesite = re.search(r'samesite=(strict|lax|none)', header, re.I)
                cookies_analysis.append({
                    "cookie": header.split('=')[0],
                    "samesite": samesite.group(1) if samesite else "Not Set",
                    "secure": "secure" in header.lower()
                })
        
        # 3. Attempt POST without CSRF token (if form_data provided)
        csrf_vulnerable = False
        if form_data:
            post_resp = await quick_req("POST", url, auth_session=auth_session, data=form_data)
            # If POST succeeds (200-299) without token, it's vulnerable
            csrf_vulnerable = post_resp and 200 <= post_resp.status_code < 300
        
        return {"status": "success", "data": {
            "has_csrf_token_in_form": has_csrf_token,
            "cookies_samesite_check": cookies_analysis,
            "csrf_vulnerable": csrf_vulnerable,
            "description": "CSRF protection requires tokens in forms AND SameSite=Strict/Lax on cookies"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_session_puzzling(url: str, test_params: Dict[str, str], auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests for session variable overwriting/puzzling attacks.
    logger.info(f"🔍 Executing test_session_puzzling")
    Attempts to pollute session namespace by injecting conflicting variables.
    WSTG-SESS-08: Testing for Session Puzzling
    """
    try:
        # Test 1: Parameter pollution - try to overwrite session vars via URL params
        pollution_tests = []
        critical_vars = ["user_id", "username", "role", "admin", "is_authenticated"]
        
        for var in critical_vars:
            # Try to inject via GET parameter
            test_url = f"{url}?{var}=attacker_value&{var}=1&session[{var}]=malicious"
            resp = await quick_req("GET", test_url, auth_session=auth_session)
            
            if resp:
                # Check if the injected value appears reflected
                reflected = "attacker_value" in resp.text or "malicious" in resp.text
                pollution_tests.append({
                    "variable": var,
                    "reflected_in_response": reflected,
                    "status_code": resp.status_code
                })
        
        # Test 2: Try session array injection (PHP-style)
        array_injection_url = f"{url}?_SESSION[user]=attacker&_SESSION[role]=admin"
        array_resp = await quick_req("GET", array_injection_url, auth_session=auth_session)
        array_vulnerable = array_resp and "attacker" in array_resp.text
        
        # Test 3: Custom test params if provided
        custom_results = {}
        if test_params:
            for key, value in test_params.items():
                custom_url = f"{url}?{key}={value}"
                custom_resp = await quick_req("GET", custom_url, auth_session=auth_session)
                custom_results[key] = {
                    "injected_value": value,
                    "reflected": custom_resp and value in custom_resp.text
                }
        
        return {"status": "success", "data": {
            "parameter_pollution_tests": pollution_tests,
            "array_injection_vulnerable": array_vulnerable,
            "custom_tests": custom_results,
            "description": "Session puzzling occurs when attackers can overwrite session variables via URL parameters"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_session_hijacking(url: str, session_cookies: Dict[str, str], auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests for session hijacking vulnerabilities.
    logger.info(f"🔍 Executing test_session_hijacking")
    Checks session token predictability, brute force resistance, and XSS-based hijacking potential.
    WSTG-SESS-09: Testing for Session Hijacking
    """
    try:
        # Test 1: Session token entropy analysis
        token_analysis = []
        if session_cookies:
            for name, value in session_cookies.items():
                # Analyze token characteristics
                token_length = len(value)
                has_numbers = any(c.isdigit() for c in value)
                has_letters = any(c.isalpha() for c in value)
                has_special = any(not c.isalnum() for c in value)
                
                # Estimate entropy (simplified)
                charset_size = 0
                if has_numbers: charset_size += 10
                if has_letters: charset_size += 52  # a-z, A-Z
                if has_special: charset_size += 10
                
                entropy_bits = token_length * (charset_size.bit_length() if charset_size > 0 else 0)
                
                token_analysis.append({
                    "cookie_name": name,
                    "token_length": token_length,
                    "entropy_estimate_bits": entropy_bits,
                    "predictable": entropy_bits < 128,  # < 128 bits = weak
                    "has_structure": bool(re.search(r'\d{10,}', value))  # Sequential numbers
                })
        
        # Test 2: Check if session cookie is HTTPOnly (prevents XSS hijacking)
        resp = await quick_req("GET", url, auth_session=auth_session)
        httponly_protected = False
        if resp:
            for header in resp.headers.get_list('set-cookie'):
                if any(name in header for name in session_cookies.keys()):
                    httponly_protected = "httponly" in header.lower()
                    break
        
        # Test 3: Session reuse after logout attempt
        logout_url = url.replace('/profile', '/logout').replace('/dashboard', '/logout')
        if logout_url != url:
            # Try to use session after logout
            await quick_req("GET", logout_url, auth_session=auth_session, cookies=session_cookies)
            reuse_resp = await quick_req("GET", url, auth_session=auth_session, cookies=session_cookies)
            session_reusable = reuse_resp and reuse_resp.status_code == 200
        else:
            session_reusable = None
        
        return {"status": "success", "data": {
            "token_analysis": token_analysis,
            "httponly_protection": httponly_protected,
            "session_reusable_after_logout": session_reusable,
            "description": "Strong sessions need: high entropy (128+ bits), HTTPOnly flag, invalidation after logout"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- Prompt ---
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domainname: str) -> str:
    # Prompt yang Anda buat sebelumnya sudah sangat baik.
    # Diperbarui sedikit untuk mencerminkan tool yang lebih kuat.
    return f"""
You are an expert penetration tester specialising in **session-management flaws**.  
Your mission is to assess the robustness of **{domainname}** in accordance with OWASP WSTG 4.2.

Primary objectives:
- **Analyze Cookie Security:** Use `analyze_cookies` to perform a comprehensive review of all cookie attributes (Secure, HttpOnly, SameSite, entropy).
- **Test Session Lifecycle:** Verify protection against session fixation, check for effective logout, and test for reasonable session timeouts.
- **Check for Information Leakage:** Scan for exposed session tokens in URLs/HTML and test for CORS misconfigurations that could leak data.
- **Verify CSRF Protection:** Ensure state-changing forms are protected by anti-CSRF tokens.

Reflect on these goals, craft an initial plan, then begin testing with the most relevant technique.  
Report findings clearly and adapt your strategy as new evidence is uncovered.
"""

# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter`n#     mcp.run(transport="stdio")

