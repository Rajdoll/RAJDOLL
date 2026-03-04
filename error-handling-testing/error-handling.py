# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import asyncio
import re
import os
import json
import httpx
import random
import string
from typing import Dict, Any, List, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [error-handling-testing] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

from urllib.parse import urlparse, urlencode, urlunparse

# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"error-handling-testing")

# --- Helpers ---
async def sh(cmd: str, timeout: int = 60) -> str:
    """Run a shell command in a Linux container using bash -lc (no WSL)."""
    proc = await asyncio.create_subprocess_exec(
        "bash", "-lc", cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        return out.decode("utf-8", errors="ignore").strip()
    except asyncio.TimeoutError:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

# Pola regex untuk mendeteksi pesan kesalahan umum
ERROR_PATTERNS = re.compile(
    r"\b(exception|traceback|stack trace|system\.exception|warning:|error:)\b|"
    r"\b(java\.lang\.\w+Exception|SQLException|ORA-\d{5}|Uncaught exception)\b|"
    r"in .*? on line \d+",
    re.IGNORECASE
)

# --- Tools (Revisi, Konsolidasi & Baru) ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def probe_for_error_leaks(base_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [KONSOLIDASI & PENINGKATAN] Probes for verbose errors and stack traces.
    Fuzzes the URL with various error-inducing payloads.
    
    Args:
        base_url: Target URL to probe for error leaks
        auth_session: Optional authentication session with cookies/headers/token
    """
    findings = {}

    # Manual fuzzing
    fuzz_payloads = ["'", "\"", "\\", "%27", "<", ">", "[", "]", "{", "}", "a" * 2048]
    fuzz_results = []
    
    # Build request kwargs with auth support
    req_kwargs = {"timeout": 10, "verify": False}
    if auth_session:
        if 'cookies' in auth_session:
            req_kwargs['cookies'] = auth_session['cookies']
        if 'headers' in auth_session:
            req_kwargs['headers'] = auth_session.get('headers', {})
        elif 'token' in auth_session:
            req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
    
    try:
        async with httpx.AsyncClient(**req_kwargs) as client:
            for payload in fuzz_payloads:
                # Menambahkan payload ke path
                fuzzed_url = f"{base_url.rstrip('/')}/{payload}"
                try:
                    resp = await client.get(fuzzed_url)
                    # Mencari pola error di body respons
                    matches = ERROR_PATTERNS.findall(resp.text)
                    if matches or resp.status_code == 500:
                        fuzz_results.append({
                            "payload": payload,
                            "url": fuzzed_url,
                            "status_code": resp.status_code,
                            "error_patterns_found": list(set(matches)),
                            "description": "Request with this payload triggered a server error or a verbose response."
                        })
                except httpx.RequestError:
                    continue
        findings["manual_fuzzing"] = fuzz_results
    except Exception as e:
        findings["manual_fuzzing"] = {"error": str(e)}

    return {"status": "success", "data": findings}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def check_generic_error_pages(base_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [BARU] Checks default server responses for 404 and 403 errors to find info leaks.
    
    Args:
        base_url: Target URL to check for generic error pages
        auth_session: Optional authentication session with cookies/headers/token
    """
    logger.info(f"🔍 Executing check_generic_error_pages")
    try:
        # Meminta path yang pasti tidak ada
        random_path = f"/{''.join(random.choices(string.ascii_lowercase, k=12))}.html"
        test_url = f"{base_url.rstrip('/')}{random_path}"
        
        # Build request kwargs with auth support
        req_kwargs = {"timeout": 10, "verify": False}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            resp = await client.get(test_url)
        
        # Pola untuk banner server umum
        server_pattern = re.compile(r"\b(Apache|IIS|nginx|LiteSpeed|gws|Jetty)[\s/][\d\.]+", re.I)
        banner_found = server_pattern.search(resp.text)
        
        return {"status": "success", "data": {
            "url_tested": test_url,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("content-type"),
            "server_banner_leaked": banner_found.group(0) if banner_found else "None",
            "description": "Checks the response for a non-existent page. Leaking server versions is an information disclosure vulnerability."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- Prompt ---
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domainname: str) -> str:
    return f"""
You are an expert penetration tester focusing on **error-handling weaknesses**.  
Your mission is to evaluate **{domainname}** in line with OWASP WSTG 4.8.

**Primary Objectives:**
1.  **Probe for Error Leaks:** Use the `probe_for_error_leaks` tool to run a comprehensive scan. This tool uses manual fuzzing to trigger and detect verbose error messages, debug information, and stack traces.
2.  **Analyze Generic Error Pages:** Use the `check_generic_error_pages` tool to test how the server responds to requests for non-existent pages. Look for server version banners or other sensitive information leaks in default 404/403 pages.

**Your Workflow:**
- Start with `probe_for_error_leaks` on the main application URL and other key endpoints.
- Follow up with `check_generic_error_pages` on the base domain.
- Analyze the JSON results from each tool. Any finding of stack traces or detailed error messages is a significant vulnerability.
- Report all findings clearly with evidence and mitigation advice.
"""

# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter`n#     mcp.run(transport="stdio")

