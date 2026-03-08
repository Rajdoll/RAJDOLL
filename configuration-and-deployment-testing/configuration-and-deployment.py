# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import httpx
import asyncio
import os
import re
import json
from typing import List, Dict, Any, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [configuration-and-deployment-testing] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


# Inisialisasi server
# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"configuration-and-deployment-management")

# Helper yang sama, pastikan encoding utf-8 untuk menangani output yang beragam
async def execute_wsl_command(command: str, timeout: int = 180) -> str:
    try:
        escaped = command.replace("'", "'\\''")
        proc = await asyncio.create_subprocess_shell(
            f"wsl /bin/bash -c '{escaped}'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out = stdout.decode('utf-8', errors='ignore').strip()
        # Stderr tidak kita sertakan langsung untuk menjaga kebersihan output bagi LLM
        return out or "No output"
    except asyncio.TimeoutError:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

# Helper function to validate ffuf findings by following redirects
async def _validate_ffuf_findings(domain: str, ffuf_results: List[Dict], auth_session: Optional[Dict[str, Any]] = None) -> List[Dict]:
    """
    Validates ffuf findings by following redirects and checking actual content.
    Returns only findings that are actually accessible admin interfaces.
    """
    validated = []
    
    # Build request kwargs with auth support
    req_kwargs = {"verify": False, "follow_redirects": True, "timeout": 10}
    if auth_session:
        if 'cookies' in auth_session:
            req_kwargs['cookies'] = auth_session['cookies']
        if 'headers' in auth_session:
            req_kwargs['headers'] = auth_session.get('headers', {})
        elif 'token' in auth_session:
            req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
    
    async with httpx.AsyncClient(**req_kwargs) as client:
        for result in ffuf_results:
            try:
                url = result.get("url", "")
                status = result.get("status", 0)
                
                # Skip if not a redirect or auth-required status
                if status not in [200, 301, 302, 401, 403]:
                    continue
                
                # Test the actual URL
                resp = await client.get(url)
                content = resp.text.lower()
                
                # Check for actual admin interface indicators
                is_admin_interface = any([
                    "login" in content and ("admin" in content or "dashboard" in content),
                    "username" in content and "password" in content and len(content) < 50000,  # Login form
                    "phpmyadmin" in content,
                    "administration" in content and "login" in content,
                    "wp-admin" in content,
                    "cpanel" in content,
                    resp.status_code == 401,  # Authentication required
                    resp.status_code == 403 and "forbidden" in content,  # Forbidden but exists
                ])
                
                # Check for false positives (common redirects to homepage)
                is_false_positive = any([
                    resp.status_code == 200 and len(content) > 10000 and "homepage" in content,
                    "home" in url.lower() and resp.status_code == 200,
                    resp.url != url and "index" in str(resp.url),  # Redirected to homepage
                    "404" in content or "not found" in content,
                ])
                
                if is_admin_interface and not is_false_positive:
                    validated.append({
                        "original_url": url,
                        "final_url": str(resp.url),
                        "status_code": resp.status_code,
                        "original_status": status,
                        "validation": "confirmed_admin_interface",
                        "indicators": _get_admin_indicators(content),
                        "content_length": len(content)
                    })
                elif status in [401, 403]:
                    # Auth required or forbidden - likely real
                    validated.append({
                        "original_url": url,
                        "final_url": str(resp.url),
                        "status_code": resp.status_code,
                        "original_status": status,
                        "validation": "access_restricted",
                        "content_length": len(content)
                    })
                    
            except Exception as e:
                # If request fails, it might be a real endpoint that's protected
                if "timeout" not in str(e).lower():
                    validated.append({
                        "original_url": url,
                        "status_code": "error",
                        "original_status": status,
                        "validation": "request_failed",
                        "error": str(e)
                    })
                continue
    
    return validated

# Helper function to identify admin interface indicators
def _get_admin_indicators(content: str) -> List[str]:
    """Returns list of indicators that suggest this is an admin interface."""
    indicators = []
    content_lower = content.lower()
    
    if "login" in content_lower and "password" in content_lower:
        indicators.append("login_form")
    if "dashboard" in content_lower:
        indicators.append("dashboard")
    if "admin" in content_lower:
        indicators.append("admin_reference")
    if "phpmyadmin" in content_lower:
        indicators.append("phpmyadmin")
    if "wp-admin" in content_lower or "wordpress" in content_lower:
        indicators.append("wordpress_admin")
    if "cpanel" in content_lower:
        indicators.append("cpanel")
    if "management" in content_lower:
        indicators.append("management_interface")
    
    return indicators

# [REVISED] Prompt diperbarui setelah subjack dipindahkan
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domain: str) -> str:
    return f"""
You are an expert web application security tester focusing on OWASP WSTG v4.2 'Configuration & Deployment Management' defects for the domain **{domain}**.

Your main objectives are:
- **Scan Network & Services:** Use Nmap to identify open ports and running services.
- **Automated Configuration Scan:** Use targeted checks/scanners to find misconfigurations, exposed panels, and common issues.
- **Find Sensitive Files:** Use ffuf to discover exposed backup, config, and administrative files or directories.
- **Check HTTP Security:** Test for insecure HTTP methods and missing security headers.

**Your Workflow:**
1.  **Reason:** State your plan before acting.
2.  **Execute:** Call a tool.
3.  **Analyze:** Process the JSON output. Summarize your findings.
4.  **Adapt:** Update your plan based on the new information.
Report all findings with clear, actionable mitigation advice.
"""

# --- TOOLS ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_network_infrastructure(domain: str) -> Dict[str, Any]:
    """
    [ENHANCED] Runs comprehensive Nmap scan and validates critical services.
    logger.info(f"🔍 Executing test_network_infrastructure")
    Phase 1: Fast scan for top 1000 open TCP ports.
    Phase 2: Detailed service scan with version detection.
    Phase 3: Validation of critical exposed services.
    """
    try:
        # Phase 1: Extended port scan for better coverage
        top_scan_cmd = f"nmap -Pn -T4 --top-ports 1000 {domain}"
        top_out = await execute_wsl_command(top_scan_cmd, timeout=180)
        open_ports = ",".join(re.findall(r"^(\d+)/tcp\s+open", top_out, re.MULTILINE))

        if not open_ports:
            return {"status": "success", "data": {"message": f"No open TCP ports found in the top 1000 for {domain}."}}

        # Phase 2: Service version detection
        svc_scan_cmd = f"nmap -Pn -T4 -sV -sC -p {open_ports} {domain}"
        svc_out = await execute_wsl_command(svc_scan_cmd, timeout=300)
        
        # Parse service information manually since JSON output might not work
        port_details = []
        critical_services = []
        
        lines = svc_out.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_num = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = ' '.join(parts[3:]) if len(parts) > 3 else "unknown"
                    
                    port_info = {
                        "port": int(port_num),
                        "service": service,
                        "version": version,
                        "risk_level": _assess_port_risk(int(port_num), service)
                    }
                    port_details.append(port_info)
                    
                    # Mark critical services
                    if port_info["risk_level"] in ["critical", "high"]:
                        critical_services.append(port_info)

        # Phase 3: Validate critical services
        validated_critical = await _validate_critical_services(domain, critical_services)

        return {
            "status": "success",
            "data": {
                "open_ports_summary": {
                    "total_open": len(port_details),
                    "critical_services": len(critical_services),
                    "validated_critical": len(validated_critical)
                },
                "port_details": port_details,
                "critical_services": critical_services,
                "validated_critical_services": validated_critical,
                "raw_nmap_output": svc_out[:1000] + "..." if len(svc_out) > 1000 else svc_out
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Helper function to assess port risk level
def _assess_port_risk(port: int, service: str) -> str:
    """Assesses the risk level of an exposed port/service."""
    critical_ports = {
        22: "ssh",
        23: "telnet", 
        3306: "mysql",
        5432: "postgresql",
        1433: "mssql",
        5900: "vnc",
        3389: "rdp",
        6379: "redis",
        27017: "mongodb"
    }
    
    high_risk_ports = {
        21: "ftp",
        25: "smtp",
        53: "dns",
        135: "rpc",
        139: "netbios",
        445: "smb",
        1521: "oracle",
        2049: "nfs"
    }
    
    if port in critical_ports:
        return "critical"
    elif port in high_risk_ports:
        return "high"
    elif port in [80, 443, 8080, 8443]:
        return "low"  # Standard web ports
    else:
        return "medium"

# Helper function to validate critical services
async def _validate_critical_services(domain: str, critical_services: List[Dict]) -> List[Dict]:
    """Validates that critical services are actually accessible and responsive."""
    validated = []
    
    for service in critical_services:
        port = service["port"]
        service_name = service["service"]
        
        try:
            # Test basic connectivity
            connectivity_test = await execute_wsl_command(
                f"timeout 5 nc -zv {domain} {port}", timeout=10
            )
            
            is_accessible = "succeeded" in connectivity_test or "open" in connectivity_test
            
            if is_accessible:
                validated.append({
                    **service,
                    "accessibility": "confirmed_accessible",
                    "validation_method": "netcat_test"
                })
            else:
                validated.append({
                    **service,
                    "accessibility": "connection_failed",
                    "validation_method": "netcat_test",
                    "note": "Port appears closed or filtered"
                })
                
        except Exception as e:
            validated.append({
                **service,
                "accessibility": "validation_error",
                "error": str(e)
            })
    
    return validated

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def find_sensitive_files_and_dirs(domain: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [ENHANCED] Brute-forces for sensitive admin panels and directories using ffuf.
    Validates findings by following redirects to determine actual accessibility.
    """
    try:
        # Menggunakan path wordlist yang Anda tentukan sebelumnya
        login_list = "/mnt/d/MCP/RAJDOLL/SecLists/Discovery/Web-Content/Logins.fuzz.txt"
        output_file = f"ffuf_output_{domain}.json"
        
        if not os.path.exists(login_list):
            return {"status": "error", "message": f"Wordlist not found at: {login_list}"}
            
        cmd = (
            f"ffuf -w {login_list} -u https://{domain}/FUZZ "
            f"-mc 200,301,302,401,403 -o {output_file} -of json"
        )
        # Add auth headers/cookies to ffuf command if auth_session provided
        if auth_session:
            if 'token' in auth_session:
                cmd += f" -H 'Authorization: Bearer {auth_session['token']}'"
            if 'cookies' in auth_session and isinstance(auth_session['cookies'], dict):
                cookie_str = "; ".join([f"{k}={v}" for k, v in auth_session['cookies'].items()])
                cmd += f" -b '{cookie_str}'"
            if 'headers' in auth_session and isinstance(auth_session['headers'], dict):
                for header_name, header_value in auth_session['headers'].items():
                    cmd += f" -H '{header_name}: {header_value}'"
        await execute_wsl_command(cmd, timeout=300)

        results = {}
        if os.path.exists(output_file):
             with open(output_file, 'r') as f:
                results = json.load(f)
             os.remove(output_file)

        # Validate findings by following redirects and checking actual content
        validated_findings = await _validate_ffuf_findings(domain, results.get("results", []), auth_session)

        return {
            "status": "success",
            "data": {"validated_findings": validated_findings} if validated_findings else {"message": "No confirmed sensitive admin interfaces found after validation."}
        }
    except Exception as e:
        return {"status": "error", "message": f"ffuf scan failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_http_methods_and_headers(domain: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [ENHANCED] Checks for enabled HTTP methods and analyzes security headers.
    logger.info(f"🔍 Executing test_http_methods_and_headers")
    Tests multiple dangerous methods and provides detailed security assessment.
    """
    try:
        # Build request kwargs with auth support
        req_kwargs = {"verify": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test basic GET request for headers
            resp = await client.get(f"https://{domain}")
            headers = {h.lower(): resp.headers[h] for h in resp.headers}

            # Test dangerous HTTP methods
            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
            method_results = {}
            
            for method in dangerous_methods:
                try:
                    method_resp = await client.request(method, f"https://{domain}")
                    method_results[method] = {
                        "status_code": method_resp.status_code,
                        "allowed": method_resp.status_code not in [400, 405, 501],
                        "response_length": len(method_resp.text) if method_resp.text else 0
                    }
                except Exception as e:
                    method_results[method] = {
                        "status_code": "error",
                        "allowed": False,
                        "error": str(e)
                    }

        # Analyze security headers
        security_headers = {
            "strict-transport-security": {
                "present": "strict-transport-security" in headers,
                "value": headers.get("strict-transport-security"),
                "secure": bool(headers.get("strict-transport-security"))
            },
            "content-security-policy": {
                "present": "content-security-policy" in headers,
                "value": headers.get("content-security-policy"),
                "secure": bool(headers.get("content-security-policy"))
            },
            "x-frame-options": {
                "present": "x-frame-options" in headers,
                "value": headers.get("x-frame-options"),
                "secure": headers.get("x-frame-options", "").upper() in ["DENY", "SAMEORIGIN"]
            },
            "x-content-type-options": {
                "present": "x-content-type-options" in headers,
                "value": headers.get("x-content-type-options"),
                "secure": headers.get("x-content-type-options", "").lower() == "nosniff"
            },
            "x-xss-protection": {
                "present": "x-xss-protection" in headers,
                "value": headers.get("x-xss-protection"),
                "secure": headers.get("x-xss-protection") in ["1", "1; mode=block"]
            }
        }

        # Calculate security score
        total_headers = len(security_headers)
        secure_headers = sum(1 for h in security_headers.values() if h["secure"])
        security_score = (secure_headers / total_headers) * 100

        # Check for dangerous methods
        dangerous_allowed = [method for method, result in method_results.items() if result.get("allowed", False)]

        return {
            "status": "success",
            "data": {
                "security_headers": security_headers,
                "security_score": round(security_score, 1),
                "http_methods": method_results,
                "dangerous_methods_allowed": dangerous_allowed,
                "server_info": {
                    "server": headers.get("server"),
                    "x-powered-by": headers.get("x-powered-by"),
                    "http_version": "HTTP/1.0" if "HTTP/1.0" in str(resp.http_version) else "HTTP/1.1+"
                }
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"HTTP method/header check failed: {str(e)}"}


# ========== OPSI B: 4 NEW CONFIGURATION & DEPLOYMENT TOOLS ==========

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_file_extensions(base_url: str, test_extensions: List[str] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests for dangerous file upload/execution capabilities.
    logger.info(f"🔍 Executing test_file_extensions")
    Checks if server executes uploaded files with dangerous extensions.
    WSTG-CONF-05: Testing for File Extension Handling
    """
    if test_extensions is None:
        test_extensions = [".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".pl", ".cgi", ".py"]
    
    try:
        findings = []
        
        # Build request kwargs with auth support
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Check if dangerous extensions are mapped to handlers
            for ext in test_extensions:
                test_url = f"{base_url.rstrip('/')}/test{ext}"
                try:
                    resp = await client.get(test_url)
                    
                    # Check if server tries to execute (vs downloading)
                    content_type = resp.headers.get("content-type", "")
                    content_disposition = resp.headers.get("content-disposition", "")
                    
                    is_executable = any([
                        "text/html" in content_type,
                        "application/x-httpd-php" in content_type,
                        "application/x-jsp" in content_type,
                        "download" not in content_disposition.lower()
                    ])
                    
                    if resp.status_code in [200, 500] and is_executable:
                        findings.append({
                            "extension": ext,
                            "status_code": resp.status_code,
                            "content_type": content_type,
                            "risk": "Server may execute files with this extension",
                            "severity": "High"
                        })
                except Exception:
                    continue
            
            # Test 2: Double extension bypass (.php.jpg)
            for ext in [".php", ".jsp", ".asp"]:
                test_url = f"{base_url.rstrip('/')}/test{ext}.jpg"
                try:
                    resp = await client.get(test_url)
                    if "php" in resp.headers.get("content-type", "").lower() or resp.status_code == 500:
                        findings.append({
                            "extension": f"{ext}.jpg",
                            "type": "double_extension_bypass",
                            "risk": "Server may parse double extensions allowing execution",
                            "severity": "Critical"
                        })
                except Exception:
                    continue
        
        return {"status": "success", "data": {
            "tested_extensions": test_extensions,
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Dangerous file extensions can allow code execution if not properly restricted"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_ria_cross_domain(base_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests for RIA cross-domain policy misconfigurations.
    logger.info(f"🔍 Executing test_ria_cross_domain")
    Checks crossdomain.xml (Flash) and clientaccesspolicy.xml (Silverlight).
    WSTG-CONF-08: Testing for RIA Cross Domain Policy
    """
    try:
        findings = []
        
        policy_files = [
            {"path": "/crossdomain.xml", "type": "Flash"},
            {"path": "/clientaccesspolicy.xml", "type": "Silverlight"}
        ]
        
        # Build request kwargs with auth support
        req_kwargs = {"verify": False, "follow_redirects": True, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            for policy in policy_files:
                url = f"{base_url.rstrip('/')}{policy['path']}"
                try:
                    resp = await client.get(url)
                    
                    if resp.status_code == 200:
                        content = resp.text
                        
                        # Check for overly permissive policies
                        is_vulnerable = any([
                            'domain="*"' in content,
                            'allow-access-from domain="*"' in content,
                            '<allow-from>' in content and '*' in content,
                            'secure="false"' in content
                        ])
                        
                        if is_vulnerable:
                            findings.append({
                                "file": policy['path'],
                                "type": policy['type'],
                                "vulnerability": "Overly permissive cross-domain policy",
                                "content_preview": content[:200],
                                "severity": "High"
                            })
                        else:
                            findings.append({
                                "file": policy['path'],
                                "type": policy['type'],
                                "status": "Policy exists but appears restrictive",
                                "severity": "Info"
                            })
                except Exception:
                    continue
        
        return {"status": "success", "data": {
            "policies_checked": [p['path'] for p in policy_files],
            "vulnerabilities_found": len([f for f in findings if f.get("severity") == "High"]),
            "findings": findings,
            "description": "Permissive RIA policies allow cross-domain data access from untrusted sources"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_file_permissions(base_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests for insecure file permissions and directory traversal.
    logger.info(f"🔍 Executing test_file_permissions")
    Attempts to access sensitive files via path traversal.
    WSTG-CONF-09: Testing for File Permission
    """
    try:
        findings = []
        
        # Path traversal payloads
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        # Sensitive files to test direct access
        sensitive_files = [
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/web.config",
            "/.git/config",
            "/.htaccess",
            "/backup.sql"
        ]
        
        # Build request kwargs with auth support
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Path traversal
            for payload in traversal_payloads:
                test_url = f"{base_url.rstrip('/')}/{payload}"
                try:
                    resp = await client.get(test_url)
                    
                    # Check for successful traversal indicators
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        if any(indicator in content for indicator in ["root:x:", "[extensions]", "bin/bash"]):
                            findings.append({
                                "type": "path_traversal",
                                "payload": payload,
                                "status_code": resp.status_code,
                                "evidence": "System file content detected",
                                "severity": "Critical"
                            })
                except Exception:
                    continue
            
            # Test 2: Direct access to sensitive files
            for file_path in sensitive_files:
                test_url = f"{base_url.rstrip('/')}{file_path}"
                try:
                    resp = await client.get(test_url)
                    
                    if resp.status_code == 200 and len(resp.text) > 0:
                        findings.append({
                            "type": "sensitive_file_access",
                            "file": file_path,
                            "status_code": resp.status_code,
                            "content_length": len(resp.text),
                            "severity": "High"
                        })
                except Exception:
                    continue
        
        return {"status": "success", "data": {
            "traversal_payloads_tested": len(traversal_payloads),
            "sensitive_files_tested": len(sensitive_files),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "File permission issues can expose sensitive system or application files"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_cloud_storage(domain: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI B] Tests for misconfigured cloud storage (S3, Azure, GCS).
    logger.info(f"🔍 Executing test_cloud_storage")
    Checks for publicly accessible buckets and containers.
    WSTG-CONF-11: Testing Cloud Storage
    """
    try:
        findings = []
        
        # Common cloud storage patterns
        cloud_patterns = [
            {"name": "AWS S3", "pattern": f"{domain.replace('.', '-')}.s3.amazonaws.com"},
            {"name": "AWS S3 Regional", "pattern": f"{domain.replace('.', '-')}.s3-us-west-2.amazonaws.com"},
            {"name": "Azure Blob", "pattern": f"{domain.replace('.', '')}.blob.core.windows.net"},
            {"name": "Google Cloud Storage", "pattern": f"{domain.replace('.', '-')}.storage.googleapis.com"},
        ]
        
        # Build request kwargs with auth support
        req_kwargs = {"verify": False, "follow_redirects": True, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        
        async with httpx.AsyncClient(**req_kwargs) as client:
            for cloud in cloud_patterns:
                url = f"https://{cloud['pattern']}"
                try:
                    resp = await client.get(url)
                    
                    if resp.status_code == 200:
                        content = resp.text
                        
                        # Check for bucket listing
                        is_public = any([
                            "<ListBucketResult" in content,  # S3 XML listing
                            "<EnumerationResults" in content,  # Azure blob listing
                            '"kind": "storage#' in content,  # GCS JSON listing
                        ])
                        
                        if is_public:
                            findings.append({
                                "cloud_provider": cloud['name'],
                                "url": url,
                                "vulnerability": "Publicly accessible cloud storage",
                                "evidence": "Bucket/container listing accessible",
                                "severity": "Critical"
                            })
                        else:
                            findings.append({
                                "cloud_provider": cloud['name'],
                                "url": url,
                                "status": "Storage exists but listing not public",
                                "severity": "Info"
                            })
                    elif resp.status_code == 403:
                        # Storage exists but access denied (good)
                        findings.append({
                            "cloud_provider": cloud['name'],
                            "url": url,
                            "status": "Storage exists with proper access control",
                            "severity": "Info"
                        })
                except Exception:
                    continue
        
        return {"status": "success", "data": {
            "cloud_providers_checked": len(cloud_patterns),
            "vulnerabilities_found": len([f for f in findings if f.get("severity") == "Critical"]),
            "findings": findings,
            "description": "Public cloud storage can expose sensitive data, backups, or credentials"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_sensitive_file_extensions(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-CONF-03: Test File Extensions Handling for Sensitive Information.
    Checks if the server exposes backup files, source code, or config files
    with sensitive extensions (.bak, .old, .swp, .env, .config, etc.).
    """
    try:
        findings = []
        base = url.rstrip('/')

        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": False}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        # Sensitive file paths to check
        sensitive_files = [
            # Backup / source files
            ("/index.php.bak", "Backup file"), ("/index.php.old", "Old file"),
            ("/index.php~", "Editor backup"), ("/index.php.swp", "Vim swap file"),
            ("/web.config", "IIS config"), ("/web.config.bak", "IIS config backup"),
            ("/.env", "Environment variables"), ("/.env.bak", "Env backup"),
            ("/config.yml", "YAML config"), ("/config.json", "JSON config"),
            ("/database.yml", "Database config"), ("/settings.py", "Django settings"),
            ("/wp-config.php.bak", "WordPress config backup"),
            # Source code / debug
            ("/.git/HEAD", "Git repository"), ("/.svn/entries", "SVN repository"),
            ("/.DS_Store", "macOS directory listing"), ("/Thumbs.db", "Windows thumbnails"),
            ("/phpinfo.php", "PHP info page"), ("/info.php", "PHP info page"),
            ("/server-status", "Apache status"), ("/server-info", "Apache info"),
            # Package managers
            ("/package.json", "Node.js dependencies"), ("/composer.json", "PHP dependencies"),
            ("/Gemfile", "Ruby dependencies"), ("/requirements.txt", "Python dependencies"),
            # Logs
            ("/error.log", "Error log"), ("/access.log", "Access log"),
            ("/debug.log", "Debug log"), ("/app.log", "Application log"),
        ]

        async with httpx.AsyncClient(**req_kwargs) as client:
            for path, file_type in sensitive_files:
                try:
                    resp = await client.get(f"{base}{path}")
                    if resp.status_code == 200 and len(resp.text) > 10:
                        # Verify it's not a generic error page
                        content = resp.text[:500].lower()
                        if '404' not in content and 'not found' not in content:
                            severity = "Critical" if any(kw in path for kw in ['.env', 'config', '.git', 'phpinfo']) else "High"
                            findings.append({
                                "path": path,
                                "type": file_type,
                                "status_code": resp.status_code,
                                "content_length": len(resp.text),
                                "severity": severity,
                                "evidence": resp.text[:200],
                                "description": f"Sensitive file accessible: {file_type}"
                            })
                except Exception:
                    continue

        return {"status": "success", "data": {
            "files_tested": len(sensitive_files),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Exposed sensitive files can reveal credentials, source code, and internal configuration"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_hsts(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-CONF-07: Test HTTP Strict Transport Security (HSTS).
    Checks for the presence and correctness of the Strict-Transport-Security header.
    """
    try:
        findings = []

        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": False}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test HTTPS endpoint
            https_url = url.replace("http://", "https://") if url.startswith("http://") else url
            try:
                resp = await client.get(https_url)
                hsts = resp.headers.get("strict-transport-security", "")

                if not hsts:
                    findings.append({
                        "type": "missing_hsts",
                        "severity": "High",
                        "description": "Strict-Transport-Security header is missing",
                        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    })
                else:
                    # Parse HSTS directives
                    import re
                    max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
                    max_age = int(max_age_match.group(1)) if max_age_match else 0

                    if max_age < 15768000:  # Less than 6 months
                        findings.append({
                            "type": "weak_hsts_max_age",
                            "severity": "Medium",
                            "description": f"HSTS max-age too short: {max_age}s (recommended >= 31536000)",
                            "current_value": hsts
                        })

                    if "includesubdomains" not in hsts.lower():
                        findings.append({
                            "type": "hsts_missing_subdomains",
                            "severity": "Low",
                            "description": "HSTS missing includeSubDomains directive",
                            "current_value": hsts
                        })

                    if "preload" not in hsts.lower():
                        findings.append({
                            "type": "hsts_missing_preload",
                            "severity": "Info",
                            "description": "HSTS missing preload directive",
                            "current_value": hsts
                        })
            except Exception:
                pass

            # Test HTTP → HTTPS redirect
            http_url = url.replace("https://", "http://") if url.startswith("https://") else url
            try:
                resp = await client.get(http_url)
                if resp.status_code not in (301, 302, 307, 308):
                    findings.append({
                        "type": "no_https_redirect",
                        "severity": "High",
                        "description": "HTTP does not redirect to HTTPS",
                        "status_code": resp.status_code
                    })
                elif resp.status_code == 302:
                    findings.append({
                        "type": "temporary_redirect",
                        "severity": "Low",
                        "description": "HTTP→HTTPS uses 302 (temporary) instead of 301 (permanent)",
                    })
            except Exception:
                pass

        return {"status": "success", "data": {
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "HSTS prevents SSL stripping attacks and ensures HTTPS-only communication"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_subdomain_takeover(domain: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-CONF-10: Test for Subdomain Takeover.
    Checks common subdomains for dangling DNS records that could be taken over.
    """
    try:
        import socket
        findings = []

        common_subdomains = [
            "www", "mail", "ftp", "blog", "dev", "staging", "test", "api",
            "cdn", "static", "assets", "admin", "portal", "app", "m",
            "shop", "store", "docs", "wiki", "status", "beta", "demo",
        ]

        # Cloud provider fingerprints indicating potential takeover
        takeover_fingerprints = {
            "GitHub Pages": ["There isn't a GitHub Pages site here"],
            "Heroku": ["No such app", "no-such-app"],
            "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
            "Azure": ["404 Web Site not found"],
            "Shopify": ["Sorry, this shop is currently unavailable"],
            "Fastly": ["Fastly error: unknown domain"],
            "Pantheon": ["404 error unknown site"],
            "Tumblr": ["There's nothing here"],
            "Zendesk": ["Help Center Closed"],
        }

        req_kwargs = {"timeout": 5, "verify": False, "follow_redirects": True}

        async with httpx.AsyncClient(**req_kwargs) as client:
            for sub in common_subdomains:
                fqdn = f"{sub}.{domain}"
                try:
                    # DNS resolution check
                    try:
                        socket.getaddrinfo(fqdn, 80)
                    except socket.gaierror:
                        # NXDOMAIN — check if CNAME exists (dangling)
                        findings.append({
                            "subdomain": fqdn,
                            "type": "nxdomain",
                            "severity": "Info",
                            "description": f"Subdomain {fqdn} does not resolve (potential dangling CNAME)"
                        })
                        continue

                    # Check if the subdomain serves content indicating takeover
                    for scheme in ["https", "http"]:
                        try:
                            resp = await client.get(f"{scheme}://{fqdn}")
                            body = resp.text

                            for provider, fingerprints in takeover_fingerprints.items():
                                for fp in fingerprints:
                                    if fp in body:
                                        findings.append({
                                            "subdomain": fqdn,
                                            "provider": provider,
                                            "type": "subdomain_takeover",
                                            "severity": "Critical",
                                            "description": f"Potential subdomain takeover on {provider}",
                                            "evidence": fp,
                                            "recommendation": f"Remove dangling DNS record or claim the resource on {provider}"
                                        })
                            break  # If https works, skip http
                        except Exception:
                            continue
                except Exception:
                    continue

        return {"status": "success", "data": {
            "subdomains_tested": len(common_subdomains),
            "vulnerabilities_found": len([f for f in findings if f.get("severity") in ("Critical", "High")]),
            "findings": findings,
            "description": "Subdomain takeover allows attackers to serve malicious content on trusted domains"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter
#     mcp.run(transport='stdio')

