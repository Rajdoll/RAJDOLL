#!/usr/bin/env python3
"""
Complete Working Information Gathering MCP Server
Self-contained with all dependencies included
"""

# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import httpx
import re
import asyncio
import os
import json
import random
import logging
from typing import List, Dict, Any, Optional
import socket
import ssl
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import subprocess
import shlex
from datetime import datetime
import hashlib

# Initialize FastMCP server
# mcp = FastMCP("information-gathering")  # REMOVED: Using JSON-RPC adapter

# Configuration constants
BASE_OUTPUT_DIR = "/mnt/d/MCP/RAJDOLL/information-gathering"
SUBRESULT_DIR = os.path.join(BASE_OUTPUT_DIR, "subresult")
LOGS_DIR = os.path.join(BASE_OUTPUT_DIR, "logs")

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

# Technology patterns for detection
TECH_PATTERNS = {
    "WordPress": r'wp-content|wp-includes|wordpress|wp-admin',
    "React": r'react|__REACT_DEVTOOLS_GLOBAL_HOOK__|_react',
    "Angular": r'ng-|angular|AngularJS|@angular',
    "Vue.js": r'vue\.js|__vue__|v-if|v-for',
    "jQuery": r'jquery|jQuery|\$\(',
    "Bootstrap": r'bootstrap|bs-|btn-|col-',
    "PHP": r'\.php|PHP|<?php',
    "ASP.NET": r'aspnet|__doPostBack|WebResource\.axd|.aspx',
    "Laravel": r'laravel|blade|artisan',
    "Django": r'django|csrf_token|{% ',
    "Apache": r'apache|httpd',
    "Nginx": r'nginx',
    "IIS": r'Microsoft-IIS|X-Powered-By.*ASP\.NET'
}

# Sensitive keywords
SENSITIVE_KEYWORDS = [
    "password", "secret", "key", "token", "internal", 
    "confidential", "api_key", "admin", "debug", "test",
    "database", "mysql", "postgresql", "mongodb"
]

# Meta files to check
META_FILES = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", 
    "/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.git/config", "/.env", "/composer.json", "/package.json"
]

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mcp-info-gathering")

# Utility functions
def sanitize_domain(domain: str) -> str:
    """Sanitize domain input to prevent command injection"""
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain.lower()

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    try:
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    except:
        return False

def ensure_directories():
    """Ensure all required directories exist"""
    for directory in [BASE_OUTPUT_DIR, SUBRESULT_DIR, LOGS_DIR]:
        os.makedirs(directory, exist_ok=True)

def get_output_path(domain: str, tool: str, extension: str = "txt") -> str:
    """Generate output file paths"""
    ensure_directories()
    filename = f"{tool}_{domain}.{extension}"
    return os.path.join(SUBRESULT_DIR, filename)

def generate_report_id(domain: str) -> str:
    """Generate unique report ID"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hash_input = f"{domain}_{timestamp}".encode()
    hash_short = hashlib.md5(hash_input).hexdigest()[:8]
    return f"INFO_{domain}_{timestamp}_{hash_short}"

def get_random_user_agent():
    """Get random user agent"""
    return random.choice(USER_AGENTS)

# Enhanced command execution
async def execute_wsl_command(command: str, timeout: int = 60, capture_stderr: bool = True) -> Dict[str, Any]:
    """Enhanced WSL command execution with comprehensive error handling"""
    try:
        escaped_command = shlex.quote(command)
        wsl_command = f"wsl /bin/bash -c {escaped_command}"
        
        proc = await asyncio.create_subprocess_shell(
            wsl_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.terminate()
            await proc.wait()
            return {
                "success": False,
                "stdout": "",
                "stderr": "",
                "error": f"Command timed out after {timeout}s",
                "return_code": -1
            }
        
        stdout_str = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
        stderr_str = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
        
        return {
            "success": proc.returncode == 0,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "error": stderr_str if proc.returncode != 0 else None,
            "return_code": proc.returncode
        }
        
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "error": f"Command execution error: {str(e)}",
            "return_code": -1
        }

# Prompt
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domainname: str) -> str:
    return f"""
You are a highly skilled penetration tester specializing in web reconnaissance, using the OWASP WSTG as your guide. Your mission is to enumerate the domain {domainname} and gather intelligence about its infrastructure.

Your primary objectives are:
- Identify and enumerate IP addresses and subdomains using tools like subfinder.
- **Check for potential subdomain takeover vulnerabilities on discovered subdomains.**
- Identify the technologies in use (server, framework, CMS, etc.).
- Discover potential information leaks from meta-files, comments, and search engines.
- Map out application entry points and overall architecture.

Begin by formulating an initial plan, then execute your reconnaissance.
"""

# Enhanced tools
# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def comprehensive_domain_recon(domain: str) -> Dict[str, Any]:
    """Performs comprehensive domain reconnaissance combining multiple techniques"""
    try:
        clean_domain = sanitize_domain(domain)
        logger.info(f"Starting comprehensive reconnaissance for {clean_domain}")
        
        results = {
            "domain": clean_domain,
            "scan_id": generate_report_id(clean_domain),
            "timestamp": datetime.now().isoformat(),
            "findings": {},
            "summary": {}
        }
        
        # Phase 1: DNS Analysis
        dns_result = await run_dig_lookup(clean_domain)
        if dns_result.get("status") == "success":
            results["findings"]["dns"] = dns_result["data"]
        
        # Phase 2: WHOIS Information  
        whois_result = await run_whois_lookup(clean_domain)
        if whois_result.get("status") == "success":
            results["findings"]["whois"] = whois_result["data"]
        
        # Phase 3: Meta Files Discovery
        meta_result = await check_meta_files(clean_domain)
        if meta_result.get("status") == "success":
            results["findings"]["meta_files"] = meta_result["data"]
        
        # Phase 4: Content Analysis
        content_result = await analyze_content(clean_domain)
        if content_result.get("status") == "success":
            results["findings"]["content"] = content_result["data"]
        
        # Phase 5: Email Security
        email_result = await check_email_security(clean_domain)
        if email_result.get("status") == "success":
            results["findings"]["email_security"] = email_result["data"]
        
        # Generate summary
        results["summary"] = {
            "total_ips": len(results["findings"].get("dns", {}).get("a_records", [])),
            "meta_files_found": len(results["findings"].get("meta_files", {}).get("found_files", [])),
            "technologies_detected": results["findings"].get("content", {}).get("technologies_detected", []),
            "email_security_configured": any([
                results["findings"].get("email_security", {}).get("spf_status") == "configured",
                results["findings"].get("email_security", {}).get("dmarc_status") == "configured", 
                results["findings"].get("email_security", {}).get("dkim_status") == "configured"
            ])
        }
        
        return {"status": "success", "data": results}
        
    except Exception as e:
        return {"status": "error", "message": f"Comprehensive reconnaissance failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def enumerate_active_subdomains(domain: str) -> Dict[str, Any]:
    """Enhanced subdomain enumeration with multiple data sources and verification"""
    try:
        clean_domain = sanitize_domain(domain)
        ensure_directories()
        
        subfinder_out = get_output_path(clean_domain, "subfinder", "txt")
        live_out = get_output_path(clean_domain, "live", "txt")
        
        # Phase 1: Subdomain Discovery
        subfinder_cmd = f"subfinder -d {clean_domain} -o {subfinder_out} -silent -timeout 10"
        result = await execute_wsl_command(subfinder_cmd, timeout=180)
        
        if not result["success"]:
            return {"status": "error", "message": f"Subfinder failed: {result.get('error', 'Unknown error')}"}
        
        # Count discovered subdomains
        count_result = await execute_wsl_command(f"test -f {subfinder_out} && wc -l < {subfinder_out} || echo 0")
        
        try:
            raw_count = int(count_result["stdout"].strip()) if count_result["success"] else 0
        except ValueError:
            raw_count = 0
        
        if raw_count == 0:
            return {
                "status": "success",
                "data": {
                    "domain": clean_domain,
                    "discovered_count": 0,
                    "live_count": 0,
                    "message": "No subdomains discovered"
                }
            }
        
        # Phase 2: Live Host Verification
        alive_codes = "200,301,302,403,401,500,502,503"
        httpx_cmd = f"cat {subfinder_out} | httpx -silent -status-code -mc {alive_codes} -o {live_out} -threads 30 -timeout 15"
        
        httpx_result = await execute_wsl_command(httpx_cmd, timeout=300)
        
        # Count live hosts
        live_count_result = await execute_wsl_command(f"test -f {live_out} && wc -l < {live_out} || echo 0")
        live_count = 0
        
        if live_count_result["success"]:
            try:
                live_count = int(live_count_result["stdout"].strip())
            except ValueError:
                live_count = 0
        
        # Get sample of live hosts
        live_sample = []
        if live_count > 0:
            sample_result = await execute_wsl_command(f"head -n 20 {live_out}")
            if sample_result["success"]:
                live_sample = sample_result["stdout"].splitlines()
        
        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "discovered_count": raw_count,
                "live_count": live_count,
                "subfinder_output_file": subfinder_out,
                "live_output_file": live_out,
                "live_sample": live_sample[:15],
                "httpx_status": "success" if httpx_result["success"] else f"partial: {httpx_result.get('error', 'unknown')}"
            }
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Subdomain enumeration failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def enumerate_applications(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-04: Enumerate applications and services on the web server

    Combines subdomain enumeration, port scanning, HTTP probing, and light path discovery.
    """
    try:
        clean_domain = sanitize_domain(domain)
        ensure_directories()

        # Use existing subdomain enumeration output if available; else run it
        subfinder_out = get_output_path(clean_domain, "subfinder", "txt")
        file_check = await execute_wsl_command(f"test -f {subfinder_out} && echo exists || echo missing")
        if not (file_check.get("success") and file_check.get("stdout", "").strip() == "exists"):
            await enumerate_active_subdomains(clean_domain)

        # Read subdomains list
        read_subs = await execute_wsl_command(f"test -f {subfinder_out} && cat {subfinder_out} || echo {clean_domain}")
        hosts = list(set([h.strip() for h in read_subs.get("stdout", "").splitlines() if h.strip()]))
        if clean_domain not in hosts:
            hosts.insert(0, clean_domain)

        # Port scanning on common web ports
        ports = [80, 443, 8080, 8443, 3000, 5000, 8000]
        target_list_path = f"/tmp/targets_{clean_domain}.txt"
        await execute_wsl_command(f"printf '%s\n' {' '.join(hosts)} > {target_list_path}")
        nmap_cmd = f"nmap -Pn -p {','.join(map(str, ports))} -oG - -iL {target_list_path}"
        nmap_res = await execute_wsl_command(nmap_cmd, timeout=300)

        host_ports: Dict[str, List[int]] = {h: [] for h in hosts}
        if nmap_res.get("success"):
            for line in nmap_res.get("stdout", "").splitlines():
                m = re.search(r"Host:\s+(\S+).*Ports:\s+(.+)$", line)
                if m:
                    host = m.group(1)
                    ports_str = m.group(2)
                    for entry in ports_str.split(','):
                        if "/open/" in entry:
                            p = entry.split("/")[0]
                            try:
                                p = int(p)
                                if host in host_ports:
                                    host_ports[host].append(p)
                                else:
                                    host_ports[host] = [p]
                            except Exception:
                                continue

        # Probe HTTP services and discover simple apps
        applications: List[Dict[str, Any]] = []
        headers = {"User-Agent": get_random_user_agent()}
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10, headers=headers) as client:
            for host in hosts:
                host_entry = {
                    "hostname": host,
                    "ip": None,
                    "ports": sorted(set(host_ports.get(host, []))),
                    "services": [],
                    "applications": [],
                }
                try:
                    host_entry["ip"] = socket.gethostbyname(host)
                except Exception:
                    host_entry["ip"] = None

                probe_ports = host_entry["ports"] or [80, 443]
                for p in probe_ports:
                    for scheme in (["https"] if p in [443, 8443] else ["http", "https"]):
                        base = f"{scheme}://{host}:{p if (scheme=='http' and p!=80) or (scheme=='https' and p!=443) else ''}"
                        base = base.rstrip(":")
                        try:
                            r = await client.get(base)
                            title = None
                            m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                            if m:
                                title = m.group(1).strip()[:120]
                            tech = []
                            for t, pat in TECH_PATTERNS.items():
                                if re.search(pat, r.text, re.IGNORECASE):
                                    tech.append(t)

                            host_entry["services"].append("https" if scheme == "https" else "http")
                            host_entry["applications"].append({
                                "path": "/",
                                "title": title or "",
                                "technology": ", ".join(sorted(set(tech))) if tech else None,
                            })

                            # Simple path discovery
                            common_paths = ["/blog", "/shop", "/admin", "/api", "/graphql", "/login"]
                            for path in common_paths:
                                try:
                                    u = urljoin(base + '/', path.lstrip('/'))
                                    resp = await client.get(u)
                                    if resp.status_code in [200, 301, 302, 401, 403]:
                                        t = None
                                        m2 = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                                        if m2:
                                            t = m2.group(1).strip()[:120]
                                        tech2 = []
                                        for tname, pat in TECH_PATTERNS.items():
                                            if re.search(pat, resp.text, re.IGNORECASE):
                                                tech2.append(tname)
                                        host_entry["applications"].append({
                                            "path": path,
                                            "title": t or "",
                                            "technology": ", ".join(sorted(set(tech2))) if tech2 else None,
                                        })
                                except Exception:
                                    continue
                        except Exception:
                            continue

                applications.append(host_entry)

        # Subdomain summary
        subdomains = [h.split(".")[0] for h in hosts if h.endswith(clean_domain) and h != clean_domain]
        total_services = sum(len(h.get("services", [])) for h in applications)

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-04",
                "applications": applications,
                "subdomains": sorted(list(set(subdomains)))[:100],
                "total_attack_surface": f"{len(subdomains)+1} subdomains, {total_services} services",
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Enumerate applications failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_subdomain_takeover(domain: str) -> Dict[str, Any]:
    """Enhanced subdomain takeover testing with detailed analysis"""
    try:
        clean_domain = sanitize_domain(domain)
        subfinder_file = get_output_path(clean_domain, "subfinder", "txt")
        
        # Verify input file exists
        file_check = await execute_wsl_command(f"test -f {subfinder_file} && echo 'exists' || echo 'missing'")
        if not file_check["success"] or file_check["stdout"].strip() != "exists":
            return {
                "status": "error",
                "message": f"Subdomain list not found: {subfinder_file}. Run enumerate_active_subdomains first."
            }
        
        takeover_output = get_output_path(clean_domain, "takeover", "txt")
        
        # Run Subjack
        cmd = f"subjack -w {subfinder_file} -t 30 -timeout 20 -ssl -o {takeover_output} -v"
        result = await execute_wsl_command(cmd, timeout=600)
        
        vulnerable = []
        potential = []
        
        # Parse output file
        try:
            read_result = await execute_wsl_command(f"test -f {takeover_output} && cat {takeover_output} || echo ''")
            if read_result["success"]:
                for line in read_result["stdout"].splitlines():
                    line = line.strip()
                    if "[Vulnerable]" in line:
                        vulnerable.append(line)
                    elif line and "[Not Vulnerable]" not in line:
                        if any(indicator in line.lower() for indicator in ["cname", "nxdomain"]):
                            potential.append(line)
        except Exception as e:
            logger.error(f"Error reading takeover results: {str(e)}")
        
        risk_level = "high" if vulnerable else "low" if potential else "none"
        
        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "vulnerable_subdomains": vulnerable,
                "potential_issues": potential,
                "risk_level": risk_level,
                "output_file": takeover_output,
                "recommendations": [
                    "Remove DNS records for unused subdomains",
                    "Implement subdomain monitoring"
                ] if vulnerable else []
            }
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Subdomain takeover test failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def advanced_technology_fingerprinting(domain: str) -> Dict[str, Any]:
    """Advanced technology fingerprinting combining multiple techniques"""
    try:
        clean_domain = sanitize_domain(domain)
        
        technologies = {
            "web_server": [],
            "cms": [],
            "frameworks": [],
            "languages": [],
            "cdn": []
        }
        
        headers_info = {}
        content = ""
        
        # HTTP Headers Analysis
        try:
            headers = {"User-Agent": get_random_user_agent()}
            
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
                for scheme in ["https", "http"]:
                    try:
                        url = f"{scheme}://{clean_domain}"
                        response = await client.get(url)
                        
                        if response.status_code == 200:
                            headers_info = dict(response.headers)
                            content = response.text
                            break
                    except Exception:
                        continue
        
        except Exception as e:
            logger.warning(f"HTTP analysis failed: {str(e)}")
        
        # Analyze headers
        if headers_info:
            server_header = headers_info.get('server', '').lower()
            powered_by = headers_info.get('x-powered-by', '').lower()
            
            if 'apache' in server_header:
                technologies["web_server"].append("Apache")
            if 'nginx' in server_header:
                technologies["web_server"].append("Nginx")
            if 'iis' in server_header:
                technologies["web_server"].append("IIS")
            if 'cloudflare' in server_header:
                technologies["cdn"].append("Cloudflare")
            if 'akamai' in server_header:
                technologies["cdn"].append("Akamai")
            if 'php' in powered_by:
                technologies["languages"].append("PHP")
        
        # Content analysis
        if content:
            for tech, pattern in TECH_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    if tech in ["WordPress"]:
                        technologies["cms"].append(tech)
                    elif tech in ["React", "Angular", "Vue.js", "jQuery", "Bootstrap"]:
                        technologies["frameworks"].append(tech)
                    elif tech in ["PHP"]:
                        technologies["languages"].append(tech)
                    elif tech in ["Apache", "Nginx", "IIS"]:
                        technologies["web_server"].append(tech)
        
        # Remove duplicates
        for category in technologies:
            technologies[category] = list(set(technologies[category]))
        
        total_indicators = sum(len(techs) for techs in technologies.values())
        confidence_score = min(100, (total_indicators * 15))
        
        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "technologies": technologies,
                "headers": headers_info,
                "confidence_score": confidence_score,
                "total_technologies": total_indicators
            }
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Technology fingerprinting failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def fingerprint_web_server(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-02: Fingerprint Web Server

    Techniques:
    - HTTP headers analysis
    - Banner grabbing (raw socket and error page)
    - HTTP methods probing and header quirks
    - Optional: whatweb and nmap http-server-header script via WSL
    """
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        detection_methods: List[str] = []
        server_info: Dict[str, Any] = {
            "server": None,
            "os": None,
            "technology_stack": {
                "web_server": None,
                "programming_language": None,
                "frameworks": [],
                "cms": None,
                "database": None,
            },
            "headers": {},
            "detection_methods": detection_methods,
        }

        # 1) HTTP headers analysis
        header_candidates = ["https", "http"]
        response_headers: Dict[str, str] = {}
        status_code = None
        final_url = None
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
                for scheme in header_candidates:
                    try:
                        url = f"{scheme}://{clean_domain}"
                        r = await client.get(url)
                        status_code = r.status_code
                        response_headers = {k.lower(): v for k, v in r.headers.items()}
                        final_url = str(r.url)
                        detection_methods.append("headers")
                        break
                    except Exception:
                        continue
        except Exception:
            pass

        if response_headers:
            server_hdr = response_headers.get("server")
            x_powered = response_headers.get("x-powered-by")
            x_aspnet = response_headers.get("x-aspnet-version")
            etag = response_headers.get("etag")
            server_info["headers"] = {
                "server": server_hdr,
                "x-powered-by": x_powered,
                "x-aspnet-version": x_aspnet,
                "etag": etag,
            }
            # Infer tech
            if server_hdr:
                server_info["server"] = server_hdr
                if "nginx" in server_hdr.lower():
                    server_info["technology_stack"]["web_server"] = server_hdr
                if "apache" in server_hdr.lower():
                    server_info["technology_stack"]["web_server"] = server_hdr
                if "microsoft-iis" in server_hdr.lower() or "iis" in server_hdr.lower():
                    server_info["technology_stack"]["web_server"] = server_hdr
            if x_powered:
                if "php" in x_powered.lower():
                    server_info["technology_stack"]["programming_language"] = x_powered
                if ".net" in x_powered.lower() or "asp" in x_powered.lower():
                    server_info["technology_stack"]["programming_language"] = x_powered

        # 2) Banner grabbing via raw socket (HTTP/1.0)
        try:
            ip = socket.gethostbyname(clean_domain)
            with socket.create_connection((ip, 80), timeout=5) as s:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + clean_domain.encode() + b"\r\n\r\n")
                data = s.recv(4096).decode(errors="ignore")
                m = re.search(r"^Server:\s*(.+)$", data, re.MULTILINE | re.IGNORECASE)
                if m:
                    server_info["server"] = server_info["server"] or m.group(1).strip()
                    detection_methods.append("banner_grab_raw")
        except Exception:
            pass

        # 3) Error page analysis (request a likely 404)
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15, headers=headers) as client:
                url_404 = f"https://{clean_domain}/this-should-not-exist-12345"
                r = await client.get(url_404)
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                if "server" in hdrs and not server_info["server"]:
                    server_info["server"] = hdrs["server"]
                detection_methods.append("error_page")
        except Exception:
            pass

        # 4) Methods probing and quirks
        methods_to_try = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "HEAD", "PATCH"]
        method_support: Dict[str, int] = {}
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10, headers=headers) as client:
                url = f"https://{clean_domain}/"
                for mth in methods_to_try:
                    try:
                        r = await client.request(mth, url)
                        method_support[mth] = r.status_code
                    except Exception:
                        method_support[mth] = 0
                detection_methods.append("methods_probe")
        except Exception:
            pass

        # 5) Optional: whatweb analysis
        whatweb_data = None
        try:
            tmp = f"/tmp/whatweb_fprint_{clean_domain}.json"
            cmd = f"whatweb --log-json={tmp} http://{clean_domain} https://{clean_domain} -a 3"
            ww = await execute_wsl_command(cmd, timeout=120)
            if ww.get("success"):
                read = await execute_wsl_command(f"test -f {tmp} && cat {tmp} || echo ''")
                if read.get("success") and read.get("stdout"):
                    try:
                        whatweb_data = [json.loads(line) for line in read["stdout"].splitlines() if line.strip()]
                        detection_methods.append("whatweb")
                    except Exception:
                        pass
        except Exception:
            pass

        # 6) Optional: nmap http-server-header script
        nmap_server_header = None
        try:
            nmap_cmd = f"nmap -p80,443 --script http-server-header -oX - {clean_domain}"
            nm = await execute_wsl_command(nmap_cmd, timeout=180)
            if nm.get("success") and nm.get("stdout"):
                # Simple parse for server header text
                m = re.search(r"Server:\s*([^<\n]+)", nm["stdout"], re.IGNORECASE)
                if m:
                    nmap_server_header = m.group(1).strip()
                    if not server_info["server"]:
                        server_info["server"] = nmap_server_header
                    detection_methods.append("nmap:http-server-header")
        except Exception:
            pass

        # Basic CVE hints (static heuristic)
        vulnerabilities: List[Dict[str, Any]] = []
        srv = (server_info.get("server") or "").lower()
        if "nginx/1.18" in srv:
            vulnerabilities.append({
                "cve": "CVE-2021-23017",
                "description": "Nginx resolver off-by-one heap write",
                "severity": "high",
            })
        if "apache/2.4.49" in srv or "apache/2.4.50" in srv:
            vulnerabilities.append({
                "cve": "CVE-2021-41773",
                "description": "Apache path traversal/RCE in 2.4.49/50",
                "severity": "critical",
            })

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-02",
                "server_info": server_info,
                "method_support": method_support,
                "whatweb": whatweb_data,
                "nmap_server_header": nmap_server_header,
                "detection_methods": detection_methods,
                "vulnerabilities": vulnerabilities,
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Web server fingerprint failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def search_engine_reconnaissance(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-01: Search engine discovery for information leakage.

    Capabilities implemented:
    - Basic dorking via Bing for exposed docs, admin panels, dir listings, backups
    - crt.sh Certificate Transparency lookup for subdomains
    - Optional GitHub code search for leaks (uses GITHUB_TOKEN if available)
    - theHarvester fallback for emails/IPs/subdomains (google/bing)
    - Paste site mentions via Bing

    Returns the expected findings structure and severity.
    """
    try:
        clean_domain = sanitize_domain(domain)

        async def _bing_search(query: str, max_results: int = 20) -> List[str]:
            # Lightweight HTML scrape with simple URL extraction; resilient to minor markup changes
            url = "https://www.bing.com/search"
            params = {"q": query, "count": min(max_results, 50)}
            headers = {"User-Agent": get_random_user_agent()}
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=20, headers=headers) as client:
                    r = await client.get(url, params=params)
                    html = r.text
                    # Extract URLs from hrefs; filter duplicates and bing own URLs
                    urls = re.findall(r'href=\"(https?://[^\"]+)\"', html)
                    urls = [u for u in urls if "bing.com" not in u and "/search?" not in u]
                    # Deduplicate while preserving order
                    seen = set()
                    ordered = []
                    for u in urls:
                        if u not in seen:
                            ordered.append(u)
                            seen.add(u)
                    return ordered[:max_results]
            except Exception:
                return []

        async def _crtsh_subdomains(dom: str) -> List[str]:
            q = f"%.{dom}"
            url = "https://crt.sh/"
            params = {"q": q, "output": "json"}
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    r = await client.get(url, params=params)
                    if r.status_code != 200:
                        return []
                    data = r.json()
                    names = []
                    for item in data:
                        name = item.get("name_value", "")
                        for part in name.split("\n"):
                            part = part.strip().lower()
                            if part.endswith("." + dom) or part == dom or part.endswith(dom):
                                names.append(part)
                    # Deduplicate
                    return sorted(set(names))[:200]
            except Exception:
                return []

        async def _github_code_search(dom: str) -> List[Dict[str, Any]]:
            token = os.getenv("GITHUB_TOKEN")
            # Search for domain plus common secret terms
            q = f'"{dom}" (password OR apikey OR api_key OR token)'
            url = "https://api.github.com/search/code"
            params = {"q": q, "per_page": 10}
            headers = {"Accept": "application/vnd.github+json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                async with httpx.AsyncClient(timeout=30, headers=headers) as client:
                    r = await client.get(url, params=params)
                    if r.status_code != 200:
                        return []
                    data = r.json()
                    items = []
                    for it in data.get("items", [])[:10]:
                        repo = it.get("repository", {})
                        items.append({
                            "repo": repo.get("full_name"),
                            "file": it.get("path"),
                            "leak_type": "potential_secret",
                            "url": it.get("html_url"),
                        })
                    return items
            except Exception:
                return []

        # 1) Dorking via Bing
        dorks = {
            "exposed_documents": [f"site:{clean_domain} filetype:pdf", f"site:{clean_domain} filetype:docx"],
            "admin_panels": [f"site:{clean_domain} inurl:admin", f"site:{clean_domain} intitle:admin"],
            "directory_listings": [f"site:{clean_domain} intitle:\"index of\""],
            "backup_files": [f"site:{clean_domain} (inurl:config OR inurl:backup)", f"site:{clean_domain} (ext:log OR ext:bak OR ext:old)"],
        }

        # 2) crt.sh subdomains
        crt_subs = await _crtsh_subdomains(clean_domain)

        # 3) Optional GitHub leaks
        gh_leaks = await _github_code_search(clean_domain)

        # 4) theHarvester for emails/IPs/subdomains (as a supplemental source)
        harvester_sources = ["google", "bing"]
        command = f"theHarvester -d {clean_domain} -b {','.join(harvester_sources)} -l 50"
        harv_result = await execute_wsl_command(command, timeout=240)
        emails: List[str] = []
        ips: List[str] = []
        harv_subs: List[str] = []
        if harv_result.get("success"):
            out = harv_result.get("stdout", "")
            try:
                emails = list({e for e in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', out) if e.lower().endswith("@" + clean_domain)})
            except Exception:
                emails = []
            try:
                ips = [h for h in set(re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', out)) if is_valid_ip(h)]
            except Exception:
                ips = []
            try:
                harv_subs = list(set(re.findall(r'([a-zA-Z0-9-]+\.' + re.escape(clean_domain) + r')', out)))
            except Exception:
                harv_subs = []

        # 5) Paste sites via Bing
        paste_queries = [
            f"site:pastebin.com {clean_domain}",
            f"site:ghostbin.com {clean_domain}",
            f"site:paste.ubuntu.com {clean_domain}",
        ]

        # Execute Bing dork searches in parallel (best-effort)
        exposed_docs_urls: List[str] = []
        admin_panel_urls: List[str] = []
        dir_listing_urls: List[str] = []
        backup_file_urls: List[str] = []
        paste_mentions: List[str] = []

        # Run dork searches
        for q in dorks["exposed_documents"]:
            exposed_docs_urls.extend(await _bing_search(q, max_results=10))
        for q in dorks["admin_panels"]:
            admin_panel_urls.extend(await _bing_search(q, max_results=10))
        for q in dorks["directory_listings"]:
            dir_listing_urls.extend(await _bing_search(q, max_results=10))
        for q in dorks["backup_files"]:
            backup_file_urls.extend(await _bing_search(q, max_results=10))
        for q in paste_queries:
            paste_mentions.extend(await _bing_search(q, max_results=10))

        # Normalize and deduplicate
        def _normalize(urls: List[str]) -> List[str]:
            unique = []
            seen = set()
            for u in urls:
                # Keep only target domain mentions where appropriate
                if clean_domain in u and u not in seen:
                    unique.append(u)
                    seen.add(u)
            return unique[:50]

        findings = {
            "exposed_documents": _normalize(exposed_docs_urls),
            "admin_panels": _normalize(admin_panel_urls),
            "directory_listings": _normalize(dir_listing_urls),
            "backup_files": _normalize(backup_file_urls),
            "github_leaks": gh_leaks,
            "subdomains_found": sorted(set(harv_subs + crt_subs))[:200],
            "pastebin_mentions": _normalize(paste_mentions),
            # Extra context from theHarvester
            "emails_found": emails[:30],
            "ips_found": ips[:30],
        }

        # Severity heuristic: any backups/admin/docs found → high; else medium if subdomains/emails; else low
        severity = "low"
        if findings["exposed_documents"] or findings["backup_files"] or findings["admin_panels"]:
            severity = "high"
        elif findings["subdomains_found"] or findings["emails_found"]:
            severity = "medium"

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-01",
                "domain": clean_domain,
                "findings": findings,
                "severity": severity,
                "sources_used": ["bing", "crt.sh", "github_api(optional)", "theHarvester"],
            },
        }

    except Exception as e:
        return {"status": "error", "message": f"Search engine reconnaissance failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def security_headers_analysis(domain: str) -> Dict[str, Any]:
    """Comprehensive security headers analysis"""
    try:
        clean_domain = sanitize_domain(domain)
        
        security_headers = {
            "x-frame-options": {"present": False, "value": None, "secure": False},
            "x-content-type-options": {"present": False, "value": None, "secure": False},
            "x-xss-protection": {"present": False, "value": None, "secure": False},
            "content-security-policy": {"present": False, "value": None, "secure": False},
            "strict-transport-security": {"present": False, "value": None, "secure": False}
        }
        
        score = 0
        max_score = len(security_headers) * 10
        
        try:
            headers = {"User-Agent": get_random_user_agent()}
            
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
                for scheme in ["https", "http"]:
                    try:
                        url = f"{scheme}://{clean_domain}"
                        response = await client.get(url)
                        
                        if response.status_code == 200:
                            response_headers = dict(response.headers)
                            
                            # Analyze each security header
                            for header_name in security_headers.keys():
                                header_value = response_headers.get(header_name.lower())
                                if header_value:
                                    security_headers[header_name]["present"] = True
                                    security_headers[header_name]["value"] = header_value
                                    
                                    # Determine if secure
                                    if header_name == "x-frame-options":
                                        security_headers[header_name]["secure"] = header_value.upper() in ["DENY", "SAMEORIGIN"]
                                    elif header_name == "x-content-type-options":
                                        security_headers[header_name]["secure"] = "nosniff" in header_value.lower()
                                    elif header_name == "strict-transport-security":
                                        security_headers[header_name]["secure"] = "max-age" in header_value.lower()
                                    else:
                                        security_headers[header_name]["secure"] = True
                                    
                                    if security_headers[header_name]["secure"]:
                                        score += 10
                                    else:
                                        score += 5
                            break
                    except Exception:
                        continue
        
        except Exception as e:
            return {"status": "error", "message": f"Security headers analysis failed: {str(e)}"}
        
        # Generate recommendations
        recommendations = []
        for header_name, info in security_headers.items():
            if not info["present"]:
                recommendations.append(f"Implement {header_name} header")
            elif not info["secure"]:
                recommendations.append(f"Improve {header_name} header configuration")
        
        security_score = (score / max_score) * 100
        risk_level = "low" if security_score > 70 else "medium" if security_score > 40 else "high"
        
        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "headers": security_headers,
                "security_score": round(security_score, 1),
                "risk_level": risk_level,
                "recommendations": recommendations
            }
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Security headers analysis failed: {str(e)}"}

# Keep all the existing basic tools but with enhanced error handling
# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def run_comprehensive_scan(domain: str) -> Dict[str, Any]:
    """Enhanced WhatWeb scan with fallback mechanisms"""
    try:
        clean_domain = sanitize_domain(domain)
        
        # Try JSON output first
        temp_file = f"/tmp/whatweb_{clean_domain}.json"
        command = f"whatweb --log-json={temp_file} http://{clean_domain} https://{clean_domain} -a 3"
        result = await execute_wsl_command(command, timeout=180)
        
        # Try to read JSON output
        read_result = await execute_wsl_command(f"test -f {temp_file} && cat {temp_file} || echo ''")
        
        if read_result["success"] and read_result["stdout"]:
            try:
                json_objects = []
                for line in read_result["stdout"].strip().split('\n'):
                    if line.strip():
                        json_objects.append(json.loads(line))
                
                await execute_wsl_command(f"rm -f {temp_file}")
                return {"status": "success", "data": {"whatweb_results": json_objects}}
            except json.JSONDecodeError:
                pass
        
        # Fallback to simple scan
        simple_command = f"whatweb {clean_domain} -a 1"
        simple_result = await execute_wsl_command(simple_command, timeout=60)
        
        if simple_result["success"]:
            return {
                "status": "partial_success",
                "data": {"raw_output": simple_result["stdout"][:2000]},
                "message": "Used simplified whatweb scan"
            }
        
        return {"status": "error", "message": "WhatWeb scan failed"}
        
    except Exception as e:
        return {"status": "error", "message": f"WhatWeb scan failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def check_meta_files(domain: str) -> Dict[str, Any]:
    """Checks common meta files and returns findings as JSON."""
    try:
        clean_domain = sanitize_domain(domain)
        found_files = []
        
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as client:
            for file_path in META_FILES:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{clean_domain}{file_path}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200 and resp.text.strip():
                            content_preview = resp.text[:500] + ("..." if len(resp.text) > 500 else "")
                            found_files.append({
                                "url": url, 
                                "status_code": resp.status_code, 
                                "content_preview": content_preview,
                                "content_length": len(resp.text)
                            })
                            break
                    except:
                        continue
                    await asyncio.sleep(0.1)
        
        return {
            "status": "success", 
            "data": {"found_files": found_files} if found_files else {"message": "No common meta files found."}
        }
    except Exception as e:
        return {"status": "error", "message": f"Meta files check failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def check_metafiles(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-03: Review Webserver Metafiles for Information Leakage

    Parses robots.txt and sitemap.xml along with common meta files providing structured findings.
    """
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}

        robots_info = {
            "found": False,
            "disallowed_paths": [],
            "allowed_paths": [],
            "sitemaps": [],
            "interesting_findings": [],
        }
        sitemap_info: Dict[str, Any] = {"found": False, "url_count": 0, "interesting_urls": []}
        security_txt: Dict[str, Any] = {"found": False}
        other_files = {"humans_txt": False, "crossdomain_xml": False}

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
            # robots.txt
            try:
                r = await client.get(f"https://{clean_domain}/robots.txt")
                if r.status_code == 200 and r.text:
                    robots_info["found"] = True
                    for line in r.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        m = re.match(r'(?i)disallow:\s*(.*)$', line)
                        if m:
                            robots_info["disallowed_paths"].append(m.group(1).strip())
                        m = re.match(r'(?i)allow:\s*(.*)$', line)
                        if m:
                            robots_info["allowed_paths"].append(m.group(1).strip())
                        m = re.match(r'(?i)sitemap:\s*(.*)$', line)
                        if m:
                            robots_info["sitemaps"].append(m.group(1).strip())
                    # interesting
                    for p in robots_info["disallowed_paths"]:
                        if any(x in p.lower() for x in ["admin", "backup", "api", "test", "dev"]):
                            robots_info["interesting_findings"].append(f"Disallowed {p} may be sensitive")
            except Exception:
                pass

            # sitemap.xml (robots reference or default)
            sitemap_urls = list(robots_info["sitemaps"]) or [f"https://{clean_domain}/sitemap.xml"]
            for smurl in sitemap_urls:
                try:
                    r = await client.get(smurl)
                    if r.status_code == 200 and r.text and "<urlset" in r.text:
                        sitemap_info["found"] = True
                        # Simple XML parse for <loc>
                        urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                        sitemap_info["url_count"] = len(urls)
                        interesting = []
                        for u in urls[:1000]:
                            if any(x in u.lower() for x in ["/admin", "/api/", "/dev", "/test", "?", "/wp-"]):
                                interesting.append(u)
                        sitemap_info["interesting_urls"] = interesting[:50]
                        break
                except Exception:
                    continue

            # security.txt
            try:
                for path in ["/.well-known/security.txt", "/security.txt"]:
                    r = await client.get(f"https://{clean_domain}{path}")
                    if r.status_code == 200 and r.text:
                        security_txt["found"] = True
                        m_contact = re.search(r"(?i)contact:\s*(.+)", r.text)
                        if m_contact:
                            security_txt["contact"] = m_contact.group(1).strip()
                        m_policy = re.search(r"(?i)policy:\s*(.+)", r.text)
                        if m_policy:
                            security_txt["policy"] = m_policy.group(1).strip()
                        break
            except Exception:
                pass

            # Other files
            try:
                r = await client.get(f"https://{clean_domain}/humans.txt")
                other_files["humans_txt"] = r.status_code == 200 and bool(r.text)
            except Exception:
                pass
            try:
                r = await client.get(f"https://{clean_domain}/crossdomain.xml")
                other_files["crossdomain_xml"] = r.status_code == 200 and bool(r.text)
            except Exception:
                pass

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-03",
                "metafiles": {
                    "robots_txt": robots_info,
                    "sitemap_xml": sitemap_info,
                    "security_txt": security_txt,
                    "other_files": other_files,
                },
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Metafiles check failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def analyze_content(domain: str) -> Dict[str, Any]:
    """Analyzes homepage content for emails, comments, and sensitive keywords."""
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
            content = ""
            final_url = ""
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{clean_domain}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        content = resp.text
                        final_url = url
                        break
                except:
                    continue
            
            if not content:
                return {"status": "error", "message": "Unable to fetch homepage content"}
        
        # Email extraction
        emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)))
        
        # HTML comments extraction
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        
        # Sensitive keywords search
        found_keywords = []
        for kw in SENSITIVE_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', content, re.IGNORECASE):
                found_keywords.append(kw)
        
        # Technology detection
        technologies = []
        for tech, pattern in TECH_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.append(tech)
        
        return {
            "status": "success",
            "data": {
                "url_accessed": final_url,
                "emails_found": emails[:10],
                "comment_count": len(comments),
                "sensitive_keywords_found": found_keywords,
                "comment_sample": [c.strip()[:200] for c in comments[:5]],
                "technologies_detected": technologies,
                "content_length": len(content)
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Content analysis failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def analyze_webpage_content(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-05: Review Webpage Content for Information Leakage.

    Uses BeautifulSoup if available; falls back to regex parsing.
    Extracts comments, metadata, JS endpoints, emails, internal IPs, usernames.
    """
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        try:
            from bs4 import BeautifulSoup  # type: ignore
        except Exception:
            BeautifulSoup = None  # type: ignore

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
            html = ""
            base_url = None
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{clean_domain}"
                    r = await client.get(url)
                    if r.status_code == 200 and r.text:
                        html = r.text
                        base_url = url
                        break
                except Exception:
                    continue
            if not html:
                return {"status": "error", "message": "Unable to fetch homepage"}

        # Comments
        html_comments: List[Dict[str, Any]] = []
        raw_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for idx, c in enumerate(raw_comments[:50]):
            sev = "low"
            if re.search(r"TODO|FIXME|DEBUG|SECRET|KEY", c, re.IGNORECASE):
                sev = "medium"
            html_comments.append({"comment": c.strip()[:300], "severity": sev, "location": f"{base_url} comment #{idx+1}"})

        # Metadata
        metadata: Dict[str, Any] = {"generator": None, "author": None, "technology_hints": []}
        if BeautifulSoup:
            try:
                soup = BeautifulSoup(html, "html.parser")
                gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
                if gen and gen.get("content"):
                    metadata["generator"] = gen["content"]
                auth = soup.find("meta", attrs={"name": re.compile("author", re.I)})
                if auth and auth.get("content"):
                    metadata["author"] = auth["content"]
                # tech hints from scripts and links
                tech_hints = []
                for tag in soup.find_all(["script", "link"]):
                    src = tag.get("src") or tag.get("href") or ""
                    if src:
                        for t, pat in TECH_PATTERNS.items():
                            if re.search(pat, src, re.IGNORECASE):
                                tech_hints.append(t)
                metadata["technology_hints"] = sorted(set(tech_hints))
            except Exception:
                pass
        else:
            # Regex fallback
            m = re.search(r'<meta[^>]+name=["\"]generator["\"][^>]+content=["\"]([^"\"]+)["\"]', html, re.I)
            if m:
                metadata["generator"] = m.group(1)
            m = re.search(r'<meta[^>]+name=["\"]author["\"][^>]+content=["\"]([^"\"]+)["\"]', html, re.I)
            if m:
                metadata["author"] = m.group(1)

        # JavaScript leaks: endpoints and potential keys (redact)
        javascript_leaks: List[Dict[str, Any]] = []
        # endpoints in inline JS
        for m in re.finditer(r'https?://[^\s\"\']+', html):
            url = m.group(0)
            if clean_domain in url or re.search(r"(api|graphql|v\d+)", url, re.I):
                javascript_leaks.append({"file": base_url or "/", "finding": f"Endpoint: {url}", "severity": "medium"})
        # API keys pattern (redacted)
        for m in re.finditer(r'(api[_-]?key|token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', html, re.I):
            javascript_leaks.append({"file": base_url or "/", "finding": "API key-like token found (redacted)", "severity": "high"})

        # Sensitive patterns
        emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', html)))[:50]
        internal_ips = list(set(re.findall(r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)\d{1,3}\.\d{1,3}\b', html)))
        usernames = list(set(re.findall(r'\b(admin|root|test|user\d{0,3})\b', html, re.I)))

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-05",
                "information_leakage": {
                    "html_comments": html_comments,
                    "metadata": metadata,
                    "javascript_leaks": javascript_leaks[:50],
                    "emails_found": emails,
                    "internal_ips": internal_ips[:20],
                    "usernames": [u.lower() for u in usernames][:20],
                },
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Analyze webpage content failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def identify_entry_points(domain: str, max_pages: int = 200, max_depth: int = 2) -> Dict[str, Any]:
    """WSTG-INFO-06: Identify Application Entry Points

    Lightweight crawler + form extractor + parameter discovery + method probing.
    Optionally seeds URLs via gospider/hakrawler if available on WSL.
    """
    try:
        clean_domain = sanitize_domain(domain)
        base_host = clean_domain
        scheme_candidates = ["https", "http"]
        headers = {"User-Agent": get_random_user_agent()}

        # Seed URLs
        seed_urls = set()
        for scheme in scheme_candidates:
            seed_urls.add(f"{scheme}://{base_host}/")

        # Optional external seeding
        try:
            # hakrawler quick seed
            cmd = f"echo https://{clean_domain} | hakrawler -plain -depth 1"
            hk = await execute_wsl_command(cmd, timeout=60)
            if hk.get("success") and hk.get("stdout"):
                for line in hk["stdout"].splitlines():
                    if clean_domain in line:
                        seed_urls.add(line.strip())
        except Exception:
            pass

        visited = set()
        q = deque()
        for u in seed_urls:
            q.append((u, 0))

        urls_found = set()
        get_params = set()
        post_params = set()
        forms = []
        api_endpoints = {}
        cookies_set = set()
        method_matrix = {}  # url -> {method: status}

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as client:
            while q and len(urls_found) < max_pages:
                url, depth = q.popleft()
                if url in visited or depth > max_depth:
                    continue
                visited.add(url)

                # Only same-domain HTTP(S)
                pu = urlparse(url)
                if pu.scheme not in ("http", "https") or not pu.netloc.endswith(base_host):
                    continue

                try:
                    r = await client.get(url)
                except Exception:
                    continue

                urls_found.add(url)
                # Collect cookies
                for c in r.cookies.jar:
                    try:
                        cookies_set.add(c.name)
                    except Exception:
                        continue

                body = r.text

                # Extract links
                for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                    href = m.group(1)
                    if href.startswith("javascript:"):
                        continue
                    nu = urljoin(url, href)
                    npu = urlparse(nu)
                    if npu.scheme in ("http", "https") and npu.netloc.endswith(base_host):
                        if nu not in visited and len(urls_found) + len(q) < max_pages:
                            q.append((nu, depth + 1))

                # Extract GET parameters
                qd = parse_qs(pu.query)
                for k in qd.keys():
                    get_params.add(k)

                # Extract forms
                for form in re.findall(r'<form[^>]*.*?</form>', body, re.DOTALL | re.I):
                    action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form, re.I)
                    method_m = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form, re.I)
                    inputs = re.findall(r'<input[^>]*>', form, re.I)
                    fields = []
                    hidden = []
                    for inp in inputs:
                        name_m = re.search(r'name\s*=\s*["\']([^"\']*)["\']', inp, re.I)
                        type_m = re.search(r'type\s*=\s*["\']([^"\']*)["\']', inp, re.I)
                        nm = name_m.group(1) if name_m else None
                        tp = (type_m.group(1).lower() if type_m else "text")
                        if nm:
                            if tp == "hidden":
                                hidden.append(nm)
                            else:
                                fields.append(nm)
                                post_params.add(nm)
                    action = action_m.group(1) if action_m else url
                    method = (method_m.group(1).upper() if method_m else "GET")
                    forms.append({
                        "action": urljoin(url, action),
                        "method": method,
                        "fields": sorted(set(fields))[:30],
                        "hidden_fields": sorted(set(hidden))[:30] if hidden else None,
                    })

                # Detect API endpoints (simple heuristics)
                for m in re.finditer(r'["\'](/(?:api|graphql)[^"\']*)["\']', body, re.I):
                    ep = urljoin(url, m.group(1))
                    api_endpoints.setdefault(ep, set())

                # Method probing for a subset of discovered pages
                test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
                if url not in method_matrix:
                    method_matrix[url] = {}
                for mth in test_methods:
                    try:
                        resp = await client.request(mth, url)
                        method_matrix[url][mth] = resp.status_code
                    except Exception:
                        method_matrix[url][mth] = 0

        # Normalize API endpoint methods by probing
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10, headers=headers) as client:
            for ep in list(api_endpoints.keys())[:200]:
                methods = []
                for mth in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                    try:
                        rr = await client.request(mth, ep)
                        if rr.status_code not in (405, 501, 0):
                            methods.append(mth)
                    except Exception:
                        continue
                api_endpoints[ep] = sorted(set(methods))

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-06",
                "entry_points": {
                    "urls_found": len(urls_found),
                    "parameters": {
                        "get_parameters": sorted(list(get_params))[:100],
                        "post_parameters": sorted(list(post_params))[:100],
                    },
                    "forms": forms[:100],
                    "api_endpoints": [
                        {"endpoint": ep, "methods": api_endpoints.get(ep, [])}
                        for ep in sorted(api_endpoints.keys())[:100]
                    ],
                    "cookies_set": sorted(list(cookies_set))[:50],
                },
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Identify entry points failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def map_execution_paths(domain: str, max_pages: int = 400, max_depth: int = 3) -> Dict[str, Any]:
    """WSTG-INFO-07: Map Execution Paths Through Application

    Depth-limited crawl, infers workflows from URL patterns and sequences.
    """
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        base = f"https://{clean_domain}"
        visited = set()
        q = deque([(base, 0)])
        graph = {}  # url -> set(next_urls)
        all_paths = set()
        hidden_paths = set()

        # include robots and sitemap as potential hidden
        robots = await check_metafiles(clean_domain)
        if robots.get("status") == "success":
            meta = robots["data"]["metafiles"]
            for p in meta.get("robots_txt", {}).get("disallowed_paths", []) or []:
                hidden_paths.add(urljoin(base + '/', p.lstrip('/')))
            for u in meta.get("sitemap_xml", {}).get("interesting_urls", []) or []:
                hidden_paths.add(u)

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as client:
            while q and len(all_paths) < max_pages:
                url, depth = q.popleft()
                if url in visited or depth > max_depth:
                    continue
                visited.add(url)
                try:
                    r = await client.get(url)
                except Exception:
                    continue
                body = r.text
                graph.setdefault(url, set())
                all_paths.add(url)
                for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                    href = m.group(1)
                    if href.startswith("javascript:"):
                        continue
                    nu = urljoin(url, href)
                    if clean_domain in urlparse(nu).netloc:
                        graph[url].add(nu)
                        if nu not in visited and len(all_paths) + len(q) < max_pages:
                            q.append((nu, depth + 1))

        # Infer workflows by common sequences
        def find_sequences(prefixes: List[str]) -> Dict[str, Any]:
            res = {}
            for start in list(graph.keys()):
                for pref in prefixes:
                    if pref in start:
                        steps = [start]
                        for nxt in list(graph.get(start, []))[:5]:
                            steps.append(nxt)
                            # add one more hop
                            for nxt2 in list(graph.get(nxt, []))[:3]:
                                steps.append(nxt2)
                        key = pref.strip('/') or pref
                        res.setdefault(key, {"steps": []})
                        res[key]["steps"] = list(dict.fromkeys(steps))[:8]
            return res

        workflows = {}
        workflows.update(find_sequences(["/register", "/signup"]))
        workflows.update(find_sequences(["/checkout", "/cart"]))

        # Basic bypass heuristics: missing intermediate steps in sequences
        for wf in workflows.values():
            steps = wf.get("steps", [])
            wf["skippable_steps"] = [s for s in steps if re.search(r"verify|review|complete", s, re.I)]
            wf["potential_bypasses"] = ["Potential step skipping via direct URL access"] if wf["skippable_steps"] else []

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-07",
                "execution_paths": workflows,
                "hidden_paths": sorted(list(hidden_paths))[:100],
                "total_unique_paths": len(all_paths),
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Map execution paths failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def fingerprint_framework(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-08: Fingerprint Web Application Framework

    Uses headers, cookies, patterns; optional wappalyzer/whatweb/retire.js.
    """
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        backend = {"name": None, "version": None, "language": None, "detection_method": None}
        frontend = {"name": None, "version": None, "detection_method": None}
        libraries: List[Dict[str, Any]] = []
        cms = None
        vulns: List[Dict[str, Any]] = []

        # Fetch home page
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as client:
            resp = None
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(f"{scheme}://{clean_domain}")
                    if resp.status_code == 200:
                        break
                except Exception:
                    continue
            if not resp:
                return {"status": "error", "message": "Unable to fetch homepage"}
            text = resp.text
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Detect by cookies
        cookie_names = [c.name for c in resp.cookies.jar] if resp else []
        if any("laravel_session" in c for c in cookie_names):
            backend.update({"name": "Laravel", "language": "PHP", "detection_method": "Cookie laravel_session"})
        if any(c.startswith("PHPSESSID") for c in cookie_names):
            backend.setdefault("language", "PHP")
        if any(".AspNetCore." in c or "ASP.NET_SessionId" in c for c in cookie_names):
            backend.update({"name": backend.get("name") or "ASP.NET", "language": ".NET", "detection_method": "ASP.NET cookie"})

        # Detect by headers
        x_powered = resp_headers.get("x-powered-by", "")
        if "php" in x_powered.lower():
            backend["language"] = "PHP"
        if "express" in x_powered.lower():
            backend.update({"name": "Express", "language": "Node.js", "detection_method": "X-Powered-By"})

        # Detect frameworks in content
        if re.search(r"wp-content|wp-admin|wp-includes", text, re.I):
            cms = "WordPress"
        if re.search(r"Drupal.settings|/sites/default/", text, re.I):
            cms = cms or "Drupal"
        if re.search(r"Joomla!|/administrator/|com_content", text, re.I):
            cms = cms or "Joomla"

        # Frontend libraries and versions via common patterns
        for lib, pat in [("jQuery", r"jquery(?:\.min)?\.js(?:\?ver=([0-9.]+))?"), ("Bootstrap", r"bootstrap(?:\.min)?\.css(?:\?ver=([0-9.]+))?")]:
            m = re.search(pat, text, re.I)
            if m:
                libraries.append({"name": lib, "version": (m.group(1) if m.lastindex else None)})

        # Optional: wappalyzer CLI
        wappa = None
        try:
            cmd = f"wappalyzer https://{clean_domain} --quiet --pretty"  # may not exist
            wr = await execute_wsl_command(cmd, timeout=60)
            if wr.get("success") and wr.get("stdout"):
                wappa = wr["stdout"][:4000]
        except Exception:
            pass

        # Optional: whatweb to add hints
        ww = await run_comprehensive_scan(clean_domain)
        if ww.get("status") == "success":
            # optionally parse technologies
            pass

        # Vulnerability hints
        if cms == "WordPress":
            vulns.append({"cve": "Multiple", "description": "Ensure WordPress core/plugins are up-to-date", "severity": "medium"})
        if backend.get("name") == "Laravel":
            vulns.append({"cve": "CVE-2021-43617", "description": "Laravel Debug Mode RCE (if debug enabled)", "severity": "critical"})

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-08",
                "framework": {
                    "backend": backend,
                    "frontend": frontend,
                    "libraries": libraries[:10],
                    "cms": cms,
                    "vulnerabilities": vulns,
                },
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Fingerprint framework failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def fingerprint_application(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-09: Fingerprint Web Application (specific app, CMS, plugins)."""
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        base = f"https://{clean_domain}"
        app_type = None
        name = None
        version = None
        is_custom = True
        cms_components = {}
        third_party_services = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as client:
            # Fingerprints for common CMS
            fingerprints = {
                "WordPress": ["/wp-login.php", "/wp-admin/", "/readme.html"],
                "Joomla": ["/administrator/", "/README.txt"],
                "Drupal": ["/core/CHANGELOG.txt", "/user/login"],
                "phpBB": ["/ucp.php", "/faq.php"],
            }
            for cms_name, paths in fingerprints.items():
                hits = 0
                for p in paths:
                    try:
                        r = await client.get(urljoin(base + '/', p.lstrip('/')))
                        if r.status_code in (200, 301, 302, 403):
                            hits += 1
                    except Exception:
                        continue
                if hits >= 1:
                    is_custom = False
                    name = name or cms_name
                    app_type = app_type or ("CMS" if cms_name in ["WordPress", "Joomla", "Drupal"] else "Forum")

            # Version heuristics from pages
            try:
                r = await client.get(base)
                if r.status_code == 200:
                    # WordPress version
                    m = re.search(r"<meta name=\"generator\" content=\"WordPress ([0-9.]+)\"", r.text, re.I)
                    if m:
                        version = m.group(1)
                    # Footer version
                    m2 = re.search(r"Version[:\s]+([0-9.]+)", r.text, re.I)
                    if m2 and not version:
                        version = m2.group(1)
                    # Third-party services
                    if "www.googletagmanager.com/gtag/js" in r.text:
                        third_party_services.append("Google Analytics")
                    if re.search(r"js\.stripe\.com", r.text):
                        third_party_services.append("Stripe Payment Gateway")
                    if "cloudflare" in (r.headers.get("server", "").lower()):
                        third_party_services.append("Cloudflare CDN")
            except Exception:
                pass

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-09",
                "application": {
                    "type": app_type or "Unknown",
                    "name": name or "Unknown",
                    "version": version or "Unknown",
                    "is_custom": is_custom,
                    "cms_components": cms_components or None,
                    "third_party_services": sorted(set(third_party_services))[:10],
                },
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Fingerprint application failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def map_architecture(domain: str) -> Dict[str, Any]:
    """WSTG-INFO-10: Map Application Architecture

    Combines DNS/WHOIS, headers, SSL cert info, optional WAF/CDN detection and Nmap.
    """
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        cdn = {"provider": None, "detected_via": None}
        waf = {"detected": False, "provider": None, "confidence": None}
        load_balancer = {"detected": False, "type": None, "evidence": None}
        web_server = None
        application_server = None
        database = None
        cache = None
        ssl_certificate = {"issuer": None, "valid_until": None, "san_domains": []}
        network = {"ip_address": None, "asn": None, "location": None}

        # Headers and server info
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as client:
            resp = None
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(f"{scheme}://{clean_domain}")
                    if resp.status_code == 200:
                        break
                except Exception:
                    continue
            if resp:
                server = resp.headers.get("server")
                if server:
                    web_server = server
                if "cloudflare" in (server or "").lower():
                    cdn = {"provider": "Cloudflare", "detected_via": "Server headers"}
                    waf = {"detected": True, "provider": "Cloudflare WAF", "confidence": "high"}

        # DNS / IP / ASN
        try:
            ip = socket.gethostbyname(clean_domain)
            network["ip_address"] = ip
            # WHOIS ASN (best effort)
            who = await run_whois_lookup(ip)
            if who.get("status") == "success":
                raw = who["data"].get("raw_output", "")
                m_asn = re.search(r"originas(?:n)?:\s*(AS\d+)", raw, re.I)
                if m_asn:
                    network["asn"] = m_asn.group(1)
        except Exception:
            pass

        # SSL Certificate via openssl (WSL)
        try:
            cmd = f"echo | openssl s_client -servername {clean_domain} -connect {clean_domain}:443 2>/dev/null | openssl x509 -noout -issuer -enddate -ext subjectAltName"
            res = await execute_wsl_command(cmd, timeout=40)
            if res.get("success") and res.get("stdout"):
                out = res["stdout"]
                mi = re.search(r"issuer=\s*([^\n]+)", out)
                if mi:
                    ssl_certificate["issuer"] = mi.group(1).strip()
                me = re.search(r"notAfter=([^\n]+)", out)
                if me:
                    ssl_certificate["valid_until"] = me.group(1).strip()
                msan = re.search(r"subjectAltName\s*:\s*([\s\S]+)$", out)
                if msan:
                    sans = re.findall(r"DNS:([^,\s]+)", out)
                    ssl_certificate["san_domains"] = sorted(set(sans))[:50]
        except Exception:
            pass

        # Optional WAF detection via wafw00f
        try:
            cmd = f"wafw00f https://{clean_domain} -o -"
            wf = await execute_wsl_command(cmd, timeout=60)
            if wf.get("success") and wf.get("stdout"):
                txt = wf["stdout"].lower()
                if "cloudflare" in txt:
                    waf = {"detected": True, "provider": "Cloudflare WAF", "confidence": "high"}
        except Exception:
            pass

        # Optional Load balancer detection via multiple IPs check
        try:
            # Resolve multiple times (rudimentary)
            ips = set()
            for _ in range(2):
                ips.add(socket.gethostbyname(clean_domain))
            if len(ips) > 1:
                load_balancer = {"detected": True, "type": None, "evidence": "Multiple A records"}
        except Exception:
            pass

        return {
            "status": "success",
            "data": {
                "test_id": "WSTG-INFO-10",
                "architecture": {
                    "cdn": cdn,
                    "waf": waf,
                    "load_balancer": load_balancer,
                    "web_server": web_server,
                    "application_server": application_server,
                    "database": database,
                    "cache": cache,
                    "ssl_certificate": ssl_certificate,
                    "network": network,
                },
            },
        }
    except Exception as e:
        return {"status": "error", "message": f"Map architecture failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def find_entry_points(domain: str) -> Dict[str, Any]:
    """Identifies forms and links with parameters on the homepage."""
    try:
        clean_domain = sanitize_domain(domain)
        headers = {"User-Agent": get_random_user_agent()}
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
            content = ""
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(f"{scheme}://{clean_domain}")
                    if resp.status_code == 200:
                        content = resp.text
                        break
                except:
                    continue
            
            if not content:
                return {"status": "error", "message": "Unable to fetch homepage content"}
        
        # Find forms
        forms_raw = re.findall(r'<form[^>]*.*?</form>', content, re.DOTALL | re.IGNORECASE)
        forms_details = []
        
        for form in forms_raw:
            action = re.search(r'action\s*=\s*[\'"]([^\'"]*)[\'"]', form, re.IGNORECASE)
            method = re.search(r'method\s*=\s*[\'"]([^\'"]*)[\'"]', form, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
            
            input_types = []
            for inp in inputs:
                inp_type = re.search(r'type\s*=\s*[\'"]([^\'"]*)[\'"]', inp, re.IGNORECASE)
                if inp_type:
                    input_types.append(inp_type.group(1))
            
            forms_details.append({
                "action": action.group(1) if action else "None",
                "method": method.group(1).upper() if method else "GET",
                "input_count": len(inputs),
                "input_types": list(set(input_types))
            })

        # Find parameterized links
        param_links = list(set(re.findall(r'<a[^>]+href\s*=\s*[\'"]([^\'"]*\?[^\'"]+)[\'"]', content, re.IGNORECASE)))
        
        # Find potential API endpoints
        js_endpoints = list(set(re.findall(r'[\'"]([^\'"]*(?:api|ajax|endpoint)[^\'"]*)[\'"]', content, re.IGNORECASE)))

        return {
            "status": "success",
            "data": {
                "forms": forms_details,
                "parameterized_links": param_links[:20],
                "potential_js_endpoints": js_endpoints[:10]
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Entry point detection failed: {str(e)}"}

# Enhanced DNS tools
# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def run_dig_lookup(domain: str) -> Dict[str, Any]:
    """Performs a DNS A record lookup and returns IPs in a JSON list."""
    try:
        clean_domain = sanitize_domain(domain)
        result = await execute_wsl_command(f"dig +short A '{clean_domain}'", timeout=30)
        
        if not result["success"]:
            return {"status": "error", "message": f"DNS lookup failed: {result.get('error', 'Unknown error')}"}
        
        ips = result["stdout"].splitlines() if result["stdout"] else []
        valid_ips = []
        cnames = []
        
        for line in ips:
            line = line.strip()
            if is_valid_ip(line):
                valid_ips.append(line)
            elif line and not line.endswith('.') and '.' in line:
                cnames.append(line)
        
        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "a_records": valid_ips,
                "cname_records": cnames
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"DNS lookup failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def run_whois_lookup(ip_or_domain: str) -> Dict[str, Any]:
    """Performs a WHOIS lookup and returns structured data."""
    try:
        clean_target = sanitize_domain(ip_or_domain) if not is_valid_ip(ip_or_domain) else ip_or_domain
        result = await execute_wsl_command(f"whois {clean_target}", timeout=45)
        
        if not result["success"]:
            return {"status": "error", "message": f"WHOIS lookup failed: {result.get('error', 'Unknown error')}"}
        
        output = result["stdout"]
        
        # Parse key information
        org_match = re.search(r'Organization:\s*(.+)', output, re.IGNORECASE)
        country_match = re.search(r'Country:\s*(.+)', output, re.IGNORECASE)
        created_match = re.search(r'Creation Date:\s*(.+)', output, re.IGNORECASE)
        registrar_match = re.search(r'Registrar:\s*(.+)', output, re.IGNORECASE)
        
        return {
            "status": "success",
            "data": {
                "target": clean_target,
                "organization": org_match.group(1).strip() if org_match else "Unknown",
                "country": country_match.group(1).strip() if country_match else "Unknown",
                "created_date": created_match.group(1).strip() if created_match else "Unknown",
                "registrar": registrar_match.group(1).strip() if registrar_match else "Unknown",
                "raw_output": output[:1500] + "..." if len(output) > 1500 else output
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"WHOIS lookup failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def check_email_security(domain: str) -> Dict[str, Any]:
    """Checks for SPF, DMARC, and DKIM records."""
    try:
        clean_domain = sanitize_domain(domain)
        
        spf_result = await execute_wsl_command(f"dig +short TXT '{clean_domain}'", timeout=20)
        dmarc_result = await execute_wsl_command(f"dig +short TXT '_dmarc.{clean_domain}'", timeout=20)
        dkim_result = await execute_wsl_command(f"dig +short TXT 'default._domainkey.{clean_domain}'", timeout=20)

        # Process SPF records
        spf_records = []
        if spf_result["success"] and spf_result["stdout"]:
            for line in spf_result["stdout"].splitlines():
                if 'v=spf1' in line.lower():
                    spf_records.append(line.strip().strip('"'))

        # Process DMARC records
        dmarc_record = "Not found"
        if dmarc_result["success"] and dmarc_result["stdout"]:
            dmarc_lines = dmarc_result["stdout"].strip()
            if dmarc_lines and not any(err in dmarc_lines.lower() for err in ['timed out', 'no servers']):
                dmarc_record = dmarc_lines.strip('"')

        # Process DKIM records
        dkim_record = "Not found"
        if dkim_result["success"] and dkim_result["stdout"]:
            dkim_lines = dkim_result["stdout"].strip()
            if dkim_lines and not any(err in dkim_lines.lower() for err in ['timed out', 'no servers']):
                dkim_record = dkim_lines.strip('"')

        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "spf_records": spf_records,
                "dmarc_record": dmarc_record,
                "dkim_default_record": dkim_record,
                "spf_status": "configured" if spf_records else "not_configured",
                "dmarc_status": "configured" if dmarc_record != "Not found" else "not_configured",
                "dkim_status": "configured" if dkim_record != "Not found" else "not_configured"
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Email security check failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def ffuf_directory_scan(target_url: str, wordlist_path: Optional[str] = None, extensions: Optional[str] = None, recursive: bool = True, max_depth: int = 2) -> Dict[str, Any]:
    """
    Advanced directory and endpoint discovery using ffuf.

    Args:
        target_url: Base URL to fuzz (e.g., http://juice-shop:3000)
        wordlist_path: Path to wordlist file (default: built-in REST API wordlist)
        extensions: Comma-separated extensions to test (e.g., ".php,.html,.json")
        recursive: Enable recursive fuzzing
        max_depth: Maximum recursion depth (default: 2)

    Returns:
        Dict with discovered endpoints, status codes, and sizes
    """
    try:
        logger.info(f"Starting ffuf scan on {target_url}")

        # Use built-in REST API wordlist if none provided
        if not wordlist_path:
            wordlist_content = """search
products/search
users/search
api/search
rest/search
api/products/search
rest/products/search
api/v1/search
api/v2/search
products
users
items
api
rest
api/v1
api/v2
api/products
api/users
rest/products
rest/users
login
auth
profile
admin
basket
cart
checkout
feedback
upload
api/Feedbacks
api/BasketItems
api/Users
api/Products
rest/user/login
rest/user/whoami
rest/admin
encryptionkeys
ftp
metrics"""
            wordlist_path = "/tmp/ffuf-rest-api.txt"
            with open(wordlist_path, 'w') as f:
                f.write(wordlist_content)

        # Build ffuf command
        cmd = [
            "ffuf",
            "-u", f"{target_url.rstrip('/')}/FUZZ",
            "-w", wordlist_path,
            "-mc", "200,201,202,204,301,302,307,401,403",  # Match interesting status codes
            "-fc", "404",  # Filter 404
            "-t", "50",  # 50 threads
            "-timeout", "10",
            "-json"  # JSON output for easy parsing
        ]

        if extensions:
            cmd.extend(["-e", extensions])

        if recursive and max_depth > 0:
            cmd.extend(["-recursion", "-recursion-depth", str(max_depth)])

        # Execute ffuf
        logger.info(f"Running: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            logger.error(f"ffuf failed: {error_msg}")
            return {"status": "error", "message": f"ffuf execution failed: {error_msg}"}

        # Parse JSON output
        try:
            output_str = stdout.decode()
            if not output_str.strip():
                return {
                    "status": "success",
                    "data": {
                        "total_found": 0,
                        "endpoints": [],
                        "message": "No endpoints found"
                    }
                }

            # ffuf outputs one JSON object per line
            results = []
            for line in output_str.strip().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            # Extract discovered endpoints
            endpoints = []
            for result in results:
                if "results" in result:
                    for entry in result["results"]:
                        endpoints.append({
                            "path": entry.get("input", {}).get("FUZZ", ""),
                            "url": entry.get("url", ""),
                            "status": entry.get("status", 0),
                            "length": entry.get("length", 0),
                            "words": entry.get("words", 0),
                            "lines": entry.get("lines", 0)
                        })

            logger.info(f"ffuf found {len(endpoints)} endpoints")

            return {
                "status": "success",
                "data": {
                    "total_found": len(endpoints),
                    "endpoints": endpoints[:100],  # Limit to first 100
                    "sample": [ep["url"] for ep in endpoints[:20]]  # Top 20 sample
                }
            }

        except Exception as parse_error:
            logger.error(f"Failed to parse ffuf output: {parse_error}")
            return {"status": "error", "message": f"Failed to parse ffuf output: {str(parse_error)}"}

    except asyncio.TimeoutError:
        return {"status": "error", "message": "ffuf scan timed out after 300 seconds"}
    except Exception as e:
        logger.error(f"ffuf scan failed: {str(e)}")
        return {"status": "error", "message": f"ffuf scan failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def dirsearch_scan(
    target_url: str,
    wordlist: Optional[str] = None,
    extensions: str = "php,html,json,txt,js,xml,asp,aspx,jsp",
    recursive: bool = True,
    recursion_depth: int = 3,
    threads: int = 50,
    exclude_status: str = "404,403",
    timeout: int = 600
) -> Dict[str, Any]:
    """
    Advanced directory and endpoint discovery using dirsearch with recursive capability.

    ADVANTAGE over ffuf: dirsearch automatically follows discovered directories and
    continues scanning subdirectories recursively, ensuring comprehensive coverage.

    Args:
        target_url: Base URL to scan (e.g., http://juice-shop:3000)
        wordlist: Path to wordlist (default: auto-select from SecLists if available)
        extensions: Comma-separated file extensions to test (default: php,html,json,txt,js,xml,asp,aspx,jsp)
        recursive: Enable recursive directory scanning (default: True)
        recursion_depth: Maximum depth for recursive scanning (default: 3 levels)
        threads: Number of concurrent threads (default: 50)
        exclude_status: Status codes to exclude from results (default: 404,403)
        timeout: Maximum execution time in seconds (default: 600)

    Returns:
        Dict with discovered endpoints, status codes, sizes, and redirect chains
    """
    try:
        logger.info(f"Starting dirsearch scan on {target_url} (recursive={recursive}, depth={recursion_depth})")

        # Auto-select best wordlist if not provided
        if not wordlist:
            import os
            # Preference order: Combined (web + API) > SecLists raft > dirsearch built-in
            combined_wordlist = "/opt/combined-web-api.txt"
            seclists_raft = "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt"
            dirsearch_default = "/usr/local/lib/python3.11/site-packages/dirsearch/db/dicc.txt"

            if os.path.exists(combined_wordlist):
                wordlist = combined_wordlist
                logger.info(f"Using combined web+API wordlist (62K+ entries with REST API patterns)")
            elif os.path.exists(seclists_raft):
                wordlist = seclists_raft
                logger.info(f"Using SecLists raft-large-directories.txt (530K+ entries)")
            elif os.path.exists(dirsearch_default):
                wordlist = dirsearch_default
                logger.info(f"Using dirsearch built-in wordlist (138K)")
            # else: let dirsearch use its default

        # Build dirsearch command (use plain text output, NOT JSON)
        cmd = [
            "dirsearch",
            "-u", target_url,
            "-e", extensions,
            "-t", str(threads),
            "--exclude-status", exclude_status,
            "--random-agent"
        ]

        # Add wordlist
        if wordlist:
            cmd.extend(["-w", wordlist])

        # NOTE: Removed --deep-recursive because it doesn't work with 500 status codes
        # Using comprehensive wordlist with nested paths instead

        logger.info(f"Running: {' '.join(cmd)}")

        # Execute dirsearch
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            return {"status": "error", "message": f"dirsearch timed out after {timeout} seconds"}

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            logger.error(f"dirsearch failed: {error_msg}")
            return {"status": "error", "message": f"dirsearch execution failed: {error_msg}"}

        # Parse dirsearch text output
        # Format: [timestamp] STATUS - SIZE - /path
        # Example: [09:12:01] 200 - 13KB - /rest/products/search
        try:
            output_str = stdout.decode()
            if not output_str.strip():
                return {
                    "status": "success",
                    "data": {
                        "total_found": 0,
                        "endpoints": [],
                        "message": "No endpoints found"
                    }
                }

            import re
            from urllib.parse import urljoin

            endpoints = []
            api_endpoints = []
            search_endpoints = []
            admin_endpoints = []

            # Regex to match dirsearch output: [HH:MM:SS] STATUS - SIZE - /path
            pattern = r'\[[\d:]+\]\s+(\d{3})\s+-\s+(\S+)\s+-\s+(\S+)'

            for line in output_str.split('\n'):
                match = re.search(pattern, line)
                if match:
                    status_code = int(match.group(1))
                    size = match.group(2)
                    path = match.group(3)

                    # Construct full URL
                    url = urljoin(target_url, path)

                    endpoint_data = {
                        "path": path.lstrip("/"),
                        "url": url,
                        "status": status_code,
                        "size": size,
                        "redirect": None
                    }

                    endpoints.append(endpoint_data)

                    # Categorize endpoints
                    path_lower = path.lower()
                    if "/api/" in path_lower or "/rest/" in path_lower or path_lower.endswith(".json"):
                        api_endpoints.append(endpoint_data)
                    if "search" in path_lower:
                        search_endpoints.append(endpoint_data)
                    if "admin" in path_lower or "dashboard" in path_lower:
                        admin_endpoints.append(endpoint_data)

            logger.info(f"✓ dirsearch found {len(endpoints)} endpoints (API: {len(api_endpoints)}, Search: {len(search_endpoints)}, Admin: {len(admin_endpoints)})")

            return {
                "status": "success",
                "data": {
                    "total_found": len(endpoints),
                    "endpoints": endpoints[:200],  # Limit to 200 most relevant
                    "api_endpoints": api_endpoints[:50],
                    "search_endpoints": search_endpoints[:50],
                    "admin_endpoints": admin_endpoints[:50],
                    "sample": [ep["url"] for ep in endpoints[:30]],  # Top 30 sample
                    "stats": {
                        "total": len(endpoints),
                        "api_count": len(api_endpoints),
                        "search_count": len(search_endpoints),
                        "admin_count": len(admin_endpoints),
                        "status_200": len([e for e in endpoints if e["status"] == 200]),
                        "status_301": len([e for e in endpoints if e["status"] == 301]),
                        "status_302": len([e for e in endpoints if e["status"] == 302]),
                    }
                }
            }

        except Exception as parse_error:
            logger.error(f"Failed to parse dirsearch output: {parse_error}")
            return {"status": "error", "message": f"Failed to parse dirsearch output: {str(parse_error)}"}

    except Exception as e:
        logger.error(f"dirsearch scan failed: {str(e)}")
        return {"status": "error", "message": f"dirsearch scan failed: {str(e)}"}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def generate_reconnaissance_report(domain: str) -> Dict[str, Any]:
    """Generate comprehensive reconnaissance report"""
    try:
        clean_domain = sanitize_domain(domain)
        logger.info(f"Generating comprehensive report for {clean_domain}")
        
        report_id = generate_report_id(clean_domain)
        start_time = datetime.now()
        
        report_data = {
            "metadata": {
                "report_id": report_id,
                "domain": clean_domain,
                "timestamp": start_time.isoformat()
            },
            "executive_summary": {},
            "technical_findings": {},
            "recommendations": [],
            "risk_assessment": {}
        }
        
        # Collect reconnaissance data
        dns_data = await run_dig_lookup(clean_domain)
        whois_data = await run_whois_lookup(clean_domain)
        headers_data = await security_headers_analysis(clean_domain)
        meta_data = await check_meta_files(clean_domain)
        content_data = await analyze_content(clean_domain)
        
        # Populate findings
        if dns_data.get("status") == "success":
            report_data["technical_findings"]["dns"] = dns_data["data"]
        if headers_data.get("status") == "success":
            report_data["technical_findings"]["security_headers"] = headers_data["data"]
            report_data["recommendations"].extend(headers_data["data"].get("recommendations", []))
        if meta_data.get("status") == "success":
            report_data["technical_findings"]["meta_files"] = meta_data["data"]
        if content_data.get("status") == "success":
            report_data["technical_findings"]["content"] = content_data["data"]
        
        # Executive summary
        total_ips = len(report_data["technical_findings"].get("dns", {}).get("a_records", []))
        security_score = report_data["technical_findings"].get("security_headers", {}).get("security_score", 0)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        report_data["executive_summary"] = {
            "domain_status": "active" if total_ips > 0 else "inactive",
            "ip_addresses_found": total_ips,
            "security_posture": "good" if security_score > 70 else "needs improvement",
            "scan_duration": f"{scan_duration:.1f}s"
        }
        
        # Save report
        report_file = get_output_path(clean_domain, "report", "json")
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save report: {str(e)}")
        
        return {
            "status": "success",
            "data": {
                "report": report_data,
                "report_file": report_file,
                "summary": f"Reconnaissance complete for {clean_domain}. Report ID: {report_id}"
            }
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Report generation failed: {str(e)}"}

if __name__ == "__main__":
    ensure_directories()
    logger.info("Enhanced Information Gathering MCP Server starting...")
#     mcp.run(transport='stdio')