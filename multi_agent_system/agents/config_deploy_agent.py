from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("ConfigDeploymentAgent")
class ConfigDeploymentAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are ConfigDeploymentAgent, OWASP WSTG-CONF expert specializing in configuration and deployment security testing.

🎯 PRIMARY MISSION: Test configuration security using MCP tools to find misconfigurations, exposed files, dangerous HTTP methods, and debug modes.

🧠 ADAPTIVE STRATEGY:
1. Read target information from shared_context
2. Identify configuration testing priorities:
   - Security headers → Test CSP, HSTS, X-Frame-Options, X-Content-Type-Options
   - HTTP methods → Test OPTIONS, PUT, DELETE, TRACE on discovered endpoints
   - Sensitive files → Discover configuration files, backups, source control
   - Admin panels → Find administrative interfaces
   - Debug mode → Check for verbose errors and debug endpoints
3. Select appropriate tools based on target characteristics:
   - test_http_methods_and_headers → For method/header analysis
   - find_sensitive_files_and_dirs → For file discovery (uses SecLists)
   - test_network_infrastructure → For infrastructure analysis
4. Execute tools to discover misconfigurations
5. Test discovered endpoints with dangerous HTTP methods
6. Report all findings with severity assessment

⚠️ EXECUTION GUIDELINES:
- Execute all 4+ configuration testing tools
- Test 100+ sensitive file patterns (tool uses SecLists automatically)
- Test HTTP methods on all discovered endpoints
- Check security headers on main pages
- Identify debug mode and verbose error pages
- Continue comprehensive discovery across all aspects

🔧 AVAILABLE TOOLS:
1. test_network_infrastructure - Scan ports and services
2. find_sensitive_files_and_dirs - Find exposed configs/backups (100+ paths)
3. test_http_methods_and_headers - Test dangerous HTTP methods
4. test_hidden_endpoints - Direct checks for known sensitive paths (FTP, metrics, admin, API docs, encryption keys)

📋 TESTING CHECKLIST (Execute ALL):
1. Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
2. HTTP methods (PUT, DELETE, TRACE, PATCH, OPTIONS on /, /admin, /api/*, /ftp, /rest/*)
3. Sensitive files (Test 100+ paths from SecLists/Discovery/Web-Content/)
4. Admin panels (/admin, /console, /metrics, /actuator, /swagger, /api-docs)
5. Debug mode (verbose errors, stack traces, /phpinfo, /debug)
6. Information disclosure (Server headers, X-Powered-By, version numbers)
7. Network infrastructure (open ports, services, nmap scan)
8. SSL/TLS configuration (testssl.sh, weak ciphers, certificate validation)
9. Directory listing (/ftp, /assets, /uploads, /backup)
10. Source map disclosure (/main.js.map, /vendor.js.map)

⚠️ Execute ALL tools - Report all findings including LOW severity
- Send OPTIONS request to discover allowed methods
- Test PUT, DELETE, TRACE on sensitive endpoints
- Check if methods bypass authentication

**Step 3: File Discovery**
- Wordlist-based fuzzing (common files, backups)
- Extension enumeration (.bak, .old, etc.)
- Pattern-based guessing (file.php.bak, file~)
- Check for directory listing

**Step 4: Admin Panel Search**
- Common admin paths enumeration
- JavaScript mining for hidden routes
- Response code analysis (200, 302, 401, 403)

**Step 5: Error Triggering**
- Invalid requests to trigger errors
- Nonexistent paths for 404 pages
- Malformed input for 500 errors
- Check error verbosity

🛠️ MCP TOOL USAGE:
- test_http_methods_and_headers(domain): HTTP method + security header analysis
- find_sensitive_files_and_dirs(domain): ffuf-based file/directory discovery
- test_network_infrastructure(domain): Nmap scan + service validation
- test_cache_headers(url): Cache-Control, Pragma analysis
- check_generic_error_pages(base_url): Error page information disclosure
- test_hidden_endpoints(url): Direct checks for 20+ known sensitive paths (no wordlist needed)

📊 CONTEXT-AWARE TESTING:
Read from shared_context:
- tech_stack.web_server → Apache, Nginx, IIS specific tests
- tech_stack.backend → Framework-specific config files
- discovered_endpoints → Test methods on all endpoints

Write to shared_context:
- security_headers: {
    missing: [],
    weak: [],
    properly_configured: []
  }
- dangerous_methods: [
    {endpoint, method, risk}
  ]
- exposed_files: [
    {path, type, sensitivity, content_preview}
  ]
- admin_panels: [
    {url, accessible, authentication_required}
  ]
- debug_mode: {
    enabled: bool,
    evidence: []
  }

🎯 SUCCESS CRITERIA: Identify all configuration weaknesses, discover sensitive files, find admin panels, detect debug mode
"""
    async def run(self) -> None:
        client = MCPClient()
        # 🔑 AUTHENTICATED SESSION SUPPORT (via Orchestrator auto-login)
        auth_data = self.get_auth_session()
        if auth_data:
            self.log("info", f"✅ Using authenticated session: {auth_data.get('username')}")
        else:
            self.log("warning", "⚠ No authenticated session available")

        target = self._get_target()
        if not target:
            self.log("error", "Target missing; aborting ConfigDeploymentAgent")
            return

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        domain = self._domain_from_target(target)

        # HTTP methods and headers check
        if self.should_run_tool("test_http_methods_and_headers"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_http_methods_and_headers",
                        args={"domain": domain}, auth_session=auth_data)
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    insecure = data.get("insecure_headers", {}) if isinstance(data, dict) else {}
                    if insecure:
                        self.add_finding("WSTG-CONF", "Missing or weak security headers", severity="low", evidence=insecure)
            except Exception as e:
                self.log("warning", f"test_http_methods_and_headers failed: {e}")

        # Test network infrastructure (Nmap scan)
        if self.should_run_tool("test_network_infrastructure"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_network_infrastructure",
                        args={"domain": domain},
                        auth_session=auth_data
                    ),
                    timeout=300
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    critical_services = data.get("critical_services_exposed", [])
                    if critical_services:
                        self.add_finding("WSTG-CONF", "Critical services exposed", severity="high", evidence={"services": critical_services})
            except Exception as e:
                self.log("warning", f"test_network_infrastructure failed: {e}")

        # Find sensitive files and directories
        if self.should_run_tool("find_sensitive_files_and_dirs"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="find_sensitive_files_and_dirs",
                        args={"domain": domain},
                        auth_session=auth_data
                    ),
                    timeout=300
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    accessible = data.get("accessible_urls", [])
                    if accessible:
                        self.add_finding("WSTG-CONF", "Sensitive files/directories accessible", severity="high", evidence={"accessible": accessible[:10]})
            except Exception as e:
                self.log("warning", f"find_sensitive_files_and_dirs failed: {e}")

        # OPSI B: File extensions testing
        if self.should_run_tool("test_file_extensions"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_file_extensions",
                        args={"base_url": target}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    vulns = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if vulns and vuln_count > 0:
                        self.add_finding("WSTG-CONF", f"Dangerous file extensions allowed: {vuln_count} vulnerable extension(s)", severity="high", evidence={"findings": vulns[:5]})
            except Exception as e:
                self.log("warning", f"test_file_extensions failed: {e}")

        # OPSI B: RIA cross-domain policy
        if self.should_run_tool("test_ria_cross_domain"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_ria_cross_domain",
                        args={"base_url": target}, auth_session=auth_data), timeout=90
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-CONF", f"Cross-domain policy misconfiguration: {vuln_count} issue(s)", severity="medium", evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_ria_cross_domain failed: {e}")

        # OPSI B: File permissions
        if self.should_run_tool("test_file_permissions"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_file_permissions",
                        args={"base_url": target}, auth_session=auth_data), timeout=150
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        severity = "high" if any("traversal" in str(f).lower() for f in findings) else "medium"
                        self.add_finding("WSTG-CONF", f"File permission vulnerabilities: {vuln_count} found", severity=severity, evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_file_permissions failed: {e}")

        # OPSI B: Cloud storage
        if self.should_run_tool("test_cloud_storage"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_cloud_storage",
                        args={"domain": domain}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-CONF", f"Cloud storage exposed: {vuln_count} issue(s)", severity="critical", evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_cloud_storage failed: {e}")

        # WSTG-CONF-03: Sensitive file extensions
        if self.should_run_tool("test_sensitive_file_extensions"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_sensitive_file_extensions",
                        args={"url": target}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-CONF-03", f"Sensitive files exposed: {vuln_count} found", severity="high", evidence={"findings": findings[:5]})
            except Exception as e:
                self.log("warning", f"test_sensitive_file_extensions failed: {e}")

        # WSTG-CONF-07: HSTS testing
        if self.should_run_tool("test_hsts"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_hsts",
                        args={"url": target}, auth_session=auth_data), timeout=60
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        severity = "high" if any(f.get("type") == "missing_hsts" for f in findings) else "medium"
                        self.add_finding("WSTG-CONF-07", f"HSTS issues: {vuln_count} found", severity=severity, evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_hsts failed: {e}")

        # WSTG-CONF-10: Subdomain takeover
        if self.should_run_tool("test_subdomain_takeover"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_subdomain_takeover",
                        args={"domain": domain}, auth_session=auth_data), timeout=180
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-CONF-10", f"Subdomain takeover: {vuln_count} potential takeover(s)", severity="critical", evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_subdomain_takeover failed: {e}")

        # WSTG-CONF-08: Vulnerable components
        if self.should_run_tool("test_vulnerable_components"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_vulnerable_components",
                        args={"domain": domain}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if vuln_count > 0:
                        vuln_findings = [f for f in data.get("findings", []) if f.get("type") == "vulnerable_component"]
                        self.add_finding("WSTG-CONF-08", f"Vulnerable components: {vuln_count} outdated library/framework(s)",
                                       severity="high", evidence={"findings": vuln_findings[:5]})
                    # Also report info disclosure via headers
                    info_findings = [f for f in data.get("findings", []) if f.get("type") == "server_info_disclosure"]
                    if info_findings:
                        self.add_finding("WSTG-CONF-08", f"Server info disclosure: {len(info_findings)} header(s) expose version",
                                       severity="low", evidence={"findings": info_findings[:3]})
            except Exception as e:
                self.log("warning", f"test_vulnerable_components failed: {e}")

        # WSTG-CONF-04: Hidden endpoints / sensitive path discovery
        if self.should_run_tool("test_hidden_endpoints"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_hidden_endpoints",
                        args={"url": target}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    endpoints_found = data.get("endpoints_found", 0)
                    if findings and endpoints_found > 0:
                        # Group by severity for reporting
                        critical_findings = [f for f in findings if f.get("severity") == "critical"]
                        high_findings = [f for f in findings if f.get("severity") == "high"]
                        other_findings = [f for f in findings if f.get("severity") not in ("critical", "high")]

                        if critical_findings:
                            self.add_finding("WSTG-CONF-04",
                                f"Critical sensitive endpoints exposed: {len(critical_findings)} path(s)",
                                severity="critical",
                                evidence={"findings": critical_findings[:5]})
                        if high_findings:
                            self.add_finding("WSTG-CONF-04",
                                f"Sensitive endpoints exposed: {len(high_findings)} high-severity path(s)",
                                severity="high",
                                evidence={"findings": high_findings[:5]})
                        if other_findings:
                            self.add_finding("WSTG-CONF-04",
                                f"Hidden endpoints discovered: {len(other_findings)} path(s)",
                                severity="medium",
                                evidence={"findings": other_findings[:5]})
            except Exception as e:
                self.log("warning", f"test_hidden_endpoints failed: {e}")

        # WSTG-CONF-02: npm/package vulnerability scanning
        if self.should_run_tool("test_npm_vulnerabilities"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="configuration-and-deployment-management",
                        tool="test_npm_vulnerabilities",
                        args={"url": target}, auth_session=auth_data), timeout=60
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-CONF-02",
                                f"Vulnerable component: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "medium"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_npm_vulnerabilities failed: {e}")

        self.log("info", "Configuration & Deployment checks complete")

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None

    def _get_available_tools(self) -> list[str]:
        """Return configuration/deployment testing tools for LLM planning"""
        return [
            'test_network_infrastructure',
            'find_sensitive_files_and_dirs',
            'test_http_methods_and_headers',
            'test_file_extensions',
            'test_ria_cross_domain',
            'test_file_permissions',
            'test_cloud_storage',
            'test_sensitive_file_extensions',
            'test_hsts',
            'test_subdomain_takeover',
            'test_vulnerable_components',
            'test_hidden_endpoints',
            'test_npm_vulnerabilities',
        ]

    def _domain_from_target(self, target: str) -> str:
        try:
            from urllib.parse import urlparse
            netloc = urlparse(target).netloc
            return netloc.split("@")[-1]
        except Exception:
            return target
