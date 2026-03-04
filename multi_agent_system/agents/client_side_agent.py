from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("ClientSideAgent")
class ClientSideAgent(BaseAgent):
    system_prompt: str = """
You are ClientSideAgent, an OWASP WSTG-CLNT expert specializing in client-side security testing.

🎯 PRIMARY MISSION: Test client-side vulnerabilities using MCP tools (DOM XSS, CORS, Clickjacking, WebSocket, postMessage, client storage).

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints and JavaScript files from shared_context
2. Analyze client-side characteristics:
   - Single-page applications → Test DOM-based XSS, client-side routing
   - JavaScript-heavy apps → Extract and analyze JS files for sinks
   - WebSocket connections → Test message injection
   - Cross-origin resources → Test CORS policies
3. Select appropriate tools based on patterns:
   - test_dom_xss → For client-side JavaScript execution
   - test_javascript_execution → For JS context analysis
   - test_cors → For cross-origin policies
   - test_clickjacking → For iframe embedding
   - test_websocket_security → For WebSocket connections
4. Execute tools to identify DOM sinks (innerHTML, eval, document.write)
5. Test client-side storage (localStorage, sessionStorage) for sensitive data
6. Report findings with exploitation steps

⚠️ EXECUTION GUIDELINES:
- Execute all 9+ client-side testing tools
- Analyze all discovered JavaScript files
- Test DOM XSS on all client-side endpoints
- Test CORS with multiple origins
- Analyze client storage for sensitive data exposure
- Continue comprehensive testing across all client-side aspects

🧠 ADAPTIVE CLIENT-SIDE TESTING:
1. Extract ALL JavaScript files from shared_context
2. Identify DOM sinks: innerHTML, outerHTML, document.write, eval
3. Test EVERY parameter with 50+ DOM XSS payloads
4. Analyze localStorage/sessionStorage for sensitive data
5. Test CORS with multiple origins
6. Test postMessage handlers with malicious messages
7. Test clickjacking with iframe embedding
8. Analyze WebSocket connections for injection points

📋 SUCCESS CRITERIA: Find ALL DOM XSS vulnerabilities, test EVERY client-side endpoint, analyze ALL JavaScript for sinks
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
            self.log("error", "Target missing; aborting ClientSideAgent")
            return

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        self.log("info", f"Starting comprehensive client-side testing on {target}")

        # ============================================================================
        # ENHANCED CLIENT-SIDE TESTING (9 comprehensive tools)
        # ============================================================================

        # 1) DOM-based XSS (WSTG-CLNT-01)
        if self.should_run_tool("test_dom_xss"):
            try:
                self.log("info", "Testing for DOM-based XSS")
                dom_xss_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_dom_xss",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=180
                )
                if isinstance(dom_xss_res, dict) and dom_xss_res.get("status") == "success":
                    data = dom_xss_res.get("data", {})
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-01", "DOM-based XSS detected", 
                                       severity="high", evidence=data,
                                       details=f"Found {len(data.get('sinks', []))} vulnerable DOM sinks")
            except Exception as e:
                self.log("warning", f"DOM XSS testing failed: {e}")

        # 2) JavaScript Execution Context (WSTG-CLNT-02)
        try:
            self.log("info", "Testing JavaScript execution context")
            js_exec_res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="client-side-testing",
                    tool="test_javascript_execution",
                    args={"url": target}, auth_session=auth_data
                ),
                timeout=150
            )
            if isinstance(js_exec_res, dict) and js_exec_res.get("status") == "success":
                data = js_exec_res.get("data", {})
                if data.get("vulnerable"):
                    self.add_finding("WSTG-CLNT-02", "JavaScript execution vulnerabilities detected", 
                                   severity="medium", evidence=data,
                                   details="Unsafe JavaScript execution patterns found")
        except Exception as e:
            self.log("warning", f"JavaScript execution testing failed: {e}")

        # 3) HTML Injection (WSTG-CLNT-03)
        try:
            self.log("info", "Testing for HTML Injection")
            html_inj_res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="client-side-testing",
                    tool="test_html_injection",
                    args={"url": target}, auth_session=auth_data
                ),
                timeout=150
            )
            if isinstance(html_inj_res, dict) and html_inj_res.get("status") == "success":
                data = html_inj_res.get("data", {})
                if data.get("vulnerable"):
                    self.add_finding("WSTG-CLNT-03", "HTML Injection detected", 
                                   severity="medium", evidence=data,
                                   details="User input reflected in HTML without encoding")
        except Exception as e:
            self.log("warning", f"HTML injection testing failed: {e}")

        # 4) Client-side URL Redirect (WSTG-CLNT-04)
        try:
            self.log("info", "Testing for client-side URL redirects")
            redirect_res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="client-side-testing",
                    tool="test_client_url_redirect",
                    args={"url": target}, auth_session=auth_data
                ),
                timeout=120
            )
            if isinstance(redirect_res, dict) and redirect_res.get("status") == "success":
                data = redirect_res.get("data", {})
                if data.get("vulnerable"):
                    self.add_finding("WSTG-CLNT-04", "Client-side URL redirect vulnerability", 
                                   severity="medium", evidence=data,
                                   details="Open redirect via client-side JavaScript")
        except Exception as e:
            self.log("warning", f"URL redirect testing failed: {e}")

        # 5) CSS Injection (WSTG-CLNT-05)
        try:
            self.log("info", "Testing for CSS Injection")
            css_inj_res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="client-side-testing",
                    tool="test_css_injection",
                    args={"url": target}, auth_session=auth_data
                ),
                timeout=120
            )
            if isinstance(css_inj_res, dict) and css_inj_res.get("status") == "success":
                data = css_inj_res.get("data", {})
                if data.get("vulnerable"):
                    self.add_finding("WSTG-CLNT-05", "CSS Injection detected", 
                                   severity="low", evidence=data,
                                   details="CSS can be injected to leak data or deface")
        except Exception as e:
            self.log("warning", f"CSS injection testing failed: {e}")

        # 6) CORS Misconfiguration (WSTG-CLNT-07)
        if self.should_run_tool("test_cors"):
            try:
                self.log("info", "Testing for CORS misconfigurations")
                cors_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_cors",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=150
                )
                if isinstance(cors_res, dict) and cors_res.get("status") == "success":
                    data = cors_res.get("data", {})
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-07", "CORS misconfiguration detected", 
                                       severity="high", evidence=data,
                                       details="Sensitive data accessible to malicious origins")
            except Exception as e:
                self.log("warning", f"CORS testing failed: {e}")

        # 7) Clickjacking (WSTG-CLNT-09)
        if self.should_run_tool("test_clickjacking"):
            try:
                self.log("info", "Testing for Clickjacking vulnerabilities")
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_clickjacking",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-09", "Clickjacking possible (missing XFO/CSP)", 
                                       severity="medium", evidence=data,
                                       details=f"Found {len(data.get('findings', []))} clickjacking issues")
            except Exception as e:
                self.log("warning", f"Clickjacking testing failed: {e}")

        # 8) WebSockets Security (WSTG-CLNT-10)
        if self.should_run_tool("test_websocket"):
            try:
                self.log("info", "Testing WebSocket security")
                ws_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_websocket",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=150
                )
                if isinstance(ws_res, dict) and ws_res.get("status") == "success":
                    data = ws_res.get("data", {})
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-10", "WebSocket security issues detected", 
                                       severity="medium", evidence=data,
                                       details="WebSocket connections lack proper security controls")
            except Exception as e:
                self.log("warning", f"WebSocket testing failed: {e}")

        # 9) Browser Storage Security (WSTG-CLNT-12)
        try:
            self.log("info", "Testing browser storage security")
            storage_res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="client-side-testing",
                    tool="test_browser_storage",
                    args={"url": target}, auth_session=auth_data
                ),
                timeout=150
            )
            if isinstance(storage_res, dict) and storage_res.get("status") == "success":
                data = storage_res.get("data", {})
                if data.get("vulnerable"):
                    severity = "high" if data.get("sensitive_data_exposed") else "medium"
                    self.add_finding("WSTG-CLNT-12", "Insecure browser storage usage", 
                                   severity=severity, evidence=data,
                                   details="Sensitive data stored in localStorage/sessionStorage")
        except Exception as e:
            self.log("warning", f"Browser storage testing failed: {e}")

        # Test CSP (Content Security Policy)
        if self.should_run_tool("test_csp"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_csp",
                        args={"url": target},
                        auth_session=auth_data
                    ),
                    timeout=30
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if not data.get("has_csp") or data.get("weak_directives"):
                        severity = "high" if not data.get("has_csp") else "medium"
                        self.add_finding("WSTG-CLNT", "CSP missing or weak", severity=severity, evidence=data)
            except Exception as e:
                self.log("warning", f"test_csp failed: {e}")

        # Legacy CSP analysis (keep for backward compatibility)
        try:
            res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="client-side-testing",
                    tool="analyze_csp",
                    args={"url": target}, auth_session=auth_data
                )
            )
            if isinstance(res, dict) and res.get("status") == "success":
                weaknesses = res.get("data", {}).get("weaknesses_found", [])
                if weaknesses:
                    self.add_finding("WSTG-CLNT", "CSP weaknesses detected", 
                                   severity="low", evidence={"issues": weaknesses[:3]})
        except Exception as e:
            self.log("warning", f"analyze_csp failed: {e}")

        # Phase 4.3: Test prototype pollution
        if self.should_run_tool("test_prototype_pollution"):
            try:
                res = await client.call_tool(
                    server="client-side-testing",
                    tool="test_prototype_pollution",
                    args={"url": target},
                    auth_session=auth_data
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        severity = "critical" if any(f.get('severity') == 'CRITICAL' for f in data.get('findings', [])) else "high"
                        self.add_finding("WSTG-CLNT-13", "Prototype pollution vulnerabilities detected",
                                       severity=severity, evidence=data,
                                       details="JavaScript prototype pollution via __proto__ or constructor.prototype")
            except Exception as e:
                self.log("warning", f"test_prototype_pollution failed: {e}")

        # Phase 4.3: Test postMessage vulnerabilities
        if self.should_run_tool("test_postmessage_vulnerabilities"):
            try:
                res = await client.call_tool(
                    server="client-side-testing",
                    tool="test_postmessage_vulnerabilities",
                    args={"url": target},
                    auth_session=auth_data
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        severity = "critical" if any(f.get('severity') == 'CRITICAL' for f in data.get('findings', [])) else "high"
                        self.add_finding("WSTG-CLNT-14", "postMessage security vulnerabilities detected",
                                       severity=severity, evidence=data,
                                       details="Cross-origin postMessage without proper origin validation")
            except Exception as e:
                self.log("warning", f"test_postmessage_vulnerabilities failed: {e}")

        # Phase 4.3: Test client-side template injection
        if self.should_run_tool("test_client_side_template_injection"):
            try:
                res = await client.call_tool(
                    server="client-side-testing",
                    tool="test_client_side_template_injection",
                    args={"url": target},
                    auth_session=auth_data
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        severity = "critical" if any(f.get('severity') == 'CRITICAL' for f in data.get('findings', [])) else "high"
                        self.add_finding("WSTG-CLNT-15", "Client-side template injection detected",
                                       severity=severity, evidence=data,
                                       details="Template injection in AngularJS/Vue.js/Handlebars framework")
            except Exception as e:
                self.log("warning", f"test_client_side_template_injection failed: {e}")

        self.log("info", "Client-side checks complete - all 12 WSTG-CLNT enhanced tests executed")

    def _get_available_tools(self) -> list[str]:
        """Return client-side security testing tools for LLM planning"""
        return [
            'test_dom_xss',
            'test_javascript_execution',
            'test_html_injection',
            'test_client_url_redirect',
            'test_css_injection',
            'test_cors_misconfiguration',
            'test_clickjacking',
            'test_websockets',
            'test_browser_storage',
            'test_prototype_pollution',  # Phase 4.3
            'test_postmessage_vulnerabilities',  # Phase 4.3
            'test_client_side_template_injection',  # Phase 4.3
        ]

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
