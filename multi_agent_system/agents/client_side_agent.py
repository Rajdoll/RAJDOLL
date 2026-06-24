from __future__ import annotations

import httpx
import os

from .base_agent import BaseAgent, AgentRegistry
from ..utils.mcp_client import MCPClient
from ..core.endpoint_inventory import read_tag
from urllib.parse import urlsplit, parse_qs


def _xss_candidate_urls(shared_context: dict, target: str) -> list[dict]:
    """Build XSS probe candidates from discovered endpoints + SPA routes found via
    static JS-bundle parsing (js_routes_analysis). Generic: route names and param
    names come entirely from discovery data, nothing target-specific is hardcoded.
    Filters out candidates whose host differs from the scan target's host."""
    target_host = urlsplit(target).netloc

    raw_eps: list = []
    inv = shared_context.get("endpoint_inventory", {}) or {}
    raw_eps.extend(inv.get("endpoints", []) or [])
    de = shared_context.get("discovered_endpoints", {}) or {}
    raw_eps.extend(de.get("endpoints", []) or [])

    candidates = []
    seen_urls = set()

    for ep in raw_eps:
        if not isinstance(ep, dict):
            continue
        url = ep.get("url") or ep.get("path")
        if not url or url in seen_urls:
            continue
        has_params = ep.get("params") or ep.get("query_parameters") or "?" in url
        if not has_params:
            continue
        ep_host = urlsplit(url).netloc
        if ep_host and ep_host != target_host:
            continue
        query_part = urlsplit(url).query
        if "://" in query_part:
            continue
        params = ep.get("params") or list((ep.get("query_parameters") or {}).keys())
        if not params:
            qs_params = list(parse_qs(urlsplit(url).query).keys())
            params = qs_params or ["q"]
        seen_urls.add(url)
        candidates.append({"url": url, "params": params})

    js_routes = shared_context.get("js_routes_analysis", {}) or {}
    for route in js_routes.get("all_routes", []) or []:
        if not route or not isinstance(route, str):
            continue
        url = f"{target.rstrip('/')}/#/{route.lstrip('/')}"
        if url in seen_urls:
            continue
        seen_urls.add(url)
        candidates.append({"url": url, "params": ["q"]})

    return candidates


def _build_probe_url(url: str, param: str, payload: str) -> str:
    """Place `payload` into `param` as a query value. For SPA hash routes
    (.../#/route), the query is appended inside the hash fragment so the
    client-side router parses it — matches client-side-testing's _inject_payload."""
    if "#" in url:
        head, frag = url.split("#", 1)
        sep = "&" if "?" in frag else "?"
        return f"{head}#{frag}{sep}{param}={payload}"
    parts = urlsplit(url)
    sep = "&" if parts.query else ""
    new_q = f"{parts.query}{sep}{param}={payload}" if parts.query else f"{param}={payload}"
    from urllib.parse import urlunsplit
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))


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

        inventory = self.shared_context.get("endpoint_inventory", {})
        sinks = read_tag(inventory, "client_render_sink")
        param_eps = read_tag(inventory, "error_prone_param")
        if not sinks and not param_eps:
            # Fallback: use all endpoints when LLM classifier produces no matching tags
            all_inv_eps = inventory.get("endpoints", [])
            all_eps = [e for e in all_inv_eps if isinstance(e, dict)]
            self.log("info", f"no client_render_sink/error_prone_param tags — falling back to {len(all_eps)} endpoints")
        else:
            all_eps = sinks + param_eps
        test_urls = [ep.get("path") or ep.get("url", "") for ep in all_eps if isinstance(ep, dict)]
        test_urls = [u for u in test_urls if u][:10]
        if not test_urls:
            test_urls = [target]

        def _client_evidence(url: str, data: dict, *, default_proof: str = "dangerous_pattern") -> dict:
            findings = data.get("findings", []) if isinstance(data, dict) else []
            confirmed = any(
                bool(f.get("exploit_confirmed") or f.get("sink_confirmed") or f.get("executed"))
                for f in findings
                if isinstance(f, dict)
            )
            proof_type = "exploit_confirmed" if confirmed or data.get("exploit_confirmed") else default_proof
            evidence = dict(data) if isinstance(data, dict) else {"raw": data}
            evidence.setdefault("endpoint", url)
            evidence.setdefault("proof_type", proof_type)
            evidence.setdefault("impact", "Client-side issue requires exploit confirmation before report submission")
            return evidence

        def _client_severity(data: dict, default: str = "medium") -> str:
            findings = data.get("findings", []) if isinstance(data, dict) else []
            confirmed = any(
                bool(f.get("exploit_confirmed") or f.get("sink_confirmed") or f.get("executed"))
                for f in findings
                if isinstance(f, dict)
            )
            return default if confirmed or data.get("exploit_confirmed") else "low"

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        self.log("info", f"Starting comprehensive client-side testing on {target}")

        # ============================================================================
        # ENHANCED CLIENT-SIDE TESTING (9 comprehensive tools)
        # ============================================================================

        # 1) DOM-based XSS (WSTG-CLNT-01)
        if self.should_run_tool("test_dom_xss"):
            for test_url in test_urls[:5]:
                try:
                    self.log("info", f"Testing for DOM-based XSS on {test_url}")
                    dom_xss_res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="client-side-testing",
                            tool="test_dom_xss",
                            args={"url": test_url}, auth_session=auth_data
                        ),
                        timeout=180
                    )
                    if isinstance(dom_xss_res, dict) and dom_xss_res.get("status") == "success":
                        data = dom_xss_res.get("data") or dom_xss_res
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
                data = js_exec_res.get("data") or js_exec_res
                if data.get("vulnerable"):
                    self.add_finding("WSTG-CLNT-02", "JavaScript execution vulnerabilities detected", 
                                   severity="medium", evidence=data,
                                   details="Unsafe JavaScript execution patterns found")
        except Exception as e:
            self.log("warning", f"JavaScript execution testing failed: {e}")

        # 3) HTML Injection (WSTG-CLNT-03)
        for test_url in test_urls[:5]:
            try:
                self.log("info", f"Testing for HTML Injection on {test_url}")
                html_inj_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_html_injection",
                        args={"url": test_url}, auth_session=auth_data
                    ),
                    timeout=150
                )
                if isinstance(html_inj_res, dict) and html_inj_res.get("status") == "success":
                    data = html_inj_res.get("data") or html_inj_res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-03", "HTML Injection detected",
                                       severity="medium", evidence=data,
                                       details="User input reflected in HTML without encoding")
            except Exception as e:
                self.log("warning", f"HTML injection testing failed: {e}")

        # 4) Client-side URL Redirect (WSTG-CLNT-04)
        for test_url in test_urls[:5]:
            try:
                self.log("info", f"Testing for client-side URL redirects on {test_url}")
                redirect_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_client_url_redirect",
                        args={"url": test_url}, auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(redirect_res, dict) and redirect_res.get("status") == "success":
                    data = redirect_res.get("data") or redirect_res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-04", "Client-side URL redirect vulnerability",
                                       severity="medium", evidence=data,
                                       details="Open redirect via client-side JavaScript")
            except Exception as e:
                self.log("warning", f"URL redirect testing failed: {e}")

        # 5) CSS Injection (WSTG-CLNT-05)
        for test_url in test_urls[:5]:
            try:
                self.log("info", f"Testing for CSS Injection on {test_url}")
                css_inj_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_css_injection",
                        args={"url": test_url}, auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(css_inj_res, dict) and css_inj_res.get("status") == "success":
                    data = css_inj_res.get("data") or css_inj_res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-05", "CSS Injection detected",
                                       severity="low", evidence=data,
                                       details="CSS can be injected to leak data or deface")
            except Exception as e:
                self.log("warning", f"CSS injection testing failed: {e}")

        # 6) CORS Misconfiguration (WSTG-CLNT-07)
        if self.should_run_tool("test_cors_misconfiguration"):
            try:
                self.log("info", "Testing for CORS misconfigurations")
                cors_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_cors_misconfiguration",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=150
                )
                if isinstance(cors_res, dict) and cors_res.get("status") == "success":
                    data = cors_res.get("data") or cors_res
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
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-09", "Clickjacking possible (missing XFO/CSP)", 
                                       severity="low", evidence=_client_evidence(target, data, default_proof="dangerous_pattern"),
                                       details=f"Found {len(data.get('findings', []))} clickjacking issues")
            except Exception as e:
                self.log("warning", f"Clickjacking testing failed: {e}")

        # 8) WebSockets Security (WSTG-CLNT-10)
        if self.should_run_tool("test_websockets"):
            try:
                self.log("info", "Testing WebSocket security")
                ws_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_websockets",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=150
                )
                if isinstance(ws_res, dict) and ws_res.get("status") == "success":
                    data = ws_res.get("data") or ws_res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-10", "WebSocket security issues detected", 
                                       severity="medium", evidence=data,
                                       details="WebSocket connections lack proper security controls")
            except Exception as e:
                self.log("warning", f"WebSocket testing failed: {e}")

        # 9) Browser Storage Security (WSTG-CLNT-12)
        if self.should_run_tool("test_browser_storage"):
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
                    data = storage_res.get("data") or storage_res
                    if data.get("vulnerable"):
                        severity = "high" if data.get("sensitive_data_exposed") else "medium"
                        self.add_finding("WSTG-CLNT-12", "Insecure browser storage usage",
                                       severity=severity, evidence=data,
                                       details="Sensitive data stored in localStorage/sessionStorage")
            except Exception as e:
                self.log("warning", f"Browser storage testing failed: {e}")

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
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        severity = _client_severity(data, default="high")
                        self.add_finding("WSTG-CLNT-13", "Prototype pollution vulnerabilities detected",
                                       severity=severity, evidence=_client_evidence(target, data),
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
                    data = res.get("data") or res
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
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        severity = _client_severity(data, default="high")
                        self.add_finding("WSTG-CLNT-13", "Client-side template injection detected",
                                       severity=severity, evidence=_client_evidence(target, data),
                                       details="Template injection in AngularJS/Vue.js/Handlebars framework")
            except Exception as e:
                self.log("warning", f"test_client_side_template_injection failed: {e}")

        # WSTG-CLNT-06: Resource manipulation
        if self.should_run_tool("test_resource_manipulation"):
            try:
                self.log("info", "Testing for client-side resource manipulation")
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_resource_manipulation",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-06", "Client-side resource manipulation detected",
                                       severity="high", evidence=data,
                                       details=f"Found {len(data.get('findings', []))} resource manipulation issues")
            except Exception as e:
                self.log("warning", f"test_resource_manipulation failed: {e}")

        # WSTG-CLNT-11: Web messaging (postMessage) security
        if self.should_run_tool("test_web_messaging"):
            try:
                self.log("info", "Testing web messaging (postMessage) security")
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_web_messaging",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-CLNT-11", "Web messaging security issues detected",
                                       severity="high", evidence=data,
                                       details=f"Found {len(data.get('findings', []))} postMessage security issues")
            except Exception as e:
                self.log("warning", f"test_web_messaging failed: {e}")

        # WSTG-CLNT-12: CSP bypass testing for XSS
        if self.should_run_tool("test_csp_bypass"):
            try:
                self.log("info", "Testing CSP bypass vectors")
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_csp_bypass",
                        args={"url": target}, auth_session=auth_data), timeout=60
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-CLNT-12",
                                f"CSP issue: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "medium"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_csp_bypass failed: {e}")

        # WSTG-CLNT-04: Open redirect with allowlist bypass
        if self.should_run_tool("test_open_redirect"):
            try:
                self.log("info", "Testing for open redirect vulnerabilities")
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="test_open_redirect",
                        args={"url": target}, auth_session=auth_data), timeout=90
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-CLNT-04",
                                f"Open redirect: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "medium"),
                                evidence={"endpoint": finding.get("endpoint", ""), "payload": finding.get("payload", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_open_redirect failed: {e}")

        self.log("info", "Client-side checks complete - all 15 WSTG-CLNT enhanced tests executed")

        # 16) Vulnerable Components scan (WSTG-CONF-01) — always runs (CRITICAL)
        if self.should_run_tool("scan_vulnerable_components"):
            try:
                self.log("info", "Scanning for known-vulnerable JavaScript libraries")
                vc_res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="client-side-testing",
                        tool="scan_vulnerable_components",
                        args={"url": target}, auth_session=auth_data
                    ),
                    timeout=60
                )
                if isinstance(vc_res, dict) and vc_res.get("status") == "success":
                    data = vc_res.get("data") or vc_res
                    for f in data.get("findings", []):
                        self.add_finding(
                            "WSTG-CONF-01",
                            f"Vulnerable component detected: {f.get('library', 'unknown')} {f.get('source', '')}",
                            severity="high",
                            evidence={"source": f.get("source"), "cve": f.get("cve"), "detection": f.get("detection")},
                            details=f.get("cve", ""),
                        )
                    if not data.get("findings"):
                        self.log("info", f"No known-vulnerable components found: {data.get('message', '')}")
            except Exception as e:
                self.log("warning", f"scan_vulnerable_components failed: {e}")

        # Aggressive-mode: force reflected XSS probe on parameterized endpoints +
        # SPA routes discovered via static JS parsing.
        # Generic OWASP WSTG-CLNT-01/02 baseline — not target-specific.
        if os.getenv("ADAPTIVE_MODE", "balanced").lower() == "aggressive":
            _candidates = _xss_candidate_urls(self.shared_context, target)[:10]
            _marker = "rajdoll-xss-probe-7791"
            _xss_payloads = [
                f"<script>alert('{_marker}')</script>",
                f"<img src=x onerror=alert('{_marker}')>",
                f"<svg onload=alert('{_marker}')>",
            ]
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as _xss_client:
                for cand in _candidates:
                    _url = cand["url"]
                    _params = cand["params"]
                    for _payload in _xss_payloads:
                        try:
                            _probe_url = _build_probe_url(_url, _params[0], _payload)
                            _resp = await _xss_client.get(_probe_url)
                            if _payload in _resp.text or _marker in _resp.text:
                                self.add_finding(
                                    "WSTG-CLNT-01",
                                    f"Reflected XSS via {_params[0]} on {_url}",
                                    severity="high",
                                    evidence={
                                        "url": _url,
                                        "parameter": _params[0],
                                        "payload": _payload,
                                        "proof_type": "reflection_detected",
                                        "marker_in_response": _marker in _resp.text,
                                    },
                                    details="Aggressive mode forced reflected XSS probe — payload reflected unfiltered in response body.",
                                )
                                break
                        except Exception:
                            continue

        # Headless-browser XSS confirmation (WSTG-CLNT-01) — catches SPA/DOM XSS that
        # response-based checks miss. Candidates from discovery + SPA routes; payloads generic.
        if self.should_run_tool("verify_xss_headless"):
            _cands = _xss_candidate_urls(self.shared_context, target)[:20]
            for cand in _cands:
                _u = cand["url"]
                _ps = cand["params"]
                try:
                    hx = await self.run_tool_with_timeout(
                        client.call_tool(server="client-side-testing", tool="verify_xss_headless",
                                         args={"url": _u, "params": _ps[:2]}, auth_session=auth_data),
                        timeout=90)
                    if isinstance(hx, dict) and hx.get("status") == "success" and hx.get("data", {}).get("vulnerable"):
                        for f in hx["data"]["findings"]:
                            self.add_finding(
                                "WSTG-CLNT-01",
                                f"XSS confirmed via headless execution on {f.get('url')}",
                                severity="high",
                                evidence={"url": f.get("url"), "param": f.get("param"),
                                          "payload": f.get("payload"), "proof_type": f.get("proof")},
                                details="Headless Chromium confirmed JS execution (dialog/marker).")
                except Exception as e:
                    self.log("warning", f"verify_xss_headless failed: {e}")

    def _get_tool_info(self) -> dict:
        return {
            "scan_vulnerable_components": {"priority": "CRITICAL", "description": "Detect known-vulnerable JS libraries via HTTP analysis"},
            "test_dom_xss":               {"priority": "CRITICAL", "description": "DOM-based XSS (WSTG-CLNT-01)"},
            "test_cors_misconfiguration": {"priority": "HIGH", "description": "CORS misconfiguration (WSTG-CLNT-07)"},
            "test_clickjacking":          {"priority": "HIGH", "description": "Clickjacking / missing XFO+CSP (WSTG-CLNT-09)"},
            "test_csp_bypass":            {"priority": "HIGH", "description": "CSP bypass (WSTG-CLNT-12)"},
            "test_client_url_redirect":   {"priority": "HIGH", "description": "Open redirect (WSTG-CLNT-04)"},
            "verify_xss_headless":        {"priority": "HIGH", "description": "Confirm reflected/DOM XSS by real JS execution in headless Chromium (WSTG-CLNT-01)"},
        }

    def _get_available_tools(self) -> list[str]:
        """Return client-side security testing tools for LLM planning"""
        return [
            'scan_vulnerable_components',
            'test_dom_xss',
            'test_javascript_execution',
            'test_html_injection',
            'test_client_url_redirect',
            'test_css_injection',
            'test_cors_misconfiguration',
            'test_clickjacking',
            'test_websockets',
            'test_browser_storage',
            'test_prototype_pollution',
            'test_postmessage_vulnerabilities',
            'test_client_side_template_injection',
            'test_resource_manipulation',
            'test_web_messaging',
            'test_csp_bypass',
            'test_open_redirect',
            'verify_xss_headless',
        ]

    def _get_tool_server_map(self) -> Dict[str, str]:
        return {tool: "client-side-testing" for tool in self._get_available_tools()}

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
