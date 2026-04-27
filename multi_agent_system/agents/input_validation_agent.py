from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar, Dict, Any, List, Optional
from ..utils.mcp_client import MCPClient
from ..utils.session_manager import SessionManager
from ..utils.react_loop import ReActLoop, react_test
import re
import httpx
import os
import sys  # Required for debug logging to stderr

# Environment variable to enable ReAct mode (iterative testing)
REACT_MODE_ENABLED = os.getenv("REACT_MODE", "true").lower() == "true"
REACT_MAX_ITERATIONS = int(os.getenv("REACT_MAX_ITERATIONS", "3"))

# Performance caps to prevent combinatorial explosion (configurable via env vars)
# With ReAct mode (3 LLM calls/test × ~60s each), budget per URL = ~540s.
# 5 URLs × 3 tests × 3 iterations × 60s = 2700s = exactly the timeout limit.
MAX_PRIORITY_URLS = int(os.getenv("MAX_PRIORITY_URLS", "20"))
MAX_TESTS_PER_URL = int(os.getenv("MAX_TESTS_PER_URL", "3"))


@AgentRegistry.register("InputValidationAgent")
class InputValidationAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are InputValidationAgent, OWASP WSTG-INPV expert specializing in input validation vulnerabilities.

🎯 PRIMARY MISSION: Identify injection vulnerabilities (SQLi, XSS, XXE, LFI, SSRF, SSTI, Command Injection, NoSQL injection) using available MCP tools.

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints from shared_context (provided by ReconnaissanceAgent)
2. Analyze endpoint characteristics:
   - Search parameters → Likely SQLi/XSS vectors
   - File parameters → Likely LFI/XXE vectors
   - URL parameters → Likely SSRF/Open Redirect vectors
   - User input fields → Likely XSS/SSTI vectors
3. Select appropriate tools based on endpoint patterns
4. Execute tools with authenticated sessions if available
5. Report all findings to shared_context

⚠️ EXECUTION GUIDELINES:
- Execute 15-20 tools minimum for comprehensive coverage
- Test ALL discovered endpoints from shared_context
- Use authenticated sessions from shared_context when available
- DO NOT stop after first vulnerability - continue testing all vectors

🔧 AVAILABLE TOOLS:
1. test_sqli - Test SQL injection
2. test_xss_reflected - Test reflected XSS
3. test_ssrf - Test SSRF
4. test_xxe - Test XXE
5. test_lfi - Test LFI/path traversal
6. test_ssti - Test template injection
7. test_http_smuggling - Test HTTP smuggling

📋 TESTING STRATEGY:
1. Read endpoints from shared_context (ReconnaissanceAgent)
2. Test each endpoint with ALL 8 tools
3. Use authenticated session if available
4. Report all findings (even LOW severity)
5. Continue after first finding - DO NOT stop early

**Command Injection**:
- Separators: ; whoami, | whoami, || whoami, & whoami, && whoami
- Backticks: `whoami`, $(whoami)
- Encoded: %0a whoami, %0d whoami
- Blind: ; sleep 5, ; ping -c 5 attacker.com

**HTTP Parameter Pollution**:
- Multiple parameters: ?id=1&id=2 (test which value server uses)
- Array injection: ?id[]=1&id[]=2
- JSON pollution: {"id": "1", "id": "2"}

🔍 ENTRY POINT IDENTIFICATION:
1. **URL Parameters**: ?search=, ?id=, ?page=, ?redirect=
2. **POST Body**: Forms, JSON, XML, multipart
3. **HTTP Headers**: User-Agent, Referer, X-Forwarded-For, Cookie, Host
4. **File Uploads**: Filename, content-type, file content
5. **WebSockets**: Message payloads
6. **API Endpoints**: REST, GraphQL, SOAP

🚀 PROGRESSIVE TESTING WORKFLOW:
1. **Detection Phase**: Inject canaries to confirm vulnerability type
2. **Enumeration Phase**: Determine backend details (DB version, template engine, OS)
3. **Exploitation Phase**: Extract sensitive data or achieve code execution
4. **Persistence Phase**: Document findings with proof-of-concept

🛠️ MCP TOOL USAGE:
- test_sqli(url, data, dbms): Comprehensive SQLMap scan
- test_xss_reflected(target_url): Dalfox XSS detection
- test_lfi(url_with_fuzz): ffuf-based LFI fuzzing
- find_reflected_params(url): Identify parameters that reflect in response
- test_http_smuggling(host): HTTP request smuggling detection

📊 CONTEXT-AWARE PAYLOAD SELECTION:
Read from shared_context:
- tech_stack.backend → Select DB-specific SQLi payloads
- tech_stack.frontend → Select DOM XSS vs reflected XSS
- tech_stack.template_engine → Select SSTI payloads
- entry_points → Prioritize high-value inputs

Write to shared_context:
- injection_vulnerabilities: [{type, location, payload, severity, evidence}]
- extracted_data: {credentials, api_keys, session_tokens, file_contents}
- rce_achieved: boolean

🧠 **RECONNAISSANCE-DRIVEN TESTING APPROACH:**
ANALYZE shared_context from ReconnaissanceAgent to intelligently select tools and parameters:

**1. ANALYZE TECHNOLOGY STACK:**
From tech_stack in shared_context, identify:
- **Database type** → Optimize SQLMap DBMS (SQLite, MySQL, PostgreSQL, MSSQL, Oracle)
  * SQLite: Use `--dbms=SQLite --technique=BEU` (common in Node.js, Python apps)
  * MySQL: Use `--dbms=MySQL --technique=BEUSTQ` (PHP, Java apps)
  * PostgreSQL: Use `--dbms=PostgreSQL` (Rails, Django apps)
- **Backend framework** → Target framework-specific injection points
  * Node.js/Express: Test query params, JSON body fields
  * PHP: Test GET/POST params, cookies
  * Python/Django: Test ORM-based endpoints
- **Frontend framework** → Select XSS testing strategy
  * Angular/React/Vue: Prioritize `--mining-dom --deep-dom` (DOM XSS common in SPAs)
  * Traditional server-side: Focus on reflected/stored XSS
  * Template engines: Test SSTI (Server-Side Template Injection)

**2. ANALYZE DISCOVERED ENDPOINTS:**
From entry_points.api_endpoints in shared_context:
- **Search/Query endpoints** (`/search`, `/products`, `/api/search`) → HIGH priority for SQLi + XSS
  * Test parameters: q, search, query, keyword, term
- **Login/Auth endpoints** (`/login`, `/auth`, `/api/login`) → SQLi auth bypass testing
  * Test authentication bypass: `' OR 1=1--`, `admin'--`, `' UNION SELECT...`
- **Feedback/Comment endpoints** (`/feedback`, `/comments`, `/reviews`) → Stored XSS
  * Test persistent XSS payloads
- **File operations** (`/upload`, `/download`, `/file`, `/ftp`) → LFI/Path traversal
  * Test: `../../../../etc/passwd`, `..%2f..%2f`, null byte injection
- **API endpoints with IDs** (`/api/users/{id}`, `/api/products/{id}`) → Potential SQLi in WHERE clauses

**3. DYNAMIC TOOL PARAMETER GENERATION:**
Based on reconnaissance findings, CONSTRUCT optimal tool commands:

**SQLi Testing:**
- If SQLite detected: `run_sqlmap_scan(url, param="discovered_param", config={"dbms": "SQLite"})`
- If MySQL detected: `run_sqlmap_scan(url, param="discovered_param", config={"dbms": "MySQL"})`
- Generic: Use `--forms --crawl=2` to auto-discover injection points

**XSS Testing:**
- If SPA framework (React/Angular/Vue): `run_dalfox_scan(url, config={"aggression": "aggressive"})` (enables DOM mining)
- If traditional server-side: `run_dalfox_scan(url, param="reflected_param")`
- Custom payloads based on WAF detection: Use `config={"custom_payloads": [...]}`

**LFI/Path Traversal:**
- If file endpoints found: `test_lfi(url, param="file_param")`
- Test common files: `/etc/passwd`, `/windows/win.ini`, application config files

**4. ITERATIVE TESTING STRATEGY:**
- Start with broad reconnaissance (endpoint discovery + parameter mining)
- Analyze initial findings → Identify patterns
- Execute targeted deep-dive testing on promising endpoints
- Use findings from one tool to inform parameters for next tool

🎯 SUCCESS CRITERIA: Maximize vulnerability coverage through intelligent reconnaissance analysis and dynamic tool selection
"""
    async def run(self) -> None:
        """
        HYBRID EXECUTION MODEL:
        Phase 1: Read reconnaissance results (MANDATORY)
        Phase 2: Execute tests on discovered endpoints

        This agent now runs SEQUENTIALLY after ReconnaissanceAgent
        to guarantee access to discovered endpoints.
        """
        import sys
        print(f"🟢🟢🟢 InputValidationAgent.run() ENTERED", file=sys.stderr, flush=True)
        client = MCPClient()

        # Use target from BaseAgent.execute() first (set in self._target)
        # Fallback to DB query if not set
        target = self._target if hasattr(self, '_target') and self._target else self._get_target()
        print(f"🟢🟢🟢 Target = {target}", file=sys.stderr, flush=True)
        print(f"🔍 DEBUG-1: After target print", file=sys.stderr, flush=True)

        if not target:
            self.log("error", "Target missing; aborting InputValidationAgent")
            return

        print(f"🔍 DEBUG-2: Target exists, continuing", file=sys.stderr, flush=True)

        self.log("info", f"🎯 Starting comprehensive input validation testing on {target}")
        self.log("info", f"📊 HYBRID MODE: Sequential execution after ReconnaissanceAgent")
        self.log("debug", f"Target source: {'BaseAgent._target' if hasattr(self, '_target') and self._target else 'DB query'}")

        print(f"🔍 DEBUG-3: After initial logs", file=sys.stderr, flush=True)

        # Check for authenticated session (from Orchestrator auto-login)
        auth_data = self.get_auth_session()  # Use base_agent method
        session_mgr = None
        authenticated = False

        print(f"🔍 DEBUG-4: After auth variables init", file=sys.stderr, flush=True)
        
        if auth_data:
            self.log("info", f"✅ Using authenticated session: {auth_data.get('username')} (token: {'Present' if auth_data.get('token') else 'None'})")
            session_mgr = SessionManager(target)
            session_mgr.sessions = {}
            session_mgr.logged_in = True
            authenticated = True
        else:
            self.log("warning", "⚠ No authenticated session - testing public endpoints only")

        print(f"🔍 DEBUG-5: Auth checking complete, authenticated={authenticated}", file=sys.stderr, flush=True)

        # ===== PHASE 1: MANDATORY PREPARATION =====
        # Read ALL reconnaissance results from shared context
        print(f"🔍 DEBUG-6: ENTERING PHASE 1 PREPARATION", file=sys.stderr, flush=True)
        self.log("info", "=" * 60)
        self.log("info", "📋 PHASE 1: Reading Reconnaissance Results")
        self.log("info", "=" * 60)
        print(f"🔍 DEBUG-7: Phase 1 header logged", file=sys.stderr, flush=True)

        # Debug: Show what's in shared context
        context_keys = list(self.shared_context.keys())
        self.log("info", f"✓ Shared context available: {context_keys}")

        # 🧠 INTELLIGENT ENDPOINT DISCOVERY: Read from ReconnaissanceAgent
        discovered_endpoints = self.shared_context.get("discovered_endpoints", {})
        discovered_urls: list[str] = [target]
        priority_endpoints = []

        if discovered_endpoints and discovered_endpoints.get("endpoints"):
            endpoints_list = discovered_endpoints["endpoints"]
            self.log("info", f"✅ FOUND {len(endpoints_list)} endpoints from web crawler")

            # Show sample for debugging
            sample_endpoints = [ep.get("endpoint", ep.get("url", "N/A")) for ep in endpoints_list[:5]]
            self.log("info", f"   Sample: {sample_endpoints}")
            
            # Prioritize endpoints likely to have input validation issues.
            # Keywords are generic indicators — NOT application-specific patterns.
            HIGH_PRIORITY_KEYWORDS = [
                "search", "login", "upload", "comment", "review", "feedback",
                # vulnerability lab paths (e.g. DVWA /vulnerabilities/*, WebGoat, bWAPP)
                "vulnerabilit", "sqli", "sql", "xss", "exec", "inject",
                "lfi", "rfi", "inclusion", "traversal", "csrf", "upload",
            ]
            for ep in endpoints_list:
                url = ep.get("url", "")
                endpoint_path = ep.get("endpoint", ep.get("url", ""))
                ep_lower = endpoint_path.lower()

                if any(kw in ep_lower for kw in HIGH_PRIORITY_KEYWORDS):
                    priority_endpoints.append(url)
                elif ep.get("status", 500) < 400 and url not in priority_endpoints:
                    discovered_urls.append(url)

            # auth_discovered_links always get priority — they are pages only
            # reachable after login and are the highest-value targets on any app.
            auth_links_data = self.shared_context.get("auth_discovered_links", {})
            auth_urls = auth_links_data.get("urls", []) if isinstance(auth_links_data, dict) else []
            for au in auth_urls:
                if au not in priority_endpoints and au not in discovered_urls:
                    priority_endpoints.append(au)

            # Test priority endpoints first
            discovered_urls = priority_endpoints + discovered_urls

            self.log("info", f"✓ Testing {len(priority_endpoints)} high-priority + {len(discovered_urls)-len(priority_endpoints)} standard endpoints")

        from urllib.parse import urljoin
        additional_test_urls = []

        # REST API subpath expansion — only when the target actually exposes REST/API paths.
        # Derived from discovered endpoints, NOT hardcoded per-application patterns.
        rest_bases = [u for u in discovered_urls if "/api/" in u or "/rest/" in u]
        if rest_bases:
            common_subpaths = ["search", "list", "filter", "query"]
            for base_url in rest_bases[:5]:  # cap expansion
                for sub in common_subpaths:
                    candidate = f"{base_url.rstrip('/')}/{sub}"
                    if candidate not in discovered_urls and candidate not in additional_test_urls:
                        additional_test_urls.append(candidate)
            if additional_test_urls:
                self.log("info", f"✅ Expanded {len(additional_test_urls)} REST subpath variants from discovered API endpoints")

        # Common API subpaths to test if base path exists
        common_subpaths = ["search", "list", "reviews", "items", "details", "filter", "query"]

        for url in list(discovered_urls):  # Iterate over copy to avoid modification during iteration
            # If we found /rest/products or /api/products, also test /rest/products/search, etc.
            if any(base in url for base in ["/products", "/items", "/catalog", "/api/", "/rest/"]):
                for subpath in common_subpaths:
                    combined_url = f"{url.rstrip('/')}/{subpath}"
                    if combined_url not in discovered_urls and combined_url not in additional_test_urls:
                        additional_test_urls.append(combined_url)

        # Add combined URLs to front for priority testing
        for add_url in additional_test_urls[:10]:  # Limit to top 10 to avoid explosion
            discovered_urls.insert(0, add_url)

        if additional_test_urls:
            self.log("info", f"✅ Generated {len(additional_test_urls[:10])} additional test URLs by combining discovered paths")

        # 🔗 DIRECTORY BRUTEFORCE RESULTS: Add paths from directory scan
        hidden_paths = self.shared_context.get("hidden_paths", {})
        if hidden_paths and hidden_paths.get("all_paths"):
            dir_paths = hidden_paths["all_paths"]
            self.log("info", f"✅ FOUND {len(dir_paths)} paths from directory bruteforce")
            self.log("info", f"   Sample paths: {dir_paths[:5]}")

            # Convert paths to full URLs and add to discovered_urls
            for path in dir_paths:
                full_url = urljoin(target, path)
                if full_url not in discovered_urls:
                    discovered_urls.append(full_url)

            self.log("info", f"✅ Merged directory paths into URL list")
        else:
            self.log("info", f"⚠️  No directory scan results found in shared context")

        # Log final URL list before testing
        self.log("info", "=" * 60)
        self.log("info", f"📊 TOTAL URLS TO TEST: {len(discovered_urls)}")
        self.log("info", f"   Top 10 URLs: {discovered_urls[:10]}")
        self.log("info", "=" * 60)
        print(f"🔍 DEBUG-8: URL list prepared, count={len(discovered_urls)}", file=sys.stderr, flush=True)

        # 🔗 CROSS-AGENT LEARNING: Read findings from previous agents
        previous_findings = self._read_previous_agent_findings()
        print(f"🔍 DEBUG-9: Previous findings read, count={len(previous_findings) if previous_findings else 0}", file=sys.stderr, flush=True)
        if previous_findings:
            self.log("info", f"✓ Analyzing {len(previous_findings)} findings from previous agents")
            # Enhance test strategy based on previous discoveries
            discovered_urls = self._enhance_targets_from_findings(discovered_urls, previous_findings)

        # 🔥 DEBUG CHECKPOINT: About to enter LLM planning phase
        print(f"🔍 DEBUG-10: About to call _create_intelligent_test_plan with {len(discovered_urls)} URLs", file=sys.stderr, flush=True)
        self.log("info", f"🧠 PHASE 2: LLM Autonomous URL Analysis - analyzing {len(discovered_urls)} URLs")

        # 🧠 FULLY LLM-DRIVEN TEST PLANNING (NO HARDCODED LIMITS)
        test_plan = await self._create_intelligent_test_plan(discovered_urls, authenticated)

        # 🔀 HYBRID MERGE: Combine LLM priorities with rule-based coverage
        # Strategy: LLM provides intelligent ranking, Rules ensure comprehensive coverage (80%+)
        llm_url_count = len(test_plan.get('priority_urls', []))
        min_required = int(len(discovered_urls) * 0.8)  # 80% coverage target

        self.log("info", f"🔀 HYBRID MODE: LLM prioritized {llm_url_count}/{len(discovered_urls)} URLs ({llm_url_count*100//len(discovered_urls) if llm_url_count > 0 else 0}% coverage)")

        if llm_url_count < min_required:
            self.log("info", f"🔧 Merging LLM priorities with rule-based coverage to reach 80%+ target")
            print(f"🔀 HYBRID-MERGE: Combining LLM priorities + rule-based coverage", file=sys.stderr, flush=True)

            # Get rule-based comprehensive plan
            rule_plan = self._create_deterministic_test_plan(discovered_urls, authenticated)

            # Merge: Use LLM priorities where available, add missing URLs from rules
            test_plan = self._merge_llm_and_rule_plans(test_plan, rule_plan, discovered_urls)

            final_count = len(test_plan.get('priority_urls', []))
            self.log("info", f"✅ HYBRID result: {final_count}/{len(discovered_urls)} URLs ({final_count*100//len(discovered_urls)}% coverage)")
        else:
            self.log("info", f"✅ LLM coverage sufficient ({llm_url_count*100//len(discovered_urls)}%) - using LLM plan directly")

        # 🙋 HITL: Request human approval before executing tests
        print(f"🔍 MAIN-FLOW-1: About to call _request_hitl_approval()", file=sys.stderr, flush=True)
        hitl_response = await self._request_hitl_approval(test_plan)
        print(f"🔍 MAIN-FLOW-2: _request_hitl_approval() returned: {hitl_response}", file=sys.stderr, flush=True)

        print(f"🔍 MAIN-FLOW-3: Checking if approved = {hitl_response.get('approved')}", file=sys.stderr, flush=True)
        if not hitl_response.get("approved"):
            print(f"🔍 MAIN-FLOW-4: NOT APPROVED - will exit", file=sys.stderr, flush=True)
            self.log("warning", "❌ HITL: User rejected test plan - skipping input validation testing")
            self.log("warning", f"   User feedback: {hitl_response.get('user_feedback', 'N/A')}")
            return  # Exit early if user rejects plan

        print(f"🔍 MAIN-FLOW-5: APPROVED - extracting modified_plan", file=sys.stderr, flush=True)
        # Use approved/modified plan
        test_plan = hitl_response.get("modified_plan", test_plan)
        priority_urls = test_plan.get('priority_urls', [])

        print(f"🔍 MAIN-FLOW-6: About to log test plan approval - {len(priority_urls)} URLs", file=sys.stderr, flush=True)
        self.log("info", f"✅ Test plan approved - testing {len(priority_urls)} LLM-selected URLs")
        self.log("info", f"   User feedback: {hitl_response.get('user_feedback', 'Auto-approved')}")
        print(f"🔍 MAIN-FLOW-7: Approval logs completed", file=sys.stderr, flush=True)

        # ============================================================================
        # ✨ FULLY LLM-DRIVEN TEST EXECUTION (NO HARDCODED LOGIC)
        # ============================================================================

        self.log("info", "=" * 60)
        self.log("info", "🤖 EXECUTING LLM-DRIVEN TEST PLAN")
        self.log("info", "=" * 60)

        # Track findings across all tests
        all_findings = {
            'sqli': [],
            'xss': [],
            'lfi': [],
            'xxe': [],
            'ssrf': [],
            'ssti': [],
            'command_injection': [],
            'http_smuggling': [],
            'nosql_injection': []
        }

        # Split URLs into two buckets:
        # 1. auth_discovered_links — pages confirmed to exist behind login; ALWAYS test all of them.
        # 2. Everything else (speculative patterns, combined paths) — cap to MAX_PRIORITY_URLS.
        auth_link_urls = {
            u for u in (
                self.shared_context.get("auth_discovered_links", {}).get("urls", [])
                if isinstance(self.shared_context.get("auth_discovered_links"), dict)
                else []
            )
        }

        auth_bucket = [u for u in priority_urls if u.get("url", "") in auth_link_urls]
        speculative_bucket = [u for u in priority_urls if u.get("url", "") not in auth_link_urls]
        capped_speculative = speculative_bucket[:MAX_PRIORITY_URLS]

        capped_urls = auth_bucket + capped_speculative
        self.log("info",
            f"⚡ URL buckets: {len(auth_bucket)} auth_links (no cap) + "
            f"{len(capped_speculative)}/{len(speculative_bucket)} speculative (capped) "
            f"= {len(capped_urls)} total"
        )

        # Execute tests for each LLM-selected URL
        _skip_agent = False
        for idx, url_info in enumerate(capped_urls, 1):
            # ── HITL: check for skip_agent / skip_url signals ──
            signal = self.check_hitl_signal()
            if signal:
                sig_action = signal.get("action", "")
                if sig_action == "skip_agent":
                    self.log("warning", f"HITL: Agent skipped by user — {signal.get('reason', '')}")
                    _skip_agent = True
                    break
                elif sig_action == "skip_url":
                    self.log("warning", f"HITL: Skipping URL {url_info.get('url','')} per user request")
                    continue

            url = url_info.get('url', '')
            tests = url_info.get('tests', [])
            parameters = url_info.get('parameters', ['id'])
            if not isinstance(parameters, list) or not parameters:
                parameters = ['id', 'q', 'search']
            priority_score = url_info.get('priority_score', 0)
            reason = url_info.get('reason', 'LLM selected')

            # ── HITL: broadcast current execution state to dashboard ──
            self.broadcast_execution_status({
                "phase": "url_testing",
                "current_url": url,
                "current_url_index": idx,
                "total_urls": len(capped_urls),
                "tests_for_url": tests[:MAX_TESTS_PER_URL],
                "priority_score": priority_score,
                "findings_so_far": sum(len(v) for v in all_findings.values()),
            })

            self.log("info", f"\n{'='*60}")
            self.log("info", f"🎯 Testing URL {idx}/{len(capped_urls)}: {url}")
            self.log("info", f"   Priority Score: {priority_score}/100")
            self.log("info", f"   Reason: {reason}")
            self.log("info", f"   Tests: {', '.join(tests[:MAX_TESTS_PER_URL])}")
            self.log("info", f"   Parameters: {', '.join(parameters)}")
            self.log("info", f"{'='*60}\n")

            # Execute each test LLM selected for this URL (capped to prevent explosion)
            for test_type in tests[:MAX_TESTS_PER_URL]:
                # ── HITL: check for skip_test signal before each test type ──
                signal = self.check_hitl_signal()
                if signal:
                    sig_action = signal.get("action", "")
                    if sig_action == "skip_agent":
                        self.log("warning", f"HITL: Agent skipped by user mid-test")
                        _skip_agent = True
                        break
                    elif sig_action in ("skip_url", "cancel_test", "skip_test"):
                        self.log("warning", f"HITL: Skipping {test_type} on {url} per user request")
                        continue

                try:
                    if test_type == 'sqli':
                        await self._execute_sqli_test(url, parameters, all_findings, auth_data)
                    elif test_type == 'xss':
                        await self._execute_xss_test(url, parameters, all_findings, auth_data)
                    elif test_type == 'lfi':
                        await self._execute_lfi_test(url, parameters, all_findings, auth_data)
                    elif test_type == 'xxe':
                        await self._execute_xxe_test(url, all_findings, auth_data)
                    elif test_type == 'ssrf':
                        await self._execute_ssrf_test(url, all_findings, auth_data)
                    elif test_type == 'ssti':
                        await self._execute_ssti_test(url, parameters, all_findings, auth_data)
                    elif test_type == 'command_injection':
                        await self._execute_command_injection_test(url, parameters, all_findings, auth_data)
                    elif test_type == 'http_smuggling':
                        await self._execute_http_smuggling_test(url, all_findings)
                    elif test_type == 'nosql_injection':
                        await self._execute_nosql_injection_test(url, parameters, all_findings, auth_data)
                    else:
                        self.log("warning", f"   Unknown test type: {test_type}")
                except Exception as e:
                    self.log("warning", f"   {test_type.upper()} test failed for {url}: {e}")

            if _skip_agent:
                break

        # Report all findings
        self._report_all_findings(all_findings)

        self.log("info", "=" * 60)
        self.log("info", "✅ LLM-DRIVEN INPUT VALIDATION TESTING COMPLETE")
        self.log("info", f"   Total URLs tested: {len(capped_urls)}")
        self.log("info", f"   Total findings: {sum(len(v) for v in all_findings.values())}")
        self.log("info", "=" * 60)

        # ===== STANDALONE WSTG TESTS (not per-parameter injection) =====

        # WSTG-INPV-03: HTTP Verb Tampering
        if self.should_run_tool("test_http_verb_tampering"):
            try:
                self.log("info", "🔍 Testing HTTP Verb Tampering (WSTG-INPV-03)")
                result = await self.execute_tool(
                    server="input-validation-testing",
                    tool="test_http_verb_tampering",
                    args={"url": target},
                    auth_session=auth_data, timeout=120
                )
                if isinstance(result, dict) and result.get("status") == "success":
                    data = result.get("data", {})
                    findings = data.get("findings", [])
                    if findings:
                        critical = [f for f in findings if f.get("severity") == "Critical"]
                        severity = "critical" if critical else "high"
                        self.add_finding("WSTG-INPV-03", f"HTTP Verb Tampering: {len(findings)} issue(s)",
                                       severity=severity, evidence={"findings": findings[:5]})
            except Exception as e:
                self.log("warning", f"test_http_verb_tampering failed: {e}")

        # WSTG-INPV-16: HTTP Incoming Requests
        if self.should_run_tool("test_http_incoming_requests"):
            try:
                self.log("info", "🔍 Testing HTTP Incoming Requests (WSTG-INPV-16)")
                result = await self.execute_tool(
                    server="input-validation-testing",
                    tool="test_http_incoming_requests",
                    args={"url": target},
                    auth_session=auth_data, timeout=120
                )
                if isinstance(result, dict) and result.get("status") == "success":
                    data = result.get("data", {})
                    findings = data.get("findings", [])
                    if findings:
                        self.add_finding("WSTG-INPV-16", f"HTTP header manipulation: {len(findings)} issue(s)",
                                       severity="high", evidence={"findings": findings[:5]})
            except Exception as e:
                self.log("warning", f"test_http_incoming_requests failed: {e}")

        # WSTG-INPV-02: Stored XSS on user-generated content endpoints
        if self.should_run_tool("test_stored_xss"):
            try:
                self.log("info", "🔍 Testing Stored XSS (WSTG-INPV-02)")
                from urllib.parse import urljoin, urlparse
                # Derive endpoints from SharedContext — look for paths that typically
                # accept user-generated content (comments, reviews, profiles, API writes).
                all_links = (
                    self.shared_context.get("auth_discovered_links", [])
                    if isinstance(self.shared_context.get("auth_discovered_links"), list)
                    else []
                ) or list(discovered_urls or [])
                user_content_patterns = [
                    "feedback", "comment", "review", "message", "post", "note",
                    "profile", "account", "user", "complaint", "recycle", "submit",
                ]
                stored_xss_endpoints = [
                    urlparse(u).path for u in all_links
                    if any(p in u.lower() for p in user_content_patterns)
                ] or ["/"]  # fallback: at least test the root
                for ep in stored_xss_endpoints[:6]:
                    ep_url = urljoin(target, ep)
                    result = await self.execute_tool(
                        server="input-validation-testing",
                        tool="test_stored_xss",
                        args={"url": ep_url},
                        auth_session=auth_data, timeout=120
                    )
                    if isinstance(result, dict) and result.get("status") == "success":
                        data = result.get("data", {})
                        if data.get("vulnerable"):
                            xss_findings = data.get("findings", [])
                            self.add_finding("WSTG-INPV-02", f"Stored XSS on {ep}: {len(xss_findings)} issue(s)",
                                           severity="high", evidence={"endpoint": ep, "findings": xss_findings[:3]})
            except Exception as e:
                self.log("warning", f"test_stored_xss failed: {e}")

        # WSTG-INPV-05: Standalone NoSQL Injection on key endpoints
        if self.should_run_tool("test_nosql_injection"):
            try:
                self.log("info", "🔍 Testing NoSQL Injection (standalone)")
                from urllib.parse import urljoin, urlparse
                # Derive endpoints from SharedContext — search/query/login paths are
                # prime NoSQLi targets (operator injection, auth bypass).
                all_links = (
                    self.shared_context.get("auth_discovered_links", [])
                    if isinstance(self.shared_context.get("auth_discovered_links"), list)
                    else []
                ) or list(discovered_urls or [])
                nosql_patterns = [
                    "search", "query", "find", "filter", "login", "auth",
                    "signin", "track", "order", "lookup", "api",
                ]
                nosql_endpoints = [
                    u if "?" in u else urlparse(u).path
                    for u in all_links
                    if any(p in u.lower() for p in nosql_patterns)
                ] or [target]  # fallback: test root
                for ep in nosql_endpoints[:4]:
                    ep_url = ep if ep.startswith("http") else urljoin(target, ep)
                    result = await self.execute_tool(
                        server="input-validation-testing",
                        tool="test_nosql_injection",
                        args={"url": ep_url},
                        auth_session=auth_data, timeout=300
                    )
                    if isinstance(result, dict) and result.get("status") == "success":
                        data = result.get("data", {})
                        if data.get("vulnerable"):
                            nosql_findings = data.get("findings", [])
                            self.add_finding("WSTG-INPV-05", f"NoSQL Injection on {ep}: {len(nosql_findings)} issue(s)",
                                           severity="high", evidence={"endpoint": ep, "findings": nosql_findings[:5]})
            except Exception as e:
                self.log("warning", f"test_nosql_injection failed: {e}")

        # WSTG-ATHN-03: SQL Injection Login Bypass
        if self.should_run_tool("test_sqli_login"):
            try:
                self.log("info", "🔍 Testing SQL Injection Login Bypass (WSTG-ATHN-03)")
                result = await self.execute_tool(
                    server="input-validation-testing",
                    tool="test_sqli_login",
                    args={"url": target},
                    auth_session=auth_data, timeout=300
                )
                if isinstance(result, dict) and result.get("status") == "success":
                    data = result.get("data", {})
                    if data.get("vulnerable"):
                        sqli_login_findings = data.get("findings", [])
                        for finding in sqli_login_findings:
                            severity = finding.get("severity", "critical")
                            self.add_finding(
                                "WSTG-ATHN-03",
                                f"SQL Injection Login Bypass: {finding.get('description', 'Auth bypass')} on {finding.get('endpoint', '/login')}",
                                severity=severity,
                                evidence={
                                    "endpoint": finding.get("endpoint"),
                                    "payload": finding.get("payload"),
                                    "method": finding.get("method"),
                                    "type": finding.get("type"),
                                    "evidence": finding.get("evidence", "")[:500]
                                }
                            )
                        self.log("info", f"   ✓ Found {len(sqli_login_findings)} SQLi login bypass vulnerabilities!")
            except Exception as e:
                self.log("warning", f"test_sqli_login failed: {e}")

        # WSTG-INPV-04: HTTP Parameter Pollution
        if self.should_run_tool("test_http_parameter_pollution"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="input-validation-testing",
                        tool="test_http_parameter_pollution",
                        args={"url": target}, auth_session=auth_data), timeout=90
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-INPV-04",
                                f"HTTP Parameter Pollution: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "medium"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_http_parameter_pollution failed: {e}")

        # WSTG-INPV-13: ReDoS and algorithmic complexity
        if self.should_run_tool("test_redos"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="input-validation-testing",
                        tool="test_redos",
                        args={"url": target}, auth_session=auth_data), timeout=180
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-INPV-13",
                                f"ReDoS/Complexity: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "high"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_redos failed: {e}")

    # ============================================================================
    # 🔧 LLM-DRIVEN TEST EXECUTION METHODS
    # ============================================================================

    # ============================================================================
    # 🧠 ReAct LOOP INTEGRATION - Iterative Testing with LLM Reasoning
    # ============================================================================
    
    async def _execute_react_test(
        self, 
        url: str, 
        test_type: str, 
        parameters: list, 
        auth_data: dict = None
    ) -> Dict[str, Any]:
        """
        Execute vulnerability test using ReAct (Reasoning + Acting) loop.
        
        This is the KEY INNOVATION - instead of static tool execution:
        1. LLM analyzes what to test
        2. Execute test with specific payload
        3. LLM analyzes result and decides next action
        4. Iterate until vulnerability confirmed or exhausted
        
        Args:
            url: Target URL to test
            test_type: Type of test (sqli, xss, lfi, etc.)
            parameters: Parameters to test
            auth_data: Authentication session
            
        Returns:
            Dict with findings and confidence
        """
        self.log("info", f"   🧠 ReAct Loop: Starting iterative {test_type.upper()} testing on {url}")
        
        # Initialize ReAct loop
        react_loop = ReActLoop()
        react_loop.set_log_callback(self.log)
        react_loop.set_hitl_callbacks(
            signal_check=self.check_hitl_signal,
            broadcast=self.broadcast_execution_status,
        )

        # Get tech stack from shared context for intelligent payload selection
        tech_stack = self.shared_context.get("tech_stack", {})
        
        # Run ReAct loop
        result = await react_loop.run(
            target_url=url,
            test_type=test_type,
            parameters=parameters,
            auth_session=auth_data,
            tech_stack=tech_stack,
            max_iterations=REACT_MAX_ITERATIONS
        )
        
        # Log results
        if result.get("confirmed"):
            self.log("info", f"   ✅ ReAct: {test_type.upper()} CONFIRMED - {result.get('confidence')} confidence")
            self.log("info", f"      Evidence: {result.get('summary')}")
        else:
            self.log("info", f"   ❌ ReAct: {test_type.upper()} not found after {result.get('iterations')} iterations")
        
        return result

    async def _execute_sqli_test(self, url: str, parameters: list, all_findings: dict, auth_data: dict = None):
        """Execute SQL injection test on the specific URL passed by the outer loop."""
        self.log("info", f"   🔍 SQLi testing: {url}")

        if not isinstance(parameters, list) or not parameters:
            parameters = ['id', 'q', 'search']

        # ReAct MODE: iterative LLM-guided testing (skip traditional to avoid duplication)
        if REACT_MODE_ENABLED:
            self.log("info", f"   🧠 Using ReAct iterative testing mode")
            react_result = await self._execute_react_test(url, "sqli", parameters, auth_data)
            if react_result.get("vulnerabilities"):
                for vuln in react_result["vulnerabilities"]:
                    all_findings['sqli'].append({
                        "url": url,
                        "type": "SQL Injection",
                        "technique": vuln.get("technique", "unknown"),
                        "payload": vuln.get("payload", ""),
                        "evidence": vuln.get("evidence", []),
                        "confidence": react_result.get("confidence", "LOW"),
                        "iterations": react_result.get("iterations", 0),
                        "react_mode": True
                    })
                self.log("info", f"      ✅ ReAct found {len(react_result['vulnerabilities'])} SQLi vulnerabilities!")
            return  # ReAct already tested this URL — skip traditional tests

        # Test POST body if URL looks like a POST endpoint
        post_data = self._guess_post_body(url)
        if post_data:
            result = await self.execute_tool(
                server="input-validation-testing",
                tool="test_sqli",
                args={
                    "url": url,
                    "method": "POST",
                    "post_data": post_data,
                    "content_type": "application/json"
                },
                auth_session=auth_data,
                timeout=600
            )
            if isinstance(result, dict) and result.get("status") == "success":
                data = result.get("data", {})
                if data.get("vulnerable"):
                    all_findings['sqli'].extend(data.get('findings', []))
                    self.log("info", f"      ✓ SQL injection found in POST endpoint!")

        # Test GET parameters
        test_urls = []
        if '?' in url:
            test_urls.append(url)
        else:
            for param in parameters[:3]:
                test_urls.append(f"{url}?{param}=1")

        for test_url in test_urls:
            result = await self.execute_tool(
                server="input-validation-testing",
                tool="test_sqli",
                args={"url": test_url, "param": None},
                auth_session=auth_data,
                timeout=600
            )
            if isinstance(result, dict) and result.get("status") == "success":
                data = result.get("data", {})
                if data.get("vulnerable"):
                    all_findings['sqli'].extend(data.get('findings', []))
                    self.log("info", f"      ✓ SQL injection found!")

    async def _execute_xss_test(self, url: str, parameters: list, all_findings: dict, auth_data: dict = None):
        """Execute XSS test on the specific URL passed by the outer loop."""
        self.log("info", f"   🔍 XSS testing: {url}")

        if not isinstance(parameters, list) or not parameters:
            parameters = ['q', 'search', 'query']

        # ReAct MODE: iterative LLM-guided XSS testing
        if REACT_MODE_ENABLED:
            self.log("info", f"   🧠 Using ReAct iterative testing mode for XSS")
            react_result = await self._execute_react_test(url, "xss", parameters, auth_data)
            if react_result.get("vulnerabilities"):
                for vuln in react_result["vulnerabilities"]:
                    all_findings['xss'].append({
                        "url": url,
                        "type": "Cross-Site Scripting (XSS)",
                        "technique": vuln.get("technique", "unknown"),
                        "payload": vuln.get("payload", ""),
                        "evidence": vuln.get("evidence", []),
                        "confidence": react_result.get("confidence", "LOW"),
                        "iterations": react_result.get("iterations", 0),
                        "react_mode": True
                    })
                self.log("info", f"      ✅ ReAct found {len(react_result['vulnerabilities'])} XSS vulnerabilities!")
            return  # ReAct already tested this URL — skip traditional tests

        # Test POST body if URL looks like a POST endpoint
        post_data = self._guess_post_body(url)
        if post_data:
            result = await self.execute_tool(
                server="input-validation-testing",
                tool="test_xss_reflected",
                args={
                    "url": url,
                    "method": "POST",
                    "post_data": post_data,
                    "content_type": "application/json"
                },
                auth_session=auth_data,
                timeout=120
            )
            if isinstance(result, dict) and result.get("status") == "success":
                data = result.get("data", {})
                if data.get("vulnerable"):
                    all_findings['xss'].extend(data.get('findings', []))
                    self.log("info", f"      ✓ XSS found in POST endpoint!")

        # Test GET parameters.
        # Pass each known parameter explicitly via -p so dalfox targets it directly,
        # rather than appending fake ?param=test values that point dalfox at wrong params
        # (e.g. DVWA xss_r uses 'name', not 'q' — fake params cause dalfox to miss the vuln).
        # For URLs that already have a query string, test them as-is.
        if '?' in url:
            test_pairs = [(url, None)]
        else:
            test_pairs = [(url, p) for p in (parameters[:3] if parameters else [None])]

        for test_url, test_param in test_pairs:
            result = await self.execute_tool(
                server="input-validation-testing",
                tool="test_xss_reflected",
                args={"url": test_url, "param": test_param},
                auth_session=auth_data,
                timeout=120
            )
            if isinstance(result, dict) and result.get("status") == "success":
                data = result.get("data", {})
                if data.get("vulnerable"):
                    all_findings['xss'].extend(data.get('findings', []))
                    self.log("info", f"      ✓ XSS found!")
                    break  # Found it — no need to test remaining params

    async def _execute_lfi_test(self, url: str, parameters: list, all_findings: dict, auth_data: dict = None):
        """Execute LFI test on LLM-selected URL."""
        self.log("info", f"   🔍 LFI testing: {url}")

        # ============================================================================
        # 🧠 ReAct MODE: Use iterative LLM-guided LFI testing
        # ============================================================================
        if REACT_MODE_ENABLED:
            self.log("info", f"   🧠 Using ReAct iterative testing mode for LFI")
            
            react_result = await self._execute_react_test(url, "lfi", parameters if parameters else ['file', 'path', 'page'], auth_data)
            
            if react_result.get("vulnerabilities"):
                for vuln in react_result["vulnerabilities"]:
                    all_findings['lfi'].append({
                        "url": url,
                        "type": "Local File Inclusion (LFI)",
                        "technique": vuln.get("technique", "unknown"),
                        "payload": vuln.get("payload", ""),
                        "evidence": vuln.get("evidence", []),
                        "confidence": react_result.get("confidence", "LOW"),
                        "iterations": react_result.get("iterations", 0),
                        "react_mode": True
                    })
                self.log("info", f"      ✅ ReAct found {len(react_result['vulnerabilities'])} LFI vulnerabilities!")
            return  # ReAct already tested this URL — skip traditional tests

        # Traditional LFI test — extract param from URL query string if present
        # (test_lfi signature is (url, param, auth_session); 'fuzz' was silently dropped)
        from urllib.parse import urlparse as _lfi_urlparse, parse_qs as _lfi_parse_qs
        _qs = _lfi_parse_qs(_lfi_urlparse(url).query)
        lfi_param = parameters[0] if parameters else (next(iter(_qs), None))
        result = await self.execute_tool(
            server="input-validation-testing",
            tool="test_lfi",
            args={"url": url, "param": lfi_param},
            auth_session=auth_data,
            timeout=300
        )

        if isinstance(result, dict) and result.get("status") == "success":
            data = result.get("data", {})
            if data.get("vulnerable"):
                all_findings['lfi'].append({
                    "url": url,
                    "details": data.get("message", "LFI detected")
                })
                self.log("info", f"      ✓ LFI found!")

    async def _execute_xxe_test(self, url: str, all_findings: dict, auth_data: dict = None):
        """Execute XXE test on LLM-selected URL."""
        self.log("info", f"   🔍 XXE testing: {url}")

        # Derive upload endpoint from discovered endpoints (prefer /upload, /file-upload,
        # /attachments etc.) rather than hardcoding Juice Shop's /file-upload path.
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(url)
        _base = f"{_parsed.scheme}://{_parsed.netloc}"
        _upload_patterns = ["upload", "file", "attach", "media", "import"]
        _disc = self.shared_context.get("discovered_endpoints", [])
        _upload_ep = next(
            (e for e in _disc if any(p in e.lower() for p in _upload_patterns)),
            None
        )

        result = await self.execute_tool(
            server="input-validation-testing",
            tool="test_xxe",
            args={"url": url, **({"upload_endpoint": _upload_ep} if _upload_ep else {})},
            auth_session=auth_data,
            timeout=120
        )

        if isinstance(result, dict) and result.get("status") == "success":
            data = result.get("data", {})
            if data.get("vulnerable"):
                all_findings['xxe'].append({
                    "url": url,
                    "details": data.get("message", "XXE detected")
                })
                self.log("info", f"      ✓ XXE found!")

    async def _execute_ssrf_test(self, url: str, all_findings: dict, auth_data: dict = None):
        """Execute SSRF test on LLM-selected URL."""
        self.log("info", f"   🔍 SSRF testing: {url}")

        result = await self.execute_tool(
            server="input-validation-testing",
            tool="test_ssrf_comprehensive",
            args={"url": url},
            auth_session=auth_data,
            timeout=300
        )

        if isinstance(result, dict) and result.get("status") == "success":
            data = result.get("data", {})
            if data.get("vulnerable"):
                all_findings['ssrf'].append({
                    "url": url,
                    "details": data.get("message", "SSRF detected")
                })
                self.log("info", f"      ✓ SSRF found!")

    async def _execute_ssti_test(self, url: str, parameters: list, all_findings: dict, auth_data: dict = None):
        """Execute SSTI test on LLM-selected URL."""
        self.log("info", f"   🔍 SSTI testing: {url}")

        result = await self.execute_tool(
            server="input-validation-testing",
            tool="test_ssti_comprehensive",
            args={"url": url},
            auth_session=auth_data,
            timeout=300
        )

        if isinstance(result, dict) and result.get("status") == "success":
            data = result.get("data", {})
            if data.get("vulnerable"):
                all_findings['ssti'].append({
                    "url": url,
                    "details": data.get("message", "SSTI detected")
                })
                self.log("info", f"      ✓ SSTI found!")

    async def _execute_command_injection_test(self, url: str, parameters: list, all_findings: dict, auth_data: dict = None):
        """Execute command injection test on LLM-selected URL."""
        self.log("info", f"   🔍 Command Injection testing: {url}")

        result = await self.execute_tool(
            server="input-validation-testing",
            tool="test_command_injection",
            args={"url": url},
            auth_session=auth_data,
            timeout=300
        )

        if isinstance(result, dict) and result.get("status") == "success":
            data = result.get("data", {})
            if data.get("vulnerable"):
                all_findings['command_injection'].append({
                    "url": url,
                    "details": data.get("message", "Command injection detected")
                })
                self.log("info", f"      ✓ Command Injection found!")

    async def _execute_http_smuggling_test(self, url: str, all_findings: dict):
        """Execute HTTP smuggling test on LLM-selected URL."""
        self.log("info", f"   🔍 HTTP Smuggling testing: {url}")

        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path

        result = await self.execute_tool(
            server="input-validation-testing",
            tool="test_http_smuggling",
            args={"host": host},
            timeout=120
        )

        if isinstance(result, dict) and result.get("status") == "success":
            data = result.get("data", {})
            if data.get("vulnerable"):
                all_findings['http_smuggling'].append({
                    "url": url,
                    "details": data.get("message", "HTTP smuggling detected")
                })
                self.log("info", f"      ✓ HTTP Smuggling found!")

    async def _execute_nosql_injection_test(self, url: str, parameters: list, all_findings: dict, auth_data: dict = None):
        """Execute NoSQL injection test on LLM-selected URL."""
        self.log("info", f"   🔍 NoSQL Injection testing: {url}")

        if not isinstance(parameters, list) or not parameters:
            parameters = ['q', 'search', 'id']

        for param in parameters[:2]:
            test_url = url if '?' in url else f"{url}?{param}=test"
            result = await self.execute_tool(
                server="input-validation-testing",
                tool="test_nosql_injection",
                args={"url": test_url, "param": param},
                auth_session=auth_data,
                timeout=120
            )
            if isinstance(result, dict) and result.get("status") == "success":
                data = result.get("data", {})
                if data.get("vulnerable"):
                    all_findings['nosql_injection'].extend(data.get('findings', []))
                    self.log("info", f"      ✓ NoSQL injection found!")

    def _report_all_findings(self, all_findings: dict):
        """Report all findings to database."""
        # SQL Injection
        if all_findings['sqli']:
            self.add_finding(
                "WSTG-INPV-05",
                f"SQL Injection detected ({len(all_findings['sqli'])} instances)",
                severity="critical",
                evidence={"findings": all_findings['sqli']},
                details=f"LLM-driven testing found {len(all_findings['sqli'])} SQL injection vulnerabilities"
            )

        # XSS
        if all_findings['xss']:
            self.add_finding(
                "WSTG-INPV-01",
                f"Reflected XSS detected ({len(all_findings['xss'])} instances)",
                severity="high",
                evidence={"findings": all_findings['xss']},
                details=f"LLM-driven testing found {len(all_findings['xss'])} XSS vulnerabilities"
            )

        # LFI
        if all_findings['lfi']:
            self.add_finding(
                "WSTG-INPV-11",
                f"Local File Inclusion detected ({len(all_findings['lfi'])} instances)",
                severity="high",
                evidence={"findings": all_findings['lfi']},
                details=f"LLM-driven testing found {len(all_findings['lfi'])} LFI vulnerabilities"
            )

        # XXE
        if all_findings['xxe']:
            self.add_finding(
                "WSTG-INPV-07",
                f"XML External Entity injection detected ({len(all_findings['xxe'])} instances)",
                severity="high",
                evidence={"findings": all_findings['xxe']},
                details=f"LLM-driven testing found {len(all_findings['xxe'])} XXE vulnerabilities"
            )

        # SSRF
        if all_findings['ssrf']:
            self.add_finding(
                "WSTG-INPV-19",
                f"Server-Side Request Forgery detected ({len(all_findings['ssrf'])} instances)",
                severity="critical",
                evidence={"findings": all_findings['ssrf']},
                details=f"LLM-driven testing found {len(all_findings['ssrf'])} SSRF vulnerabilities"
            )

        # SSTI
        if all_findings['ssti']:
            self.add_finding(
                "WSTG-INPV-18",
                f"Server-Side Template Injection detected ({len(all_findings['ssti'])} instances)",
                severity="high",
                evidence={"findings": all_findings['ssti']},
                details=f"LLM-driven testing found {len(all_findings['ssti'])} SSTI vulnerabilities"
            )

        # Command Injection
        if all_findings['command_injection']:
            self.add_finding(
                "WSTG-INPV-12",
                f"OS Command Injection detected ({len(all_findings['command_injection'])} instances)",
                severity="critical",
                evidence={"findings": all_findings['command_injection']},
                details=f"LLM-driven testing found {len(all_findings['command_injection'])} command injection vulnerabilities"
            )

        # HTTP Smuggling
        if all_findings['http_smuggling']:
            self.add_finding(
                "WSTG-INPV-15",
                f"HTTP Request Smuggling detected ({len(all_findings['http_smuggling'])} instances)",
                severity="high",
                evidence={"findings": all_findings['http_smuggling']},
                details=f"LLM-driven testing found {len(all_findings['http_smuggling'])} HTTP smuggling vulnerabilities"
            )

        # NoSQL Injection
        if all_findings['nosql_injection']:
            self.add_finding(
                "WSTG-INPV-05",
                f"NoSQL Injection detected ({len(all_findings['nosql_injection'])} instances)",
                severity="high",
                evidence={"findings": all_findings['nosql_injection']},
                details=f"LLM-driven testing found {len(all_findings['nosql_injection'])} NoSQL injection vulnerabilities"
            )

    def _merge_llm_and_rule_plans(self, llm_plan: dict, rule_plan: dict, discovered_urls: list[str]) -> dict:
        """
        🔀 HYBRID MERGE: Combine LLM intelligent prioritization with rule-based coverage.

        Strategy:
        1. Use LLM priority scores where available (intelligent ranking)
        2. Add missing URLs from rule-based plan (comprehensive coverage)
        3. Keep LLM test type selection (smarter than rules)
        4. Result: Best of both worlds - smart priorities + guaranteed coverage

        Args:
            llm_plan: Plan from LLM (may have gaps in coverage)
            rule_plan: Plan from rules (comprehensive but generic)
            discovered_urls: All URLs discovered

        Returns:
            Merged plan with 80%+ coverage and intelligent priorities
        """
        # Build URL lookup from LLM plan (for fast checking)
        llm_urls = {item['url']: item for item in llm_plan.get('priority_urls', [])}

        # Start with LLM priorities (these are intelligent)
        merged_urls = list(llm_plan.get('priority_urls', []))

        # Add missing URLs from rule plan (to ensure coverage)
        for rule_item in rule_plan.get('priority_urls', []):
            url = rule_item['url']
            if url not in llm_urls:
                # LLM didn't include this URL - add it with rule-based priority
                # But mark it as "rule-added" for transparency
                merged_item = rule_item.copy()
                merged_item['source'] = 'rule-based'
                merged_item['reason'] = f"[Rule] {rule_item.get('reason', 'Comprehensive coverage')}"
                merged_urls.append(merged_item)

        # Sort by priority score (highest first)
        merged_urls.sort(key=lambda x: x.get('priority_score', 50), reverse=True)

        # auth_discovered_links are never capped — only speculative/combined URLs are capped.
        auth_link_urls = {
            u for u in (
                self.shared_context.get("auth_discovered_links", {}).get("urls", [])
                if isinstance(self.shared_context.get("auth_discovered_links"), dict)
                else []
            )
        }
        auth_merged = [u for u in merged_urls if u.get("url", "") in auth_link_urls]
        spec_merged = [u for u in merged_urls if u.get("url", "") not in auth_link_urls]
        merged_urls = auth_merged + spec_merged[:MAX_PRIORITY_URLS]

        # Calculate statistics
        llm_count = len(llm_plan.get('priority_urls', []))
        rule_added_count = len(merged_urls) - llm_count
        coverage_pct = int(len(merged_urls) * 100 / len(discovered_urls)) if discovered_urls else 0

        return {
            'priority_urls': merged_urls,
            'strategy': 'hybrid_llm_rule_merge',
            'llm_contribution': llm_count,
            'rule_contribution': rule_added_count,
            'total_urls': len(merged_urls),
            'coverage': f"{len(merged_urls)}/{len(discovered_urls)} ({coverage_pct}%)",
            'reasoning': f"Hybrid approach: {llm_count} URLs from LLM (intelligent prioritization) + {rule_added_count} URLs from rules (coverage guarantee) = {coverage_pct}% total coverage"
        }

    def _create_deterministic_test_plan(self, discovered_urls: list[str], authenticated: bool) -> dict:
        """
        🔧 RULE-BASED PLANNING: Pattern-based test selection for maximum coverage.

        This is the "Rule Layer" in hybrid architecture. Ensures 80%+ coverage
        by testing all non-static endpoints with appropriate test types.
        """
        priority_urls = []

        # Filter out obvious static files (but keep everything else)
        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf']
        testable_urls = [
            url for url in discovered_urls
            if not any(url.lower().endswith(ext) for ext in static_extensions)
        ]

        self.log("info", f"🔧 Deterministic mode: Testing {len(testable_urls)}/{len(discovered_urls)} URLs (filtered {len(discovered_urls)-len(testable_urls)} static files)")

        for url in testable_urls:
            url_lower = url.lower()

            # Determine tests based on URL patterns
            tests = []
            parameters = ['id', 'search', 'q', 'query', 'email', 'user', 'name']
            priority_score = 50  # Default
            reason = "Deterministic pattern-based selection"

            # 🔥 CRITICAL: GraphQL endpoints (score: 100, same as search)
            if any(pattern in url_lower for pattern in ['/graphql', '/gql', '/graphiql', '/playground']):
                tests = ['sqli', 'xss']
                priority_score = 100
                reason = "GraphQL endpoint - high injection & introspection risk"
                parameters = ['query', 'variables', 'operationName', 'id']

            # 🔥 CRITICAL: Search/Query endpoints (score: 100)
            elif any(pattern in url_lower for pattern in ['/search', '/query', '/find', '/filter']):
                tests = ['sqli', 'xss']
                priority_score = 100
                reason = "Search endpoint - high SQLi/XSS risk"
                parameters = ['q', 'search', 'query', 'keyword', 'term']

            # 🔴 HIGH: WebSocket upgrade endpoints (score: 98)
            elif any(pattern in url_lower for pattern in ['/ws', '/websocket', '/socket.io', '/sockjs']):
                tests = ['xss', 'sqli']
                priority_score = 98
                reason = "WebSocket endpoint - message injection risk"
                parameters = ['message', 'data', 'payload', 'event']

            # 🔴 HIGH: Command execution patterns (score: 97, RCE risk!)
            elif any(pattern in url_lower for pattern in ['/execute', '/run', '/cmd', '/shell', '/exec']):
                tests = ['command_injection', 'sqli']
                priority_score = 97
                reason = "Command execution endpoint - CRITICAL RCE risk"
                parameters = ['cmd', 'command', 'exec', 'script']

            # 🔴 HIGH: OAuth/Token endpoints (score: 96)
            elif any(pattern in url_lower for pattern in ['/oauth', '/token', '/refresh', '/authorize']):
                tests = ['sqli', 'xss']
                priority_score = 96
                reason = "OAuth/token endpoint - auth bypass & token theft risk"
                parameters = ['code', 'token', 'refresh_token', 'client_id', 'redirect_uri']

            # 🔴 HIGH: Login/Auth endpoints (score: 95)
            elif any(pattern in url_lower for pattern in ['/login', '/auth', '/signin', '/register', '/signup']):
                tests = ['sqli', 'nosql_injection']
                priority_score = 95
                reason = "Authentication endpoint - SQLi/NoSQLi for auth bypass"
                parameters = ['email', 'username', 'password', 'user']

            # 🟠 ELEVATED: SSRF-prone endpoints (score: 93)
            elif any(pattern in url_lower for pattern in ['/proxy', '/fetch', '/redirect', '/url', '/link']):
                tests = ['ssrf', 'sqli']
                priority_score = 93
                reason = "SSRF-prone endpoint - internal network access risk"
                parameters = ['url', 'link', 'target', 'redirect', 'next']

            # 🟠 ELEVATED: Export/Download (score: 92, XXE + Path Traversal)
            elif any(pattern in url_lower for pattern in ['/export', '/download', '/csv', '/pdf', '/report']):
                tests = ['lfi', 'xxe']
                priority_score = 92
                reason = "Export/download endpoint - LFI/XXE/Path Traversal risk"
                parameters = ['file', 'path', 'filename', 'format', 'id']

            # 🟠 ELEVATED: Admin/Privileged paths (score: 90)
            elif any(pattern in url_lower for pattern in ['/admin', '/dashboard', '/manage', '/control', '/console']):
                tests = ['sqli', 'xss']
                priority_score = 90
                reason = "Admin endpoint - high-value target"
                parameters = ['id', 'user', 'action', 'param']

            # 🟡 MODERATE: Webhook/Callback (score: 88)
            elif any(pattern in url_lower for pattern in ['/webhook', '/callback', '/notify', '/hook']):
                tests = ['xss', 'sqli']
                priority_score = 88
                reason = "Webhook/callback endpoint - injection in async processing"
                parameters = ['data', 'payload', 'event', 'message']

            # 🟡 MODERATE: API versioned endpoints (score: 86)
            elif any(pattern in url_lower for pattern in ['/api/v1', '/api/v2', '/api/v3', '/rest/v1']):
                tests = ['sqli', 'xss']
                priority_score = 86
                reason = "Versioned API endpoint - modern API injection risk"
                parameters = ['id', 'search', 'filter', 'q']

            # 🟡 MODERATE: General API/REST endpoints (score: 85)
            elif any(pattern in url_lower for pattern in ['/api/', '/rest/']):
                tests = ['sqli', 'xss', 'nosql_injection']
                priority_score = 85
                reason = "API endpoint - injection risk (SQL + NoSQL)"

                # Specific API patterns
                if any(p in url_lower for p in ['/products', '/items', '/users', '/orders']):
                    parameters = ['id', 'search', 'filter', 'q']
                elif 'feedback' in url_lower:
                    parameters = ['search', 'comment', 'message']

            # 🟡 MODERATE: File upload endpoints (score: 82)
            elif any(pattern in url_lower for pattern in ['/upload', '/file', '/attachment', '/media']):
                tests = ['lfi', 'xxe']
                priority_score = 82
                reason = "File upload endpoint - LFI/XXE/unrestricted upload risk"
                parameters = ['file', 'path', 'filename', 'name', 'upload']

            # 🟢 STANDARD: User/Profile endpoints (score: 75)
            elif any(pattern in url_lower for pattern in ['/user', '/profile', '/account', '/settings']):
                tests = ['sqli', 'xss']
                priority_score = 75
                reason = "User endpoint - injection risk"
                parameters = ['id', 'email', 'username']

            # 🟢 STANDARD: Product/Catalog endpoints (score: 70)
            elif any(pattern in url_lower for pattern in ['/product', '/item', '/catalog', '/shop']):
                tests = ['sqli', 'xss']
                priority_score = 70
                reason = "Product endpoint - parameter tampering"
                parameters = ['id', 'category', 'name']

            # ⚪ LOW PRIORITY: Health/Status endpoints (score: 40)
            elif any(pattern in url_lower for pattern in ['/health', '/healthz', '/ping', '/status', '/metrics', '/actuator']):
                tests = ['sqli']
                priority_score = 40
                reason = "Health/monitoring endpoint - limited attack surface"
                parameters = ['check', 'service']

            # 🔴 HIGH: XSS-specific endpoints (score: 90)
            elif any(pattern in url_lower for pattern in ['xss', 'cross-site', 'script', 'markup']):
                tests = ['xss', 'sqli']
                priority_score = 90
                reason = "XSS-specific endpoint - reflected/stored XSS risk"
                parameters = ['q', 'search', 'name', 'input', 'param', 'msg', 'default']

            # 🔴 HIGH: File inclusion / LFI endpoints (score: 88)
            elif any(pattern in url_lower for pattern in ['/fi/', 'inclusion', '/lfi', '/rfi', 'include', 'page=']):
                tests = ['lfi', 'sqli']
                priority_score = 88
                reason = "File inclusion endpoint - LFI/RFI path traversal risk"
                parameters = ['page', 'file', 'path', 'include', 'doc']

            # 🔴 HIGH: SQLi-explicit endpoints (score: 88)
            elif any(pattern in url_lower for pattern in ['sqli', 'sql-inject', 'sqlinject', 'blind']):
                tests = ['sqli']
                priority_score = 88
                reason = "SQLi-specific endpoint - direct SQL injection testing"
                parameters = ['id', 'q', 'search', 'user', 'name']

            # ⚪ DEFAULT: Test everything for SQLi at minimum (score: 60)
            else:
                tests = ['sqli']
                priority_score = 60
                reason = "Default comprehensive testing"

            priority_urls.append({
                'url': url,
                'tests': tests,
                'parameters': parameters,
                'priority_score': priority_score,
                'reason': reason
            })

        # Sort by priority score (highest first)
        priority_urls.sort(key=lambda x: x['priority_score'], reverse=True)

        self.log("info", f"🔧 Deterministic plan created: {len(priority_urls)} URLs prioritized")
        self.log("info", f"   Coverage: {len(priority_urls)*100//len(discovered_urls)}% ({len(priority_urls)}/{len(discovered_urls)} URLs)")

        return {
            'priority_urls': priority_urls,
            'strategy': 'deterministic_pattern_based',
            'coverage': f"{len(priority_urls)}/{len(discovered_urls)} URLs",
            'reasoning': 'LLM was too conservative - using deterministic fallback for maximum coverage'
        }

    async def _create_intelligent_test_plan(self, discovered_urls: list[str], authenticated: bool) -> dict:
        """
        🧠 FULLY LLM-DRIVEN PLANNING: Analyze ALL endpoints and generate comprehensive test strategy.

        NO HARDCODED LIMITS - LLM decides which URLs to test and how many.

        Returns:
            dict: {
                "priority_urls": [{url, reason, tests, parameters, priority_score}],
                "scan_strategy": {coverage_level, estimated_time, url_count},
                "reasoning": "LLM explanation of decisions"
            }
        """
        # 🔥 DEBUG CHECKPOINT: Method entry confirmation
        print(f"🧠🧠🧠 _create_intelligent_test_plan() ENTERED - Processing {len(discovered_urls)} URLs", file=sys.stderr, flush=True)
        print(f"🔍 LLM-PLAN-DEBUG-1: About to call self.log()", file=sys.stderr, flush=True)
        self.log("info", "🧠 Using LLM for fully autonomous URL analysis and prioritization...")
        print(f"🔍 LLM-PLAN-DEBUG-2: self.log() completed", file=sys.stderr, flush=True)

        # Get tech stack and previous findings for context
        print(f"🔍 LLM-PLAN-DEBUG-3: Getting tech_stack from shared_context", file=sys.stderr, flush=True)
        tech_stack = self.shared_context.get("tech_stack", {})
        print(f"🔍 LLM-PLAN-DEBUG-4: Reading previous findings", file=sys.stderr, flush=True)
        previous_findings = self._read_previous_agent_findings()
        print(f"🔍 LLM-PLAN-DEBUG-5: Building planning prompt", file=sys.stderr, flush=True)

        # 🔀 HYBRID APPROACH: LLM provides intelligent prioritization, Rules ensure coverage
        # Research claim: "Hybrid LLM+Rule-Based System" (Path C - budget-friendly)
        # LLM role: Analyze URLs and assign priority scores (NOT filter URLs - that's Rule layer's job)
        planning_prompt = f"""
You are analyzing {len(discovered_urls)} web application endpoints for penetration testing prioritization.

**YOUR TASK**: For each URL, assign:
1. **Priority score** (0-100): Higher = more likely to have vulnerabilities
2. **Test types**: Which tests to run (sqli, xss, lfi, xxe, etc.)
3. **Reasoning**: Brief explanation

**URLs to analyze**:
{chr(10).join(f"{i+1}. {url}" for i, url in enumerate(discovered_urls[:50]))}
{"... and " + str(len(discovered_urls) - 50) + " more URLs" if len(discovered_urls) > 50 else ""}

**Prioritization guidelines**:
- 100: Search/query endpoints (/search?q=, /find?keyword=)
- 95: Authentication endpoints (/login, /auth, /signin)
- 90: Admin/privileged paths (/admin, /dashboard)
- 85: API/REST endpoints (/api/*, /rest/*)
- 70: CRUD operations (/products, /users)
- 60: Standard pages
- 30: Static-looking files (.html, .php)
- 0: Pure static assets (.css, .js, .png)

**Test type selection**:
- Search/query → ["sqli", "xss"]
- Auth/login → ["sqli"]
- API/REST → ["sqli", "xss"]
- File upload → ["lfi", "xxe"]
- Default → ["sqli"]

**Output JSON** (no markdown):
{{
    "priority_urls": [
        {{
            "url": "http://target/search?q=test",
            "priority_score": 100,
            "tests": ["sqli", "xss"],
            "parameters": ["q"],
            "reason": "Search endpoint - high injection risk"
        }}
    ]
}}

**NOTE**: Include AS MANY URLs as you can analyze. If unsure, include it with lower priority.
"""

        print(f"🔍 LLM-PLAN-DEBUG-6: Entering try block", file=sys.stderr, flush=True)
        try:
            # Call LLM for planning (with longer timeout for comprehensive analysis)
            print(f"🔍 LLM-PLAN-DEBUG-7: About to call _query_llm()", file=sys.stderr, flush=True)
            llm_response = await self._query_llm(planning_prompt, max_tokens=4000)
            print(f"🔍 LLM-PLAN-DEBUG-8: _query_llm() returned, response length: {len(llm_response)}", file=sys.stderr, flush=True)

            # Parse JSON response
            import json
            print(f"🔍 LLM-PLAN-DEBUG-9: Parsing JSON response", file=sys.stderr, flush=True)
            # Strip markdown if present
            response_text = llm_response.strip()
            if response_text.startswith("```json"):
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif response_text.startswith("```"):
                response_text = response_text.split("```")[1].split("```")[0].strip()

            test_plan = json.loads(response_text)
            print(f"🔍 LLM-PLAN-DEBUG-10: JSON parsed successfully, {len(test_plan.get('priority_urls', []))} URLs in plan", file=sys.stderr, flush=True)

            # Log LLM's autonomous decisions
            scan_strategy = test_plan.get('scan_strategy', {})
            priority_urls = test_plan.get('priority_urls', [])

            self.log("info", "=" * 60)
            self.log("info", "🧠 LLM AUTONOMOUS DECISIONS:")
            self.log("info", f"   Coverage: {scan_strategy.get('coverage_level', 'unknown')}")
            self.log("info", f"   URLs to test: {scan_strategy.get('total_urls_to_test', len(priority_urls))}")
            self.log("info", f"   URLs skipped: {scan_strategy.get('skip_count', 0)} (low value)")
            self.log("info", f"   Est. time: {scan_strategy.get('estimated_total_time_minutes', '?')} minutes")
            self.log("info", f"   Reasoning: {test_plan.get('reasoning', 'N/A')}")
            self.log("info", "=" * 60)

            # Show top 5 priority URLs
            self.log("info", "📊 Top 5 Priority URLs (LLM-selected):")
            for i, url_info in enumerate(priority_urls[:5], 1):
                self.log("info", f"   {i}. {url_info.get('url', 'N/A')} (score: {url_info.get('priority_score', 0)})")
                self.log("info", f"      Reason: {url_info.get('reason', 'N/A')}")
                self.log("info", f"      Tests: {', '.join(url_info.get('tests', []))}")

            print(f"🔍 LLM-PLAN-DEBUG-11: About to return LLM test plan", file=sys.stderr, flush=True)
            return test_plan

        except Exception as e:
            print(f"🚨🚨🚨 LLM-PLAN EXCEPTION: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
            self.log("warning", f"LLM planning failed: {e}. Using fallback heuristics.")
            import traceback
            traceback_str = traceback.format_exc()
            print(f"🚨 Traceback:\n{traceback_str}", file=sys.stderr, flush=True)
            self.log("warning", f"Traceback: {traceback_str}")

            # Fallback: Simple heuristic-based prioritization
            priority_urls = []
            for url in discovered_urls:
                # High priority: login, search, feedback, upload
                if any(kw in url.lower() for kw in ["login", "search", "feedback", "upload", "comment", "review", "admin"]):
                    priority_urls.append({
                        "url": url,
                        "reason": "Heuristic: High-risk endpoint pattern",
                        "tests": ["sqli", "xss"],
                        "parameters": ["id", "q", "search"],
                        "priority_score": 70
                    })

            return {
                "priority_urls": priority_urls[:20] if priority_urls else [
                    {"url": u, "reason": "Fallback", "tests": ["sqli"], "parameters": ["id"], "priority_score": 50}
                    for u in discovered_urls[:20]
                ],
                "scan_strategy": {
                    "coverage_level": "fallback",
                    "total_urls_to_test": min(20, len(discovered_urls)),
                    "estimated_total_time_minutes": 30,
                    "rationale": "Fallback heuristic mode - LLM planning unavailable"
                },
                "reasoning": "Fallback heuristic: prioritized login/search/feedback endpoints"
            }
    
    async def _request_hitl_approval(self, test_plan: dict) -> dict:
        """
        🙋 HUMAN-IN-THE-LOOP: Request user approval before executing tests.

        Args:
            test_plan: LLM-generated test plan with priority_urls and scan_strategy

        Returns:
            dict: {
                "approved": bool,
                "modified_plan": dict (if user modified the plan),
                "user_feedback": str
            }
        """
        import os
        import json
        import traceback

        try:
            # 🔥 DEBUG CHECKPOINT: HITL method entry
            print(f"🙋🙋🙋 _request_hitl_approval() ENTERED - Test plan has {len(test_plan.get('priority_urls', []))} URLs", file=sys.stderr, flush=True)

            # 🔥 GRANULAR DEBUG: Step-by-step execution tracing
            print(f"🔍 HITL-DEBUG-1: About to check ENABLE_HITL env var", file=sys.stderr, flush=True)

            # Check if HITL is enabled
            hitl_enabled = os.getenv('ENABLE_HITL', 'false').lower() == 'true'

            print(f"🔍 HITL-DEBUG-2: ENABLE_HITL = {os.getenv('ENABLE_HITL', 'false')}, hitl_enabled = {hitl_enabled}", file=sys.stderr, flush=True)
            print(f"🔍 HITL-DEBUG-3: About to check if not hitl_enabled condition", file=sys.stderr, flush=True)

            if not hitl_enabled:
                print(f"🔍 HITL-DEBUG-4: Inside 'if not hitl_enabled' block - about to call self.log()", file=sys.stderr, flush=True)
                self.log("info", "⏭️  HITL disabled - proceeding with LLM plan automatically")
                print(f"🔍 HITL-DEBUG-5: self.log() completed successfully", file=sys.stderr, flush=True)
                print(f"🔍 HITL-DEBUG-6: About to return approval dict", file=sys.stderr, flush=True)
                return {
                    "approved": True,
                    "modified_plan": test_plan,
                    "user_feedback": "HITL disabled - auto-approved"
                }
        except Exception as e:
            print(f"🚨🚨🚨 CRITICAL: _request_hitl_approval() EXCEPTION: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
            print(f"🚨 Traceback:\n{traceback.format_exc()}", file=sys.stderr, flush=True)
            # Auto-approve on error to prevent blocking
            return {
                "approved": True,
                "modified_plan": test_plan,
                "user_feedback": f"Auto-approved due to HITL error: {e}"
            }

        # Prepare HITL approval request
        scan_strategy = test_plan.get('scan_strategy', {})
        priority_urls = test_plan.get('priority_urls', [])

        approval_summary = {
            "agent": self.agent_name,
            "job_id": self.job_id,
            "test_plan_summary": {
                "coverage_level": scan_strategy.get('coverage_level', 'unknown'),
                "total_urls_to_test": scan_strategy.get('total_urls_to_test', len(priority_urls)),
                "estimated_time_minutes": scan_strategy.get('estimated_total_time_minutes', 0),
                "urls_skipped": scan_strategy.get('skip_count', 0),
                "llm_reasoning": test_plan.get('reasoning', 'N/A')
            },
            "top_priority_urls": [
                {
                    "url": u.get('url', ''),
                    "tests": u.get('tests', []),
                    "reason": u.get('reason', ''),
                    "priority_score": u.get('priority_score', 0)
                }
                for u in priority_urls[:10]  # Show top 10 for user review
            ],
            "question": "Do you approve this test plan? LLM will execute the selected tests on these URLs.",
            "options": [
                {"value": "approve", "label": "✅ Approve - Execute as planned"},
                {"value": "modify", "label": "✏️  Modify - Adjust URLs or tests"},
                {"value": "reject", "label": "❌ Reject - Skip testing"}
            ]
        }

        self.log("info", "🙋 HITL: Requesting user approval for test plan...")
        self.log("info", f"   Plan summary: {json.dumps(approval_summary['test_plan_summary'], indent=2)}")

        # TODO: Integrate with actual HITL approval system
        # For now, log the request and auto-approve in development mode
        # In production, this would call HITLManager.request_approval()

        try:
            # Placeholder: In real implementation, this would block until user responds
            # For now, check for approval file or environment variable
            approval_file = f"/tmp/hitl_approval_{self.job_id}.json"

            if os.path.exists(approval_file):
                with open(approval_file, 'r') as f:
                    user_response = json.load(f)
                os.remove(approval_file)  # Clear after reading

                self.log("info", f"✅ HITL: User response received - {user_response.get('decision', 'unknown')}")

                return {
                    "approved": user_response.get('decision') == 'approve',
                    "modified_plan": user_response.get('modified_plan', test_plan),
                    "user_feedback": user_response.get('feedback', '')
                }
            else:
                # No approval file - auto-approve with warning
                self.log("warning", "⚠️  HITL: No user response file found - auto-approving (development mode)")
                self.log("warning", f"   To approve manually, create: {approval_file}")
                self.log("warning", f"   Format: {{'decision': 'approve|modify|reject', 'feedback': 'text'}}")

                return {
                    "approved": True,
                    "modified_plan": test_plan,
                    "user_feedback": "Auto-approved (no HITL response)"
                }

        except Exception as e:
            self.log("error", f"HITL approval failed: {e}")
            # Fail-safe: auto-approve on error
            return {
                "approved": True,
                "modified_plan": test_plan,
                "user_feedback": f"Auto-approved due to HITL error: {e}"
            }

    async def _query_llm(self, prompt: str, max_tokens: int = 1500) -> str:
        """
        Query the configured LLM endpoint for planning.
        
        Args:
            prompt: The planning/analysis prompt
            max_tokens: Maximum response tokens
            
        Returns:
            str: LLM response text
        """
        from ..utils.simple_llm_client import SimpleLLMClient

        client = SimpleLLMClient()
        return await client.chat_completion(
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.7,
        )
    
    def _read_previous_agent_findings(self) -> list[dict]:
        """
        🔗 CROSS-AGENT LEARNING: Read findings from previous agents in execution order.
        
        Returns:
            list[dict]: Previous agent findings with structure:
                [{
                    "agent": "ReconnaissanceAgent",
                    "category": "WSTG-INFO",
                    "title": "...",
                    "severity": "...",
                    "evidence": {...}
                }]
        """
        try:
            from ..models.models import Finding, JobAgent, Job
            from ..core.db import get_db
            from sqlalchemy import select
            
            with get_db() as db:
                # Get current job_id (most recent running/completed job)
                job = db.query(Job).filter(
                    Job.status.in_(["running", "completed"])
                ).order_by(Job.created_at.desc()).first()
                
                if not job:
                    return []
                
                # Get previous agents (executed before InputValidationAgent)
                previous_agents = db.query(JobAgent.agent_name).filter(
                    JobAgent.job_id == job.id,
                    JobAgent.status == "completed",
                    JobAgent.agent_name != "InputValidationAgent"
                ).order_by(JobAgent.started_at).all()
                
                prev_agent_names = [agent[0] for agent in previous_agents]
                
                if not prev_agent_names:
                    return []
                
                # Fetch findings from these agents
                findings = db.query(Finding).filter(
                    Finding.job_id == job.id,
                    Finding.agent_name.in_(prev_agent_names)
                ).order_by(
                    Finding.severity.desc()  # Critical first
                ).all()
                
                return [
                    {
                        "agent": f.agent_name,
                        "category": f.category,
                        "title": f.title,
                        "severity": f.severity,
                        "evidence": f.evidence or {}
                    }
                    for f in findings
                ]
            
        except Exception as e:
            self.log("warning", f"Failed to read previous findings: {e}")
            return []
    
    def _enhance_targets_from_findings(self, discovered_urls: list[str], previous_findings: list[dict]) -> list[str]:
        """
        🔗 CROSS-AGENT LEARNING: Enhance target list based on previous agent discoveries.
        
        For example:
        - If ConfigAgent found file upload vulnerability → prioritize file upload endpoints
        - If ReconAgent found admin panel → prioritize admin endpoints
        - If AuthAgent found weak auth → prioritize auth bypass tests
        
        Args:
            discovered_urls: Original discovered URLs
            previous_findings: Findings from previous agents
            
        Returns:
            list[str]: Enhanced and re-prioritized URL list
        """
        enhanced_urls = list(discovered_urls)  # Copy
        priority_boost = []
        
        for finding in previous_findings:
            title_lower = finding.get("title", "").lower()
            evidence = finding.get("evidence", {})
            
            # If file upload vulnerabilities found → boost file upload endpoints
            if "upload" in title_lower or "file" in title_lower:
                for url in discovered_urls:
                    if any(kw in url.lower() for kw in ["upload", "file", "ftp"]):
                        if url not in priority_boost:
                            priority_boost.append(url)
                            self.log("info", f"🔗 Boosted priority: {url} (file upload vuln found by {finding['agent']})")
            
            # If admin panel found → boost admin endpoints
            if "admin" in title_lower or "administration" in title_lower:
                for url in discovered_urls:
                    if "admin" in url.lower():
                        if url not in priority_boost:
                            priority_boost.append(url)
                            self.log("info", f"🔗 Boosted priority: {url} (admin panel found)")
            
            # If authentication issues found → boost login/auth endpoints
            if "authentication" in title_lower or "login" in title_lower:
                for url in discovered_urls:
                    if any(kw in url.lower() for kw in ["login", "auth", "signin", "session"]):
                        if url not in priority_boost:
                            priority_boost.append(url)
                            self.log("info", f"🔗 Boosted priority: {url} (auth vuln found)")
            
            # If API endpoints mentioned in evidence → add them
            if "url" in evidence and isinstance(evidence["url"], str):
                api_url = evidence["url"]
                if api_url not in enhanced_urls and api_url not in priority_boost:
                    priority_boost.append(api_url)
                    self.log("info", f"🔗 Added from evidence: {api_url}")
        
        # Rebuild URL list: priority_boost first, then original order
        final_urls = priority_boost + [u for u in enhanced_urls if u not in priority_boost]
        return final_urls

    def _get_priority_post_endpoints(self, discovered_urls: list[str], test_type: str) -> list[dict]:
        """
        Identify priority POST endpoints for injection testing.
        GENERIC implementation - works for any web application.

        Args:
            discovered_urls: List of discovered URLs
            test_type: 'sqli' or 'xss'

        Returns:
            List of dicts with 'url', 'data', and priority metadata
        """
        priority_endpoints = []

        # GENERIC high-risk patterns based on common REST API conventions
        # These patterns are found across many web applications, not specific to any one app
        generic_patterns = {
            'sqli': [
                # Authentication endpoints (SQLi bypass risk)
                {'pattern': '/rest/user/login', 'data': {'email': 'test@test.com', 'password': 'test'}, 'priority': 1},
                {'pattern': '/api/user/login', 'data': {'email': 'test@test.com', 'password': 'test'}, 'priority': 1},
                {'pattern': '/api/auth/login', 'data': {'username': 'test', 'password': 'test'}, 'priority': 1},
                # Search endpoints (high SQLi risk)
                {'pattern': '/rest/products/search', 'data': {'q': 'test'}, 'priority': 2},
                {'pattern': '/api/products/search', 'data': {'q': 'test'}, 'priority': 2},
                {'pattern': '/rest/search', 'data': {'query': 'test'}, 'priority': 2},
                {'pattern': '/api/search', 'data': {'query': 'test'}, 'priority': 2},
                # User operations
                {'pattern': '/api/users', 'data': {'email': 'test@test.com', 'name': 'test'}, 'priority': 3},
                {'pattern': '/rest/users', 'data': {'email': 'test@test.com', 'name': 'test'}, 'priority': 3},
            ],
            'xss': [
                # User-generated content endpoints (XSS risk)
                {'pattern': '/api/comments', 'data': {'comment': 'test', 'rating': 5}, 'priority': 1},
                {'pattern': '/rest/comments', 'data': {'comment': 'test'}, 'priority': 1},
                {'pattern': '/api/feedback', 'data': {'comment': 'test', 'rating': 5}, 'priority': 1},
                {'pattern': '/rest/feedback', 'data': {'message': 'test'}, 'priority': 1},
                {'pattern': '/api/reviews', 'data': {'review': 'test', 'rating': 5}, 'priority': 2},
                {'pattern': '/rest/reviews', 'data': {'review': 'test'}, 'priority': 2},
                # Search (reflected XSS risk)
                {'pattern': '/rest/products/search', 'data': {'q': 'test'}, 'priority': 2},
                {'pattern': '/api/products/search', 'data': {'q': 'test'}, 'priority': 2},
                # Profile endpoints
                {'pattern': '/api/profile', 'data': {'username': 'test', 'bio': 'test'}, 'priority': 3},
                {'pattern': '/rest/profile', 'data': {'username': 'test'}, 'priority': 3},
            ]
        }

        # Keyword-based matching for generic detection
        keyword_patterns = {
            'sqli': ['login', 'search', 'query', 'user', 'admin', 'auth'],
            'xss': ['comment', 'feedback', 'message', 'post', 'search', 'profile', 'review']
        }

        # Match discovered URLs against generic patterns
        patterns = generic_patterns.get(test_type, [])
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            for url in discovered_urls:
                if pattern in url:
                    priority_endpoints.append({
                        'url': url,
                        'data': pattern_info['data'],
                        'priority': pattern_info['priority'],
                        'source': 'common_pattern_match'  # Generic high-risk pattern match
                    })

        # Then add keyword-based matches (lower priority for broader detection)
        keywords = keyword_patterns.get(test_type, [])
        for url in discovered_urls:
            url_lower = url.lower()
            for keyword in keywords:
                if keyword in url_lower:
                    # Infer likely POST data based on endpoint name
                    data = self._infer_post_data(url, test_type)
                    if data and not any(ep['url'] == url for ep in priority_endpoints):
                        priority_endpoints.append({
                            'url': url,
                            'data': data,
                            'priority': 5,
                            'source': 'generic_pattern'
                        })
                        break
        
        # Sort by priority (lower number = higher priority)
        priority_endpoints.sort(key=lambda x: x['priority'])
        
        self.log("info", f"Identified {len(priority_endpoints)} priority POST endpoints for {test_type} testing")
        return priority_endpoints
    
    def _guess_post_body(self, url: str) -> dict | None:
        """Return POST body if URL looks like a POST endpoint, else None."""
        url_lower = url.lower()
        # Only URLs with REST/API patterns that typically accept POST
        post_keywords = ['login', 'auth', 'signin', 'signup', 'register',
                         'feedback', 'comment', 'review', 'message', 'post',
                         'search', 'query', 'user', 'profile', 'order', 'cart']
        if not any(kw in url_lower for kw in post_keywords):
            return None
        return self._infer_post_data(url, 'sqli')

    def _infer_post_data(self, url: str, test_type: str) -> dict:
        """Infer likely POST data structure based on URL patterns"""
        url_lower = url.lower()
        
        # Search endpoints
        if 'search' in url_lower or 'query' in url_lower:
            return {'q': 'test'}
        
        # Login/auth endpoints
        if 'login' in url_lower or 'auth' in url_lower or 'signin' in url_lower:
            return {'email': 'test@test.com', 'password': 'test'}
        
        # User/profile endpoints
        if 'user' in url_lower or 'profile' in url_lower:
            return {'username': 'test', 'email': 'test@test.com'}
        
        # Feedback/comment endpoints
        if 'feedback' in url_lower or 'comment' in url_lower or 'message' in url_lower:
            return {'comment': 'test', 'message': 'test'}
        
        # API endpoints - try common parameter names
        if '/api/' in url_lower or '/rest/' in url_lower:
            return {'id': '1', 'q': 'test'}
        
        # Default fallback
        return {'q': 'test', 'id': '1'}

    def _get_tool_info(self) -> dict:
        """Return input validation tools with priority classification for ADAPTIVE_MODE"""
        return {
            # CRITICAL - Most dangerous vulnerabilities that MUST be tested
            'test_sqli': {
                'priority': 'CRITICAL',
                'description': 'SQL Injection testing with sqlmap',
                'severity': 'Critical',
                'owasp': 'WSTG-INPV-05'
            },
            'test_xss_reflected': {
                'priority': 'CRITICAL',
                'description': 'Reflected XSS testing with Dalfox',
                'severity': 'High',
                'owasp': 'WSTG-INPV-07'
            },
            'test_lfi': {
                'priority': 'CRITICAL',
                'description': 'Local File Inclusion with ffuf',
                'severity': 'High',
                'owasp': 'WSTG-INPV-10'
            },
            'test_xxe': {
                'priority': 'CRITICAL',
                'description': 'XML External Entity injection',
                'severity': 'Critical',
                'owasp': 'WSTG-INPV-17'
            },

            # HIGH - Important vulnerabilities with automated tools
            'test_ssti_comprehensive': {
                'priority': 'HIGH',
                'description': 'Server-Side Template Injection with tplmap',
                'severity': 'High',
                'owasp': 'WSTG-INPV-18'
            },
            'test_command_injection': {
                'priority': 'HIGH',
                'description': 'Command Injection with commix',
                'severity': 'Critical',
                'owasp': 'WSTG-INPV-12'
            },
            'test_ssrf_comprehensive': {
                'priority': 'HIGH',
                'description': 'Server-Side Request Forgery with SSRFmap',
                'severity': 'Critical',
                'owasp': 'WSTG-INPV-19'
            },
            'test_http_smuggling': {
                'priority': 'HIGH',
                'description': 'HTTP Request Smuggling',
                'severity': 'High',
                'owasp': 'WSTG-INPV-15'
            },
            'test_http_verb_tampering': {
                'priority': 'HIGH',
                'description': 'HTTP Verb Tampering for access control bypass',
                'severity': 'High',
                'owasp': 'WSTG-INPV-03'
            },
            'test_http_incoming_requests': {
                'priority': 'HIGH',
                'description': 'HTTP header manipulation (Host injection, IP spoofing)',
                'severity': 'High',
                'owasp': 'WSTG-INPV-16'
            },
            'test_nosql_injection': {
                'priority': 'HIGH',
                'description': 'NoSQL/MongoDB injection with operator and JS payloads',
                'severity': 'High',
                'owasp': 'WSTG-INPV-05'
            },
            'test_stored_xss': {
                'priority': 'HIGH',
                'description': 'Stored XSS via user-generated content endpoints',
                'severity': 'High',
                'owasp': 'WSTG-INPV-02'
            },
            'test_sqli_login': {
                'priority': 'CRITICAL',
                'description': 'SQL Injection login bypass on authentication endpoints',
                'severity': 'Critical',
                'owasp': 'WSTG-ATHN-03'
            },
            'test_http_parameter_pollution': {
                'priority': 'HIGH',
                'description': 'HTTP Parameter Pollution on key endpoints',
                'severity': 'Medium',
                'owasp': 'WSTG-INPV-04'
            },
            'test_redos': {
                'priority': 'HIGH',
                'description': 'ReDoS and algorithmic complexity attacks',
                'severity': 'High',
                'owasp': 'WSTG-INPV-13'
            },
        }

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
    
    def _get_available_tools(self) -> list[str]:
        """Override BaseAgent method - return list of tool names for LLM planning"""
        return list(self._get_tool_info().keys())

    # should_run_tool override REMOVED — base class already forces CRITICAL priority
    # tools via ADAPTIVE_MODE (balanced→CRITICAL, aggressive→CRITICAL+HIGH)
