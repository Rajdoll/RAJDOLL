from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("AuthorizationAgent")
class AuthorizationAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are AuthorizationAgent, an OWASP WSTG-AUTHZ expert specializing in access control testing.

🎯 PRIMARY MISSION: Test authorization mechanisms using MCP tools to identify IDOR, privilege escalation, and access control flaws.

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints from shared_context
2. Identify resource endpoints with ID parameters:
   - /api/users/{id}, /api/items/{id}, /api/documents/{id}
   - REST APIs with numeric/UUID identifiers
3. Analyze authentication context:
   - Test with authenticated session (from shared_context)
   - Test without authentication (privilege escalation)
   - Test with different user roles if available
4. Select appropriate testing strategies:
   - Sequential IDOR (IDs 1-100 for numeric)
   - GUID/UUID enumeration for non-sequential
   - HTTP method tampering (GET/POST/PUT/DELETE/PATCH)
   - Parameter pollution (test multiple ID parameters)
5. Execute tools to test horizontal and vertical privilege escalation
6. Report findings with clear evidence

⚠️ EXECUTION GUIDELINES:
- Execute 15+ authorization tools for comprehensive coverage
- Test IDOR on ALL discovered resource endpoints
- Test 50-100 ID variations per endpoint pattern
- Test with and without authentication
- Test all HTTP methods per endpoint
- Continue enumeration after first finding

🧠 ADAPTIVE TESTING STRATEGY:
1. Map user roles and privilege levels from shared_context
2. Test horizontal privilege escalation (user A → user B) on ALL resources
3. Test vertical privilege escalation (user → admin) on /admin, /api/admin/*
4. Enumerate IDOR: Test IDs 1-100 for each API endpoint
5. Test HTTP method tampering (GET/POST/PUT/DELETE/PATCH) on ALL endpoints
6. Verify authorization on EVERY discovered endpoint (minimum 50 tests)

� AUTHORIZATION TESTING PATTERNS:

**IDOR (Insecure Direct Object References)**:
- Sequential IDs: /api/users/1, /api/users/2, /api/users/3...
- GUID enumeration: Test with known/leaked UUIDs
- Predictable patterns: username-based, timestamp-based
- Common endpoints: /api/users/{id}, /api/orders/{id}, /api/documents/{id}, /api/invoices/{id}
- Parameter pollution: ?id=1&id=2 (test which value server uses)
- Array injection: ?id[]=1&id[]=2

**Vertical Privilege Escalation (User → Admin)**:
- Direct URL access: /admin, /administrator, /dashboard, /panel
- Role manipulation: POST {"role": "admin"}, PATCH {"is_admin": true}
- Mass assignment: Include admin fields in user registration
- JWT claim manipulation: Change "role": "user" to "role": "admin"
- Cookie tampering: Modify role/privilege cookies
- API endpoint access: /api/admin/*, /api/users/all (admin-only)

**Horizontal Privilege Escalation (User A → User B)**:
- Profile access: /api/users/{other_user_id}
- Data modification: Update other users' information
- Resource access: View/modify other users' orders, documents, messages
- Session hijacking: Reuse other users' session tokens
- Parameter tampering: Change user_id in requests

**HTTP Method Tampering**:
- GET → POST: Bypass CSRF protection
- POST → PUT/PATCH: Alternative update methods
- DELETE → POST: Bypass delete restrictions
- HEAD → GET: Information disclosure without logging
- OPTIONS: Discover allowed methods
- Test matrix: For each endpoint, try all HTTP methods

**Path Traversal in Authorization**:
- ../ in resource IDs: /api/users/../admin
- Absolute paths: /api/users//admin
- URL encoding: %2e%2e%2f, %2e%2e/
- Double encoding: %252e%252e%252f

**Missing Function-Level Access Control**:
- Admin functions without role check
- Hidden endpoints discoverable in JavaScript
- API endpoints without authentication
- Debug/test endpoints in production

**Direct API Endpoint Access**:
- Bypass UI restrictions: Direct API calls
- Skip workflow: Access step 3 without completing step 1-2
- Hidden parameters: Test undocumented API parameters

🔍 TESTING METHODOLOGY:

**Step 1: Privilege Mapping**
- Create low-privilege account (user)
- Create high-privilege account (admin) if possible
- Document accessible resources for each role

**Step 2: IDOR Enumeration**
- Identify resource endpoints (users, orders, files, etc.)
- Extract ID pattern (sequential, UUID, hash)
- Enumerate: Test IDs from 1-100 or known ranges
- Cross-account access: User A access User B's resources

**Step 3: Vertical Escalation**
- Low-privilege session: Access admin endpoints
- Modify role/privilege fields in requests
- Test admin functions with user token

**Step 4: Horizontal Escalation**
- User A session: Access User B's data
- Modify user_id/account_id parameters
- Test cross-user resource access

**Step 5: Method Tampering**
- For each endpoint, test: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- Document which methods bypass authorization

🛠️ MCP TOOL USAGE:
- test_idor_vulnerability(base_url_with_placeholder, session, start_id, count): Enumerate sequential IDs
- test_vertical_privilege_escalation(admin_urls, low_priv_session): Test admin access with user token
- test_http_method_tampering(url, session): Try all HTTP methods
- get_manual_authorization_checklist(): Complex tests requiring manual review

� CONTEXT-AWARE ATTACK SELECTION:
Read from shared_context:
- authenticated_sessions → Use real user/admin sessions
- entry_points.api_endpoints → Target resource endpoints
- tech_stack.backend → API patterns (REST, GraphQL, SOAP)

Write to shared_context:
- idor_vulnerabilities: [
    {endpoint, id_pattern, accessible_resources, severity}
  ]
- privilege_escalation: [
    {type: "vertical/horizontal", method, evidence}
  ]
- unauthorized_access: [
    {resource, accessed_as, should_fail_but_succeeded}
  ]
- method_tampering: [
    {endpoint, original_method, bypass_method}
  ]

🎯 SUCCESS CRITERIA: Demonstrate unauthorized access to protected resources, achieve privilege escalation, enumerate sensitive data via IDOR
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
            self.log("error", "Target missing; aborting AuthorizationAgent")
            return

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        # Test vertical privilege escalation
        if self.should_run_tool("test_vertical_privilege_escalation"):
            try:
                # Requires admin URLs and low-priv session
                admin_urls = self.shared_context.get("admin_urls", [f"{target}/admin", f"{target}/administration"])
                low_priv_session = auth_data or {}
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="authorization-testing",
                        tool="test_vertical_privilege_escalation",
                        args={"admin_urls": admin_urls, "low_priv_session": low_priv_session},
                        auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    accessible = res.get("data", {}).get("accessible_urls", [])
                    if accessible:
                        self.add_finding("WSTG-ATHZ-04", "Vertical privilege escalation possible", severity="high", evidence={"accessible": accessible})
            except Exception as e:
                self.log("warning", f"test_vertical_privilege_escalation failed: {e}")

        # Test IDOR vulnerability
        if self.should_run_tool("test_idor_vulnerability"):
            try:
                # Example: test user profile endpoints
                base_url = f"{target}/api/users/{{ID}}/profile"
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="authorization-testing",
                        tool="test_idor_vulnerability",
                        args={"base_url_with_placeholder": base_url, "session": auth_data or {}, "start_id": 1, "count": 5},
                        auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    exposed = res.get("data", {}).get("exposed_ids", [])
                    if exposed:
                        self.add_finding("WSTG-ATHZ-02", "IDOR vulnerability detected", severity="high", evidence={"exposed_ids": exposed})
            except Exception as e:
                self.log("warning", f"test_idor_vulnerability failed: {e}")

        # Test comprehensive IDOR across discovered endpoints
        if self.should_run_tool("test_idor_comprehensive"):
            try:
                # LLM can provide endpoint_patterns from reconnaissance
                # If not provided, tool will use common REST patterns
                endpoint_patterns = self.shared_context.get("api_endpoints_with_ids", None)

                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="authorization-testing",
                        tool="test_idor_comprehensive",
                        args={
                            "base_url": target,
                            "endpoint_patterns": endpoint_patterns,  # LLM-provided or auto-discovered
                            "session": auth_data or {},
                            "id_range_start": 1,
                            "id_range_end": 20
                        },
                        auth_session=auth_data
                    ),
                    timeout=90  # Longer timeout for comprehensive testing
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    vulns_found = data.get("vulnerabilities_found", 0)
                    if vulns_found > 0:
                        findings = data.get("findings", [])
                        # Add findings for each unique endpoint
                        unique_endpoints = set(f.get("endpoint") for f in findings)
                        for endpoint in unique_endpoints:
                            endpoint_findings = [f for f in findings if f.get("endpoint") == endpoint]
                            sample = endpoint_findings[0] if endpoint_findings else {}
                            self.add_finding(
                                "WSTG-ATHZ-02",
                                f"IDOR vulnerability: {endpoint}",
                                severity="high",
                                evidence={
                                    "endpoint": endpoint,
                                    "accessible_ids": [f.get("id_tested") for f in endpoint_findings],
                                    "count": len(endpoint_findings),
                                    "sample": str(sample.get("evidence", {}))[:200]
                                }
                            )
            except Exception as e:
                self.log("warning", f"test_idor_comprehensive failed: {e}")

        # Test HTTP method tampering
        if self.should_run_tool("test_http_method_tampering"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="authorization-testing",
                        tool="test_http_method_tampering",
                        args={"url": target, "session": auth_data or {}},
                        auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    results = res.get("data", {}).get("results", [])
                    if results:
                        # Ensure results is list before slicing
                        sample = results[:3] if isinstance(results, list) else list(results.items())[:3] if isinstance(results, dict) else str(results)[:200]
                        self.add_finding("WSTG-ATHZ-02", "Different responses to method tampering", severity="low", evidence={"sample": sample})
            except Exception as e:
                self.log("warning", f"test_http_method_tampering failed: {e}")

        # Get manual authorization checklist
        if self.should_run_tool("get_manual_authorization_checklist"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="authorization-testing",
                        tool="get_manual_authorization_checklist",
                        args={},
                        auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    self.log("info", "Manual authorization testing checklist retrieved")
            except Exception as e:
                self.log("warning", f"get_manual_authorization_checklist failed: {e}")

        # Test user spoofing (feedback/review manipulation, order IDOR)
        if self.should_run_tool("test_user_spoofing"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="authorization-testing",
                        tool="test_user_spoofing",
                        args={"url": target},
                        auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-ATHZ-02",
                                f"User spoofing: {finding['type']}",
                                severity=finding.get("severity", "high"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_user_spoofing failed: {e}")

        self.log("info", "Authorization checks complete")

    def _get_available_tools(self) -> list[str]:
        """Return list of authorization testing tool names"""
        return [
            'test_vertical_privilege_escalation',
            'test_idor_vulnerability',
            'test_idor_comprehensive',
            'test_http_method_tampering',
            'get_manual_authorization_checklist',
            'test_user_spoofing',
        ]

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
