from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("SessionManagementAgent")
class SessionManagementAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are SessionManagementAgent, an OWASP WSTG-SESS expert specializing in session security testing.

🎯 PRIMARY MISSION: Test session management mechanisms using MCP tools to identify weak tokens, fixation, timeout issues, and CORS flaws.

🧠 ADAPTIVE STRATEGY:
1. Read authenticated sessions from shared_context (provided by AuthenticationAgent)
2. Identify session mechanism type:
   - Cookie-based → Analyze Secure, HttpOnly, SameSite flags
   - JWT-based → Analyze token structure, claims, signature
   - Session storage → Check localStorage/sessionStorage usage
   - Custom tokens → Analyze entropy and predictability
3. Select appropriate tools based on mechanism:
   - analyze_cookies → For cookie-based sessions
   - test_session_fixation → For login workflows
   - test_cors → For cross-origin policies
   - analyze_jwt → For JWT token security
4. Execute tools to test session lifecycle (creation, validation, expiration, destruction)
5. Test with multiple session samples for entropy analysis
6. Report vulnerabilities with clear evidence

⚠️ EXECUTION GUIDELINES:
- Execute 15+ session management tools
- Use authenticated sessions from shared_context
- Collect 100+ session tokens for entropy analysis
- Test session fixation across login workflows
- Test CORS with multiple origins
- Continue testing all session aspects comprehensively

🧠 ADAPTIVE TESTING STRATEGY:
1. Identify session mechanism (cookies, JWT, tokens, session storage)
2. Analyze token entropy and predictability with 100+ samples
3. Test session lifecycle (creation, validation, expiration, destruction)
4. Verify secure transmission and storage
5. Test cross-origin resource sharing (CORS) policies with multiple origins
6. Test concurrent sessions, session fixation, CSRF

� SESSION TESTING BY MECHANISM:

**Cookie-Based Sessions**:
- Secure flag: Must be set for HTTPS-only transmission
- HttpOnly flag: Prevents JavaScript access (XSS mitigation)
- SameSite flag: CSRF protection (Strict, Lax, None)
- Domain scope: Wildcard domains allow subdomain hijacking
- Path scope: Overly permissive paths expose cookies
- Expiration: Session vs persistent cookies
- Entropy analysis: Predictable tokens allow session hijacking

**JWT (JSON Web Tokens)**:
- Algorithm validation: None, HS256/RS256 confusion
- Expiration claims: 'exp', 'nbf', 'iat' presence and validity
- Signature verification: Weak secrets, key injection
- Claim manipulation: role, user_id, permissions tampering
- Token rotation: Refresh token security
- Revocation: Logout invalidates tokens server-side

**HTML5 Session/Local Storage**:
- Exposure to JavaScript: XSS can steal tokens
- Cross-tab pollution: Shared storage between tabs
- Persistence: LocalStorage survives browser close
- Third-party access: Iframe/script access to storage

**API Keys & Bearer Tokens**:
- Transmission security: HTTPS enforcement
- Header vs query string: Tokens in URLs leak via logs/referrer
- Rate limiting: Brute-force protection
- Rotation policy: Key refresh mechanisms

🔍 VULNERABILITY TESTING PATTERNS:

**Session Fixation**:
1. Obtain session ID before authentication
2. Force victim to use attacker's session ID
3. Victim authenticates with fixated session
4. Attacker hijacks authenticated session
Detection: Check if session ID changes after login

**Session Prediction/Hijacking**:
- Collect multiple session tokens
- Analyze for sequential patterns, timestamps
- Test for weak randomness (low entropy)
- Attempt to forge valid session IDs

**Session Timeout Issues**:
- Absolute timeout: Session expires after fixed time
- Idle timeout: Session expires after inactivity
- Test: Wait configured time, verify session invalidated
- Check: Concurrent session limits

**Logout Functionality**:
- Client-side only: Token removed from browser but still valid
- Server-side revocation: Token blacklisted/invalidated
- Test: Logout → Reuse old token → Should fail
- Token refresh after logout: Should not issue new tokens

**CORS (Cross-Origin Resource Sharing)**:
- Access-Control-Allow-Origin: * → Allows any domain
- Access-Control-Allow-Credentials: true → Exposes cookies
- Wildcard + credentials: Critical vulnerability
- Origin reflection: Server echoes Origin header
- Null origin: file:// scheme exploitation

**Cross-Site Request Forgery (CSRF)**:
- Anti-CSRF token presence in forms
- Token validation on server-side
- SameSite cookie attribute
- Custom header requirement

**Session Puzzling/Variable Overloading**:
- Multiple session variables with same name
- Privilege escalation via variable collision
- Session scope confusion (user vs admin sessions)

🛠️ MCP TOOL USAGE:
- analyze_cookies(url): Comprehensive cookie attribute analysis + entropy check
- test_session_fixation(login_url, login_data): Pre/post-auth session comparison
- test_logout_functionality(logout_url, protected_url, initial_session): Token reuse after logout
- test_session_timeout(url, session, wait_seconds): Idle timeout validation
- test_cors_misconfiguration(url): CORS policy analysis
- test_exposed_session_vars(url): Session variable exposure in URL/HTML

📊 CONTEXT-AWARE ANALYSIS:
Read from shared_context:
- tech_stack.auth_mechanism → JWT, Cookie, Token
- authenticated_sessions → Test with real sessions from ReconAgent
- entry_points.login_forms → Fixation testing targets

Write to shared_context:
- session_vulnerabilities: [
    {type, severity, evidence, exploit_steps}
  ]
- cookie_analysis: {
    flags: {secure, httpOnly, sameSite},
    entropy: "high/medium/low",
    predictability_score: float
  }
- cors_issues: [
    {origin, credentials, severity}
  ]
- logout_security: {
    server_side_revocation: bool,
    token_reuse_possible: bool
  }

🎯 SUCCESS CRITERIA: Identify all session management flaws, demonstrate token reuse/fixation/prediction, verify logout security
"""
    async def run(self) -> None:
        client = MCPClient()

        #  AUTHENTICATED SESSION SUPPORT
        auth_sessions = self.shared_context.get("authenticated_sessions", {})
        auth_data = None
        if auth_sessions and auth_sessions.get('sessions', {}).get('logged_in'):
            successful_logins = auth_sessions.get('successful_logins', [])
            if successful_logins:
                first_login = successful_logins[0]
                auth_data = {
                    'username': first_login.get('username'),
                    'session_type': first_login.get('session_type'),
                }
                self.log("info", f" Using authenticated session: {first_login.get('username')}")


        target = self._get_target()
        if not target:
            self.log("error", "Target missing; aborting SessionManagementAgent")
            return

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        # Analyze cookies
        if self.should_run_tool("analyze_cookies"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="session-management-testing",
                        tool="analyze_cookies",
                        args={"url": target}, auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    cookies = res.get("data", {}).get("cookies", [])
                    if isinstance(cookies, list):
                        weak = [c for c in cookies if not c.get("is_secure") or not c.get("is_httponly") or c.get("samesite") in ("Not Set", "none")]
                        if weak:
                            self.add_finding("WSTG-SESS", "Weak cookie attributes detected", severity="medium", evidence={"sample": weak[:3]})
            except Exception as e:
                self.log("warning", f"analyze_cookies failed: {e}")

        # CORS misconfiguration basics
        if self.should_run_tool("test_cors_misconfiguration"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="session-management-testing",
                        tool="test_cors_misconfiguration",
                        args={"url": target}, auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        self.add_finding("WSTG-SESS", "CORS misconfiguration could leak credentials", severity="high", evidence=data)
            except Exception as e:
                self.log("warning", f"test_cors_misconfiguration failed: {e}")

        # Test session timeout
        if self.should_run_tool("test_session_timeout"):
            try:
                if auth_data:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="session-management-testing",
                            tool="test_session_timeout",
                            args={"url": target, "session": auth_data, "wait_seconds": 30}
                        ),
                        timeout=60
                    )
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("session_still_valid"):
                            self.add_finding("WSTG-SESS", "Session timeout not enforced", severity="medium", evidence=data)
            except Exception as e:
                self.log("warning", f"test_session_timeout failed: {e}")

        # Test logout functionality
        if self.should_run_tool("test_logout_functionality"):
            try:
                if auth_data and auth_sessions.get('successful_logins'):
                    first_login = auth_sessions.get('successful_logins', [])[0]
                    logout_url = first_login.get('logout_url', f"{target}/logout")
                    protected_url = first_login.get('protected_url', f"{target}/profile")
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="session-management-testing",
                            tool="test_logout_functionality",
                            args={"logout_url": logout_url, "protected_url": protected_url, "initial_session": auth_data}
                        ),
                        timeout=45
                    )
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("session_valid_after_logout"):
                            self.add_finding("WSTG-SESS", "Session remains valid after logout", severity="high", evidence=data)
            except Exception as e:
                self.log("warning", f"test_logout_functionality failed: {e}")

        # Test session fixation
        if self.should_run_tool("test_session_fixation"):
            try:
                login_url = f"{target}/login"
                login_data = {"username": "test", "password": "test123"}
                if auth_sessions.get('successful_logins'):
                    first_login = auth_sessions.get('successful_logins', [])[0]
                    login_url = first_login.get('login_url', login_url)
                    login_data = {"username": first_login.get('username'), "password": "test"}
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="session-management-testing",
                        tool="test_session_fixation",
                        args={"login_url": login_url, "login_data": login_data}
                    ),
                    timeout=60
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable_to_fixation"):
                        self.add_finding("WSTG-SESS", "Session fixation vulnerability detected", severity="high", evidence=data)
            except Exception as e:
                self.log("warning", f"test_session_fixation failed: {e}")

        # Test exposed session variables
        if self.should_run_tool("test_exposed_session_vars"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="session-management-testing",
                        tool="test_exposed_session_vars",
                        args={"url": target}
                    ),
                    timeout=30
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    exposed = data.get("exposed_vars", [])
                    if exposed:
                        self.add_finding("WSTG-SESS", "Session variables exposed in URL or page", severity="medium", evidence={"exposed": exposed})
            except Exception as e:
                self.log("warning", f"test_exposed_session_vars failed: {e}")

        # OPSI B: CSRF Protection Testing
        try:
            res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="session-management-testing",
                    tool="test_csrf_protection",
                    args={"url": target, "form_data": {"test": "data"}}, auth_session=auth_data
                ),
                timeout=30
            )
            if isinstance(res, dict) and res.get("status") == "success":
                data = res.get("data", {})
                if data.get("csrf_vulnerable") or not data.get("has_csrf_token_in_form"):
                    self.add_finding("WSTG-SESS", "Missing or weak CSRF protection", severity="high", 
                                   evidence={"csrf_token_present": data.get("has_csrf_token_in_form"),
                                           "vulnerable": data.get("csrf_vulnerable")})
                weak_samesite = [c for c in data.get("cookies_samesite_check", []) if c.get("samesite") == "Not Set"]
                if weak_samesite:
                    self.add_finding("WSTG-SESS", "Session cookies without SameSite protection", severity="medium",
                                   evidence={"cookies": weak_samesite})
        except Exception as e:
            self.log("warning", f"test_csrf_protection failed: {e}")

        # OPSI B: Session Puzzling/Variable Overwriting
        try:
            res = await self.run_tool_with_timeout(
                client.call_tool(
                    server="session-management-testing",
                    tool="test_session_puzzling",
                    args={"url": target, "test_params": {"admin": "1", "role": "administrator"}}, auth_session=auth_data
                ),
                timeout=45
            )
            if isinstance(res, dict) and res.get("status") == "success":
                data = res.get("data", {})
                if data.get("array_injection_vulnerable"):
                    self.add_finding("WSTG-SESS", "Session puzzling: array injection possible", severity="high",
                                   evidence={"array_injection": True})
                reflected_vars = [t for t in data.get("parameter_pollution_tests", []) if t.get("reflected_in_response")]
                if reflected_vars:
                    self.add_finding("WSTG-SESS", "Session variable pollution possible", severity="medium",
                                   evidence={"reflected_variables": [v["variable"] for v in reflected_vars]})
        except Exception as e:
            self.log("warning", f"test_session_puzzling failed: {e}")

        # OPSI B: Session Hijacking Tests
        if auth_data and auth_sessions.get('successful_logins'):
            try:
                # Extract session cookies from authenticated session
                first_login = auth_sessions.get('successful_logins', [])[0]
                session_cookies = {"token": first_login.get('username', 'test_token')}  # Simplified
                
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="session-management-testing",
                        tool="test_session_hijacking",
                        args={"url": target, "session_cookies": session_cookies}, auth_session=auth_data
                    ),
                    timeout=40
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    weak_tokens = [t for t in data.get("token_analysis", []) if t.get("predictable")]
                    if weak_tokens:
                        self.add_finding("WSTG-SESS", "Weak session token entropy - hijacking risk", severity="high",
                                       evidence={"weak_tokens": weak_tokens})
                    if not data.get("httponly_protection"):
                        self.add_finding("WSTG-SESS", "Session cookies without HTTPOnly - XSS hijacking risk", severity="high",
                                       evidence={"httponly": False})
                    if data.get("session_reusable_after_logout"):
                        self.add_finding("WSTG-SESS", "Session remains valid after logout", severity="high",
                                       evidence={"session_reuse": True})
            except Exception as e:
                self.log("warning", f"test_session_hijacking failed: {e}")

        self.log("info", "Session management checks complete (OPSI B tools included)")

    def _get_available_tools(self) -> list[str]:
        """Return session management testing tools for LLM planning"""
        return [
            'analyze_cookies',
            'test_session_timeout',
            'test_logout_functionality',
            'test_session_fixation',
            'test_cors_misconfiguration',
            'test_exposed_session_vars'
        ]

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
