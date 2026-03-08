from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("AuthenticationAgent")
class AuthenticationAgent(BaseAgent):
	system_prompt: ClassVar[str] = """
You are AuthenticationAgent, an OWASP WSTG-ATHN expert specializing in authentication security testing.

🎯 PRIMARY MISSION: Test authentication mechanisms using available MCP tools to identify vulnerabilities.

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints from shared_context
2. Identify authentication endpoints (login, register, password-reset, OAuth, SSO)
3. Analyze authentication mechanism type:
   - Form-based → Test SQLi bypass, default credentials, brute force
   - JWT-based → Test algorithm confusion, claim manipulation, signature bypass
   - OAuth/SSO → Test redirect_uri, state parameter, token leakage
   - API key → Test key exposure, rotation, rate limiting
4. Select appropriate tools for each mechanism type
5. Execute tools progressively (simple → complex attacks)
6. Store successful credentials in shared_context for other agents

⚠️ EXECUTION GUIDELINES:
- Execute 15+ authentication tools for comprehensive testing
- Test ALL discovered authentication endpoints
- Attempt multiple bypass techniques per endpoint
- Extract and analyze all authentication tokens
- Report successful authentications to shared_context
- Continue testing even after successful bypass

🧠 ADAPTIVE TESTING STRATEGY:
1. Identify authentication endpoints (login, registration, password reset, OAuth callback)
2. Analyze authentication mechanism (form-based, JWT, session cookies, API keys, OAuth, SAML)
3. Test progressively: default creds → SQLi → logic flaws → cryptographic attacks
4. Chain attacks: bypass → privilege escalation → persistence
5. Test ALL discovered endpoints exhaustively

� AUTHENTICATION BYPASS TECHNIQUES:

**SQL Injection Login Bypass**:
- Classic: ' OR '1'='1'--, ' OR 1=1--, admin'--
- Email-based: user@example.com'--,  user@example.com' OR '1'='1
- Union-based credential extraction: ' UNION SELECT username, password FROM users--
- Boolean blind: ' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
- Time-based blind: ' AND IF(1=1, SLEEP(5), 0)--
- Second-order: Inject in registration, trigger in login

**Default & Common Credentials**:
- Admin accounts: admin/admin, administrator/password, root/root, admin/123456
- Service accounts: test/test, demo/demo, guest/guest, user/user
- Vendor defaults: Consult manufacturer documentation
- Common patterns: username/username, company_name/year

**Weak Password Policies**:
- Test minimum requirements: single char, no uppercase, no numbers, no symbols
- Predictable patterns: Password1, Welcome123, Company2024
- Common passwords: password, 123456, qwerty, admin

**JWT (JSON Web Token) Attacks**:
- None algorithm bypass: Change "alg":"RS256" to "alg":"none", remove signature
- Algorithm confusion: RS256 (asymmetric) → HS256 (symmetric), sign with public key as HMAC secret
- Weak secret brute-force: Use hashcat/john with common wordlists
- Key injection: "kid" parameter → SQL injection, path traversal
- Claim manipulation: Change role, user_id, exp (expiration), iat (issued at)
- Token forgery: If public key accessible, attempt algorithm confusion
- JKU/X5U header injection: Point to attacker-controlled keys

**OAuth 2.0 / OpenID Connect Flaws**:
- Open redirect: Manipulate redirect_uri to attacker domain
- State parameter missing: CSRF attacks possible
- Code reuse: Reuse authorization code multiple times
- Client secret exposure: Check JavaScript, mobile apps, public repos
- Implicit grant: Extract access_token from URL fragment (#)

**Multi-Factor Authentication (2FA/MFA) Bypass**:
- Direct access: Request protected resource without 2FA step
- Response manipulation: Change {"2fa_required": true} to false
- Code reuse: Reuse previously valid TOTP/SMS codes
- Brute-force: 6-digit TOTP codes = 1M combinations (rate limiting critical)
- Backup codes: Test for weak generation (predictable, reusable)
- Recovery flow: Exploit weak "forgot 2FA" mechanisms
- SQLi extraction: Extract TOTP secrets from database (base32 encoded)

**CAPTCHA Bypass**:
- Missing server-side validation: Submit form without CAPTCHA token
- Reusable tokens: Use same CAPTCHA solution multiple times
- Empty value: captcha_response=""
- OCR/API solving: Use automated solving services
- Rate limiting absence: Brute-force without CAPTCHA

**Password Reset Flaws**:
- Token predictability: Sequential, timestamp-based, weak randomness
- Token reuse: Use same reset token multiple times
- Email parameter manipulation: Change email in request to takeover accounts
- Host header injection: Manipulate password reset link domain
- Token leakage: Check Referer header, logs, error messages

**Session Fixation**:
- Pre-authentication session: Set session ID before login, reuse after
- Cookie injection: Force victim to use attacker's session ID
- Missing regeneration: Session ID not changed after authentication

**Username Enumeration**:
- Timing differences: Slower response for existing usernames
- Error message differences: "Invalid password" vs "User not found"
- Registration page: "Email already exists"
- Password reset: Different responses for existing/non-existing users
- HTTP response codes: 200 vs 401 for valid/invalid users

**Brute-Force & Credential Stuffing**:
- Rate limiting check: Test 10-20 rapid attempts
- Account lockout: Test if account locks after N failed attempts
- IP-based blocking: Test from multiple IPs or using proxies
- Credential stuffing: Use leaked credential databases (Have I Been Pwned)

�️ MCP TOOL USAGE:
- test_auth_bypass(url): ffuf-based authentication bypass fuzzing
- test_default_credentials(target): Default credential checks
- analyze_jwt(token): Decode JWT, check algorithm, expiration, claims
- test_session_fixation(login_url, login_data): Set session before/after auth
- get_manual_testing_checklist(topic): Checklists for 'security_questions', 'alt_channel'

📊 CONTEXT-AWARE ATTACK SELECTION:
Read from shared_context:
- tech_stack.auth_mechanism → JWT, OAuth, SAML, form-based
- tech_stack.backend → SQL injection dialect (MySQL, PostgreSQL, etc.)
- entry_points.login_forms → Target URLs for bypass attempts
- authenticated_sessions → Reuse existing sessions from ReconAgent

Write to shared_context:
- bypassed_accounts: [{username, password, method, privileges}]
- jwt_vulnerabilities: [{type, severity, exploit_steps}]
- default_credentials: [{service, username, password}]
- weak_policies: [findings]

🎯 SUCCESS CRITERIA: Gain unauthorized access through any available bypass technique, extract credentials, escalate privileges
"""
	async def run(self) -> None:
		client = MCPClient()
		
		# 🔑 AUTHENTICATED SESSION SUPPORT (via Orchestrator auto-login)
		auth_data = self.get_auth_session()
		if auth_data:
			self.log("info", f"✅ Using authenticated session: {auth_data.get('username')}")
		else:
			self.log("info", "🔓 No pre-existing session - AuthenticationAgent will test login mechanisms")

		target = self._get_target()
		if not target:
			self.log("error", "Target missing; aborting AuthenticationAgent")
			return

		# Log tool execution plan based on LLM selection
		self.log_tool_execution_plan()

		# Quick passive checks on the login form HTML (CSRF, method, autocomplete)
		try:
			import httpx, re
			async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as http:
				resp = await http.get(target)
				html = resp.text if resp is not None else ""
				# CSRF token presence (heuristic)
				csrf_present = bool(re.search(r'<input[^>]+name=["\'](?:csrf|_token|authenticity_token)["\']', html, re.I))
				# Method POST on the login form
				form_method_post = bool(re.search(r'<form[^>]+method=["\']post["\']', html, re.I))
				# Password field autocomplete
				autocomplete_weak = bool(re.search(r'<input[^>]+type=["\']password["\'][^>]*autocomplete=["\']?on', html, re.I))
				if not csrf_present:
					self.add_finding("WSTG-ATHN", "Possible missing CSRF token on login form", severity="medium")
				if not form_method_post:
					self.add_finding("WSTG-ATHN", "Login form may not use POST method", severity="high")
				if autocomplete_weak:
					self.add_finding("WSTG-ATHN", "Password field allows autocomplete", severity="low")
		except Exception as e:
			self.log("warning", f"passive login form checks failed: {e}")
		
		# Test TLS credentials
		if self.should_run_tool("test_tls_credentials"):
			try:
				res = await self.run_tool_with_timeout(
					client.call_tool(
						server="authentication-testing",
						tool="test_tls_credentials",
						args={"login_url": target}, auth_session=auth_data
					)
				)
				if isinstance(res, dict) and res.get("status") == "success":
					data = res.get("data", {})
				# Sanitize evidence - extract safe fields only
				safe_evidence = {
					"page_served_over_https": bool(data.get("page_served_over_https")),
					"form_action_is_https": bool(data.get("form_action_is_https"))
				}
				if not data.get("page_served_over_https") or not data.get("form_action_is_https"):
					self.add_finding("WSTG-ATHN", "Login not fully over HTTPS", severity="medium", evidence=safe_evidence)
				else:
					self.add_finding("WSTG-ATHN", "Login served over HTTPS", severity="info", evidence=safe_evidence)
			except Exception as e:
				self.log("warning", f"test_tls_credentials failed: {e}")

		# Test cache headers
		if self.should_run_tool("test_cache_headers"):
			try:
				res = await self.run_tool_with_timeout(
					client.call_tool(
						server="authentication-testing",
						tool="test_cache_headers",
						args={"url": target}, auth_session=auth_data
					)
				)
				if isinstance(res, dict) and res.get("status") == "success":
					data = res.get("data", {})
					if not data.get("is_caching_disabled"):
						# Sanitize cache evidence
						safe_evidence = {"is_caching_disabled": bool(data.get("is_caching_disabled"))}
						self.add_finding("WSTG-ATHN", "Sensitive pages may be cacheable", severity="low", evidence=safe_evidence)
			except Exception as e:
				self.log("warning", f"test_cache_headers failed: {e}")

		# OPSI B: Account Lockout Mechanism
		if self.should_run_tool("test_lockout_mechanism"):
			try:
				login_url = target if '/login' in target else f"{target}/login"
				res = await self.run_tool_with_timeout(
					client.call_tool(
						server="authentication-testing",
						tool="test_lockout_mechanism",
						args={"login_url": login_url, "username": "testuser", "wrong_password": "wrongpass123", "attempts": 6}, auth_session=auth_data
					),
					timeout=45
				)
				if isinstance(res, dict) and res.get("status") == "success":
					data = res.get("data", {})
					if not data.get("lockout_detected") and not data.get("rate_limiting_suspected"):
						# Sanitize lockout evidence - ensure serializable
						attempts = data.get("total_attempts")
						safe_attempts = int(attempts) if isinstance(attempts, (int, float)) else str(attempts) if attempts is not None else "unknown"
						self.add_finding("WSTG-ATHN", "No account lockout or rate limiting detected", severity="high",
									   evidence={"attempts_allowed": safe_attempts})
					elif data.get("rate_limiting_suspected"):
						self.add_finding("WSTG-ATHN", "Rate limiting detected (good security)", severity="info",
									   evidence={"mechanism": "rate_limiting"})
			except Exception as e:
				self.log("warning", f"test_lockout_mechanism failed: {e}")

		# OPSI B: Security Questions Weakness
		if self.should_run_tool("test_security_questions"):
			try:
				# Check common security question endpoints
				for path in ["/forgot-password", "/reset-password", "/security-question"]:
					sec_q_url = f"{target.rstrip('/')}{path}"
					res = await self.run_tool_with_timeout(
						client.call_tool(
							server="authentication-testing",
							tool="test_security_questions",
							args={"url": sec_q_url}, auth_session=auth_data
						),
						timeout=30
					)
					if isinstance(res, dict) and res.get("status") == "success":
						data = res.get("data", {})
						if data.get("security_questions_found"):
							severity = "medium" if data.get("rate_limiting") else "high"
						severity = "medium" if data.get("rate_limiting") else "high"
						# Sanitize questions - might contain unhashable objects
						questions = data.get("sample_questions", [])
						safe_questions = str(questions) if not isinstance(questions, (list, dict, str, int, float, bool, type(None))) else questions
						self.add_finding("WSTG-ATHN", "Security questions may be predictable", severity=severity,
									   evidence={"questions": safe_questions, "rate_limiting": data.get("rate_limiting")})
						break
				self.log("warning", f"test_security_questions failed: {e}")
			except Exception as e:
				self.log("warning", f"test_security_questions failed: {e}")
		if self.should_run_tool("test_password_reset"):
			try:
				reset_url = f"{target.rstrip('/')}/reset-password"
				res = await self.run_tool_with_timeout(
					client.call_tool(
						server="authentication-testing",
						tool="test_password_reset",
						args={"reset_url": reset_url, "email": "test@example.com"}, auth_session=auth_data
					),
					timeout=40
				)
				if isinstance(res, dict) and res.get("status") == "success":
					data = res.get("data", {})
					if data.get("vulnerabilities_found", 0) > 0:
						for finding in data.get("findings", []):
							severity_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
							# Sanitize finding to remove unhashable objects
							safe_evidence = {"description": finding.get("description", ""), "severity": finding.get("severity", "medium")}
							self.add_finding("WSTG-ATHN", f"Password reset: {finding.get('description')}", 
										   severity=severity_map.get(finding.get("severity"), "medium"),
										   evidence=safe_evidence)
			except Exception as e:
				self.log("warning", f"test_password_reset failed: {e}")

		# OPSI B: Alternative Channel Authentication
		if self.should_run_tool("test_alternative_channel_auth"):
			try:
				res = await self.run_tool_with_timeout(
					client.call_tool(
						server="authentication-testing",
						tool="test_alternative_channel_auth",
						args={"base_url": target}, auth_session=auth_data
					),
					timeout=60
				)
				if isinstance(res, dict) and res.get("status") == "success":
					data = res.get("data", {})
					if data.get("vulnerabilities_found", 0) > 0:
						for finding in data.get("findings", []):
							severity_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
							# Sanitize finding to remove unhashable objects
							safe_evidence = {"description": finding.get("description", ""), "severity": finding.get("severity", "medium")}
							self.add_finding("WSTG-ATHN", f"Alt channel: {finding.get('description')}", 
										   severity=severity_map.get(finding.get("severity"), "medium"),
										   evidence=safe_evidence)
			except Exception as e:
				self.log("warning", f"test_alternative_channel_auth failed: {e}")

		# WSTG-ATHN-06: Auth bypass via schema manipulation
		if self.should_run_tool("test_auth_bypass_schema"):
			try:
				res = await self.run_tool_with_timeout(
					client.call_tool(
						server="authentication-testing",
						tool="test_auth_bypass_schema",
						args={"url": target}, auth_session=auth_data
					),
					timeout=120
				)
				if isinstance(res, dict) and res.get("status") == "success":
					data = res.get("data", {})
					if data.get("vulnerabilities_found", 0) > 0:
						for finding in data.get("findings", [])[:5]:
							severity_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
							safe_evidence = {"type": finding.get("type", ""), "path": finding.get("path", "")}
							self.add_finding("WSTG-ATHN-06", f"Auth bypass: {finding.get('description', 'Schema manipulation')}",
										   severity=severity_map.get(finding.get("severity"), "high"),
										   evidence=safe_evidence)
			except Exception as e:
				self.log("warning", f"test_auth_bypass_schema failed: {e}")

		self.log("info", "Authentication checks complete (OPSI B tools included)")

	def _get_available_tools(self) -> list[str]:
		"""Return list of authentication testing tool names"""
		return [
			'test_default_credentials',
			'test_lockout_mechanism',
			'test_tls_credentials',
			'test_password_reset',
			'test_security_questions',
			'test_cache_headers',
			'test_alternative_channel_auth',
			'test_auth_bypass_schema',
		]

	def _get_target(self) -> str | None:
		from ..core.db import get_db
		from ..models.models import Job
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			return job.target if job else None

