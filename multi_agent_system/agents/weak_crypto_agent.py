from __future__ import annotations

from urllib.parse import urlparse

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("WeakCryptographyAgent")
class WeakCryptographyAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are WeakCryptographyAgent, an OWASP WSTG-CRYP expert specializing in cryptographic security testing.

🎯 PRIMARY MISSION: Test cryptographic implementations using MCP tools to identify weak encryption, JWT flaws, TLS misconfigurations, and insecure randomness.

🧠 ADAPTIVE STRATEGY:
1. Read authentication context from shared_context
2. Identify cryptographic implementations:
   - JWT tokens → Extract from Authorization headers, cookies
   - Session tokens → Analyze entropy and predictability
   - Password hashes → Extract via SQLi findings (if available)
   - TLS/SSL → Analyze certificate and cipher configuration
3. Select appropriate tools based on implementations found:
   - analyze_jwt → For JWT structure and claims analysis
   - test_jwt_vulnerabilities → For algorithm confusion, none bypass
   - test_tls_configuration → For SSL/TLS security
   - analyze_token_entropy → For randomness testing
   - crack_password_hashes → For password strength analysis
4. Execute tools progressively (detection → exploitation)
5. Test multiple tokens for pattern analysis
6. Report cryptographic weaknesses with impact assessment

⚠️ EXECUTION GUIDELINES:
- Execute all cryptography testing tools
- Extract and analyze ALL authentication tokens
- Test JWT with 10+ attack vectors (tools handle this)
- Analyze TLS configuration comprehensively
- Test token entropy with 100+ samples
- Continue testing all cryptographic aspects

🧠 ADAPTIVE TESTING STRATEGY:
1. Extract ALL tokens/JWTs from authenticated requests (from shared_context)
2. Test JWT security (10+ attack vectors above)
3. Analyze TLS/SSL configuration (protocols, ciphers, certificates) with testssl.sh
4. Test randomness and entropy (100+ session tokens, statistical analysis)
5. Verify data transmission security (plaintext vs encrypted, HTTPS enforcement)
6. Extract password hashes via SQLi and analyze strength (MD5, bcrypt, argon2)

� CRYPTOGRAPHIC VULNERABILITY PATTERNS:

**Weak Password Hashing**:
- MD5: Cryptographically broken, fast to crack with rainbow tables
- SHA1: Deprecated, collision attacks possible
- Plain hash without salt: Vulnerable to rainbow table attacks
- Weak salt: Predictable, reused, or too short
- Low iteration count: bcrypt/PBKDF2 with rounds < 10,000
- Identify: Extract hashes via SQLi, error messages, API responses
- Crack: CrackStation, hashcat, john the ripper

**JWT (JSON Web Token) Vulnerabilities**:
- None algorithm bypass: Set "alg":"none", remove signature
- Algorithm confusion: RS256 (asymmetric) → HS256 (symmetric)
  - Download public key, sign with it as HMAC secret
- Weak secret: Brute-force HMAC key with wordlists
- Key injection: "kid" parameter → SQLi, path traversal, command injection
- Claim manipulation: Modify exp, role, user_id, permissions
- Missing expiration: No 'exp' claim = token never expires
- Token not revoked: Valid after logout (no blacklist/database check)
- JKU/X5U header exploitation: Point to attacker's public keys

**TLS/SSL Configuration Issues**:
- Outdated protocols: SSLv2, SSLv3, TLS 1.0, TLS 1.1 (deprecated)
- Weak ciphers: RC4, DES, 3DES, NULL ciphers, export-grade
- Missing HSTS: No Strict-Transport-Security header
- HSTS weak configuration: max-age too short, no includeSubDomains
- Certificate issues: Self-signed, expired, wrong hostname, weak signature (MD5, SHA1)
- Mixed content: HTTPS page loading HTTP resources
- SSL stripping: Downgrade attack possible

**Insecure Randomness/Entropy**:
- Predictable session IDs: Sequential, timestamp-based, weak PRNG
- Weak CSRF tokens: Low entropy, reusable
- Predictable reset tokens: Based on username, email, time
- Insecure random number generation: rand() instead of cryptographically secure RNG
- Statistical analysis: Collect multiple tokens, analyze for patterns
- Entropy measurement: Shannon entropy, chi-square test

**Cleartext Transmission**:
- HTTP instead of HTTPS: Credentials, tokens, session IDs in plaintext
- HTTPS downgrade: Missing HSTS allows protocol downgrade
- Sensitive data in URLs: Tokens, passwords in query strings (logged!)
- HTTP Basic Auth over HTTP: Base64-encoded credentials in plaintext
- Cookie without Secure flag: Transmitted over HTTP

**Weak Encryption Algorithms**:
- DES, 3DES: Deprecated block ciphers
- RC4: Stream cipher with biases
- ECB mode: Electronic Codebook (pattern leakage)
- No IV/nonce: Reused initialization vectors
- Hardcoded keys: Encryption keys in source code/config

**Padding Oracle Attacks**:
- CBC mode with padding: Vulnerable if error messages differ
- Error-based decryption: "Invalid padding" vs "Invalid MAC"
- Test: Send modified ciphertext, observe error responses

**Insufficient Key Length**:
- RSA < 2048 bits: Factorization attacks
- AES < 128 bits: Brute-force feasible
- HMAC with short keys: < 128 bits vulnerable

**Insecure Key Storage**:
- Keys in source code: Hardcoded secrets
- Keys in client-side JavaScript: Publicly accessible
- Keys in configuration files: .env, web.config exposed
- Keys in mobile apps: APK/IPA reverse engineering

**Null Byte Injection (Cryptographic Context)**:
- %00 in filenames: Bypass extension validation
- Null byte in certificate CN: Bypass hostname verification
- String truncation: Null byte terminates validation

🔍 TESTING METHODOLOGY:

**Step 1: Password Hash Extraction**
- SQLi to extract password hashes
- API responses leaking hashes
- Error messages revealing hash format
- Identify algorithm: Length (MD5=32, SHA1=40, bcrypt=60)

**Step 2: JWT Analysis**
- Decode token (base64url)
- Check algorithm: None, HS256, RS256, ES256
- Verify expiration: 'exp', 'iat', 'nbf' claims
- Test algorithm confusion: Switch RS256↔HS256
- Attempt signature bypass: None algorithm
- Brute-force weak secrets: jwt_tool, hashcat

**Step 3: TLS/SSL Testing**
- Protocol enumeration: SSLv2, SSLv3, TLS 1.0/1.1/1.2/1.3
- Cipher suite analysis: Weak, medium, strong
- Certificate validation: Expiry, hostname, chain
- HSTS check: Presence, max-age, preload
- Downgrade attack: Force HTTP connection

**Step 4: Randomness Testing**
- Collect multiple tokens (100+)
- Analyze patterns: Sequential, timestamp-based
- Statistical tests: Entropy, distribution
- Predictability: Forecast next token

**Step 5: Cleartext Detection**
- Network traffic analysis: HTTP vs HTTPS
- Check for mixed content: HTTPS page, HTTP resources
- URL parameter inspection: Sensitive data in GET
- Cookie flags: Secure, HttpOnly

🛠️ MCP TOOL USAGE:
- test_tls_configuration(host, port): testssl.sh comprehensive TLS scan
- analyze_jwt(token): Decode + vulnerability analysis
- test_cleartext_info(domain): Check HTTP transmission of sensitive data
- run_nuclei_crypto_scan(url, tags): Nuclei crypto-related templates
- analyze_token_randomness(tokens): Statistical entropy analysis

📊 CONTEXT-AWARE TESTING:
Read from shared_context:
- tech_stack.auth_mechanism → JWT, session cookies
- extracted_data.credentials → Password hashes to crack
- tech_stack.backend → Expected crypto libraries

Write to shared_context:
- weak_hashing: [
    {algorithm, hash_samples, cracked_passwords}
  ]
- jwt_vulnerabilities: [
    {type, severity, exploit_technique, forged_token}
  ]
- tls_issues: [
    {protocol_version, weak_ciphers, certificate_problems}
  ]
- insecure_randomness: [
    {token_type, entropy_score, predictability}
  ]
- cleartext_transmission: [
    {endpoint, data_type, sensitive_info}
  ]

🎯 SUCCESS CRITERIA: Crack password hashes, forge JWT tokens, identify TLS weaknesses, demonstrate token predictability
"""
    
    async def run(self) -> None:
        client = MCPClient()
        # 🔑 AUTHENTICATED SESSION SUPPORT
        auth_sessions = self.shared_context.get("authenticated_sessions", {})
        auth_data = None
        if auth_sessions and auth_sessions.get('sessions', {}).get('logged_in'):
            successful_logins = auth_sessions.get('successful_logins', [])
            if successful_logins:
                first_login = successful_logins[0]
                auth_data = {
                    'username': first_login.get('username'),
                    'session_type': first_login.get('session_type'),
                    'token': first_login.get('token'),  # BUGFIX: Include JWT token for authenticated API calls
                    'cookies': first_login.get('cookies', {}),  # Include cookies if available
                }
                self.log("info", f"✅ Using authenticated session: {first_login.get('username')} (token: {first_login.get('token')[:20] if first_login.get('token') else 'None'}...)")

        target = self._get_target()
        if not target:
            self.log("error", "Target missing; aborting WeakCryptographyAgent")
            return

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        parsed = urlparse(target)
        host = parsed.netloc or parsed.hostname or target

        # TLS configuration
        if self.should_run_tool("test_tls_configuration"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="weak-cryptography-testing",
                        tool="test_tls_configuration",
                        args={"host": host, "port": 443}, auth_session=auth_data)
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    summary = res.get("data", {}).get("summary", {})
                    if summary:
                        self.add_finding("WSTG-CRYP", "TLS configuration issues found", severity="medium", evidence={"sample": list(summary.items())[:3]})
            except Exception as e:
                self.log("warning", f"test_tls_configuration failed: {e}")

        # Cleartext info over HTTP
        if self.should_run_tool("test_cleartext_info"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="weak-cryptography-testing",
                        tool="test_cleartext_info",
                        args={"domain": host}, auth_session=auth_data)
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("http_reachable") and (data.get("password_field_on_http") or data.get("form_posts_to_http")):
                        self.add_finding("WSTG-CRYP", "Sensitive info over HTTP", severity="high", evidence=data)
            except Exception as e:
                self.log("warning", f"test_cleartext_info failed: {e}")

        # Run nuclei crypto scan
        if self.should_run_tool("run_nuclei_crypto_scan"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="weak-cryptography-testing",
                        tool="run_nuclei_crypto_scan",
                        args={"url": target, "tags": ["crypto", "ssl", "tls"]}, auth_session=auth_data), timeout=600
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    findings = res.get("data", {}).get("findings", [])
                    if findings:
                        self.add_finding("WSTG-CRYP", "Cryptography vulnerabilities detected by nuclei", severity="medium", evidence={"sample": findings[:3]})
            except Exception as e:
                self.log("warning", f"run_nuclei_crypto_scan failed: {e}")

        # Analyze token randomness
        if self.should_run_tool("analyze_token_randomness"):
            try:
                # Get session tokens from context
                tokens = self.shared_context.get("session_tokens", [])
                if tokens and len(tokens) >= 10:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="weak-cryptography-testing",
                            tool="analyze_token_randomness",
                            args={"tokens": tokens}, auth_session=auth_data)
                    )
                    if isinstance(res, dict) and res.get("status") == "success":
                        analysis = res.get("data", {})
                        if analysis.get("weak_randomness"):
                            self.add_finding("WSTG-CRYP", "Weak session token randomness detected", severity="high", evidence=analysis)
                else:
                    self.log("info", "Insufficient tokens for randomness analysis (need >= 10)")
            except Exception as e:
                self.log("warning", f"analyze_token_randomness failed: {e}")

        # PHASE 2.4: Test JWT weakness
        if self.should_run_tool("test_jwt_weakness"):
            try:
                # Extract JWT from authenticated session
                jwt_token = None
                if auth_sessions and auth_sessions.get('successful_logins'):
                    for login in auth_sessions['successful_logins']:
                        if login.get('token'):
                            jwt_token = login['token']
                            break

                if jwt_token:
                    self.log("info", f"Testing JWT token for vulnerabilities (length: {len(jwt_token)})")
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="weak-cryptography-testing",
                            tool="test_jwt_weakness",
                            args={"token": jwt_token, "target_url": target}
                        ), timeout=300
                    )
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("vulnerable"):
                            findings = data.get("findings", [])
                            critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                            high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
                            severity = "critical" if critical_count > 0 else ("high" if high_count > 0 else "medium")
                            self.add_finding("WSTG-CRYP-02", f"JWT vulnerabilities found: {len(findings)} issues ({critical_count} critical, {high_count} high)", severity=severity, evidence={"findings": findings, "token_info": data.get("token_info", {})})
                            self.log("info", f"JWT weakness test found {len(findings)} vulnerabilities")
                        else:
                            self.log("info", "No JWT vulnerabilities detected")
                else:
                    self.log("info", "No JWT token available for testing (requires authenticated session)")
            except Exception as e:
                self.log("warning", f"test_jwt_weakness failed: {e}")

        self.log("info", "Weak cryptography checks complete")

    def _get_available_tools(self) -> list[str]:
        """Return weak cryptography testing tools for LLM planning"""
        return [
            'test_tls_configuration',
            'test_cleartext_info',
            'run_nuclei_crypto_scan',
            'analyze_token_randomness',
            'test_jwt_weakness'  # PHASE 2.4: JWT vulnerability testing
        ]

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
