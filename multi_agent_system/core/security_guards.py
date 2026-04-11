"""
Security Guards Module

Implements authorization controls, rate limiting, and ethical safeguards
to prevent misuse of automated penetration testing system.

Author: Martua Raja Doli Pangaribuan
Version: 2.0
Last Updated: December 14, 2025
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx


class UnauthorizedTargetError(Exception):
    """Raised when target is not whitelisted"""
    pass


class SecurityPolicyViolation(Exception):
    """Raised when target explicitly disallows scanning"""
    pass


class InvalidAuthTokenError(Exception):
    """Raised when authorization token is invalid"""
    pass


class UserAbortedError(Exception):
    """Raised when user cancels scan"""
    pass


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded"""
    pass


@dataclass
class SecurityPolicy:
    """Container for target security policy"""
    disallow_scanning: bool = False
    contact_email: Optional[str] = None
    policy_url: Optional[str] = None


class SecurityGuardRails:
    """
    Prevent misuse of automated pentesting system
    
    Features:
    - Domain whitelist enforcement
    - Authorization token validation
    - Rate limiting
    - Human-in-the-loop (HITL) confirmation
    - Security policy checking (robots.txt, security.txt)
    """
    
    def __init__(self):
        self.whitelist_domains: List[str] = []
        self.require_authorization_token = True
        self.max_concurrent_scans = 3
        self.rate_limiting_enabled = True
        self.hitl_mode = True
        self.auto_approve_domains: Set[str] = {
            "localhost",
            "127.0.0.1",
            "dvwa.local",
            "juice-shop.local",
            "juice-shop",  # Docker hostname
            "owaspjuiceshop",  # External Juice Shop container
            "dvwa"  # Docker hostname
        }
        
        # Token storage (in production: use database or secure vault)
        self._valid_tokens: Dict[str, Dict] = {}
        
        # Load default whitelist
        self._load_default_whitelist()
    
    # Internal hosts always allowed (MCP containers use loopback)
    INTERNAL_HOSTS: frozenset = frozenset({"localhost", "127.0.0.1"})

    def is_host_allowed(self, host: str | None) -> bool:
        """Check if hostname matches whitelist (exact or fnmatch glob)."""
        if not host:
            return False
        host = host.lower().strip()
        if host in self.INTERNAL_HOSTS:
            return True
        for pattern in self.whitelist_domains:
            if fnmatch.fnmatch(host, pattern.lower().strip()):
                return True
        return False

    def _load_default_whitelist(self):
        """Load whitelist from ALLOWED_DOMAINS env var (comma-separated).

        Default is empty — all targets require explicit whitelist addition
        via POST /api/whitelist or whitelist_domain in POST /api/scans.
        """
        import os
        env_domains = os.getenv("ALLOWED_DOMAINS", "")
        self.whitelist_domains = [d.strip() for d in env_domains.split(",") if d.strip()]
    
    async def validate_target(
        self, 
        url: str, 
        auth_token: Optional[str] = None
    ) -> bool:
        """
        Validate target is authorized for testing
        
        Args:
            url: Target URL to test
            auth_token: Authorization token
        
        Returns:
            True if authorized
        
        Raises:
            UnauthorizedTargetError: If target not whitelisted
            SecurityPolicyViolation: If target explicitly disallows scanning
            InvalidAuthTokenError: If auth token invalid/missing
            UserAbortedError: If user cancels confirmation
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]  # Remove port
        
        # Check 1: Domain whitelist
        if not self.is_whitelisted(domain):
            raise UnauthorizedTargetError(
                f"Domain '{domain}' not in whitelist. "
                "Add to whitelist via: POST /api/whitelist\n"
                f"Current whitelist: {', '.join(self.whitelist_domains[:5])}..."
            )
        
        # Check 2: Authorization token (skip for auto-approve domains)
        if self.require_authorization_token and domain not in self.auto_approve_domains:
            if not auth_token or not self.verify_token(auth_token, domain):
                raise InvalidAuthTokenError(
                    "Valid authorization token required. "
                    "Obtain from system administrator or target owner."
                )
        
        # Check 3: Security policy (robots.txt, security.txt)
        security_policy = await self.check_security_policy(url)
        if security_policy.disallow_scanning:
            raise SecurityPolicyViolation(
                f"Target '{domain}' explicitly disallows automated scanning.\n"
                f"Policy: {security_policy.policy_url}\n"
                f"Contact: {security_policy.contact_email}"
            )
        
        # Check 4: Human-in-the-loop confirmation
        if self.hitl_mode and domain not in self.auto_approve_domains:
            await self.request_user_confirmation(url)
        
        return True
    
    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is in whitelist. Delegates to is_host_allowed()."""
        domain = domain.split(':')[0]  # Remove port if present
        return self.is_host_allowed(domain)
    
    def add_to_whitelist(self, domain: str, auth_token: str) -> bool:
        """
        Add domain to whitelist (requires admin token)
        
        Args:
            domain: Domain to whitelist
            auth_token: Admin authorization token
        
        Returns:
            True if successfully added
        """
        # Verify admin token
        if not self.verify_admin_token(auth_token):
            raise InvalidAuthTokenError("Admin token required to modify whitelist")
        
        if domain not in self.whitelist_domains:
            self.whitelist_domains.append(domain)
            print(f"✓ Added '{domain}' to whitelist")
            return True
        
        return False
    
    def generate_token(self, domain: str, issued_by: str, expires_days: int = 90) -> str:
        """
        Generate authorization token for domain
        
        Args:
            domain: Domain this token authorizes
            issued_by: Who issued this token (email)
            expires_days: Token expiration (default 90 days)
        
        Returns:
            Authorization token string
        """
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        # Generate token hash
        token_data = f"{domain}:{issued_by}:{expires_at.isoformat()}"
        token_hash = hashlib.sha256(token_data.encode()).hexdigest()[:32]
        
        # Store token
        self._valid_tokens[token_hash] = {
            "domain": domain,
            "issued_by": issued_by,
            "issued_at": datetime.utcnow(),
            "expires_at": expires_at
        }
        
        return token_hash
    
    def verify_token(self, token: str, domain: str) -> bool:
        """
        Verify authorization token is valid for domain
        
        Args:
            token: Authorization token
            domain: Domain to check authorization for
        
        Returns:
            True if token is valid
        """
        if token not in self._valid_tokens:
            return False
        
        token_data = self._valid_tokens[token]
        
        # Check domain match
        if token_data["domain"] != domain:
            # Allow wildcard domains (*.example.com)
            if not domain.endswith(token_data["domain"]):
                return False
        
        # Check expiration
        if datetime.utcnow() > token_data["expires_at"]:
            print(f"⚠️  Token expired: {token}")
            return False
        
        return True
    
    def verify_admin_token(self, token: str) -> bool:
        """Verify admin token — reads from ADMIN_TOKEN env var."""
        import os
        import warnings
        admin_token = os.getenv("ADMIN_TOKEN")
        if not admin_token:
            warnings.warn(
                "[SecurityGuard] ADMIN_TOKEN env var not set — whitelist management disabled",
                stacklevel=2,
            )
            return False
        return token == admin_token
    
    async def check_security_policy(self, url: str) -> SecurityPolicy:
        """
        Check target's security policy (robots.txt, security.txt)
        
        RFC 9116: https://www.rfc-editor.org/rfc/rfc9116
        
        Returns:
            SecurityPolicy object
        """
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check security.txt (RFC 9116)
        security_txt_urls = [
            f"{base_url}/.well-known/security.txt",
            f"{base_url}/security.txt"
        ]
        
        for security_url in security_txt_urls:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(security_url, follow_redirects=True)
                    
                    if resp.status_code == 200:
                        policy = self._parse_security_txt(resp.text, security_url)
                        if policy.disallow_scanning:
                            return policy
            except:
                pass
        
        # Check robots.txt
        try:
            robots_url = f"{base_url}/robots.txt"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(robots_url)
                
                if resp.status_code == 200:
                    # Look for disallow scanning directive
                    if "Disallow: /" in resp.text or "User-agent: *\nDisallow: /" in resp.text:
                        # Check if security scanners are explicitly disallowed
                        if "sqlmap" in resp.text.lower() or "scanner" in resp.text.lower():
                            return SecurityPolicy(
                                disallow_scanning=True,
                                policy_url=robots_url
                            )
        except:
            pass
        
        return SecurityPolicy(disallow_scanning=False)
    
    def _parse_security_txt(self, content: str, url: str) -> SecurityPolicy:
        """Parse security.txt content"""
        lines = content.split('\n')
        
        contact_email = None
        disallow_scanning = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Contact:'):
                email_match = re.search(r'[\w\.-]+@[\w\.-]+', line)
                if email_match:
                    contact_email = email_match.group(0)
            
            # Check for scanning restrictions
            if 'scanning' in line.lower() and 'not permitted' in line.lower():
                disallow_scanning = True
        
        return SecurityPolicy(
            disallow_scanning=disallow_scanning,
            contact_email=contact_email,
            policy_url=url
        )
    
    async def request_user_confirmation(self, url: str):
        """
        Human-in-the-loop approval before aggressive testing
        
        Displays warning and requires explicit 'YES' confirmation
        """
        print("\n" + "="*70)
        print("⚠️  SECURITY WARNING: AGGRESSIVE PENETRATION TEST")
        print("="*70)
        print(f"Target: {url}")
        print("\nThis scan will execute:")
        print("  • SQL injection attempts (blind SQLi, time-based)")
        print("  • XSS payloads (reflected, stored, DOM-based)")
        print("  • Authentication brute-forcing")
        print("  • Directory traversal / LFI attacks")
        print("  • Command injection attempts")
        print("  • File upload malicious payloads")
        print("\nThese tests may:")
        print("  • Trigger security alerts (IDS/IPS)")
        print("  • Generate significant traffic")
        print("  • Temporarily impact target performance")
        print("="*70)
        
        confirmation = input("\nType 'YES' to proceed (or anything else to abort): ")
        
        if confirmation.strip() != "YES":
            raise UserAbortedError("User cancelled scan")
        
        print("✓ User confirmation received. Starting scan...\n")


class RateLimiter:
    """
    Prevent overwhelming target systems with requests
    
    Implements token bucket algorithm with per-domain tracking
    """
    
    def __init__(self):
        self.max_requests_per_second = 10
        self.max_concurrent_requests = 5
        self.backoff_on_429 = True
        self.backoff_on_503 = True
        
        # Track request rates per domain
        self._domain_buckets: Dict[str, Dict] = {}
        self._concurrent_requests: Dict[str, int] = {}
    
    async def wait_if_needed(self, target_url: str):
        """
        Wait if rate limit would be exceeded
        
        Args:
            target_url: URL being requested
        """
        domain = self._extract_domain(target_url)
        
        # Initialize bucket if needed
        if domain not in self._domain_buckets:
            self._domain_buckets[domain] = {
                "tokens": self.max_requests_per_second,
                "last_update": datetime.utcnow()
            }
        
        bucket = self._domain_buckets[domain]
        
        # Refill tokens based on time elapsed
        now = datetime.utcnow()
        elapsed = (now - bucket["last_update"]).total_seconds()
        bucket["tokens"] = min(
            self.max_requests_per_second,
            bucket["tokens"] + (elapsed * self.max_requests_per_second)
        )
        bucket["last_update"] = now
        
        # Wait if no tokens available
        if bucket["tokens"] < 1:
            wait_time = (1 - bucket["tokens"]) / self.max_requests_per_second
            await asyncio.sleep(wait_time)
            bucket["tokens"] = 1
        
        # Consume token
        bucket["tokens"] -= 1
        
        # Check concurrent requests
        concurrent = self._concurrent_requests.get(domain, 0)
        if concurrent >= self.max_concurrent_requests:
            # Wait for concurrent requests to decrease
            while self._concurrent_requests.get(domain, 0) >= self.max_concurrent_requests:
                await asyncio.sleep(0.1)
    
    def increment_concurrent(self, target_url: str):
        """Increment concurrent request counter"""
        domain = self._extract_domain(target_url)
        self._concurrent_requests[domain] = self._concurrent_requests.get(domain, 0) + 1
    
    def decrement_concurrent(self, target_url: str):
        """Decrement concurrent request counter"""
        domain = self._extract_domain(target_url)
        if domain in self._concurrent_requests:
            self._concurrent_requests[domain] = max(0, self._concurrent_requests[domain] - 1)
    
    async def handle_http_error(self, status_code: int, target_url: str, retry_after: Optional[int] = None):
        """
        Handle rate limit responses from target
        
        Args:
            status_code: HTTP status code
            target_url: URL that returned error
            retry_after: Retry-After header value (seconds)
        """
        domain = self._extract_domain(target_url)
        
        if status_code == 429 and self.backoff_on_429:  # Too Many Requests
            wait_time = retry_after or 60
            print(f"⚠️  Rate limited by {domain}, waiting {wait_time}s")
            await asyncio.sleep(wait_time)
        
        elif status_code == 503 and self.backoff_on_503:  # Service Unavailable
            wait_time = 30
            print(f"⚠️  {domain} unavailable, backing off {wait_time}s")
            await asyncio.sleep(wait_time)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc.split(':')[0]


class SensitiveDataRedactor:
    """
    Auto-redact credentials and PII from reports
    
    Patterns for common sensitive data types
    """
    
    PATTERNS = {
        "password": r'(?i)(password|passwd|pwd|pass)[\s:=]+([^\s,;\n]+)',
        "api_key": r'(?i)(api[_-]?key|apikey|api_secret)[\s:=]+([^\s,;\n]+)',
        "token": r'(?i)(token|bearer|jwt)[\s:=]+([^\s,;\n]{20,})',
        "credit_card": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "private_key": r'-----BEGIN (RSA |)PRIVATE KEY-----',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    }
    
    def redact(self, text: str) -> str:
        """
        Redact sensitive data from text
        
        Args:
            text: Text potentially containing sensitive data
        
        Returns:
            Text with sensitive data redacted
        """
        if not text:
            return text
        
        redacted = text
        
        for data_type, pattern in self.PATTERNS.items():
            redacted = re.sub(
                pattern,
                f"[{data_type.upper()}_REDACTED]",
                redacted
            )
        
        return redacted
    
    def redact_finding(self, finding) -> None:
        """
        Redact sensitive data from finding object (in-place)
        
        Args:
            finding: Finding object to redact
        """
        finding.description = self.redact(finding.description)
        finding.evidence = self.redact(finding.evidence)
        
        if hasattr(finding, 'exploitation_details') and finding.exploitation_details:
            finding.exploitation_details = self.redact(finding.exploitation_details)
        
        if hasattr(finding, 'remediation') and finding.remediation:
            finding.remediation = self.redact(finding.remediation)


class AuditLogger:
    """
    Comprehensive audit trail for compliance
    
    Logs all security-relevant actions to append-only log file
    """
    
    def __init__(self, log_file: str = "/var/log/rajdoll/audit.log"):
        self.log_file = log_file
        self.redactor = SensitiveDataRedactor()
    
    def log_scan_started(
        self, 
        job_id: int, 
        target: str, 
        user: str, 
        auth_token_hash: str = None
    ):
        """Log when scan initiated"""
        self._write_log({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "scan_started",
            "job_id": job_id,
            "target": target,
            "initiated_by": user,
            "auth_token_hash": (auth_token_hash[:8] + "...") if auth_token_hash else "auto_approved"
        })
    
    def log_finding_discovered(self, job_id: int, finding):
        """Log each vulnerability found"""
        self._write_log({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "finding_discovered",
            "job_id": job_id,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
            "category": finding.category,
            "agent": finding.agent_name
        })
    
    def log_aggressive_test(self, job_id: int, tool: str, target: str):
        """Log potentially dangerous operations"""
        self._write_log({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "aggressive_test_executed",
            "job_id": job_id,
            "tool": tool,
            "target": target,
            "warning": "This test may trigger security alerts"
        })
    
    def log_unauthorized_attempt(self, target: str, reason: str, source_ip: str = "unknown"):
        """Log unauthorized access attempts"""
        self._write_log({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "unauthorized_attempt",
            "target": target,
            "reason": reason,
            "source_ip": source_ip,
            "severity": "high"
        })
    
    def _write_log(self, entry: dict):
        """Write to append-only audit log"""
        import json
        import os
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            # Fallback to stdout if file write fails
            print(f"⚠️  Audit log write failed: {e}")
            print(f"AUDIT: {json.dumps(entry)}")


# Module-level instances
security_guard = SecurityGuardRails()
rate_limiter = RateLimiter()
data_redactor = SensitiveDataRedactor()
audit_logger = AuditLogger()
