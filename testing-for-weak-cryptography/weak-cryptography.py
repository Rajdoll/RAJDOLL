# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import asyncio
import os
import re
import json
import httpx
import math
from collections import Counter
from typing import Dict, Any, List, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [testing-for-weak-cryptography] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

from urllib.parse import urlparse

# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"weak-cryptography-testing")

# --- Helpers ---
async def sh(cmd: str, timeout: int = 120) -> str:
    proc = await asyncio.create_subprocess_exec(
        "bash", "-lc", cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        return out.decode("utf-8", errors="ignore").strip()
    except asyncio.TimeoutError:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

# --- Tools (Revisi, Peningkatan & Baru) ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_tls_configuration(host: str, port: int = 443) -> Dict[str, Any]:
    """
    [PENINGKATAN] Runs testssl.sh and parses its JSON output for a comprehensive TLS/SSL analysis.
    logger.info(f"🔍 Executing test_tls_configuration")
    This provides much more reliable and detailed results than text parsing.
    """
    try:
        output_file = f"testssl_output_{host}.json"
        # Menjalankan testssl.sh dengan output JSON
        cmd = f"testssl.sh --quiet --jsonfile {output_file} https://{host}:{port}"
        await sh(cmd, 180)

        if not os.path.exists(output_file):
            return {"status": "error", "message": "testssl.sh did not produce an output file."}

        with open(output_file, 'r') as f:
            scan_results = json.load(f).get("scanResult", [])
        os.remove(output_file)

        findings = {}
        for result in scan_results:
            # Ekstrak informasi kunci dari hasil pemindaian
            check_id = result.get("id")
            severity = result.get("severity")
            finding_text = result.get("finding")
            if severity in ["FATAL", "ERROR", "WARN", "LOW"] and "not vulnerable" not in finding_text:
                findings[check_id] = {
                    "severity": severity,
                    "finding": finding_text
                }
        
        return {"status": "success", "data": {"summary": findings}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_cleartext_info(domain: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [REVISI] Checks for sensitive data transmission over plain HTTP.
    logger.info(f"🔍 Executing test_cleartext_info")

    Args:
        domain: Target domain or full URL to check
        auth_session: Optional authentication session with cookies/headers/token
    """
    try:
        # Handle both bare domain and full URL
        if "://" in str(domain):
            parsed = urlparse(str(domain))
            url = f"http://{parsed.hostname}"
            if parsed.port and parsed.port != 80:
                url += f":{parsed.port}"
        else:
            url = f"http://{domain}"
        req_kwargs = {"timeout": 8, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            resp = await client.get(url)
        
        if resp.status_code >= 400:
            return {"status": "success", "data": {"http_reachable": False, "message": "Plain-HTTP service not reachable."}}

        html = resp.text
        password_field_found = bool(re.search(r'<input[^>]+type=["\']?password', html, re.I))
        form_posts_to_http = bool(re.search(r'<form[^>]+action=["\']?http://', html, re.I))

        return {"status": "success", "data": {
            "http_reachable": True,
            "status_code": resp.status_code,
            "password_field_on_http": password_field_found,
            "form_posts_to_http": form_posts_to_http
        }}
    except httpx.RequestError:
        return {"status": "success", "data": {"http_reachable": False, "message": "Plain-HTTP service not reachable."}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def analyze_token_randomness(tokens: List[str]) -> Dict[str, Any]:
    """
    [BARU] Performs a basic statistical analysis on a list of tokens to check for weak randomness.
    """
    if not tokens or len(tokens) < 2:
        return {"status": "error", "message": "At least two tokens are required for analysis."}

    # 1. Analisis Panjang Token
    lengths = {len(t) for t in tokens}
    constant_length = len(lengths) == 1

    # 2. Analisis Set Karakter
    char_sets = [set(t) for t in tokens]
    common_chars = set.intersection(*char_sets)

    # 3. Analisis Entropi Shannon (rata-rata)
    total_entropy = 0
    for token in tokens:
        if not token: continue
        counts = Counter(token)
        token_len = len(token)
        entropy = -sum((count / token_len) * math.log2(count / token_len) for count in counts.values())
        total_entropy += entropy
    average_entropy = total_entropy / len(tokens) if tokens else 0
    
    # Entropi ideal untuk Alphanumeric (62 karakter) ~ 5.95 bits/char
    is_low_entropy = average_entropy < 4.0 

    return {"status": "success", "data": {
        "token_count": len(tokens),
        "is_length_constant": constant_length,
        "lengths_found": list(lengths),
        "average_shannon_entropy": round(average_entropy, 4),
        "is_low_entropy": is_low_entropy,
        "description": "Checks for basic randomness properties. Low entropy or non-constant length might indicate predictability."
    }}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_jwt_weakness(token: str, target_url: str) -> Dict[str, Any]:
    """
    PHASE 2.4: Test JWT for algorithm confusion, signature bypass, and weak secrets.

    Tests:
    1. Algorithm "none" bypass (CVE-2015-9235)
    2. Algorithm confusion (RS256 to HS256)
    3. Weak secret brute force
    4. JWT validity testing

    Args:
        token: JWT token to test
        target_url: URL to test token validity against

    Returns:
        Dict with vulnerability findings
    """
    try:
        import base64
        import hmac
        import hashlib

        findings = []

        # Parse JWT (format: header.payload.signature)
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"status": "error", "message": "Invalid JWT format (expected 3 parts)"}

            header_b64, payload_b64, signature = parts

            # Decode header and payload
            def b64_decode(data):
                # Add padding if needed
                padding = 4 - len(data) % 4
                if padding:
                    data += '=' * padding
                return base64.urlsafe_b64decode(data).decode('utf-8')

            header = json.loads(b64_decode(header_b64))
            payload = json.loads(b64_decode(payload_b64))

            logger.info(f"[test_jwt_weakness] Original algorithm: {header.get('alg')}")

        except Exception as e:
            return {"status": "error", "message": f"Failed to parse JWT: {e}"}

        # TEST 1: Algorithm "none" bypass
        try:
            none_header = header.copy()
            none_header['alg'] = 'none'
            none_header_b64 = base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip('=')
            none_token = f"{none_header_b64}.{payload_b64}."

            is_valid = await _test_jwt_validity(target_url, none_token)
            if is_valid:
                findings.append({
                    "type": "JWT_ALG_NONE",
                    "severity": "CRITICAL",
                    "description": "JWT accepts 'none' algorithm - signature verification bypassed",
                    "evidence": "Modified token accepted with alg:none"
                })
                logger.info("[test_jwt_weakness] CRITICAL: alg:none bypass successful!")
        except Exception as e:
            logger.warning(f"[test_jwt_weakness] alg:none test failed: {e}")

        # TEST 2: Algorithm confusion (RS256 to HS256)
        # This requires knowing the public key, which is often available
        if header.get('alg') == 'RS256':
            try:
                # Attempt to get public key from common endpoints
                public_key = await _get_public_key(target_url)
                if public_key:
                    hs256_header = header.copy()
                    hs256_header['alg'] = 'HS256'
                    hs256_header_b64 = base64.urlsafe_b64encode(json.dumps(hs256_header).encode()).decode().rstrip('=')

                    # Sign with public key as HMAC secret
                    message = f"{hs256_header_b64}.{payload_b64}"
                    signature = hmac.new(
                        public_key.encode(),
                        message.encode(),
                        hashlib.sha256
                    ).digest()
                    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                    confused_token = f"{message}.{signature_b64}"

                    is_valid = await _test_jwt_validity(target_url, confused_token)
                    if is_valid:
                        findings.append({
                            "type": "JWT_ALG_CONFUSION",
                            "severity": "CRITICAL",
                            "description": "JWT vulnerable to algorithm confusion (RS256->HS256)",
                            "evidence": "Token signed with public key as HMAC secret accepted"
                        })
                        logger.info("[test_jwt_weakness] CRITICAL: Algorithm confusion successful!")
            except Exception as e:
                logger.warning(f"[test_jwt_weakness] Algorithm confusion test failed: {e}")

        # TEST 3: Weak secret brute force (comprehensive list)
        common_secrets = [
            # Most common JWT secrets
            "secret", "secret123", "secretkey", "secret_key", "jwt_secret", "jwt-secret", "jwtsecret", "jwtSecret", "JWT_SECRET",
            # Application defaults
            "your-256-bit-secret", "your-secret-key", "your_secret_key", "mysecret", "mysecretkey", "my-secret-key", "my_secret_key", "mySecretKey",
            # Framework defaults
            "changeme", "changethis", "please-change-me", "default", "defaultsecret", "default_secret",
            # Common passwords
            "password", "password123", "123456", "12345678", "admin", "admin123", "administrator", "root", "toor", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "login",
            # Development/test
            "test", "testing", "test123", "testkey", "dev", "development", "devkey", "debug", "demo", "example", "sample",
            # API/Token patterns
            "api", "apikey", "api_key", "api-key", "api123", "token", "tokenkey", "token123", "auth", "authkey", "authentication",
            # Random looking but common
            "abc123", "abcdef", "qwerty123", "asdfgh", "zxcvbn", "1234567890",
            # Base64 common values
            "c2VjcmV0", "cGFzc3dvcmQ=", "YWRtaW4=",
            # Hex patterns
            "deadbeef", "cafebabe", "0123456789abcdef",
            # Uber secret patterns
            "supersecret", "super_secret", "super-secret", "topsecret", "top_secret", "verysecret",
            # Key patterns
            "key", "key123", "privatekey", "private_key", "private-key", "signingkey", "signing_key", "signing-key",
            # Framework names
            "node", "nodejs", "express", "flask", "django", "rails", "spring", "laravel"
        ]

        for secret in common_secrets:
            try:
                # Re-sign token with common secret
                message = f"{header_b64}.{payload_b64}"
                test_signature = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()
                test_signature_b64 = base64.urlsafe_b64encode(test_signature).decode().rstrip('=')

                # Check if this matches original signature
                if test_signature_b64 == signature:
                    findings.append({
                        "type": "JWT_WEAK_SECRET",
                        "severity": "HIGH",
                        "description": f"JWT signed with weak secret: '{secret}'",
                        "evidence": f"Token signature matched common secret",
                        "secret": secret
                    })
                    logger.info(f"[test_jwt_weakness] HIGH: Weak secret found: {secret}")
                    break
            except:
                continue

        # TEST 4: Expired token test
        if 'exp' in payload:
            import time
            exp_time = payload['exp']
            current_time = int(time.time())
            if exp_time < current_time:
                # Try using expired token
                is_valid = await _test_jwt_validity(target_url, token)
                if is_valid:
                    findings.append({
                        "type": "JWT_EXPIRED_ACCEPTED",
                        "severity": "MEDIUM",
                        "description": "Application accepts expired JWT tokens",
                        "evidence": f"Token expired at {exp_time}, current time {current_time}"
                    })
                    logger.info("[test_jwt_weakness] MEDIUM: Expired token accepted!")

        return {
            "status": "success",
            "data": {
                "vulnerable": len(findings) > 0,
                "findings": findings,
                "token_info": {
                    "algorithm": header.get('alg'),
                    "has_expiration": 'exp' in payload,
                    "payload_keys": list(payload.keys())
                }
            }
        }

    except Exception as e:
        return {"status": "error", "message": f"JWT testing failed: {e}"}


async def _test_jwt_validity(url: str, token: str) -> bool:
    """Test if a JWT token is accepted by the target URL."""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Try common authenticated endpoints
            test_endpoints = [
                f"{url}/api/me",
                f"{url}/api/user",
                f"{url}/api/profile",
                f"{url}/rest/user/whoami",
                f"{url}/rest/user/authentication-details",
            ]

            for endpoint in test_endpoints:
                try:
                    resp = await client.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    # 200 = valid, 401 = invalid, 404 = endpoint doesn't exist
                    if resp.status_code == 200:
                        return True
                except:
                    continue

            return False
    except:
        return False


async def _get_public_key(url: str) -> str:
    """Attempt to retrieve JWT public key from common endpoints."""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            jwks_endpoints = [
                f"{url}/.well-known/jwks.json",
                f"{url}/jwks.json",
                f"{url}/api/.well-known/jwks.json",
                f"{url}/.well-known/openid-configuration",
            ]

            for endpoint in jwks_endpoints:
                try:
                    resp = await client.get(endpoint)
                    if resp.status_code == 200:
                        data = resp.json()
                        # Extract first public key
                        if 'keys' in data and len(data['keys']) > 0:
                            key = data['keys'][0]
                            # For simplicity, return the key ID or modulus
                            return key.get('n', '') or key.get('kid', '')
                except:
                    continue

            return None
    except:
        return None


# --- Prompt ---
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domainname: str) -> str:
    return f"""
You are an expert penetration tester focused on **cryptographic weaknesses**.  
Your mission is to evaluate **{domainname}** in accordance with OWASP WSTG 4.9.

**Primary Objectives:**
1.  **Analyze TLS Configuration:** Use `test_tls_configuration` to perform a deep scan of the server's SSL/TLS settings, identifying weak protocols, ciphers, and certificate issues.
2.  **Scan for Application-Layer Flaws:** Focus on JWT weaknesses, TLS misconfigurations, and weak crypto patterns via the available tools.
3.  **Verify Data in Transit:** Use `test_cleartext_info` to ensure no sensitive information is handled over unencrypted HTTP.
4.  **Assess Token Strength:** If you discover any application-generated tokens (e.g., from password resets, API keys), use `analyze_token_randomness` to check for weak entropy or predictability.

Reflect on these goals, craft a brief plan, then begin testing. Analyze each JSON result, adapt quickly, and clearly report your findings.
"""

# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter`n#     mcp.run(transport="stdio")

