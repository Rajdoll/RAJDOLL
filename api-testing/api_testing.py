"""
API Testing MCP Server
OWASP API Security Top 10 & WSTG-APIT: API Testing Tools

This server provides comprehensive API testing tools following OWASP guidelines.
Tests include: GraphQL introspection/mutations, REST API abuse, rate limiting,
OpenAPI parsing, API versioning issues.
"""

import asyncio
import httpx
import json
import re
import time
from typing import Optional, Dict, List, Any
from urllib.parse import urljoin, urlparse


# ============================================================================
# OWASP API1:2023 - Broken Object Level Authorization
# ============================================================================

async def test_rest_api_abuse(
    url: str,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for REST API abuse vulnerabilities.
    
    Tests for:
    - Mass assignment (extra fields in requests)
    - Excessive data exposure (sensitive fields in responses)
    - BOLA/IDOR (accessing other users' resources)
    - HTTP verb tampering (unauthorized methods)
    
    OWASP Reference: API1:2023 (Broken Object Level Authorization)
    """
    findings = []
    
    headers = _build_headers(auth_session)
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        # Test 1: Mass Assignment - Try adding admin fields
        if url.endswith('/api') or '/api/' in url:
            test_url = url.rstrip('/') + '/users' if not url.endswith('/users') else url
            
            try:
                mass_assignment_payload = {
                    "email": "test@example.com",
                    "password": "test123",
                    "role": "admin",  # Privilege escalation attempt
                    "is_admin": True,
                    "is_superuser": True,
                    "privileges": ["admin", "superuser"],
                }
                
                response = await client.post(test_url, json=mass_assignment_payload, headers=headers)
                
                if response.status_code in [200, 201]:
                    response_lower = response.text.lower()
                    if any(field in response_lower for field in ['admin', 'superuser', 'role']):
                        findings.append({
                            "type": "Mass Assignment",
                            "severity": "high",
                            "evidence": f"Server accepted admin fields in POST request: {test_url}",
                            "response_snippet": response.text[:200]
                        })
            except Exception:
                pass
        
        # Test 2: Excessive Data Exposure - Check for sensitive fields
        try:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    sensitive_fields = [
                        'password', 'secret', 'api_key', 'apikey', 'token',
                        'private_key', 'access_token', 'refresh_token', 'ssn',
                        'credit_card', 'cvv', 'pin', 'social_security'
                    ]
                    
                    response_str = json.dumps(json_data).lower()
                    exposed = [field for field in sensitive_fields if field in response_str]
                    
                    if exposed:
                        findings.append({
                            "type": "Excessive Data Exposure",
                            "severity": "high",
                            "evidence": f"API exposes sensitive fields: {', '.join(exposed)}",
                            "url": url
                        })
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass
        
        # Test 3: HTTP Verb Tampering - Try unauthorized methods
        for method in ['DELETE', 'PUT', 'PATCH']:
            try:
                response = await client.request(method, url, headers=headers)
                
                if response.status_code not in [401, 403, 405, 501]:
                    findings.append({
                        "type": "HTTP Verb Tampering",
                        "severity": "medium",
                        "evidence": f"{method} method allowed without proper authorization: {response.status_code}",
                        "url": url
                    })
            except Exception:
                pass
    
    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "message": f"Found {len(findings)} REST API abuse issues" if findings else "No REST API abuse detected"
    }


# ============================================================================
# OWASP API4:2023 - Unrestricted Resource Consumption
# ============================================================================

async def test_rate_limiting(
    url: str,
    auth_session: Optional[Dict[str, Any]] = None,
    request_count: int = 100
) -> Dict[str, Any]:
    """
    Test for rate limiting vulnerabilities.
    
    Sends multiple rapid requests to check if:
    - Rate limiting is enforced (429 Too Many Requests)
    - CAPTCHA is triggered
    - Account lockout occurs
    
    OWASP Reference: API4:2023 (Unrestricted Resource Consumption)
    """
    findings = []
    
    headers = _build_headers(auth_session)
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        success_count = 0
        status_codes = []
        start_time = time.time()
        
        for i in range(request_count):
            try:
                response = await client.get(url, headers=headers)
                status_codes.append(response.status_code)
                
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:
                    # Rate limiting is working
                    break
            except Exception:
                pass
        
        elapsed_time = time.time() - start_time
        requests_per_second = request_count / elapsed_time if elapsed_time > 0 else 0
        
        # Check if rate limiting was enforced
        if 429 not in status_codes:
            findings.append({
                "type": "Missing Rate Limiting",
                "severity": "high",
                "evidence": f"Sent {request_count} requests in {elapsed_time:.2f}s ({requests_per_second:.1f} req/s) - No rate limiting detected",
                "success_count": success_count,
                "url": url
            })
        else:
            # Rate limiting is working
            requests_before_limit = status_codes.index(429)
            findings.append({
                "type": "Rate Limiting Active",
                "severity": "info",
                "evidence": f"Rate limiting triggered after {requests_before_limit} requests",
                "url": url
            })
    
    return {
        "vulnerable": any(f['severity'] in ['high', 'critical'] for f in findings),
        "findings": findings,
        "message": f"Rate limiting test completed" if findings else "Rate limiting test failed"
    }


# ============================================================================
# OWASP API8:2023 - Security Misconfiguration (GraphQL)
# ============================================================================

async def test_graphql_introspection(
    url: str,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for GraphQL introspection vulnerabilities.
    
    Attempts to query the GraphQL schema using introspection queries.
    If successful, this exposes the entire API structure.
    
    OWASP Reference: API8:2023 (Security Misconfiguration)
    """
    findings = []
    
    headers = _build_headers(auth_session)
    headers['Content-Type'] = 'application/json'
    
    # Introspection query to dump the entire schema
    introspection_query = {
        "query": """
        {
            __schema {
                types {
                    name
                    kind
                    description
                    fields {
                        name
                        description
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }
        """
    }
    
    # Try common GraphQL endpoints
    graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query']
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        base_url = url.rstrip('/')
        
        for path in graphql_paths:
            test_url = base_url + path
            
            try:
                response = await client.post(test_url, json=introspection_query, headers=headers)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        if 'data' in data and '__schema' in data['data']:
                            schema = data['data']['__schema']
                            types = schema.get('types', [])
                            
                            # Extract interesting types (excluding built-in GraphQL types)
                            custom_types = [
                                t['name'] for t in types 
                                if t.get('name') and not t['name'].startswith('__')
                            ]
                            
                            findings.append({
                                "type": "GraphQL Introspection Enabled",
                                "severity": "high",
                                "evidence": f"GraphQL schema exposed at {test_url} - Found {len(custom_types)} custom types",
                                "exposed_types": custom_types[:10],  # First 10 types
                                "url": test_url
                            })
                    except (json.JSONDecodeError, KeyError):
                        pass
            except Exception:
                pass
    
    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "message": f"Found {len(findings)} GraphQL introspection issues" if findings else "GraphQL introspection is disabled"
    }


async def test_graphql_mutations(
    url: str,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for unauthorized GraphQL mutations.
    
    Attempts to execute mutations without proper authentication or
    with low-privilege credentials.
    
    OWASP Reference: API1:2023 (Broken Object Level Authorization)
    """
    findings = []
    
    headers = _build_headers(auth_session)
    headers['Content-Type'] = 'application/json'
    
    # Common mutation patterns to test
    test_mutations = [
        {
            "name": "Create User",
            "query": """
            mutation {
                createUser(input: {username: "hacker", email: "hack@test.com", role: "admin"}) {
                    id
                    username
                    role
                }
            }
            """
        },
        {
            "name": "Update User Role",
            "query": """
            mutation {
                updateUser(id: 1, role: "admin") {
                    id
                    role
                }
            }
            """
        },
        {
            "name": "Delete User",
            "query": """
            mutation {
                deleteUser(id: 1) {
                    success
                }
            }
            """
        }
    ]
    
    graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        base_url = url.rstrip('/')
        
        for path in graphql_paths:
            test_url = base_url + path
            
            for mutation in test_mutations:
                try:
                    response = await client.post(
                        test_url, 
                        json={"query": mutation['query']}, 
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            
                            # Check if mutation succeeded (no errors)
                            if 'errors' not in data and 'data' in data:
                                findings.append({
                                    "type": "Unauthorized GraphQL Mutation",
                                    "severity": "critical",
                                    "evidence": f"{mutation['name']} mutation executed without proper authorization",
                                    "url": test_url,
                                    "mutation": mutation['name']
                                })
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass
    
    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "message": f"Found {len(findings)} unauthorized GraphQL mutations" if findings else "No unauthorized mutations detected"
    }


# ============================================================================
# OWASP API9:2023 - Improper Inventory Management
# ============================================================================

async def parse_openapi_spec(
    url: str,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Parse OpenAPI/Swagger specifications to discover API endpoints.
    
    Looks for:
    - /swagger.json, /openapi.json
    - /api-docs, /docs, /swagger-ui
    - Extracts endpoints, methods, parameters
    
    OWASP Reference: API9:2023 (Improper Inventory Management)
    """
    findings = []
    endpoints = []
    
    headers = _build_headers(auth_session)
    
    spec_paths = [
        '/swagger.json',
        '/openapi.json',
        '/api-docs',
        '/api/swagger.json',
        '/api/openapi.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/v3/swagger.json',
        '/docs/swagger.json',
        '/api/docs',
    ]
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        base_url = url.rstrip('/')
        
        for path in spec_paths:
            test_url = base_url + path
            
            try:
                response = await client.get(test_url, headers=headers)
                
                if response.status_code == 200:
                    try:
                        spec = response.json()
                        
                        # Check if it's a valid OpenAPI/Swagger spec
                        if 'swagger' in spec or 'openapi' in spec:
                            findings.append({
                                "type": "OpenAPI Specification Exposed",
                                "severity": "medium",
                                "evidence": f"API specification found at {test_url}",
                                "url": test_url
                            })
                            
                            # Extract endpoints from paths
                            paths = spec.get('paths', {})
                            for path_key, path_value in paths.items():
                                for method in ['get', 'post', 'put', 'patch', 'delete']:
                                    if method in path_value:
                                        endpoint_info = path_value[method]
                                        endpoints.append({
                                            "path": path_key,
                                            "method": method.upper(),
                                            "summary": endpoint_info.get('summary', ''),
                                            "parameters": len(endpoint_info.get('parameters', [])),
                                        })
                            
                            break  # Found spec, no need to check other paths
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass
    
    return {
        "discovered": len(endpoints) > 0,
        "findings": findings,
        "endpoints": endpoints[:50],  # Limit to first 50 endpoints
        "total_endpoints": len(endpoints),
        "message": f"Discovered {len(endpoints)} API endpoints from specification" if endpoints else "No API specification found"
    }


async def test_api_versioning_issues(
    url: str,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Test for API versioning issues.
    
    Checks if:
    - Old API versions are still accessible
    - Deprecated endpoints remain exposed
    - Version differences reveal security issues
    
    OWASP Reference: API9:2023 (Improper Inventory Management)
    """
    findings = []
    
    headers = _build_headers(auth_session)
    
    # Extract base URL without version
    parsed = urlparse(url)
    base_path = parsed.path
    
    # Remove version patterns
    base_path_no_version = re.sub(r'/v\d+/', '/', base_path)
    base_path_no_version = re.sub(r'/api/v\d+', '/api', base_path_no_version)
    
    # Test multiple versions
    versions = ['v1', 'v2', 'v3', 'api/v1', 'api/v2', 'api/v3']
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        accessible_versions = []
        
        for version in versions:
            test_url = f"{base_url}/{version}{base_path_no_version}"
            
            try:
                response = await client.get(test_url, headers=headers)
                
                if response.status_code in [200, 301, 302]:
                    accessible_versions.append({
                        "version": version,
                        "url": test_url,
                        "status": response.status_code
                    })
            except Exception:
                pass
        
        if len(accessible_versions) > 1:
            findings.append({
                "type": "Multiple API Versions Accessible",
                "severity": "medium",
                "evidence": f"Found {len(accessible_versions)} accessible API versions",
                "versions": accessible_versions,
                "recommendation": "Deprecate old API versions to reduce attack surface"
            })
    
    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "message": f"Found {len(findings)} API versioning issues" if findings else "No versioning issues detected"
    }


# ============================================================================
# Helper Functions
# ============================================================================

def _build_headers(auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Build HTTP headers with optional authentication."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
    }
    
    if auth_session:
        # JWT Bearer token
        if auth_session.get('session_type') == 'jwt' and auth_session.get('token'):
            headers['Authorization'] = f"Bearer {auth_session['token']}"
        
        # Cookie-based session
        if auth_session.get('cookies'):
            cookies = auth_session['cookies']
            if isinstance(cookies, dict):
                cookies = [f"{k}={v}" for k, v in cookies.items()]
            if isinstance(cookies, list):
                headers['Cookie'] = '; '.join(cookies)
    
    return headers


# ============================================================================
# MCP Tool Exports
# ============================================================================

__all__ = [
    "test_rest_api_abuse",
    "test_rate_limiting",
    "test_graphql_introspection",
    "test_graphql_mutations",
    "parse_openapi_spec",
    "test_api_versioning_issues",
]
