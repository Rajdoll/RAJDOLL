"""
API Testing Agent
OWASP API Security Top 10 & WSTG-APIT Specialist

This agent specializes in testing API security following OWASP API Security Top 10.
Tests REST APIs, GraphQL, rate limiting, OpenAPI specs, and versioning issues.
"""

import asyncio
from typing import Dict, Any, Optional, List
from .base_agent import BaseAgent, AgentRegistry
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("APITestingAgent")
class APITestingAgent(BaseAgent):
    """
    OWASP API Security Top 10 Expert Agent
    
    Specializes in:
    - API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    - API4:2023 - Unrestricted Resource Consumption (rate limiting)
    - API8:2023 - Security Misconfiguration (GraphQL introspection)
    - API9:2023 - Improper Inventory Management (OpenAPI specs, versioning)
    
    Tests REST APIs, GraphQL endpoints, rate limiting, and API documentation exposure.
    """
    
    system_prompt = """You are APITestingAgent, OWASP API Security Top 10 expert specializing in API security testing.

🎯 PRIMARY MISSION: Test API security using MCP tools to identify BOLA/IDOR, mass assignment, GraphQL issues, rate limiting, and versioning flaws.

🧠 ADAPTIVE STRATEGY:
1. Read discovered API endpoints from shared_context
2. Identify API characteristics:
   - REST APIs → Test BOLA/IDOR, mass assignment, excessive data exposure
   - GraphQL → Test introspection, unauthorized mutations
   - OpenAPI/Swagger → Check documentation exposure
   - API versioning → Test old/deprecated versions
3. Analyze endpoint patterns:
   - Resource endpoints with IDs → Test IDOR (IDs 1-100)
   - Create/Update endpoints → Test mass assignment
   - Authentication endpoints → Test rate limiting
   - Admin endpoints → Test unauthorized access
4. Select appropriate testing tools:
   - parse_openapi_spec → Discover API endpoints
   - test_rest_api_abuse → Test BOLA, mass assignment
   - test_graphql_introspection → Test schema exposure
   - test_graphql_mutations → Test unauthorized operations
   - test_rate_limiting → Verify rate limits
   - test_api_versioning_issues → Find old versions
5. Execute tools comprehensively (tools handle 50-100 ID tests automatically)
6. Report findings with clear business impact

⚠️ EXECUTION GUIDELINES:
- Execute all 6 API testing tools
- Test BOLA/IDOR on ALL resource endpoints (tools test IDs 1-100)
- Test mass assignment with admin fields (role, permissions)
- Test rate limiting with 100+ requests
- Test GraphQL if discovered
- Continue comprehensive testing across all API aspects

🔧 AVAILABLE TOOLS:
1. parse_openapi_spec - Find OpenAPI/Swagger specs
2. test_rest_api_abuse - Test BOLA, mass assignment, excessive data exposure
3. test_graphql_introspection - Test GraphQL schema exposure
4. test_graphql_mutations - Test unauthorized GraphQL mutations
5. test_rate_limiting - Verify rate limiting
6. test_api_versioning_issues - Find old API versions
"""

    async def run(self):
        """Execute API security testing workflow."""
        target = self._target or self.shared_context.get("target", "")
        
        if not target:
            self.log("error", "No target URL provided")
            return
        
        self.log("info", f"Starting API security testing for {target}")
        
        # Extract authenticated session if available (from AuthenticationAgent)
        auth_data = self._extract_auth_from_context()
        
        if auth_data:
            self.log("info", f"Using authenticated session: {auth_data.get('session_type', 'unknown')}")
        else:
            self.log("info", "No authenticated session available - testing unauthenticated")
        
        # Initialize MCP client
        client = MCPClient()
        
        # Phase 1: Discover API endpoints from OpenAPI/Swagger specs
        api_endpoints = []
        if self.should_run_tool("parse_openapi_spec"):
            try:
                self.log("info", "Phase 1: Discovering API endpoints from specifications")
                result = await client.call_tool(
                    server="api-testing",
                    tool="parse_openapi_spec",
                    args={
                        "url": target,
                        "auth_session": auth_data
                    }
                )
                
                if result.get("data", {}).get("discovered"):
                    api_endpoints = result["data"].get("endpoints", [])
                    findings = result["data"].get("findings", [])
                    
                    self.log("info", f"Discovered {len(api_endpoints)} API endpoints")
                    
                    # Record finding if OpenAPI spec is exposed
                    for finding in findings:
                        self.add_finding(
                            category="WSTG-APIT-01",
                            title=finding['type'],
                            severity=finding['severity'],
                            evidence=finding['evidence'],
                            recommendation="Consider restricting access to API documentation in production"
                        )
            except Exception as e:
                self.log("error", f"Error discovering API endpoints: {e}")
        
        # Phase 2: Test REST API abuse (mass assignment, excessive data exposure, BOLA)
        if self.should_run_tool("test_rest_api_abuse"):
            try:
                self.log("info", "Phase 2: Testing REST API abuse vulnerabilities")
                
                # Test main target URL
                test_urls = [target]
                
                # Add discovered API endpoints (sample first 5)
                for endpoint in api_endpoints[:5]:
                    endpoint_url = target.rstrip('/') + endpoint['path']
                    test_urls.append(endpoint_url)
                
                for test_url in test_urls:
                    result = await client.call_tool(
                        server="api-testing",
                        tool="test_rest_api_abuse",
                        args={
                            "url": test_url,
                            "auth_session": auth_data
                        }
                    )
                    
                    if result.get("data", {}).get("vulnerable"):
                        findings = result["data"].get("findings", [])
                        
                        for finding in findings:
                            self.add_finding(
                                category="WSTG-APIT-02",
                                title=f"REST API Abuse: {finding['type']}",
                                severity=finding['severity'],
                                evidence=finding['evidence'],
                                recommendation=self._get_recommendation(finding['type'])
                            )
            except Exception as e:
                self.log("error", f"Error testing REST API abuse: {e}")
        
        # Phase 3: Test GraphQL introspection
        if self.should_run_tool("test_graphql_introspection"):
            try:
                self.log("info", "Phase 3: Testing GraphQL introspection")
                result = await client.call_tool(
                    server="api-testing",
                    tool="test_graphql_introspection",
                    args={
                        "url": target,
                        "auth_session": auth_data
                    }
                )
                
                if result.get("data", {}).get("vulnerable"):
                    findings = result["data"].get("findings", [])
                    
                    for finding in findings:
                        exposed_types = finding.get('exposed_types', [])
                        evidence = finding['evidence']
                        if exposed_types:
                            evidence += f"\nExposed types: {', '.join(exposed_types[:5])}"
                        
                        self.add_finding(
                            category="WSTG-APIT-03",
                            title="GraphQL Introspection Enabled",
                            severity="high",
                            evidence=evidence,
                            recommendation="Disable GraphQL introspection in production environments"
                        )
            except Exception as e:
                self.log("error", f"Error testing GraphQL introspection: {e}")
        
        # Phase 4: Test unauthorized GraphQL mutations
        if self.should_run_tool("test_graphql_mutations"):
            try:
                self.log("info", "Phase 4: Testing unauthorized GraphQL mutations")
                result = await client.call_tool(
                    server="api-testing",
                    tool="test_graphql_mutations",
                    args={
                        "url": target,
                        "auth_session": auth_data
                    }
                )
                
                if result.get("data", {}).get("vulnerable"):
                    findings = result["data"].get("findings", [])
                    
                    for finding in findings:
                        self.add_finding(
                            category="WSTG-APIT-04",
                            title=f"Unauthorized GraphQL Mutation: {finding.get('mutation', 'Unknown')}",
                            severity="critical",
                            evidence=finding['evidence'],
                            recommendation="Implement proper authorization checks for all GraphQL mutations"
                        )
            except Exception as e:
                self.log("error", f"Error testing GraphQL mutations: {e}")
        
        # Phase 5: Test rate limiting
        if self.should_run_tool("test_rate_limiting"):
            try:
                self.log("info", "Phase 5: Testing rate limiting")
                
                # Test rate limiting on API endpoints
                test_endpoints = [target]
                
                # Add critical endpoints if discovered
                for endpoint in api_endpoints[:3]:
                    if any(keyword in endpoint['path'].lower() for keyword in ['login', 'auth', 'password', 'api']):
                        endpoint_url = target.rstrip('/') + endpoint['path']
                        test_endpoints.append(endpoint_url)
                
                for test_url in test_endpoints:
                    result = await client.call_tool(
                        server="api-testing",
                        tool="test_rate_limiting",
                        args={
                            "url": test_url,
                            "auth_session": auth_data,
                            "request_count": 50  # Reduced to 50 to avoid overload
                        }
                    )
                    
                    if result.get("data", {}).get("vulnerable"):
                        findings = result["data"].get("findings", [])
                        
                        for finding in findings:
                            if finding['severity'] in ['high', 'critical']:
                                self.add_finding(
                                    category="WSTG-APIT-05",
                                    title="Missing Rate Limiting",
                                    severity=finding['severity'],
                                    evidence=finding['evidence'],
                                    recommendation="Implement rate limiting to prevent abuse and DoS attacks"
                                )
            except Exception as e:
                self.log("error", f"Error testing rate limiting: {e}")
        
        # Phase 6: Test API versioning issues
        if self.should_run_tool("test_api_versioning_issues"):
            try:
                self.log("info", "Phase 6: Testing API versioning issues")
                result = await client.call_tool(
                    server="api-testing",
                    tool="test_api_versioning_issues",
                    args={
                        "url": target,
                        "auth_session": auth_data
                    }
                )
                
                if result.get("data", {}).get("vulnerable"):
                    findings = result["data"].get("findings", [])
                    
                    for finding in findings:
                        versions = finding.get('versions', [])
                        evidence = finding['evidence']
                        if versions:
                            version_list = ', '.join([v['version'] for v in versions])
                            evidence += f"\nAccessible versions: {version_list}"
                        
                        self.add_finding(
                            category="WSTG-APIT-06",
                            title="Multiple API Versions Accessible",
                            severity="medium",
                            evidence=evidence,
                            recommendation=finding.get('recommendation', 'Deprecate old API versions')
                        )
            except Exception as e:
                self.log("error", f"Error testing API versioning: {e}")
        
        self.log("info", "API security testing completed")
    
    def _extract_auth_from_context(self) -> Optional[Dict[str, Any]]:
        """Extract authenticated session from shared_context."""
        auth_sessions = self.shared_context.get("authenticated_sessions", {})
        
        if not auth_sessions:
            return None
        
        # Check if there are successful logins
        successful_logins = auth_sessions.get('successful_logins', [])
        if not successful_logins:
            return None
        
        # Use the first successful login
        first_login = successful_logins[0]
        
        return {
            'username': first_login.get('username', ''),
            'session_type': first_login.get('session_type', 'cookie'),
            'token': first_login.get('token', ''),
            'cookies': first_login.get('cookies', {})
        }
    
    def _get_recommendation(self, finding_type: str) -> str:
        """Get recommendation based on finding type."""
        recommendations = {
            "Mass Assignment": "Implement whitelist-based input validation. Only accept expected fields in API requests.",
            "Excessive Data Exposure": "Implement response filtering. Only return necessary data fields in API responses.",
            "HTTP Verb Tampering": "Implement proper authorization checks for all HTTP methods (GET, POST, PUT, DELETE, PATCH).",
        }
        return recommendations.get(finding_type, "Review and implement proper API security controls")
    
    def _get_available_tools(self) -> List[str]:
        """Return list of available MCP tools for this agent."""
        return [
            'parse_openapi_spec',
            'test_rest_api_abuse',
            'test_graphql_introspection',
            'test_graphql_mutations',
            'test_rate_limiting',
            'test_api_versioning_issues',
        ]
