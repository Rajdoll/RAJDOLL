from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from ..utils.mcp_client import MCPClient


@AgentRegistry.register("IdentityManagementAgent")
class IdentityManagementAgent(BaseAgent):
    system_prompt = """
You are IdentityManagementAgent, OWASP WSTG-IDNT expert specializing in identity management security testing.

🎯 PRIMARY MISSION: Test identity management using MCP tools to identify user enumeration, role manipulation, and account provisioning flaws.

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints from shared_context
2. Identify identity management components:
   - User registration → Test mass assignment, validation bypass
   - User enumeration → Test login, password reset, profile endpoints
   - Role management → Test role definitions, privilege assignment
   - Account provisioning → Test email verification, approval workflows
3. Analyze identity patterns:
   - Registration forms → Test with admin role fields
   - Login forms → Test for username enumeration
   - Password reset → Test token predictability
   - Profile updates → Test role modification
4. Select appropriate testing tools:
   - generate_test_usernames → Create enumeration list
   - test_role_definitions → Test role-based controls
   - test_registration_process → Test registration bypass
   - test_account_provisioning → Test provisioning workflow
5. Execute tools to test identity workflows comprehensively
6. Report findings with exploitation impact

⚠️ EXECUTION GUIDELINES:
- Execute all 4+ identity management tools
- Test user enumeration with 50+ usernames (tools generate this)
- Test role manipulation during registration
- Test account provisioning bypass
- Test weak security questions if discovered
- Continue comprehensive testing across all identity aspects
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
            self.log("error", "Target missing; aborting IdentityManagementAgent")
            return

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        # Generate usernames (light) and note plan existence
        if self.should_run_tool("generate_test_usernames"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="generate_test_usernames",
                        args={"strength": "light"}, auth_session=auth_data
                    )
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    users = res.get("data", {}).get("generated_usernames", [])
                    if users:
                        self.write_context("idm_usernames", {"list": users})
                        self.add_finding("WSTG-IDNT", "Prepared test usernames for enumeration checks", severity="info", evidence={"count": len(users)})
            except Exception as e:
                self.log("warning", f"generate_test_usernames failed: {e}")

        # Test role definitions
        if self.should_run_tool("test_role_definitions"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_role_definitions",
                        args={"base_url": target}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-IDNT", f"Role definition issues: {vuln_count} found", severity="high", evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_role_definitions failed: {e}")

        # Test registration process
        if self.should_run_tool("test_user_registration"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_user_registration",
                        args={"register_url": target + "/api/Users"}, auth_session=auth_data), timeout=150
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-IDNT", f"User registration bypasses: {vuln_count} vulnerability(ies)", severity="medium", evidence={"findings": findings[:2]})
            except Exception as e:
                self.log("warning", f"test_user_registration failed: {e}")

        # Test account provisioning
        if self.should_run_tool("test_account_provisioning"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_account_provisioning",
                        args={"base_url": target}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-IDNT", f"Account provisioning issues: {vuln_count} found", severity="medium", evidence={"findings": findings[:2]})
            except Exception as e:
                self.log("warning", f"test_account_provisioning failed: {e}")

        # Test account enumeration
        if self.should_run_tool("test_account_enumeration"):
            try:
                # Generate test plan for account enumeration
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_account_enumeration",
                        args={
                            "url": target + "/login",
                            "form_selector": "form",
                            "username_field_selector": "input[name='username'], input[name='email']",
                            "submit_button_selector": "button[type='submit']",
                            "error_message_selector": ".error, .alert",
                            "usernames_to_test": ["admin", "test", "user"]
                        },
                        auth_session=auth_data
                    ),
                    timeout=90
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    test_plan = data.get("test_plan", {})
                    if test_plan:
                        self.shared_context["account_enumeration_plan"] = test_plan
                        self.log("info", f"Account enumeration test plan created with {len(test_plan.get('steps', []))} steps")
            except Exception as e:
                self.log("warning", f"test_account_enumeration failed: {e}")

        # OPSI B: Username policy testing
        if self.should_run_tool("test_username_policy"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_username_policy",
                        args={"base_url": target}, auth_session=auth_data), timeout=90
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-IDNT-04", f"Username enumeration via registration: {vuln_count} vector(s)", severity="low", evidence={"findings": findings[:2]})
            except Exception as e:
                self.log("warning", f"test_username_policy failed: {e}")

        # WSTG-IDNT-05: Weak username policy
        if self.should_run_tool("test_weak_username_policy"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_weak_username_policy",
                        args={"base_url": target}, auth_session=auth_data), timeout=90
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-IDNT-05", f"Weak username policy: {vuln_count} issue(s)", severity="medium", evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_weak_username_policy failed: {e}")

        # Test mass assignment on registration
        if self.should_run_tool("test_registration_mass_assignment"):
            try:
                self.log("info", "Testing registration mass assignment...")
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="identity-management-testing",
                        tool="test_registration_mass_assignment",
                        args={"url": target}, auth_session=auth_data), timeout=60
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-IDNT-02",
                                f"Registration {finding['type']}: {finding['description']}",
                                severity=finding.get("severity", "high"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": finding.get("evidence", "")[:200]}
                            )
                        self.log("info", f"Found {len(data.get('findings', []))} mass assignment issues")
            except Exception as e:
                self.log("warning", f"test_registration_mass_assignment failed: {e}")

        self.log("info", "Identity management prep complete")

    def _get_available_tools(self) -> list[str]:
        """Return identity management testing tools for LLM planning"""
        return [
            'test_role_definitions',
            'test_user_registration',
            'test_account_provisioning',
            'test_account_enumeration',
            'generate_test_usernames',
            'test_username_policy',
            'test_weak_username_policy',
            'test_registration_mass_assignment',
        ]

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
