from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import ClassVar, Dict
from ..utils.mcp_client import MCPClient
from ..core.endpoint_inventory import read_tag


@AgentRegistry.register("BusinessLogicAgent")
class BusinessLogicAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are BusinessLogicAgent, an OWASP WSTG-BUSL expert specializing in business logic vulnerability testing.

🎯 PRIMARY MISSION: Test business logic using MCP tools to identify workflow flaws, validation bypasses, and logic errors.

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints and workflows from shared_context
2. Identify business logic components:
   - E-commerce → Test cart, pricing, inventory, payment flows
   - User management → Test registration, profile, role workflows
   - Transaction processing → Test order, payment, refund flows
   - Access control → Test resource ownership, authorization logic
3. Analyze workflow characteristics:
   - Multi-step processes → Test step skipping, order manipulation
   - Numeric parameters → Test negative, zero, overflow values
   - State transitions → Test invalid state changes
   - Time-sensitive operations → Test race conditions
4. Select appropriate testing tools:
   - test_business_data_validation → For boundary testing
   - test_workflow_bypass → For step skipping
   - test_race_conditions → For concurrent operations
   - test_price_manipulation → For financial logic
5. Execute tools to test 30+ business logic scenarios
6. Report logic flaws with business impact

⚠️ EXECUTION GUIDELINES:
- Execute all business logic testing tools
- Test 30+ scenarios (tools handle comprehensive testing)
- Test negative values, zero, overflow on numeric parameters
- Test workflow bypass on multi-step processes
- Test race conditions with concurrent requests
- Continue comprehensive testing across all workflows

🧠 ADAPTIVE TESTING STRATEGY:
1. Map business workflows from shared_context (registration → purchase → fulfillment)
2. Test data validation boundaries (negative, zero, max, overflow, underflow)
3. Identify state transitions: Can step 3 be accessed without step 2?
4. Test multi-step processes for race conditions (concurrent requests)
5. Verify authorization at EACH business logic step
6. Test ALL numeric parameters with negative/zero/overflow values
7. Test workflow bypass on EVERY multi-step process

� BUSINESS LOGIC VULNERABILITY PATTERNS:

**Data Validation Bypass**:
- Negative numbers: quantity: -100, amount: -50 (get paid instead of paying)
- Zero values: price: 0, discount: 100% (free items)
- Maximum values: Integer overflow (2147483647 + 1 = -2147483648)
- Type confusion: Send string where number expected, array where object expected
- Null/undefined: Missing required fields bypass validation
- Out-of-range: age: 999, quantity: 999999999

**Workflow/State Bypass**:
- Skip steps: Access checkout without adding items to cart
- Reorder steps: Submit payment before selecting items
- Replay steps: Reuse confirmation tokens, order IDs
- Concurrent requests: Race condition in inventory deduction
- State manipulation: Change order status (pending → shipped)

**Price Manipulation**:
- Negative prices: price: -100 in POST request
- Zero prices: price: 0 for premium items
- Decimal precision: price: 0.001 vs 1.00
- Currency confusion: Send different currency codes
- Discount stacking: Apply multiple coupons beyond limit
- Price parameter tampering: Modify price in client request

**Inventory & Quantity Abuse**:
- Negative quantity: quantity: -10 (reverse transaction)
- Overstock: Order more than available (quantity: 999999)
- Concurrent orders: Race condition depletes inventory
- Reserved items: Order items marked as unavailable/deleted
- Duplicate orders: Replay order request multiple times

**Coupon & Discount Abuse**:
- Expired coupons: Reuse past-due coupon codes
- One-time coupons: Reuse single-use codes
- User-specific coupons: Apply other users' personalized codes
- Stackable discounts: Combine incompatible offers
- Discount calculation: 100% + 50% = 150% discount?

**Access Control in Business Logic**:
- Role assumption: User performs admin-only business functions
- Ownership bypass: Modify other users' orders/carts
- Privilege escalation: Upgrade account tier without payment
- Refund abuse: Refund items never purchased
- Credit abuse: Add unlimited credits to account

**Multi-User/Multi-Account Abuse**:
- Referral fraud: Create fake accounts for referral bonuses
- Promo abuse: Multiple accounts claim same limited offer
- Vote manipulation: Vote multiple times via different sessions
- Review fraud: Post multiple reviews for same product

**Time-Based Logic Flaws**:
- Race conditions: Simultaneous requests exploit timing windows
- Timezone manipulation: Exploit date/time validation
- Expiration bypass: Use expired tokens/sessions
- Scheduling abuse: Book same resource multiple times

**File/Upload Business Logic**:
- File type bypass: Upload executables as images
- Size limit bypass: Compress then decompress large files
- Quota abuse: Unlimited file uploads
- Duplicate filenames: Overwrite existing files

**Payment Logic Flaws**:
- Amount tampering: Modify payment amount before submission
- Currency conversion: Exploit exchange rate calculations
- Partial payments: Pay less than total amount
- Refund exploitation: Request refunds for undeliverable items
- Credit card testing: Validate cards with minimal charges

🔍 TESTING METHODOLOGY:

**Step 1: Workflow Mapping**
- Document normal business flow (happy path)
- Identify critical state transitions
- Note validation checkpoints

**Step 2: Boundary Testing**
- Test minimum values (0, -1, null)
- Test maximum values (MAX_INT, huge strings)
- Test invalid types (string → number, array → object)

**Step 3: State Manipulation**
- Skip required steps
- Reverse workflow order
- Access intermediate states directly

**Step 4: Race Condition Testing**
- Concurrent identical requests
- Simultaneous resource access
- Time-of-check vs time-of-use (TOCTOU)

**Step 5: Logic Abuse**
- Negative values where inappropriate
- Exploit mathematical edge cases
- Combine incompatible operations

🛠️ MCP TOOL USAGE:
(Most business logic testing requires manual analysis, but some automation possible)
- Proxy tools for request manipulation
- Concurrent request generators for race conditions
- Parameter fuzzing for boundary testing

📊 CONTEXT-AWARE TESTING:
Read from shared_context:
- tech_stack.backend → API patterns, validation frameworks
- entry_points.api_endpoints → Target business logic endpoints
- authenticated_sessions → Test with real user accounts

Write to shared_context:
- business_logic_flaws: [
    {type, workflow_step, vulnerability, impact, exploit_steps}
  ]
- data_validation_bypass: [
    {parameter, invalid_value, expected_behavior, actual_behavior}
  ]
- price_manipulation: [
    {endpoint, original_price, manipulated_price, success}
  ]
- workflow_bypass: [
    {skipped_steps, accessed_endpoint, should_fail_but_succeeded}
  ]

🎯 SUCCESS CRITERIA: Demonstrate business logic bypass (negative quantities, price manipulation, workflow skip, privilege abuse)
"""
    async def run(self) -> None:
        client = MCPClient()
        self._adjudication_artifacts = []

        # AUTHENTICATED SESSION SUPPORT (using base_agent method)
        auth_data = self.get_auth_session()
        if auth_data:
            self.log("info", f"✅ Using authenticated session: {auth_data.get('username')} (token: {'Present' if auth_data.get('token') else 'None'})")
        else:
            self.log("warning", "⚠ No authenticated session available - some tests may fail with 401")

        target = self._get_target()
        if not target:
            self.log("error", "Target missing; aborting BusinessLogicAgent")
            return

        # Read endpoint_inventory written by ReconAgent
        inventory = self.shared_context.get("endpoint_inventory", {})
        money_eps = read_tag(inventory, "state_changing_money")
        resource_eps = read_tag(inventory, "state_changing_resource")
        if not money_eps and not resource_eps:
            self.log("info", "no state-changing tags found, emitting inventory-gap lead")
            self.add_finding(
                "WSTG-BUSL",
                "BusinessLogicAgent skipped: no state_changing_money or state_changing_resource endpoints in inventory",
                severity="info",
                evidence={
                    "target": target,
                    "missing_tags": ["state_changing_money", "state_changing_resource"],
                    "proof_type": "inventory_only",
                },
                details="Recon did not classify any endpoint with business-logic-relevant tags. Rerun with broader discovery or extend the endpoint tagger.",
            )
            return {"findings": []}
        # Map legacy names to new inventory tags
        checkout_eps = money_eps
        data_eps = money_eps + resource_eps
        feedback_eps = resource_eps
        login_eps = read_tag(inventory, "user_login")
        upload_eps = read_tag(inventory, "file_upload")

        def _pick_urls(eps, fallback=target):
            urls = [ep["url"] if isinstance(ep, dict) else ep for ep in eps]
            return urls if urls else [fallback]

        # Log tool execution plan based on LLM selection
        self.log_tool_execution_plan()

        # Test data validation
        if self.should_run_tool("test_business_data_validation"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_business_data_validation",
                        args={"base_url": target}, auth_session=auth_data), timeout=180
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
                        severity = "critical" if critical_count > 0 else "high"
                        self.add_finding("WSTG-BUSL-01", f"Business data validation flaws: {vuln_count} found ({critical_count} critical)", severity=severity, evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_business_data_validation failed: {e}")

        # Test workflow bypass
        if self.should_run_tool("test_workflow_bypass"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_workflow_bypass",
                        args={"base_url": target}, auth_session=auth_data), timeout=180
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = data.get("bypass_vulnerabilities_found", 0)
                    if findings and vuln_count > 0:
                        self.add_finding("WSTG-BUSL-07", f"Workflow bypasses: {vuln_count} multi-step process bypass(es)", severity="high", evidence={"findings": findings[:2]})
            except Exception as e:
                self.log("warning", f"test_workflow_bypass failed: {e}")

        # Test race conditions
        if self.should_run_tool("test_race_conditions"):
            for race_url in _pick_urls(data_eps)[:3]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_race_conditions",
                            args={"target_url": race_url}, auth_session=auth_data), timeout=120
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("race_condition_detected"):
                            self.add_finding("WSTG-BUSL-07", f"Race condition vulnerabilities: {data.get('successful_responses', 0)} concurrent request(s) succeeded", severity="high", evidence={"successful_responses": data.get("successful_responses"), "results": data.get("results", [])[:3]})
                except Exception as e:
                    self.log("warning", f"test_race_conditions failed: {e}")

        # Test function limits (rate limiting, burst protection)
        if self.should_run_tool("test_function_limits"):
            for limit_url in _pick_urls(login_eps)[:2]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_function_limits",
                            args={"target_url": limit_url}, auth_session=auth_data), timeout=150
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if not data.get("rate_limiting_detected"):
                            self.add_finding("WSTG-BUSL-05", f"Function limit bypasses: no rate limiting after {data.get('burst_requests_sent', 0)} burst request(s)", severity="medium", evidence={"burst_requests_sent": data.get("burst_requests_sent"), "sample_results": data.get("sample_results", [])[:3], "average_response_time_ms": data.get("average_response_time_ms")})
                except Exception as e:
                    self.log("warning", f"test_function_limits failed: {e}")

        # PHASE 2.5: Test shopping cart manipulation
        if self.should_run_tool("test_shopping_cart_manipulation"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_shopping_cart_manipulation",
                        args={"base_url": target},
                        auth_session=auth_data
                    ), timeout=180
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    vuln_count = len(findings) if findings else 0
                    if findings and vuln_count > 0:
                        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
                        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
                        severity = "critical" if critical_count > 0 else ("high" if high_count > 0 else "medium")
                        self.add_finding("WSTG-BUSL-01", f"Shopping cart manipulation vulnerabilities: {vuln_count} found ({critical_count} critical, {high_count} high)", severity=severity, evidence={"findings": findings[:5]})
                        self.log("info", f"Shopping cart manipulation test found {vuln_count} vulnerabilities")
            except Exception as e:
                self.log("warning", f"test_shopping_cart_manipulation failed: {e}")

        # WSTG-BUSL-03: Integrity checks
        if self.should_run_tool("test_integrity_checks"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_integrity_checks",
                        args={"url": target}, auth_session=auth_data), timeout=180
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    if findings:
                        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
                        severity = "critical" if critical_count > 0 else "high"
                        self.add_finding("WSTG-BUSL-03", f"Integrity check failures: {len(findings)} found", severity=severity, evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_integrity_checks failed: {e}")

        # WSTG-BUSL-07: Application misuse defenses
        if self.should_run_tool("test_application_misuse_defenses"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_application_misuse_defenses",
                        args={"url": target}, auth_session=auth_data), timeout=180
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    findings = data.get("findings", [])
                    if findings:
                        self.add_finding("WSTG-BUSL-07", f"Missing misuse defenses: {len(findings)} issue(s)", severity="medium", evidence={"findings": findings[:3]})
            except Exception as e:
                self.log("warning", f"test_application_misuse_defenses failed: {e}")

        # WSTG-BUSL-02: Parameter tampering
        if self.should_run_tool("test_parameter_tampering"):
            try:
                # Test removing key parameters from API requests
                for tamper_url in _pick_urls(data_eps)[:3]:
                    for param in ["price", "quantity", "discount", "total"]:
                        res = await self.run_tool_with_timeout(
                            client.call_tool(
                                server="business-logic-testing",
                                tool="test_parameter_tampering",
                                args={"url": tamper_url, "param_to_remove": param}, auth_session=auth_data), timeout=60
                        )
                        if isinstance(res, dict):
                            self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                        if isinstance(res, dict) and res.get("status") == "success":
                            data = res.get("data", {})
                            if data.get("vulnerable"):
                                self.add_finding("WSTG-BUSL-02", f"Parameter tampering: removing '{param}' bypasses validation", severity="high", evidence=data)
                                break
            except Exception as e:
                self.log("warning", f"test_parameter_tampering failed: {e}")

        # WSTG-BUSL-02: Mass assignment
        if self.should_run_tool("test_mass_assignment"):
            for mass_url in _pick_urls(data_eps)[:3]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_mass_assignment",
                            args={
                                "url": mass_url,
                                "method": "PUT",
                                "valid_data": {"email": "test@test.com"},
                                "evil_params": {"role": "admin", "isAdmin": True}
                            }, auth_session=auth_data), timeout=60
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        # test_mass_assignment computes no automated verdict (its own
                        # response says "Manually verify..."); always surface the raw
                        # evidence as a human-review lead, never auto-reportable.
                        evidence = dict(data)
                        evidence["proof_type"] = "heuristic"
                        self.add_finding("WSTG-BUSL-02", "Mass assignment: privileged fields submitted, needs manual verification", severity="critical", evidence=evidence)
                except Exception as e:
                    self.log("warning", f"test_mass_assignment failed: {e}")

        # WSTG-BUSL-05: Forge requests (payment manipulation)
        if self.should_run_tool("test_forge_requests"):
            for forge_url in _pick_urls(checkout_eps)[:2]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_forge_requests",
                            args={
                                "payment_url": forge_url,
                                "legitimate_order": {"orderPrice": 0.01, "deliveryPrice": 0}
                            }, auth_session=auth_data), timeout=120
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("vulnerable"):
                            self.add_finding("WSTG-BUSL-05", "Forged payment request accepted", severity="critical", evidence=data)
                except Exception as e:
                    self.log("warning", f"test_forge_requests failed: {e}")

        # WSTG-BUSL-04: Race condition via timing
        if self.should_run_tool("test_process_timing_race_condition"):
            for timing_url in _pick_urls(checkout_eps + data_eps)[:3]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_process_timing_race_condition",
                            args={"url": timing_url, "method": "POST", "runs": 10}, auth_session=auth_data), timeout=120
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("successful_requests", 0) > 1:
                            self.add_finding("WSTG-BUSL-04", f"Race condition in process timing: {data.get('successful_requests')} concurrent request(s) succeeded", severity="high", evidence={"successful_requests": data.get("successful_requests"), "total_requests": data.get("total_requests"), "status_codes_received": data.get("status_codes_received", [])})
                except Exception as e:
                    self.log("warning", f"test_process_timing_race_condition failed: {e}")

        # WSTG-BUSL-06: Usage limits burst
        if self.should_run_tool("test_usage_limits_burst"):
            for burst_url in _pick_urls(feedback_eps)[:2]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_usage_limits_burst",
                            args={"url": burst_url, "method": "POST", "burst_count": 20}, auth_session=auth_data), timeout=120
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if not data.get("rate_limit_enforced"):
                            self.add_finding("WSTG-BUSL-06", f"No usage limits: burst of {data.get('total_requests', 0)} requests accepted without rate limiting", severity="medium", evidence={"total_requests": data.get("total_requests"), "status_codes_received": data.get("status_codes_received", [])})
                except Exception as e:
                    self.log("warning", f"test_usage_limits_burst failed: {e}")

        # WSTG-BUSL-08: Unexpected file upload in business logic
        if self.should_run_tool("test_unexpected_file_upload"):
            for upload_url in _pick_urls(upload_eps)[:2]:
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="business-logic-testing",
                            tool="test_unexpected_file_upload",
                            args={"upload_url": upload_url}, auth_session=auth_data), timeout=120
                    )
                    if isinstance(res, dict):
                        self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data", {})
                        if data.get("unsafe_uploads_accepted", 0) > 0:
                            self.add_finding("WSTG-BUSL-08", f"Unexpected file types accepted in upload: {data.get('unsafe_uploads_accepted')} file(s)", severity="high", evidence={"findings": data.get("findings", [])[:3], "unsafe_uploads_accepted": data.get("unsafe_uploads_accepted")})
                except Exception as e:
                    self.log("warning", f"test_unexpected_file_upload failed: {e}")

        # WSTG-BUSL-05: CAPTCHA bypass and rate limiting abuse
        if self.should_run_tool("test_captcha_and_rate_limit"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_captcha_and_rate_limit",
                        args={"url": target}, auth_session=auth_data), timeout=120
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-BUSL-05",
                                f"Rate limiting bypass: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "medium"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_captcha_and_rate_limit failed: {e}")

        # WSTG-BUSL-09: Coupon code forgery and pricing abuse
        if self.should_run_tool("test_coupon_forgery"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="business-logic-testing",
                        tool="test_coupon_forgery",
                        args={"url": target}, auth_session=auth_data), timeout=90
                )
                if isinstance(res, dict):
                    self._adjudication_artifacts.extend(res.get("artifacts", []) or [])
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data", {})
                    if data.get("vulnerable"):
                        for finding in data.get("findings", []):
                            self.add_finding(
                                "WSTG-BUSL-09",
                                f"Coupon/pricing vulnerability: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "high"),
                                evidence={"endpoint": finding.get("endpoint", ""), "evidence": str(finding.get("evidence", ""))[:200]}
                            )
            except Exception as e:
                self.log("warning", f"test_coupon_forgery failed: {e}")

        self.log("info", "Business logic checks complete")

        from ..adjudication.runner import run_adjudication
        try:
            await run_adjudication(self, self._adjudication_artifacts)
        except Exception as e:
            self.log("warning", f"run_adjudication failed: {e}")

    def _get_available_tools(self) -> list[str]:
        """Return business logic testing tools for LLM planning"""
        return [
            'test_business_data_validation',
            'test_workflow_bypass',
            'test_race_conditions',
            'test_function_limits',
            'test_shopping_cart_manipulation',
            'test_integrity_checks',
            'test_application_misuse_defenses',
            'test_parameter_tampering',
            'test_mass_assignment',
            'test_forge_requests',
            'test_process_timing_race_condition',
            'test_usage_limits_burst',
            'test_unexpected_file_upload',
            'test_captcha_and_rate_limit',
            'test_coupon_forgery',
        ]

    def _get_tool_server_map(self) -> Dict[str, str]:
        return {tool: "business-logic-testing" for tool in self._get_available_tools()}

    def _get_tool_info(self) -> dict:
        return {
            'test_race_conditions':              {'priority': 'HIGH', 'description': 'TOCTOU race condition testing'},
            'test_process_timing_race_condition': {'priority': 'HIGH', 'description': 'Process timing race conditions'},
            'test_captcha_and_rate_limit':        {'priority': 'HIGH', 'description': 'CAPTCHA and rate limit bypass'},
            'test_shopping_cart_manipulation':    {'priority': 'HIGH', 'description': 'Cart price/quantity manipulation'},
            'test_integrity_checks':              {'priority': 'HIGH', 'description': 'Integrity check bypass'},
            'test_workflow_bypass':               {'priority': 'HIGH', 'description': 'Multi-step workflow bypass'},
            'test_forge_requests':                {'priority': 'HIGH', 'description': 'Request forgery (coupon, payment)'},
            'test_coupon_forgery':                {'priority': 'HIGH', 'description': 'Coupon code forgery'},
            'test_business_data_validation':      {'priority': 'MEDIUM', 'description': 'Numeric/string validation extremes'},
            'test_parameter_tampering':           {'priority': 'MEDIUM', 'description': 'URL parameter manipulation'},
            'test_mass_assignment':               {'priority': 'MEDIUM', 'description': 'Mass assignment via extra fields'},
            'test_function_limits':               {'priority': 'MEDIUM', 'description': 'Function invocation limits'},
            'test_usage_limits_burst':            {'priority': 'MEDIUM', 'description': 'Burst usage limit bypass'},
            'test_unexpected_file_upload':        {'priority': 'MEDIUM', 'description': 'Unexpected file upload paths'},
            'test_application_misuse_defenses':   {'priority': 'MEDIUM', 'description': 'Misuse defense testing'},
        }

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
