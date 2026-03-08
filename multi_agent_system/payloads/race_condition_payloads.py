"""
Race Condition Detection Payloads for Generic Vulnerability Assessment

This module provides comprehensive race condition testing patterns for detecting
TOCTOU (Time-of-Check to Time-of-Use) and other concurrency vulnerabilities.

Categories:
1. Financial Race Conditions (balance, transfers, purchases)
2. Authentication Race Conditions (session, login)
3. Authorization Race Conditions (privilege escalation)
4. Resource Race Conditions (inventory, coupons, votes)
5. File Operation Race Conditions
6. Database Race Conditions

Reference: OWASP Testing Guide - Race Condition Testing
"""

from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
import time


class RaceConditionType(Enum):
    """Types of race condition vulnerabilities"""
    FINANCIAL = "financial"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RESOURCE = "resource"
    FILE_OPERATION = "file_operation"
    DATABASE = "database"


@dataclass
class RaceConditionScenario:
    """Represents a race condition test scenario"""
    name: str
    description: str
    type: RaceConditionType
    endpoint_pattern: str
    method: str
    concurrent_requests: int
    delay_between_ms: int
    detection_indicators: List[str]
    severity: str


# =============================================================================
# FINANCIAL RACE CONDITIONS
# =============================================================================

FINANCIAL_RACE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "double_spend_transfer",
        "description": "Transfer same funds multiple times simultaneously",
        "endpoint_patterns": [
            "/api/transfer", "/api/send", "/api/payment", "/api/withdraw",
            "/transfer", "/send-money", "/payment/process", "/wallet/send"
        ],
        "method": "POST",
        "concurrent_requests": 10,
        "payload_template": {"amount": 100, "to": "recipient"},
        "detection": "Check if total transferred > initial balance",
        "severity": "critical"
    },
    {
        "name": "balance_manipulation",
        "description": "Manipulate balance during concurrent operations",
        "endpoint_patterns": [
            "/api/balance", "/api/account", "/api/wallet",
            "/balance/update", "/account/credit"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "detection": "Balance inconsistency after concurrent updates",
        "severity": "critical"
    },
    {
        "name": "discount_stacking",
        "description": "Apply same discount code multiple times",
        "endpoint_patterns": [
            "/api/coupon", "/api/discount", "/api/promo",
            "/apply-coupon", "/redeem", "/voucher/apply"
        ],
        "method": "POST",
        "concurrent_requests": 15,
        "payload_template": {"code": "DISCOUNT10"},
        "detection": "Discount applied more than once",
        "severity": "high"
    },
    {
        "name": "refund_race",
        "description": "Request multiple refunds for same transaction",
        "endpoint_patterns": [
            "/api/refund", "/api/return", "/order/refund",
            "/payment/refund", "/transaction/reverse"
        ],
        "method": "POST",
        "concurrent_requests": 10,
        "detection": "Multiple refunds for single purchase",
        "severity": "critical"
    },
    {
        "name": "purchase_below_stock",
        "description": "Purchase more items than available inventory",
        "endpoint_patterns": [
            "/api/purchase", "/api/buy", "/api/order",
            "/cart/checkout", "/order/place", "/buy"
        ],
        "method": "POST",
        "concurrent_requests": 50,
        "payload_template": {"quantity": 1, "item_id": "target"},
        "detection": "Total purchased > available stock",
        "severity": "high"
    },
]


# =============================================================================
# AUTHENTICATION RACE CONDITIONS
# =============================================================================

AUTHENTICATION_RACE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "session_fixation_race",
        "description": "Create multiple sessions simultaneously",
        "endpoint_patterns": [
            "/api/login", "/api/auth", "/login", "/signin",
            "/api/session", "/authenticate"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "detection": "Multiple valid sessions for same user",
        "severity": "high"
    },
    {
        "name": "password_reset_race",
        "description": "Request multiple password reset tokens",
        "endpoint_patterns": [
            "/api/password/reset", "/api/forgot-password",
            "/reset-password", "/forgot", "/recover"
        ],
        "method": "POST",
        "concurrent_requests": 10,
        "detection": "Multiple valid reset tokens generated",
        "severity": "medium"
    },
    {
        "name": "token_refresh_race",
        "description": "Refresh authentication tokens concurrently",
        "endpoint_patterns": [
            "/api/token/refresh", "/api/refresh", "/auth/refresh",
            "/token/renew", "/session/extend"
        ],
        "method": "POST",
        "concurrent_requests": 15,
        "detection": "Token generation inconsistency",
        "severity": "medium"
    },
    {
        "name": "registration_race",
        "description": "Register same username/email concurrently",
        "endpoint_patterns": [
            "/api/register", "/api/signup", "/register",
            "/signup", "/create-account", "/user/new"
        ],
        "method": "POST",
        "concurrent_requests": 10,
        "payload_template": {"username": "testuser", "email": "test@test.com"},
        "detection": "Duplicate accounts created",
        "severity": "medium"
    },
    {
        "name": "otp_bypass_race",
        "description": "Submit OTP verification concurrently",
        "endpoint_patterns": [
            "/api/verify-otp", "/api/2fa/verify", "/otp/verify",
            "/mfa/confirm", "/verify-code"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "detection": "OTP accepted multiple times or bypassed",
        "severity": "critical"
    },
]


# =============================================================================
# AUTHORIZATION RACE CONDITIONS
# =============================================================================

AUTHORIZATION_RACE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "privilege_escalation_race",
        "description": "Change user role during permission check",
        "endpoint_patterns": [
            "/api/user/role", "/api/permissions", "/user/upgrade",
            "/admin/grant", "/role/change"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "detection": "User gains unauthorized privileges",
        "severity": "critical"
    },
    {
        "name": "access_grant_race",
        "description": "Grant access to resource concurrently",
        "endpoint_patterns": [
            "/api/share", "/api/access/grant", "/permissions/add",
            "/share", "/grant-access"
        ],
        "method": "POST",
        "concurrent_requests": 15,
        "detection": "Duplicate or excessive access grants",
        "severity": "high"
    },
    {
        "name": "group_membership_race",
        "description": "Add user to group during membership check",
        "endpoint_patterns": [
            "/api/group/add", "/api/team/join", "/group/member",
            "/team/add", "/organization/invite"
        ],
        "method": "POST",
        "concurrent_requests": 10,
        "detection": "User in group without proper authorization",
        "severity": "high"
    },
]


# =============================================================================
# RESOURCE RACE CONDITIONS
# =============================================================================

RESOURCE_RACE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "like_spam_race",
        "description": "Like/vote same item multiple times",
        "endpoint_patterns": [
            "/api/like", "/api/vote", "/api/upvote", "/api/favorite",
            "/like", "/vote", "/upvote", "/star", "/heart"
        ],
        "method": "POST",
        "concurrent_requests": 50,
        "detection": "Like count > expected (1 per user)",
        "severity": "medium"
    },
    {
        "name": "coupon_reuse_race",
        "description": "Use single-use coupon multiple times",
        "endpoint_patterns": [
            "/api/coupon/redeem", "/api/voucher/use", "/redeem",
            "/coupon/apply", "/promo/use"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "payload_template": {"code": "SINGLE_USE_CODE"},
        "detection": "Single-use coupon used multiple times",
        "severity": "high"
    },
    {
        "name": "inventory_oversell_race",
        "description": "Purchase limited stock item concurrently",
        "endpoint_patterns": [
            "/api/inventory/reserve", "/api/stock/claim",
            "/reserve", "/claim", "/add-to-cart"
        ],
        "method": "POST",
        "concurrent_requests": 100,
        "detection": "Reserved items > available stock",
        "severity": "high"
    },
    {
        "name": "captcha_bypass_race",
        "description": "Submit form with same CAPTCHA solution",
        "endpoint_patterns": [
            "/api/submit", "/api/form", "/contact",
            "/feedback", "/report"
        ],
        "method": "POST",
        "concurrent_requests": 10,
        "detection": "CAPTCHA solution accepted multiple times",
        "severity": "medium"
    },
    {
        "name": "file_quota_race",
        "description": "Upload files to exceed quota",
        "endpoint_patterns": [
            "/api/upload", "/api/file", "/upload",
            "/files/add", "/storage/upload"
        ],
        "method": "POST",
        "concurrent_requests": 30,
        "detection": "Total uploaded > quota limit",
        "severity": "medium"
    },
    {
        "name": "reward_claim_race",
        "description": "Claim same reward multiple times",
        "endpoint_patterns": [
            "/api/reward/claim", "/api/bonus", "/api/points/redeem",
            "/claim-reward", "/redeem-points"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "detection": "Reward claimed more than once",
        "severity": "high"
    },
]


# =============================================================================
# FILE OPERATION RACE CONDITIONS
# =============================================================================

FILE_OPERATION_RACE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "symlink_race",
        "description": "Replace file with symlink during operation",
        "endpoint_patterns": [
            "/api/file/process", "/api/file/read", "/file/download",
            "/process", "/export"
        ],
        "method": "GET",
        "concurrent_requests": 10,
        "detection": "File operation on unintended target",
        "severity": "critical"
    },
    {
        "name": "temp_file_race",
        "description": "Access temporary file before cleanup",
        "endpoint_patterns": [
            "/tmp/", "/temp/", "/cache/",
            "/api/temp", "/api/cache"
        ],
        "method": "GET",
        "concurrent_requests": 50,
        "detection": "Sensitive data in temporary files",
        "severity": "high"
    },
    {
        "name": "file_delete_race",
        "description": "Read file during delete operation",
        "endpoint_patterns": [
            "/api/file/delete", "/api/remove", "/file/trash",
            "/delete", "/remove"
        ],
        "method": "DELETE",
        "concurrent_requests": 20,
        "detection": "File accessed after deletion started",
        "severity": "medium"
    },
]


# =============================================================================
# DATABASE RACE CONDITIONS
# =============================================================================

DATABASE_RACE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "counter_increment_race",
        "description": "Increment counter without proper locking",
        "endpoint_patterns": [
            "/api/counter", "/api/increment", "/api/count",
            "/increment", "/count/add"
        ],
        "method": "POST",
        "concurrent_requests": 100,
        "detection": "Counter value < expected increments",
        "severity": "medium"
    },
    {
        "name": "unique_constraint_race",
        "description": "Insert duplicate before constraint check",
        "endpoint_patterns": [
            "/api/create", "/api/insert", "/api/add",
            "/create", "/new", "/add"
        ],
        "method": "POST",
        "concurrent_requests": 20,
        "detection": "Duplicate entries despite unique constraint",
        "severity": "medium"
    },
    {
        "name": "sequence_number_race",
        "description": "Generate duplicate sequence numbers",
        "endpoint_patterns": [
            "/api/sequence", "/api/order/number", "/api/ticket",
            "/generate-id", "/new-ticket"
        ],
        "method": "POST",
        "concurrent_requests": 50,
        "detection": "Duplicate sequence/ticket numbers",
        "severity": "medium"
    },
]


# =============================================================================
# RACE CONDITION DETECTION PATTERNS
# =============================================================================

def get_race_condition_indicators() -> List[str]:
    """Get patterns indicating successful race condition exploitation."""
    return [
        # Balance/financial indicators
        r"balance.*negative",
        r"insufficient.*funds.*bypass",
        r"overdraft",
        r"duplicate.*transaction",
        
        # Count/quantity anomalies
        r"count.*mismatch",
        r"quantity.*exceeded",
        r"stock.*negative",
        r"inventory.*oversold",
        
        # Duplicate indicators
        r"duplicate.*entry",
        r"already.*exists",
        r"constraint.*violation",
        r"unique.*conflict",
        
        # Authentication anomalies
        r"multiple.*sessions",
        r"token.*conflict",
        r"session.*overlap",
        
        # Success despite limits
        r"limit.*exceeded",
        r"quota.*exceeded",
        r"rate.*limit.*bypass",
        r"maximum.*reached",
        
        # Error messages revealing race
        r"deadlock",
        r"lock.*timeout",
        r"concurrent.*modification",
        r"optimistic.*lock.*failed",
        r"transaction.*conflict",
    ]


# =============================================================================
# RACE CONDITION ENDPOINT PATTERNS
# =============================================================================

# Endpoints commonly vulnerable to race conditions
RACE_PRONE_ENDPOINTS: List[str] = [
    # Financial
    "/api/transfer", "/api/payment", "/api/withdraw", "/api/deposit",
    "/api/purchase", "/api/buy", "/api/checkout", "/api/order",
    "/api/refund", "/api/coupon", "/api/discount", "/api/redeem",
    
    # Authentication
    "/api/login", "/api/register", "/api/session", "/api/token",
    "/api/password", "/api/otp", "/api/2fa", "/api/verify",
    
    # Resources
    "/api/like", "/api/vote", "/api/favorite", "/api/follow",
    "/api/subscribe", "/api/claim", "/api/reserve", "/api/book",
    
    # Inventory
    "/api/stock", "/api/inventory", "/api/cart", "/api/basket",
    "/api/quantity", "/api/availability",
    
    # User actions
    "/api/profile", "/api/settings", "/api/preferences",
    "/api/update", "/api/delete", "/api/create",
]

# HTTP methods for race condition testing
RACE_CONDITION_METHODS: List[str] = ["POST", "PUT", "PATCH", "DELETE"]


# =============================================================================
# TIMING CONFIGURATIONS
# =============================================================================

TIMING_CONFIGS: Dict[str, Dict[str, int]] = {
    "aggressive": {
        "concurrent_requests": 100,
        "delay_between_ms": 0,
        "timeout_ms": 5000,
        "retry_count": 3
    },
    "moderate": {
        "concurrent_requests": 50,
        "delay_between_ms": 10,
        "timeout_ms": 10000,
        "retry_count": 2
    },
    "conservative": {
        "concurrent_requests": 20,
        "delay_between_ms": 50,
        "timeout_ms": 15000,
        "retry_count": 1
    },
    "stealth": {
        "concurrent_requests": 10,
        "delay_between_ms": 100,
        "timeout_ms": 20000,
        "retry_count": 1
    }
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_race_scenarios() -> List[Dict[str, Any]]:
    """Get all race condition scenarios combined."""
    return (
        FINANCIAL_RACE_SCENARIOS +
        AUTHENTICATION_RACE_SCENARIOS +
        AUTHORIZATION_RACE_SCENARIOS +
        RESOURCE_RACE_SCENARIOS +
        FILE_OPERATION_RACE_SCENARIOS +
        DATABASE_RACE_SCENARIOS
    )


def get_scenarios_by_type(race_type: RaceConditionType) -> List[Dict[str, Any]]:
    """Get race condition scenarios filtered by type."""
    type_mapping = {
        RaceConditionType.FINANCIAL: FINANCIAL_RACE_SCENARIOS,
        RaceConditionType.AUTHENTICATION: AUTHENTICATION_RACE_SCENARIOS,
        RaceConditionType.AUTHORIZATION: AUTHORIZATION_RACE_SCENARIOS,
        RaceConditionType.RESOURCE: RESOURCE_RACE_SCENARIOS,
        RaceConditionType.FILE_OPERATION: FILE_OPERATION_RACE_SCENARIOS,
        RaceConditionType.DATABASE: DATABASE_RACE_SCENARIOS,
    }
    return type_mapping.get(race_type, [])


def get_race_payload_summary() -> Dict[str, int]:
    """Get summary of all race condition scenarios."""
    return {
        "financial": len(FINANCIAL_RACE_SCENARIOS),
        "authentication": len(AUTHENTICATION_RACE_SCENARIOS),
        "authorization": len(AUTHORIZATION_RACE_SCENARIOS),
        "resource": len(RESOURCE_RACE_SCENARIOS),
        "file_operation": len(FILE_OPERATION_RACE_SCENARIOS),
        "database": len(DATABASE_RACE_SCENARIOS),
        "race_prone_endpoints": len(RACE_PRONE_ENDPOINTS),
        "total_scenarios": len(get_all_race_scenarios()),
    }


def match_endpoint_to_scenarios(endpoint: str) -> List[Dict[str, Any]]:
    """
    Find race condition scenarios that match a given endpoint.
    
    Args:
        endpoint: The API endpoint to check
        
    Returns:
        List of matching race condition scenarios
    """
    matching = []
    endpoint_lower = endpoint.lower()
    
    for scenario in get_all_race_scenarios():
        for pattern in scenario.get("endpoint_patterns", []):
            if pattern.lower() in endpoint_lower or endpoint_lower in pattern.lower():
                matching.append(scenario)
                break
    
    return matching


def generate_race_test_config(
    endpoint: str,
    method: str = "POST",
    intensity: str = "moderate"
) -> Dict[str, Any]:
    """
    Generate a race condition test configuration for an endpoint.
    
    Args:
        endpoint: Target endpoint
        method: HTTP method
        intensity: Test intensity level
        
    Returns:
        Test configuration dictionary
    """
    timing = TIMING_CONFIGS.get(intensity, TIMING_CONFIGS["moderate"])
    scenarios = match_endpoint_to_scenarios(endpoint)
    
    return {
        "endpoint": endpoint,
        "method": method,
        "concurrent_requests": timing["concurrent_requests"],
        "delay_between_ms": timing["delay_between_ms"],
        "timeout_ms": timing["timeout_ms"],
        "matched_scenarios": scenarios,
        "indicators": get_race_condition_indicators(),
    }


# =============================================================================
# ASYNC RACE CONDITION TESTER (Stub for integration)
# =============================================================================

async def execute_race_condition_test(
    url: str,
    method: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    concurrent_count: int,
    delay_ms: int = 0
) -> Dict[str, Any]:
    """
    Execute a race condition test with concurrent requests.
    
    This is a stub that should be integrated with actual HTTP client.
    
    Args:
        url: Target URL
        method: HTTP method
        payload: Request payload
        headers: Request headers
        concurrent_count: Number of concurrent requests
        delay_ms: Delay between request batches
        
    Returns:
        Test results with response analysis
    """
    # This would be implemented with aiohttp or similar
    # Returning stub result for now
    return {
        "url": url,
        "method": method,
        "concurrent_requests": concurrent_count,
        "status": "stub_implementation",
        "note": "Integrate with aiohttp for actual testing"
    }


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "RaceConditionType",
    "RaceConditionScenario",
    
    # Scenario lists
    "FINANCIAL_RACE_SCENARIOS",
    "AUTHENTICATION_RACE_SCENARIOS",
    "AUTHORIZATION_RACE_SCENARIOS",
    "RESOURCE_RACE_SCENARIOS",
    "FILE_OPERATION_RACE_SCENARIOS",
    "DATABASE_RACE_SCENARIOS",
    
    # Configuration
    "RACE_PRONE_ENDPOINTS",
    "RACE_CONDITION_METHODS",
    "TIMING_CONFIGS",
    
    # Functions
    "get_race_condition_indicators",
    "get_all_race_scenarios",
    "get_scenarios_by_type",
    "get_race_payload_summary",
    "match_endpoint_to_scenarios",
    "generate_race_test_config",
    "execute_race_condition_test",
]


if __name__ == "__main__":
    summary = get_race_payload_summary()
    print("Race Condition Scenarios Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
