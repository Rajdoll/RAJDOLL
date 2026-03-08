"""
Security Misconfiguration Detection Patterns
Phase 3 of RAJDOLL Improvement Plan

Target: >80% misconfiguration detection rate
Categories:
- HTTP Security Headers Analysis
- CORS Misconfiguration
- Debug/Admin Endpoints
- Default Credentials
- SSL/TLS Issues
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class MisconfigCategory(Enum):
    SECURITY_HEADERS = "security_headers"
    CORS = "cors"
    DEBUG_ENDPOINTS = "debug_endpoints"
    ADMIN_PANELS = "admin_panels"
    DEFAULT_CREDENTIALS = "default_credentials"
    SOURCE_EXPOSURE = "source_exposure"
    SSL_TLS = "ssl_tls"
    INFORMATION_DISCLOSURE = "information_disclosure"


@dataclass
class SecurityHeader:
    """Security header check configuration"""
    name: str
    required: bool = True
    recommended_values: List[str] = field(default_factory=list)
    dangerous_values: List[str] = field(default_factory=list)
    description: str = ""
    severity: str = "medium"


# ============================================================================
# HTTP Security Headers - 15 headers to check
# ============================================================================

SECURITY_HEADERS: List[SecurityHeader] = [
    SecurityHeader(
        name="Content-Security-Policy",
        required=True,
        recommended_values=["default-src 'self'", "script-src 'self'"],
        dangerous_values=["unsafe-inline", "unsafe-eval", "*"],
        description="Prevents XSS by controlling resource loading",
        severity="high"
    ),
    SecurityHeader(
        name="X-Frame-Options",
        required=True,
        recommended_values=["DENY", "SAMEORIGIN"],
        dangerous_values=["ALLOW-FROM *"],
        description="Prevents clickjacking attacks",
        severity="medium"
    ),
    SecurityHeader(
        name="X-Content-Type-Options",
        required=True,
        recommended_values=["nosniff"],
        dangerous_values=[],
        description="Prevents MIME type sniffing",
        severity="medium"
    ),
    SecurityHeader(
        name="Strict-Transport-Security",
        required=True,
        recommended_values=["max-age=31536000; includeSubDomains", "max-age=31536000; includeSubDomains; preload"],
        dangerous_values=["max-age=0"],
        description="Enforces HTTPS connections",
        severity="high"
    ),
    SecurityHeader(
        name="X-XSS-Protection",
        required=False,
        recommended_values=["1; mode=block", "0"],  # 0 is now recommended due to vulnerabilities
        dangerous_values=["1"],  # Without mode=block can introduce vulnerabilities
        description="Legacy XSS filter (deprecated in modern browsers)",
        severity="low"
    ),
    SecurityHeader(
        name="Referrer-Policy",
        required=True,
        recommended_values=["no-referrer", "strict-origin-when-cross-origin", "same-origin"],
        dangerous_values=["unsafe-url", "no-referrer-when-downgrade"],
        description="Controls referrer information leakage",
        severity="medium"
    ),
    SecurityHeader(
        name="Permissions-Policy",
        required=True,
        recommended_values=["geolocation=(), camera=(), microphone=()"],
        dangerous_values=["*"],
        description="Controls browser feature access",
        severity="medium"
    ),
    SecurityHeader(
        name="Cache-Control",
        required=True,
        recommended_values=["no-store", "no-cache, no-store, must-revalidate", "private, no-cache"],
        dangerous_values=["public"],
        description="Prevents caching of sensitive data",
        severity="medium"
    ),
    SecurityHeader(
        name="Pragma",
        required=False,
        recommended_values=["no-cache"],
        dangerous_values=[],
        description="HTTP/1.0 cache control",
        severity="low"
    ),
    SecurityHeader(
        name="X-Permitted-Cross-Domain-Policies",
        required=False,
        recommended_values=["none", "master-only"],
        dangerous_values=["all"],
        description="Controls Adobe Flash/PDF cross-domain access",
        severity="low"
    ),
    SecurityHeader(
        name="Cross-Origin-Embedder-Policy",
        required=False,
        recommended_values=["require-corp"],
        dangerous_values=["unsafe-none"],
        description="Controls cross-origin resource embedding",
        severity="medium"
    ),
    SecurityHeader(
        name="Cross-Origin-Opener-Policy",
        required=False,
        recommended_values=["same-origin"],
        dangerous_values=["unsafe-none"],
        description="Controls window opener relationships",
        severity="medium"
    ),
    SecurityHeader(
        name="Cross-Origin-Resource-Policy",
        required=False,
        recommended_values=["same-origin", "same-site"],
        dangerous_values=["cross-origin"],
        description="Controls resource cross-origin access",
        severity="medium"
    ),
    SecurityHeader(
        name="X-Download-Options",
        required=False,
        recommended_values=["noopen"],
        dangerous_values=[],
        description="Prevents IE from executing downloads in site context",
        severity="low"
    ),
    SecurityHeader(
        name="X-DNS-Prefetch-Control",
        required=False,
        recommended_values=["off"],
        dangerous_values=["on"],
        description="Controls DNS prefetching (privacy concern)",
        severity="low"
    ),
]

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS: List[Dict] = [
    {"name": "Server", "reason": "Reveals server software version", "severity": "low"},
    {"name": "X-Powered-By", "reason": "Reveals technology stack", "severity": "low"},
    {"name": "X-AspNet-Version", "reason": "Reveals ASP.NET version", "severity": "medium"},
    {"name": "X-AspNetMvc-Version", "reason": "Reveals ASP.NET MVC version", "severity": "medium"},
    {"name": "X-Runtime", "reason": "Reveals server processing time", "severity": "low"},
    {"name": "X-Version", "reason": "Reveals application version", "severity": "medium"},
    {"name": "X-Debug-Token", "reason": "Debug mode enabled", "severity": "high"},
    {"name": "X-Debug-Token-Link", "reason": "Debug mode enabled with profiler", "severity": "high"},
]

# ============================================================================
# CORS Misconfiguration Test Payloads - 25 patterns
# ============================================================================

CORS_TEST_ORIGINS: List[Dict] = [
    # Wildcard and null origin tests
    {"origin": "*", "description": "Wildcard origin", "severity": "high"},
    {"origin": "null", "description": "Null origin bypass", "severity": "high"},
    
    # Origin reflection tests
    {"origin": "https://evil.com", "description": "Arbitrary origin reflection", "severity": "critical"},
    {"origin": "https://attacker.com", "description": "Attacker domain reflection", "severity": "critical"},
    {"origin": "http://malicious-site.com", "description": "Malicious site reflection", "severity": "critical"},
    
    # Subdomain bypass attempts
    {"origin": "https://target.com.evil.com", "description": "Subdomain suffix bypass", "severity": "high"},
    {"origin": "https://evil-target.com", "description": "Prefix bypass", "severity": "high"},
    {"origin": "https://targetcom.evil.com", "description": "No dot bypass", "severity": "high"},
    {"origin": "https://target.com.attacker.com", "description": "Trust subdomain bypass", "severity": "high"},
    
    # Protocol downgrade
    {"origin": "http://target.com", "description": "HTTP downgrade", "severity": "medium"},
    
    # Special characters bypass
    {"origin": "https://target.com%00.evil.com", "description": "Null byte injection", "severity": "high"},
    {"origin": "https://target.com%0d%0a.evil.com", "description": "CRLF injection in origin", "severity": "high"},
    {"origin": "https://target.com@evil.com", "description": "@ symbol bypass", "severity": "high"},
    {"origin": "https://target.com#.evil.com", "description": "Fragment bypass", "severity": "medium"},
    {"origin": "https://target.com?.evil.com", "description": "Query string bypass", "severity": "medium"},
    
    # Case sensitivity
    {"origin": "https://TARGET.COM", "description": "Uppercase origin", "severity": "low"},
    {"origin": "https://Target.Com", "description": "Mixed case origin", "severity": "low"},
    
    # Localhost variations
    {"origin": "http://localhost", "description": "Localhost origin", "severity": "medium"},
    {"origin": "http://127.0.0.1", "description": "Loopback IP origin", "severity": "medium"},
    {"origin": "http://[::1]", "description": "IPv6 localhost origin", "severity": "medium"},
    {"origin": "http://localhost:8080", "description": "Localhost with port", "severity": "medium"},
    
    # File protocol
    {"origin": "file://", "description": "File protocol origin", "severity": "medium"},
    
    # Unicode/IDN bypass
    {"origin": "https://tаrget.com", "description": "Homograph attack (Cyrillic 'а')", "severity": "high"},
    {"origin": "https://targеt.com", "description": "Homograph attack (Cyrillic 'е')", "severity": "high"},
    
    # Port variations
    {"origin": "https://target.com:443", "description": "Explicit port", "severity": "low"},
]

CORS_CREDENTIAL_TESTS: List[str] = [
    "Access-Control-Allow-Credentials: true",  # With wildcard = critical
]

# ============================================================================
# Debug/Admin Endpoint Discovery - 80+ paths
# ============================================================================

DEBUG_ENDPOINTS: List[Dict] = [
    # Debug/Development endpoints
    {"path": "/debug", "description": "Debug endpoint", "severity": "high"},
    {"path": "/debug/", "description": "Debug directory", "severity": "high"},
    {"path": "/debug/default/view", "description": "Debug view", "severity": "high"},
    {"path": "/debug/pprof/", "description": "Go pprof profiler", "severity": "high"},
    {"path": "/_debug", "description": "Hidden debug", "severity": "high"},
    {"path": "/trace", "description": "Trace endpoint", "severity": "high"},
    {"path": "/trace.axd", "description": "ASP.NET trace", "severity": "high"},
    {"path": "/elmah.axd", "description": "ASP.NET error log", "severity": "high"},
    {"path": "/console", "description": "Console endpoint", "severity": "critical"},
    {"path": "/console/", "description": "Console directory", "severity": "critical"},
    {"path": "/_console", "description": "Hidden console", "severity": "critical"},
    {"path": "/shell", "description": "Shell access", "severity": "critical"},
    {"path": "/terminal", "description": "Terminal access", "severity": "critical"},
    {"path": "/repl", "description": "REPL access", "severity": "critical"},
    
    # Spring Boot Actuator (Java)
    {"path": "/actuator", "description": "Spring Actuator root", "severity": "high"},
    {"path": "/actuator/health", "description": "Health check", "severity": "low"},
    {"path": "/actuator/info", "description": "App info", "severity": "medium"},
    {"path": "/actuator/env", "description": "Environment variables", "severity": "critical"},
    {"path": "/actuator/configprops", "description": "Configuration properties", "severity": "critical"},
    {"path": "/actuator/beans", "description": "Spring beans", "severity": "medium"},
    {"path": "/actuator/mappings", "description": "URL mappings", "severity": "medium"},
    {"path": "/actuator/heapdump", "description": "Heap dump", "severity": "critical"},
    {"path": "/actuator/threaddump", "description": "Thread dump", "severity": "high"},
    {"path": "/actuator/loggers", "description": "Logger config", "severity": "high"},
    {"path": "/actuator/metrics", "description": "Metrics", "severity": "medium"},
    {"path": "/actuator/prometheus", "description": "Prometheus metrics", "severity": "medium"},
    {"path": "/actuator/scheduledtasks", "description": "Scheduled tasks", "severity": "medium"},
    {"path": "/actuator/httptrace", "description": "HTTP trace", "severity": "high"},
    {"path": "/actuator/shutdown", "description": "Shutdown endpoint", "severity": "critical"},
    {"path": "/actuator/jolokia", "description": "JMX over HTTP", "severity": "critical"},
    {"path": "/actuator/logfile", "description": "Log file access", "severity": "high"},
    
    # PHP specific
    {"path": "/phpinfo.php", "description": "PHP info page", "severity": "high"},
    {"path": "/info.php", "description": "PHP info", "severity": "high"},
    {"path": "/test.php", "description": "Test PHP", "severity": "medium"},
    {"path": "/php_info.php", "description": "PHP info variant", "severity": "high"},
    {"path": "/i.php", "description": "Short PHP info", "severity": "medium"},
    {"path": "/_phpinfo.php", "description": "Hidden PHP info", "severity": "high"},
    
    # Python/Django/Flask
    {"path": "/__debug__/", "description": "Django debug toolbar", "severity": "high"},
    {"path": "/debug/toolbar/", "description": "Debug toolbar", "severity": "high"},
    {"path": "/_debugbar", "description": "Laravel debug bar", "severity": "high"},
    {"path": "/debugbar", "description": "Debug bar", "severity": "high"},
    
    # Node.js/Express
    {"path": "/status", "description": "Status endpoint", "severity": "low"},
    {"path": "/__coverage__", "description": "Code coverage", "severity": "medium"},
    {"path": "/__inspect__", "description": "Node inspect", "severity": "high"},
    
    # API Documentation (information disclosure)
    {"path": "/swagger", "description": "Swagger docs", "severity": "medium"},
    {"path": "/swagger/", "description": "Swagger directory", "severity": "medium"},
    {"path": "/swagger-ui/", "description": "Swagger UI", "severity": "medium"},
    {"path": "/swagger-ui.html", "description": "Swagger UI HTML", "severity": "medium"},
    {"path": "/swagger.json", "description": "Swagger JSON spec", "severity": "medium"},
    {"path": "/swagger.yaml", "description": "Swagger YAML spec", "severity": "medium"},
    {"path": "/api-docs", "description": "API documentation", "severity": "medium"},
    {"path": "/api-docs/", "description": "API docs directory", "severity": "medium"},
    {"path": "/v2/api-docs", "description": "API docs v2", "severity": "medium"},
    {"path": "/v3/api-docs", "description": "API docs v3", "severity": "medium"},
    {"path": "/openapi.json", "description": "OpenAPI spec", "severity": "medium"},
    {"path": "/openapi.yaml", "description": "OpenAPI YAML", "severity": "medium"},
    {"path": "/redoc", "description": "ReDoc API docs", "severity": "medium"},
    {"path": "/graphql", "description": "GraphQL endpoint", "severity": "medium"},
    {"path": "/graphiql", "description": "GraphQL IDE", "severity": "high"},
    {"path": "/graphql/console", "description": "GraphQL console", "severity": "high"},
    {"path": "/altair", "description": "GraphQL Altair client", "severity": "high"},
    {"path": "/playground", "description": "GraphQL Playground", "severity": "high"},
    
    # Metrics and monitoring
    {"path": "/metrics", "description": "Metrics endpoint", "severity": "medium"},
    {"path": "/prometheus", "description": "Prometheus metrics", "severity": "medium"},
    {"path": "/health", "description": "Health check", "severity": "low"},
    {"path": "/healthz", "description": "Kubernetes health", "severity": "low"},
    {"path": "/readyz", "description": "Kubernetes readiness", "severity": "low"},
    {"path": "/livez", "description": "Kubernetes liveness", "severity": "low"},
    {"path": "/stats", "description": "Statistics", "severity": "medium"},
    {"path": "/server-status", "description": "Apache status", "severity": "high"},
    {"path": "/server-info", "description": "Apache info", "severity": "high"},
    {"path": "/nginx_status", "description": "Nginx status", "severity": "high"},
    {"path": "/stub_status", "description": "Nginx stub status", "severity": "medium"},
    {"path": "/__metrics", "description": "Hidden metrics", "severity": "medium"},
]

ADMIN_PANELS: List[Dict] = [
    # Generic admin paths
    {"path": "/admin", "description": "Admin panel", "severity": "high"},
    {"path": "/admin/", "description": "Admin directory", "severity": "high"},
    {"path": "/administrator", "description": "Administrator panel", "severity": "high"},
    {"path": "/administrator/", "description": "Administrator directory", "severity": "high"},
    {"path": "/admin.php", "description": "PHP admin", "severity": "high"},
    {"path": "/admin.html", "description": "HTML admin", "severity": "high"},
    {"path": "/adminpanel", "description": "Admin panel", "severity": "high"},
    {"path": "/admin-panel", "description": "Admin panel dash", "severity": "high"},
    {"path": "/_admin", "description": "Hidden admin", "severity": "high"},
    {"path": "/__admin", "description": "Hidden admin", "severity": "high"},
    {"path": "/adm", "description": "Short admin", "severity": "medium"},
    {"path": "/adm/", "description": "Short admin dir", "severity": "medium"},
    {"path": "/backend", "description": "Backend panel", "severity": "high"},
    {"path": "/backend/", "description": "Backend directory", "severity": "high"},
    {"path": "/manage", "description": "Management panel", "severity": "high"},
    {"path": "/management", "description": "Management panel", "severity": "high"},
    {"path": "/manager", "description": "Manager panel", "severity": "high"},
    {"path": "/manager/html", "description": "Tomcat manager", "severity": "critical"},
    {"path": "/dashboard", "description": "Dashboard", "severity": "medium"},
    {"path": "/cpanel", "description": "cPanel", "severity": "high"},
    {"path": "/controlpanel", "description": "Control panel", "severity": "high"},
    {"path": "/control-panel", "description": "Control panel", "severity": "high"},
    {"path": "/portal", "description": "Portal", "severity": "medium"},
    {"path": "/cms", "description": "CMS admin", "severity": "high"},
    {"path": "/cms/admin", "description": "CMS admin panel", "severity": "high"},
    {"path": "/system", "description": "System admin", "severity": "high"},
    {"path": "/sys", "description": "System short", "severity": "medium"},
    {"path": "/superadmin", "description": "Super admin", "severity": "critical"},
    {"path": "/root", "description": "Root admin", "severity": "critical"},
    {"path": "/wp-admin", "description": "WordPress admin", "severity": "high"},
    {"path": "/wp-login.php", "description": "WordPress login", "severity": "medium"},
    {"path": "/user/login", "description": "User login", "severity": "low"},
    {"path": "/login", "description": "Login page", "severity": "low"},
    {"path": "/signin", "description": "Sign in page", "severity": "low"},
    {"path": "/auth/login", "description": "Auth login", "severity": "low"},
]

# ============================================================================
# Source Code/Config Exposure - 50+ paths
# ============================================================================

SOURCE_EXPOSURE_PATHS: List[Dict] = [
    # Git exposure
    {"path": "/.git", "description": "Git directory", "severity": "critical"},
    {"path": "/.git/", "description": "Git directory", "severity": "critical"},
    {"path": "/.git/config", "description": "Git config", "severity": "critical"},
    {"path": "/.git/HEAD", "description": "Git HEAD", "severity": "critical"},
    {"path": "/.git/index", "description": "Git index", "severity": "critical"},
    {"path": "/.git/logs/HEAD", "description": "Git logs", "severity": "high"},
    {"path": "/.git/objects/", "description": "Git objects", "severity": "critical"},
    {"path": "/.git/refs/heads/master", "description": "Git refs master", "severity": "high"},
    {"path": "/.git/refs/heads/main", "description": "Git refs main", "severity": "high"},
    {"path": "/.gitignore", "description": "Git ignore file", "severity": "medium"},
    {"path": "/.gitattributes", "description": "Git attributes", "severity": "low"},
    
    # SVN exposure
    {"path": "/.svn", "description": "SVN directory", "severity": "critical"},
    {"path": "/.svn/", "description": "SVN directory", "severity": "critical"},
    {"path": "/.svn/entries", "description": "SVN entries", "severity": "critical"},
    {"path": "/.svn/wc.db", "description": "SVN database", "severity": "critical"},
    
    # Other VCS
    {"path": "/.hg", "description": "Mercurial directory", "severity": "critical"},
    {"path": "/.hg/", "description": "Mercurial directory", "severity": "critical"},
    {"path": "/.bzr", "description": "Bazaar directory", "severity": "critical"},
    {"path": "/CVS", "description": "CVS directory", "severity": "critical"},
    {"path": "/CVS/Root", "description": "CVS root", "severity": "critical"},
    
    # Environment files
    {"path": "/.env", "description": "Environment file", "severity": "critical"},
    {"path": "/.env.local", "description": "Local env file", "severity": "critical"},
    {"path": "/.env.production", "description": "Production env", "severity": "critical"},
    {"path": "/.env.development", "description": "Development env", "severity": "critical"},
    {"path": "/.env.staging", "description": "Staging env", "severity": "critical"},
    {"path": "/.env.backup", "description": "Env backup", "severity": "critical"},
    {"path": "/.env.bak", "description": "Env backup", "severity": "critical"},
    {"path": "/.env.old", "description": "Old env file", "severity": "critical"},
    {"path": "/env", "description": "Environment file", "severity": "high"},
    {"path": "/env.js", "description": "JS env file", "severity": "high"},
    
    # Config files
    {"path": "/config.php", "description": "PHP config", "severity": "critical"},
    {"path": "/config.inc.php", "description": "PHP include config", "severity": "critical"},
    {"path": "/configuration.php", "description": "Configuration file", "severity": "critical"},
    {"path": "/settings.php", "description": "Settings file", "severity": "critical"},
    {"path": "/settings.py", "description": "Python settings", "severity": "critical"},
    {"path": "/config.py", "description": "Python config", "severity": "critical"},
    {"path": "/config.json", "description": "JSON config", "severity": "high"},
    {"path": "/config.yml", "description": "YAML config", "severity": "high"},
    {"path": "/config.yaml", "description": "YAML config", "severity": "high"},
    {"path": "/application.yml", "description": "Spring config", "severity": "critical"},
    {"path": "/application.yaml", "description": "Spring config", "severity": "critical"},
    {"path": "/application.properties", "description": "Java properties", "severity": "critical"},
    {"path": "/appsettings.json", "description": ".NET config", "severity": "critical"},
    {"path": "/web.config", "description": "IIS config", "severity": "critical"},
    {"path": "/.htaccess", "description": "Apache config", "severity": "high"},
    {"path": "/.htpasswd", "description": "Apache password", "severity": "critical"},
    {"path": "/nginx.conf", "description": "Nginx config", "severity": "critical"},
    
    # Package/Dependency files
    {"path": "/package.json", "description": "NPM packages", "severity": "medium"},
    {"path": "/package-lock.json", "description": "NPM lock file", "severity": "medium"},
    {"path": "/yarn.lock", "description": "Yarn lock file", "severity": "medium"},
    {"path": "/composer.json", "description": "Composer packages", "severity": "medium"},
    {"path": "/composer.lock", "description": "Composer lock", "severity": "medium"},
    {"path": "/requirements.txt", "description": "Python requirements", "severity": "medium"},
    {"path": "/Pipfile", "description": "Pipenv file", "severity": "medium"},
    {"path": "/Pipfile.lock", "description": "Pipenv lock", "severity": "medium"},
    {"path": "/Gemfile", "description": "Ruby gems", "severity": "medium"},
    {"path": "/Gemfile.lock", "description": "Ruby gems lock", "severity": "medium"},
    {"path": "/pom.xml", "description": "Maven POM", "severity": "medium"},
    {"path": "/build.gradle", "description": "Gradle build", "severity": "medium"},
    {"path": "/go.mod", "description": "Go modules", "severity": "medium"},
    {"path": "/go.sum", "description": "Go sum", "severity": "medium"},
    {"path": "/Cargo.toml", "description": "Rust cargo", "severity": "medium"},
    {"path": "/Cargo.lock", "description": "Rust cargo lock", "severity": "medium"},
    
    # Backup files
    {"path": "/backup.sql", "description": "SQL backup", "severity": "critical"},
    {"path": "/backup.zip", "description": "Backup archive", "severity": "critical"},
    {"path": "/backup.tar.gz", "description": "Backup tarball", "severity": "critical"},
    {"path": "/db.sql", "description": "Database dump", "severity": "critical"},
    {"path": "/database.sql", "description": "Database dump", "severity": "critical"},
    {"path": "/dump.sql", "description": "SQL dump", "severity": "critical"},
    {"path": "/data.sql", "description": "Data dump", "severity": "critical"},
    
    # IDE/Editor files
    {"path": "/.idea/", "description": "IntelliJ IDEA", "severity": "medium"},
    {"path": "/.vscode/", "description": "VS Code", "severity": "medium"},
    {"path": "/.vscode/settings.json", "description": "VS Code settings", "severity": "medium"},
    {"path": "/.sublime-project", "description": "Sublime project", "severity": "low"},
    {"path": "/.project", "description": "Eclipse project", "severity": "low"},
    {"path": "/.DS_Store", "description": "macOS metadata", "severity": "low"},
    {"path": "/Thumbs.db", "description": "Windows thumbnails", "severity": "low"},
    
    # Docker files
    {"path": "/Dockerfile", "description": "Docker file", "severity": "medium"},
    {"path": "/docker-compose.yml", "description": "Docker compose", "severity": "high"},
    {"path": "/docker-compose.yaml", "description": "Docker compose", "severity": "high"},
    {"path": "/.dockerignore", "description": "Docker ignore", "severity": "low"},
    
    # CI/CD
    {"path": "/.travis.yml", "description": "Travis CI config", "severity": "medium"},
    {"path": "/.gitlab-ci.yml", "description": "GitLab CI config", "severity": "medium"},
    {"path": "/.github/workflows/", "description": "GitHub Actions", "severity": "medium"},
    {"path": "/Jenkinsfile", "description": "Jenkins pipeline", "severity": "medium"},
    {"path": "/azure-pipelines.yml", "description": "Azure DevOps", "severity": "medium"},
    {"path": "/bitbucket-pipelines.yml", "description": "Bitbucket pipelines", "severity": "medium"},
    
    # Kubernetes
    {"path": "/k8s/", "description": "Kubernetes configs", "severity": "high"},
    {"path": "/kubernetes/", "description": "Kubernetes configs", "severity": "high"},
    {"path": "/helm/", "description": "Helm charts", "severity": "high"},
]

# ============================================================================
# Default Credentials - 50 common pairs
# ============================================================================

DEFAULT_CREDENTIALS: List[Dict] = [
    # Generic defaults
    {"username": "admin", "password": "admin", "description": "Default admin"},
    {"username": "admin", "password": "password", "description": "Admin/password"},
    {"username": "admin", "password": "123456", "description": "Admin/123456"},
    {"username": "admin", "password": "admin123", "description": "Admin/admin123"},
    {"username": "admin", "password": "administrator", "description": "Admin/administrator"},
    {"username": "admin", "password": "1234", "description": "Admin/1234"},
    {"username": "admin", "password": "12345", "description": "Admin/12345"},
    {"username": "admin", "password": "pass", "description": "Admin/pass"},
    {"username": "admin", "password": "test", "description": "Admin/test"},
    {"username": "admin", "password": "guest", "description": "Admin/guest"},
    {"username": "admin", "password": "master", "description": "Admin/master"},
    {"username": "admin", "password": "changeme", "description": "Admin/changeme"},
    {"username": "admin", "password": "root", "description": "Admin/root"},
    {"username": "admin", "password": "", "description": "Admin blank password"},
    
    {"username": "administrator", "password": "administrator", "description": "Administrator default"},
    {"username": "administrator", "password": "admin", "description": "Administrator/admin"},
    {"username": "administrator", "password": "password", "description": "Administrator/password"},
    
    {"username": "root", "password": "root", "description": "Root default"},
    {"username": "root", "password": "password", "description": "Root/password"},
    {"username": "root", "password": "toor", "description": "Root/toor"},
    {"username": "root", "password": "", "description": "Root blank password"},
    {"username": "root", "password": "admin", "description": "Root/admin"},
    {"username": "root", "password": "123456", "description": "Root/123456"},
    
    {"username": "user", "password": "user", "description": "User default"},
    {"username": "user", "password": "password", "description": "User/password"},
    {"username": "user", "password": "123456", "description": "User/123456"},
    
    {"username": "test", "password": "test", "description": "Test default"},
    {"username": "test", "password": "password", "description": "Test/password"},
    {"username": "test", "password": "123456", "description": "Test/123456"},
    
    {"username": "guest", "password": "guest", "description": "Guest default"},
    {"username": "guest", "password": "password", "description": "Guest/password"},
    {"username": "guest", "password": "", "description": "Guest blank password"},
    
    {"username": "demo", "password": "demo", "description": "Demo default"},
    {"username": "demo", "password": "password", "description": "Demo/password"},
    
    # Database defaults
    {"username": "sa", "password": "", "description": "MSSQL SA blank"},
    {"username": "sa", "password": "sa", "description": "MSSQL SA default"},
    {"username": "sa", "password": "password", "description": "MSSQL SA/password"},
    {"username": "postgres", "password": "postgres", "description": "PostgreSQL default"},
    {"username": "postgres", "password": "password", "description": "PostgreSQL/password"},
    {"username": "mysql", "password": "mysql", "description": "MySQL default"},
    {"username": "oracle", "password": "oracle", "description": "Oracle default"},
    {"username": "sysdba", "password": "sysdba", "description": "Oracle sysdba"},
    {"username": "scott", "password": "tiger", "description": "Oracle scott/tiger"},
    
    # Application defaults
    {"username": "tomcat", "password": "tomcat", "description": "Tomcat default"},
    {"username": "manager", "password": "manager", "description": "Manager default"},
    {"username": "weblogic", "password": "weblogic", "description": "WebLogic default"},
    {"username": "jboss", "password": "jboss", "description": "JBoss default"},
    {"username": "admin", "password": "admin@123", "description": "Admin common"},
    {"username": "Admin", "password": "Admin", "description": "Admin case-sensitive"},
    
    # Common weak passwords
    {"username": "admin", "password": "qwerty", "description": "Admin/qwerty"},
    {"username": "admin", "password": "letmein", "description": "Admin/letmein"},
    {"username": "admin", "password": "welcome", "description": "Admin/welcome"},
    {"username": "admin", "password": "password1", "description": "Admin/password1"},
    {"username": "admin", "password": "Password1", "description": "Admin/Password1"},
    {"username": "admin", "password": "P@ssw0rd", "description": "Admin/P@ssw0rd"},
    {"username": "admin", "password": "passw0rd", "description": "Admin/passw0rd"},
]

# ============================================================================
# Information Disclosure Patterns
# ============================================================================

ERROR_PATTERNS: List[Dict] = [
    # Stack traces
    {"pattern": r"at\s+[\w.]+\([\w.]+:\d+\)", "description": "Java stack trace", "severity": "medium"},
    {"pattern": r"Traceback \(most recent call last\)", "description": "Python traceback", "severity": "medium"},
    {"pattern": r"File \"[^\"]+\", line \d+", "description": "Python file reference", "severity": "medium"},
    {"pattern": r"at\s+[\w\$]+\.[\w\$]+\s+\([^)]+\.js:\d+:\d+\)", "description": "JavaScript stack trace", "severity": "medium"},
    {"pattern": r"Error:\s+\w+\s+at\s+", "description": "Node.js error", "severity": "medium"},
    {"pattern": r"Stack trace:", "description": "Generic stack trace", "severity": "medium"},
    {"pattern": r"^\s+at\s+\S+\s+\(\S+:\d+:\d+\)", "description": "V8 stack trace", "severity": "medium"},
    
    # Database errors
    {"pattern": r"SQL syntax.*MySQL", "description": "MySQL error", "severity": "high"},
    {"pattern": r"Warning.*mysql_", "description": "PHP MySQL warning", "severity": "high"},
    {"pattern": r"PostgreSQL.*ERROR", "description": "PostgreSQL error", "severity": "high"},
    {"pattern": r"ORA-\d{5}", "description": "Oracle error", "severity": "high"},
    {"pattern": r"Microsoft.*ODBC.*SQL Server", "description": "MSSQL error", "severity": "high"},
    {"pattern": r"Unclosed quotation mark", "description": "SQL syntax error", "severity": "high"},
    {"pattern": r"sqlite3\.OperationalError", "description": "SQLite error", "severity": "high"},
    {"pattern": r"SQLITE_ERROR", "description": "SQLite error", "severity": "high"},
    
    # Framework errors
    {"pattern": r"RuntimeException", "description": "Java runtime exception", "severity": "medium"},
    {"pattern": r"NullPointerException", "description": "Java NPE", "severity": "medium"},
    {"pattern": r"ClassNotFoundException", "description": "Java class not found", "severity": "medium"},
    {"pattern": r"Django.*Exception", "description": "Django error", "severity": "medium"},
    {"pattern": r"Flask.*Error", "description": "Flask error", "severity": "medium"},
    {"pattern": r"Laravel.*Exception", "description": "Laravel error", "severity": "medium"},
    {"pattern": r"Express.*Error", "description": "Express error", "severity": "medium"},
    
    # Path disclosure
    {"pattern": r"/home/[\w/]+", "description": "Unix home path", "severity": "low"},
    {"pattern": r"/var/www/[\w/]+", "description": "Web root path", "severity": "low"},
    {"pattern": r"/usr/[\w/]+", "description": "Unix system path", "severity": "low"},
    {"pattern": r"C:\\[\w\\]+", "description": "Windows path", "severity": "low"},
    {"pattern": r"D:\\[\w\\]+", "description": "Windows drive path", "severity": "low"},
    
    # Internal IPs
    {"pattern": r"192\.168\.\d{1,3}\.\d{1,3}", "description": "Internal IP (192.168.x.x)", "severity": "low"},
    {"pattern": r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "description": "Internal IP (10.x.x.x)", "severity": "low"},
    {"pattern": r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "description": "Internal IP (172.16-31.x.x)", "severity": "low"},
]

# ============================================================================
# Cookie Security Checks
# ============================================================================

COOKIE_FLAGS: List[Dict] = [
    {"flag": "Secure", "required": True, "description": "Cookie sent only over HTTPS", "severity": "high"},
    {"flag": "HttpOnly", "required": True, "description": "Cookie not accessible via JavaScript", "severity": "high"},
    {"flag": "SameSite", "required": True, "recommended": ["Strict", "Lax"], "description": "CSRF protection", "severity": "medium"},
    {"flag": "Path", "required": False, "description": "Cookie path restriction", "severity": "low"},
    {"flag": "Domain", "required": False, "description": "Cookie domain restriction", "severity": "low"},
]

SESSION_COOKIE_NAMES: List[str] = [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session", "sessionid",
    "sid", "connect.sid", "token", "auth_token", "access_token", "jwt",
    "laravel_session", "django_session", "_session_id", "rack.session",
]

# ============================================================================
# Summary Statistics
# ============================================================================

def get_misconfig_stats() -> Dict:
    """Get statistics about misconfiguration patterns"""
    return {
        "security_headers": len(SECURITY_HEADERS),
        "dangerous_headers": len(DANGEROUS_HEADERS),
        "cors_test_origins": len(CORS_TEST_ORIGINS),
        "debug_endpoints": len(DEBUG_ENDPOINTS),
        "admin_panels": len(ADMIN_PANELS),
        "source_exposure_paths": len(SOURCE_EXPOSURE_PATHS),
        "default_credentials": len(DEFAULT_CREDENTIALS),
        "error_patterns": len(ERROR_PATTERNS),
        "cookie_flags": len(COOKIE_FLAGS),
        "total_checks": (
            len(SECURITY_HEADERS) + 
            len(DANGEROUS_HEADERS) + 
            len(CORS_TEST_ORIGINS) + 
            len(DEBUG_ENDPOINTS) + 
            len(ADMIN_PANELS) + 
            len(SOURCE_EXPOSURE_PATHS) + 
            len(DEFAULT_CREDENTIALS) +
            len(ERROR_PATTERNS)
        )
    }


if __name__ == "__main__":
    stats = get_misconfig_stats()
    print("=" * 60)
    print("PHASE 3: Security Misconfiguration Patterns")
    print("=" * 60)
    print(f"Security Headers to check:     {stats['security_headers']}")
    print(f"Dangerous Headers to detect:   {stats['dangerous_headers']}")
    print(f"CORS Test Origins:             {stats['cors_test_origins']}")
    print(f"Debug Endpoints:               {stats['debug_endpoints']}")
    print(f"Admin Panel Paths:             {stats['admin_panels']}")
    print(f"Source Exposure Paths:         {stats['source_exposure_paths']}")
    print(f"Default Credentials:           {stats['default_credentials']}")
    print(f"Error Disclosure Patterns:     {stats['error_patterns']}")
    print("-" * 60)
    print(f"TOTAL CHECKS:                  {stats['total_checks']}")
    print("=" * 60)
