"""
Directory Bruteforcing Module for ReconnaissanceAgent
Discovers hidden directories and files using wordlist-based fuzzing
"""

import asyncio
import httpx
import logging
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class DirectoryScanner:
    """Advanced directory and file discovery using fuzzing techniques"""
    
    # Built-in mini wordlists for common paths (will be expanded with SecLists)
    QUICK_WORDLIST = [
        # Admin panels & dashboards
        "admin", "administrator", "administration", "panel", "dashboard", "manage", "management",
        "control-panel", "cpanel", "wp-admin", "phpmyadmin", "adminer", "admin-console",
        
        # API & Documentation
        "api", "api-docs", "swagger", "api/v1", "api/v2", "graphql", "docs", "documentation",
        "redoc", "openapi", "swagger-ui", "api-explorer",
        
        # Configuration & Metadata
        "config", "configuration", "settings", "env", "environment", ".env", ".env.local",
        "web.config", "app.config", ".git", ".svn", ".hg", "config.php", "config.yml",
        
        # Common monitoring, debugging & sensitive directories
        "ftp", "encryptionkeys", "support", "support/logs", "metrics", "prometheus",
        "actuator", "health", "info", "debug", "trace",
        
        # Backup & temporary files
        "backup", "backups", "bak", "old", "tmp", "temp", "cache", "_old", "_bak",
        "backup.zip", "backup.tar.gz", "db_backup.sql", "database.sql",
        
        # Upload directories
        "uploads", "files", "documents", "images", "assets", "static", "media",
        "attachments", "download", "public", "resources",
        
        # Development & testing
        "test", "tests", "testing", "dev", "development", "staging", "demo", "sandbox",
        "phpinfo", "info.php", "test.php", "debug.php", "shell.php",
        
        # Hidden endpoints
        "private", "internal", "secret", "hidden", "confidential", "restricted",
        
        # Common files
        "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
        "crossdomain.xml", "package.json", "composer.json", "package.json.bak",
        "package-lock.json", "yarn.lock", "Gemfile", "Gemfile.lock",
        
        # JavaScript & frontend
        "main.js", "bundle.js", "app.js", "vendor.js", "runtime.js", "polyfills.js",
        "scripts", "js", "javascript", "node_modules",
        
        # Database & data
        "db", "database", "data", "sql", "mysql", "postgres", "mongodb", "redis",
        "phpmyadmin", "adminer", "db-admin",
        
        # Security specific
        "security", "auth", "login", "logout", "signin", "signup", "register",
        "forgot-password", "reset-password", "2fa", "mfa", "oauth", "saml",
        
        # Logs & monitoring
        "logs", "log", "logging", "access.log", "error.log", "debug.log",
        "application.log", "server.log", "audit.log",
        
        # Archives & exports
        "export", "exports", "archive", "archives", "dump", "dumps", "snapshot",
        
        # E-commerce & shopping (generic patterns)
        "products", "product", "items", "item", "catalog", "catalogue", "shop", "store",
        "cart", "checkout", "basket", "orders", "order", "order-history", "track-order",
        "reviews", "review", "search", "browse", "categories", "category",
        "wishlist", "favorites", "compare", "deals", "sales", "promotions",

        # User & profile (generic)
        "profile", "account", "dashboard", "settings", "preferences", "user", "users",
        "address", "addresses", "payment", "payments", "saved-payment-methods", "wallet",
        "contact", "about", "feedback", "support", "help",

        # Additional common paths
        "score-board", "administration", "chatbot", "metrics", "health", "status",
        
        # B2B & Enterprise
        "b2b", "enterprise", "corporate", "partner", "partners", "reseller",
        "wholesale", "bulk", "invoice", "invoices", "order-history",
    ]
    
    SENSITIVE_EXTENSIONS = [
        ".bak", ".backup", ".old", ".tmp", ".swp", ".swo", ".save", "~",
        ".conf", ".config", ".cfg", ".ini", ".xml", ".yml", ".yaml", ".json",
        ".sql", ".db", ".sqlite", ".mdb", ".log", ".txt", ".md", ".key",
        ".pem", ".cer", ".crt", ".p12", ".pfx", ".zip", ".tar", ".gz", ".7z",
        ".rar", ".war", ".jar", ".ear", ".tar.gz", ".tgz"
    ]
    
    def __init__(self, timeout: int = 5, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.found_paths: Set[str] = set()
        
    async def scan_directories(
        self, 
        target_url: str, 
        wordlist: Optional[List[str]] = None,
        depth: int = 1,
        check_extensions: bool = True
    ) -> Dict[str, any]:
        """
        Scan for hidden directories and files
        
        Args:
            target_url: Base URL to scan (e.g., http://juice-shop:3000)
            wordlist: Custom wordlist, defaults to QUICK_WORDLIST
            depth: Recursion depth for found directories
            check_extensions: Test sensitive extensions on found files
            
        Returns:
            Dictionary with discovered paths, status codes, and directory listings
        """
        logger.info(f"🔍 Starting directory scan on {target_url}")
        
        wordlist = wordlist or self.QUICK_WORDLIST
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        findings = {
            'accessible_paths': [],
            'directory_listings': [],
            'sensitive_files': [],
            'potential_apis': [],
            'backup_files': [],
            'config_files': [],
            'total_checked': 0,
            'total_found': 0
        }
        
        # Create request semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async with httpx.AsyncClient(
            timeout=self.timeout, 
            follow_redirects=True,
            verify=False
        ) as client:
            # Test all wordlist entries
            tasks = []
            for path in wordlist:
                task = self._check_path(client, base_url, path, semaphore)
                tasks.append(task)
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            findings['total_checked'] = len(results)
            
            # Process results
            for result in results:
                if isinstance(result, dict) and result.get('accessible'):
                    self.found_paths.add(result['path'])
                    findings['total_found'] += 1
                    
                    entry = {
                        'path': result['path'],
                        'status_code': result['status_code'],
                        'content_type': result.get('content_type', ''),
                        'size': result.get('size', 0),
                        'has_directory_listing': result.get('has_listing', False)
                    }
                    
                    findings['accessible_paths'].append(entry)
                    
                    # Categorize findings
                    if result.get('has_listing'):
                        findings['directory_listings'].append(entry)
                    
                    if self._is_api_path(result['path']):
                        findings['potential_apis'].append(entry)
                    
                    if self._is_sensitive_file(result['path']):
                        findings['sensitive_files'].append(entry)
                    
                    if self._is_backup_file(result['path']):
                        findings['backup_files'].append(entry)
                        
                    if self._is_config_file(result['path']):
                        findings['config_files'].append(entry)
            
            # Test sensitive extensions on found files
            if check_extensions and findings['accessible_paths']:
                extension_findings = await self._test_extensions(
                    client, base_url, findings['accessible_paths'], semaphore
                )
                findings['backup_files'].extend(extension_findings)
                findings['total_found'] += len(extension_findings)
        
        logger.info(f"✅ Directory scan complete: {findings['total_found']}/{findings['total_checked']} paths found")
        
        return findings
    
    async def _check_path(
        self, 
        client: httpx.AsyncClient, 
        base_url: str, 
        path: str, 
        semaphore: asyncio.Semaphore
    ) -> Dict[str, any]:
        """Check if a single path is accessible"""
        async with semaphore:
            try:
                # Ensure path starts with /
                if not path.startswith('/'):
                    path = '/' + path
                    
                url = urljoin(base_url, path)
                
                response = await client.get(url)
                
                # Consider 200, 301, 302, 403 as "found" (403 = exists but forbidden)
                if response.status_code in [200, 301, 302, 403]:
                    # CRITICAL: Detect SPA false positives (Angular/React/Vue apps)
                    # Check if response is the default SPA index.html
                    content = response.text
                    is_spa_fallback = (
                        response.status_code == 200 and
                        '<app-root>' in content or  # Angular
                        '<div id="root">' in content or  # React
                        '<div id="app">' in content or  # Vue
                        'ng-version=' in content or  # Angular indicator
                        len(response.content) > 50000  # Large HTML typically = SPA app
                    )
                    
                    # Skip if it's the SPA fallback page
                    if is_spa_fallback:
                        return {'accessible': False, 'reason': 'spa_fallback'}
                    
                    result = {
                        'accessible': True,
                        'path': path,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'size': len(response.content)
                    }
                    
                    # Check for directory listing
                    if response.status_code == 200:
                        result['has_listing'] = self._detect_directory_listing(response.text)
                    
                    return result
                    
            except Exception as e:
                pass  # Path not accessible or timeout
                
        return {'accessible': False}
    
    async def _test_extensions(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        found_files: List[Dict],
        semaphore: asyncio.Semaphore
    ) -> List[Dict]:
        """Test sensitive extensions on found files"""
        findings = []
        tasks = []
        
        for file_entry in found_files:
            path = file_entry['path']
            # Skip if already has a backup extension
            if any(path.endswith(ext) for ext in self.SENSITIVE_EXTENSIONS):
                continue
                
            # Test common backup patterns
            for ext in ['.bak', '.old', '.backup', '~', '.swp']:
                task = self._check_path(client, base_url, path + ext, semaphore)
                tasks.append(task)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            findings = [r for r in results if isinstance(r, dict) and r.get('accessible')]
        
        return findings
    
    def _detect_directory_listing(self, html_content: str) -> bool:
        """Detect if response contains directory listing"""
        indicators = [
            'Index of /',
            'Directory listing for',
            'Parent Directory',
            '<title>Directory listing',
            'Directory Contents',
            '[To Parent Directory]'
        ]
        return any(indicator.lower() in html_content.lower() for indicator in indicators)
    
    def _is_api_path(self, path: str) -> bool:
        """Check if path is likely an API endpoint"""
        api_indicators = ['api', 'rest', 'graphql', 'swagger', 'openapi', 'v1', 'v2', 'v3']
        return any(indicator in path.lower() for indicator in api_indicators)
    
    def _is_sensitive_file(self, path: str) -> bool:
        """Check if file is potentially sensitive"""
        sensitive = ['.env', 'config', 'password', 'secret', 'key', 'token', 
                    'credential', 'private', '.pem', '.key', 'jwt']
        return any(s in path.lower() for s in sensitive)
    
    def _is_backup_file(self, path: str) -> bool:
        """Check if file is a backup"""
        return any(path.endswith(ext) for ext in self.SENSITIVE_EXTENSIONS)
    
    def _is_config_file(self, path: str) -> bool:
        """Check if file is a configuration file"""
        config_patterns = ['config', '.env', 'settings', 'web.config', '.ini', '.yml', '.yaml']
        return any(pattern in path.lower() for pattern in config_patterns)
