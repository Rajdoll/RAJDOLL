"""
Authenticated Session Manager for Multi-Agent Security Testing

Handles:
- Auto-login to web applications (Juice Shop, DVWA, etc.)
- Session cookie persistence across agents
- Multi-user credential testing
- Token refresh and session validation
"""

import httpx
import asyncio
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse


class SessionManager:
    """Manages authenticated sessions for penetration testing"""
    
    # Common default credentials to test (order matters - try most likely first)
    DEFAULT_CREDENTIALS = [
        # Juice Shop defaults (common in CTF/training apps)
        {"username": "admin@juice-sh.op", "password": "admin123"},
        {"username": "jim@juice-sh.op", "password": "ncc-1701"},
        {"username": "bender@juice-sh.op", "password": "OhG0dPlease1nsertLiquor!"},
        {"username": "test@test.com", "password": "test"},
        {"username": "demo@demo.com", "password": "demo"},
        # DVWA specific
        {"username": "admin", "password": "password"},
        {"username": "gordonb", "password": "abc123"},
        {"username": "1337", "password": "charley"},
        {"username": "pablo", "password": "letmein"},
        {"username": "smithy", "password": "password"},
        # Generic defaults
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "admin123"},
        {"username": "test", "password": "test"},
        {"username": "user", "password": "user"},
        {"username": "demo", "password": "demo"},
    ]
    
    # Juice Shop specific endpoints
    JUICE_SHOP_PATTERNS = {
        "login_endpoint": "/rest/user/login",
        "register_endpoint": "/api/Users/",
        "feedback_endpoint": "/api/Feedbacks/",
        "product_review": "/rest/products/{id}/reviews",
        "admin_endpoints": ["/administration", "/rest/admin/application-configuration"],
    }
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.sessions: Dict[str, Dict[str, Any]] = {}  # username -> session data
        self.cookies: Dict[str, str] = {}  # Cookie jar
        self.tokens: Dict[str, str] = {}  # CSRF/JWT tokens
        self.logged_in = False
        
    async def detect_application_type(self) -> str:
        """Detect if target is Juice Shop, DVWA, or generic"""
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                resp = await client.get(self.target_url)
                html = resp.text.lower()
                
                # Check Juice Shop signatures
                if "juice shop" in html or "juice-shop" in html or "/rest/user/login" in html:
                    return "juice-shop"
                
                # Check DVWA signatures
                if "dvwa" in html or "damn vulnerable web application" in html:
                    return "dvwa"
                
                # Check common frameworks
                if "wordpress" in html:
                    return "wordpress"
                if "drupal" in html:
                    return "drupal"
                
                return "generic"
        except Exception:
            return "generic"
    
    async def discover_login_forms(self) -> List[Dict[str, Any]]:
        """Discover login forms and API endpoints"""
        login_forms = []
        
        # PRIORITY: Check for known applications first
        app_type = await self.detect_application_type()
        
        # Juice Shop: Use JSON API directly (SPA doesn't have HTML form)
        if app_type == "juice-shop":
            login_forms.append({
                "url": urljoin(self.target_url, "/rest/user/login"),
                "type": "json_api",
                "fields": {"email": "", "password": ""},
                "method": "POST"
            })
            self.log_message = f"Detected Juice Shop - using API login"
            return login_forms
        
        # DVWA: Known login form
        if app_type == "dvwa":
            login_forms.append({
                "url": urljoin(self.target_url, "/login.php"),
                "type": "html_form",
                "action": urljoin(self.target_url, "/login.php"),
                "fields": {
                    "username_field": "username",
                    "password_field": "password"
                },
                "method": "POST"
            })
            return login_forms
        
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                # Try common login paths for generic apps
                login_paths = [
                    "/", "/login", "/login.php", "/signin", "/auth",
                    "/user/login", "/admin/login", "/wp-login.php",
                    "/rest/user/login", "/api/login", "/api/auth/login"
                ]
                
                for path in login_paths:
                    try:
                        url = urljoin(self.target_url, path)
                        resp = await client.get(url)
                        
                        # Check if it's a login endpoint
                        if resp.status_code == 200:
                            html = resp.text.lower()
                            
                            # HTML form detection
                            if ('<form' in html and 
                                ('password' in html or 'passwd' in html) and
                                ('username' in html or 'email' in html or 'user' in html)):
                                
                                # Extract form details
                                form_action = self._extract_form_action(resp.text, url)
                                form_fields = self._extract_form_fields(resp.text)
                                
                                login_forms.append({
                                    "url": url,
                                    "type": "html_form",
                                    "action": form_action,
                                    "fields": form_fields,
                                    "method": "POST"
                                })
                            
                            # JSON API detection (Juice Shop style)
                            elif 'application/json' in resp.headers.get('content-type', ''):
                                login_forms.append({
                                    "url": url,
                                    "type": "json_api",
                                    "fields": {"email": "", "password": ""},
                                    "method": "POST"
                                })
                    except Exception:
                        continue
        
        except Exception:
            pass
        
        return login_forms
    
    def _extract_form_action(self, html: str, base_url: str) -> str:
        """Extract form action URL"""
        match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
        if match:
            action = match.group(1)
            return urljoin(base_url, action)
        return base_url
    
    def _extract_form_fields(self, html: str) -> Dict[str, str]:
        """Extract form input fields"""
        fields = {}
        
        # Find username/email field
        username_match = re.search(
            r'<input[^>]*name=["\']([^"\']*(?:user|email|login)[^"\']*)["\']',
            html, re.I
        )
        if username_match:
            fields['username_field'] = username_match.group(1)
        
        # Find password field
        password_match = re.search(
            r'<input[^>]*name=["\']([^"\']*pass(?:word|wd)?[^"\']*)["\']',
            html, re.I
        )
        if password_match:
            fields['password_field'] = password_match.group(1)
        
        # Find CSRF token
        csrf_match = re.search(
            r'<input[^>]*name=["\']([^"\']*(?:csrf|token|_token)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']',
            html, re.I
        )
        if csrf_match:
            fields['csrf_field'] = csrf_match.group(1)
            fields['csrf_token'] = csrf_match.group(2)
        
        return fields
    
    async def attempt_login(
        self, 
        login_form: Dict[str, Any], 
        credentials: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """Attempt login with given credentials"""
        try:
            async with httpx.AsyncClient(
                timeout=20, 
                follow_redirects=True, 
                verify=False
            ) as client:
                
                if login_form['type'] == 'json_api':
                    # JSON API login (Juice Shop)
                    headers = {'Content-Type': 'application/json'}
                    data = {
                        'email': credentials.get('username', credentials.get('email')),
                        'password': credentials['password']
                    }
                    
                    resp = await client.post(
                        login_form['url'],
                        json=data,
                        headers=headers
                    )
                    
                    # Check for successful login
                    if resp.status_code in [200, 201]:
                        try:
                            json_resp = resp.json()
                            
                            # Extract JWT token (Juice Shop)
                            token = json_resp.get('authentication', {}).get('token')
                            if token:
                                return {
                                    "success": True,
                                    "username": credentials.get('username'),
                                    "cookies": dict(resp.cookies),
                                    "token": token,
                                    "headers": {"Authorization": f"Bearer {token}"},
                                    "type": "jwt"
                                }
                        except Exception:
                            pass
                    
                    # Check cookies even if no JSON response
                    if resp.cookies:
                        return {
                            "success": True,
                            "username": credentials.get('username'),
                            "cookies": dict(resp.cookies),
                            "type": "cookie"
                        }
                
                elif login_form['type'] == 'html_form':
                    # HTML form login (DVWA, generic)
                    fields = login_form.get('fields', {})
                    
                    form_data = {
                        fields.get('username_field', 'username'): credentials.get('username'),
                        fields.get('password_field', 'password'): credentials.get('password'),
                    }
                    
                    # Add CSRF token if present
                    if 'csrf_token' in fields:
                        form_data[fields['csrf_field']] = fields['csrf_token']
                    
                    # Add common submit fields
                    form_data['Login'] = 'Login'
                    form_data['submit'] = 'submit'
                    
                    resp = await client.post(
                        login_form['action'],
                        data=form_data,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'}
                    )
                    
                    # Check for successful login indicators
                    success_indicators = [
                        'logout', 'dashboard', 'welcome', 'profile',
                        'successfully logged in', 'authentication successful'
                    ]
                    
                    html_lower = resp.text.lower()
                    if any(indicator in html_lower for indicator in success_indicators):
                        return {
                            "success": True,
                            "username": credentials.get('username'),
                            "cookies": dict(resp.cookies),
                            "type": "cookie"
                        }
        
        except Exception as e:
            pass
        
        return None
    
    async def auto_login(self) -> Dict[str, Any]:
        """
        Automatically discover login and attempt authentication
        
        Returns:
            Dict with login results including sessions for all successful logins
        """
        results = {
            "app_type": "unknown",
            "login_forms": [],
            "successful_logins": [],
            "failed_attempts": 0,
        }
        
        # Detect application type
        results['app_type'] = await self.detect_application_type()
        
        # Discover login forms
        login_forms = await self.discover_login_forms()
        results['login_forms'] = login_forms
        
        if not login_forms:
            return results
        
        # Try credentials on each login form
        for login_form in login_forms[:2]:  # Try first 2 forms
            for creds in self.DEFAULT_CREDENTIALS:
                session = await self.attempt_login(login_form, creds)
                
                if session and session.get('success'):
                    # Store session
                    username = creds.get('username')
                    self.sessions[username] = session
                    self.logged_in = True
                    
                    # Store cookies globally
                    self.cookies.update(session.get('cookies', {}))
                    
                    # Store token if JWT
                    if session.get('token'):
                        self.tokens[username] = session['token']
                    
                    results['successful_logins'].append({
                        "username": username,
                        "password": creds['password'],
                        "login_url": login_form['url'],
                        "session_type": session['type']
                    })
                    
                    # Don't test all credentials if we got admin
                    if username in ['admin', 'admin@juice-sh.op']:
                        break
                else:
                    results['failed_attempts'] += 1
                
                # Rate limiting
                await asyncio.sleep(0.5)
        
        return results
    
    def get_authenticated_client(self, username: Optional[str] = None) -> httpx.AsyncClient:
        """
        Get httpx client with authenticated session
        
        Args:
            username: Specific user session, or None for first available
        """
        if username and username in self.sessions:
            session = self.sessions[username]
        elif self.sessions:
            # Get first available session
            session = list(self.sessions.values())[0]
        else:
            # No authentication available
            return httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False)
        
        # Build client with auth
        headers = session.get('headers', {})
        cookies = session.get('cookies', {})
        
        return httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            verify=False,
            headers=headers,
            cookies=cookies
        )
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get session information for agents"""
        return {
            "logged_in": self.logged_in,
            "sessions": {
                username: {
                    "type": session.get('type'),
                    "has_token": bool(session.get('token')),
                    "cookies": list(session.get('cookies', {}).keys())
                }
                for username, session in self.sessions.items()
            },
            "available_users": list(self.sessions.keys())
        }
