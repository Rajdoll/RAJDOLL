"""
Session Service - Handles authenticated sessions for multi-agent security testing

This module provides functionality to:
1. Login to target application (supporting multiple auth mechanisms)
2. Extract and manage session tokens (JWT, cookies)
3. Provide auth headers for other agents to use
"""
from __future__ import annotations

import asyncio
import httpx
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class SessionService:
    """
    Manages authenticated sessions for security testing.
    
    Supports:
    - JWT-based authentication (Juice Shop, modern APIs)
    - Cookie-based sessions (traditional web apps)
    - Basic authentication
    - API key authentication
    """
    
    # Common login endpoints to try
    LOGIN_ENDPOINTS = [
        # Juice Shop specific
        {"path": "/rest/user/login", "method": "POST", "content_type": "json", 
         "payload_template": {"email": "{username}", "password": "{password}"}},
        # Generic REST APIs
        {"path": "/api/login", "method": "POST", "content_type": "json",
         "payload_template": {"username": "{username}", "password": "{password}"}},
        {"path": "/api/auth/login", "method": "POST", "content_type": "json",
         "payload_template": {"username": "{username}", "password": "{password}"}},
        {"path": "/auth/login", "method": "POST", "content_type": "json",
         "payload_template": {"email": "{username}", "password": "{password}"}},
        # Traditional form-based
        {"path": "/login", "method": "POST", "content_type": "form",
         "payload_template": {"username": "{username}", "password": "{password}"}},
        {"path": "/login", "method": "POST", "content_type": "form",
         "payload_template": {"email": "{username}", "password": "{password}"}},
        # DVWA-style PHP login (with CSRF token auto-extraction)
        {"path": "/login.php", "method": "POST", "content_type": "form",
         "payload_template": {"username": "{username}", "password": "{password}", "Login": "Login"}},
        # bWAPP-style login
        {"path": "/login.php", "method": "POST", "content_type": "form",
         "payload_template": {"login": "{username}", "password": "{password}", "security_level": "0", "form": "submit"}},
    ]
    
    # Common default credentials to try
    DEFAULT_CREDENTIALS = [
        # Generic common defaults only — app-specific credentials go in POST /api/scans
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("admin", "123456"),
        ("test", "test"),
        ("user", "user"),
        ("demo", "demo"),
    ]
    
    def __init__(self, target_url: str):
        """Initialize session service with target URL."""
        self.target_url = target_url.rstrip("/")
        self.base_url = self._extract_base_url(target_url)
        self.session_data: Dict[str, Any] = {
            "logged_in": False,
            "jwt_token": None,
            "cookies": {},
            "headers": {},
            "username": None,
            "auth_method": None,
        }
        
    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def attempt_login(
        self, 
        username: str, 
        password: str,
        login_endpoint: Optional[str] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Attempt to login with given credentials.
        
        Returns:
            Tuple of (success: bool, session_data: dict)
        """
        endpoints_to_try = []
        
        if login_endpoint:
            # Use specific endpoint if provided
            endpoints_to_try = [{"path": login_endpoint, "method": "POST", "content_type": "json",
                                "payload_template": {"email": "{username}", "password": "{password}"}}]
        else:
            endpoints_to_try = self.LOGIN_ENDPOINTS
        
        async with httpx.AsyncClient(
            timeout=15, 
            follow_redirects=True, 
            verify=False
        ) as client:
            # Prime the session (get any initial cookies)
            try:
                await client.get(self.base_url)
            except Exception:
                pass
            
            for endpoint in endpoints_to_try:
                url = urljoin(self.base_url, endpoint["path"])
                payload = self._build_payload(endpoint["payload_template"], username, password)

                try:
                    if endpoint["content_type"] == "form":
                        # Extract hidden CSRF tokens from login page before POSTing
                        try:
                            login_page = await client.get(url)
                            import re
                            hidden = re.findall(
                                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
                                login_page.text, re.IGNORECASE
                            )
                            hidden += re.findall(
                                r'<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']hidden["\'][^>]+value=["\']([^"\']*)["\']',
                                login_page.text, re.IGNORECASE
                            )
                            for name, value in hidden:
                                if name not in payload:
                                    payload[name] = value
                        except Exception:
                            pass

                    if endpoint["content_type"] == "json":
                        resp = await client.post(url, json=payload)
                    else:
                        resp = await client.post(url, data=payload)
                    
                    success, session = self._parse_login_response(resp, username, endpoint["path"])
                    
                    if success:
                        logger.info(f"[SessionService] Login successful via {endpoint['path']} as {username}")
                        self.session_data.update(session)
                        return True, session
                        
                except Exception as e:
                    logger.debug(f"[SessionService] Login attempt failed for {url}: {e}")
                    continue
        
        return False, {}
    
    def _build_payload(self, template: Dict[str, str], username: str, password: str) -> Dict[str, str]:
        """Build login payload from template."""
        return {
            k: v.format(username=username, password=password) 
            for k, v in template.items()
        }
    
    def _parse_login_response(
        self, 
        response: httpx.Response, 
        username: str,
        endpoint: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """Parse login response and extract session data."""
        
        # Check for successful status
        if response.status_code not in (200, 201, 302):
            return False, {}
        
        session_data = {
            "logged_in": False,
            "jwt_token": None,
            "cookies": {},
            "headers": {},
            "username": username,
            "auth_method": None,
            "login_endpoint": endpoint,
        }
        
        # Extract cookies
        for cookie_name, cookie_value in response.cookies.items():
            session_data["cookies"][cookie_name] = cookie_value
        
        # Try to extract JWT from JSON response
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                data = response.json()
                if isinstance(data, dict):
                    # Juice Shop format: {"authentication": {"token": "..."}}
                    if "authentication" in data and isinstance(data["authentication"], dict):
                        token = data["authentication"].get("token")
                        if token:
                            session_data["jwt_token"] = token
                            session_data["headers"]["Authorization"] = f"Bearer {token}"
                            session_data["logged_in"] = True
                            session_data["auth_method"] = "jwt"
                            logger.info(f"[SessionService] Extracted JWT token for {username}")
                            return True, session_data
                    
                    # Generic format: {"token": "..."} or {"access_token": "..."}
                    token = data.get("token") or data.get("access_token") or data.get("jwt")
                    if token:
                        session_data["jwt_token"] = token
                        session_data["headers"]["Authorization"] = f"Bearer {token}"
                        session_data["logged_in"] = True
                        session_data["auth_method"] = "jwt"
                        return True, session_data
                        
            except Exception as e:
                logger.debug(f"[SessionService] Failed to parse JSON response: {e}")
        
        # Check for session cookies indicating successful login
        session_cookies = ["session", "sessionid", "connect.sid", "PHPSESSID", "JSESSIONID"]
        for cookie_name in session_cookies:
            if cookie_name.lower() in [c.lower() for c in session_data["cookies"].keys()]:
                session_data["logged_in"] = True
                session_data["auth_method"] = "cookie"
                return True, session_data
        
        # Check Set-Cookie header for auth tokens
        set_cookie = response.headers.get("set-cookie", "")
        if "token" in set_cookie.lower() or "auth" in set_cookie.lower():
            session_data["logged_in"] = True
            session_data["auth_method"] = "cookie"
            return True, session_data
        
        return False, {}
    
    async def auto_login(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Automatically attempt to login using default credentials.
        
        Returns:
            Tuple of (success: bool, session_data: dict)
        """
        logger.info(f"[SessionService] Attempting auto-login to {self.base_url}")
        
        for username, password in self.DEFAULT_CREDENTIALS:
            success, session = await self.attempt_login(username, password)
            if success:
                logger.info(f"[SessionService] Auto-login successful with {username}")
                return True, session
        
        logger.warning("[SessionService] Auto-login failed with all default credentials")
        return False, {}
    
    def get_auth_session(self) -> Optional[Dict[str, Any]]:
        """
        Get authentication session data for use with MCP tools.
        
        Returns dict with:
            - cookies: Dict of cookie name->value
            - headers: Dict of headers (including Authorization)
            - token: JWT token if available
        """
        if not self.session_data.get("logged_in"):
            return None
        
        return {
            "cookies": self.session_data.get("cookies", {}),
            "headers": self.session_data.get("headers", {}),
            "token": self.session_data.get("jwt_token"),
            "username": self.session_data.get("username"),
            "auth_method": self.session_data.get("auth_method"),
        }
    
    def to_shared_context(self) -> Dict[str, Any]:
        """
        Convert session data to format suitable for shared_context storage.
        """
        return {
            "authenticated_session": {
                "logged_in": self.session_data.get("logged_in", False),
                "username": self.session_data.get("username"),
                "auth_method": self.session_data.get("auth_method"),
                "jwt_token": self.session_data.get("jwt_token"),
                "cookies": self.session_data.get("cookies", {}),
                "headers": self.session_data.get("headers", {}),
                "login_endpoint": self.session_data.get("login_endpoint"),
            }
        }


async def create_authenticated_session(
    target_url: str,
    credentials: Optional[List[Tuple[str, str]]] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Convenience function to create an authenticated session.
    
    Args:
        target_url: Target application URL
        credentials: Optional list of (username, password) tuples to try
        
    Returns:
        Tuple of (success: bool, session_data: dict)
    """
    service = SessionService(target_url)
    
    if credentials:
        for username, password in credentials:
            success, session = await service.attempt_login(username, password)
            if success:
                return True, service.to_shared_context()["authenticated_session"]
    
    # Fallback to auto-login
    success, session = await service.auto_login()
    if success:
        return True, service.to_shared_context()["authenticated_session"]
    
    return False, {}
