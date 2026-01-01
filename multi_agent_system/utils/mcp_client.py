from __future__ import annotations

import asyncio
import inspect
import importlib.util
import os
import json
from itertools import count
from functools import lru_cache
from typing import Any, Dict

import httpx

from .agent_runtime import CURRENT_AGENT

# 🆕 Rate limiting integration
from ..core.security_guards import rate_limiter, RateLimitExceededError


class MCPClient:
    """
    Minimal MCP client abstraction.
    NOTE: To keep momentum, we implement a direct-import fallback for the
    'information-gathering' server by loading its module and calling tool
    functions directly. This preserves your existing tool logic now, and can be
    replaced by a true JSON-RPC MCP runner later without changing agents.
    """

    def __init__(self, workspace_root: str | None = None) -> None:
        # Prefer explicit env override, else pick /app (Docker) or D:\MCP\RAJDOLL (Windows) if exists, else CWD
        env_root = os.getenv("WORKSPACE_ROOT")
        if workspace_root:
            self.workspace_root = workspace_root
        elif env_root:
            self.workspace_root = env_root
        elif os.path.exists("/app"):
            self.workspace_root = "/app"
        elif os.path.exists(r"d:\\MCP\\RAJDOLL"):
            self.workspace_root = r"d:\\MCP\\RAJDOLL"
        else:
            self.workspace_root = os.getcwd()

    @lru_cache(maxsize=4)
    def _load_module(self, file_path: str):
        spec = importlib.util.spec_from_file_location("_mcp_module", file_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load module from {file_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
        return module

    async def call_tool(
        self, 
        server: str, 
        tool: str, 
        args: Dict[str, Any], 
        timeout: int = 300,
        auth_session: Dict[str, Any] | None = None
    ) -> Dict[str, Any] | str:
        """
        If MCP_SERVER_URLS is provided in env (JSON map of server=>url), use JSON-RPC to call the tool on that server.
        Otherwise, fallback to direct-import of local modules to preserve current logic.
        
        Args:
            server: MCP server name (e.g., "input-validation-testing")
            tool: Tool name to call
            args: Tool arguments
            timeout: Request timeout in seconds
            auth_session: Optional authenticated session data:
                - cookies: Dict of cookie name->value
                - headers: Dict of additional headers (e.g., Authorization: Bearer token)
                - token: JWT token if available
        """
        # 0) Give the active agent (if any) a chance to request HITL approval or
        # modify the arguments before the tool is executed.
        agent = CURRENT_AGENT.get()
        if agent is not None and hasattr(agent, "_before_tool_execution"):
            decision = await agent._before_tool_execution(server, tool, args)
            if not decision.get("approved", True):
                return {"status": "skipped", "message": "Tool execution rejected by user"}
            args = decision.get("arguments") or args
        
        # 🚦 RATE LIMITING: Wait if needed to avoid overwhelming target
        target_url = args.get('domain') or args.get('url') or args.get('target')
        if target_url:
            try:
                await rate_limiter.wait_if_needed(target_url)
            except RateLimitExceededError as e:
                return {"status": "rate_limited", "message": str(e)}

        # 1) Try JSON-RPC over HTTP when configured
        try:
            mapping_raw = os.getenv("MCP_SERVER_URLS", "{}")
            server_urls: Dict[str, str] = json.loads(mapping_raw) if mapping_raw else {}
        except Exception:
            server_urls = {}

        if server in server_urls:
            url = server_urls[server]
            
            # Inject authenticated session into tool arguments if provided
            if auth_session:
                # Pass auth data as special arguments that MCP tools can use
                args = args.copy()  # Don't mutate original
                if 'cookies' in auth_session:
                    args['_auth_cookies'] = auth_session['cookies']
                if 'headers' in auth_session:
                    args['_auth_headers'] = auth_session['headers']
                if 'token' in auth_session:
                    args['_auth_token'] = auth_session['token']
            
            # JSON-RPC 2.0 payload for tools/call
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": args,
                },
            }
            async with httpx.AsyncClient(timeout=timeout) as client:
                try:
                    resp = await client.post(url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    # Expecting { jsonrpc, id, result } or error
                    if "error" in data:
                        raise RuntimeError(f"MCP server error: {data['error']}")
                    return data.get("result", data)
                except httpx.HTTPStatusError as e:
                    # 🚦 Handle rate limiting responses (429, 503)
                    if e.response.status_code in [429, 503] and target_url:
                        retry_after = e.response.headers.get('Retry-After')
                        await rate_limiter.handle_http_error(
                            e.response.status_code,
                            target_url,
                            retry_after=int(retry_after) if retry_after else None
                        )
                        return {"status": "rate_limited", "message": f"HTTP {e.response.status_code}: Rate limited, backing off"}
                    raise

        # 2) Direct-import fallback map (for dev or when MCP servers aren't provided)
        server_module_map = {
            # Information gathering
            "information-gathering": os.path.join(self.workspace_root, "information-gathering", "information_gathering.py"),
            # Authentication
            "authentication-testing": os.path.join(self.workspace_root, "authentication-testing", "authentication.py"),
            # Authorization
            "authorization-testing": os.path.join(self.workspace_root, "authorization-testing", "authorization.py"),
            # Session Management
            "session-management-testing": os.path.join(self.workspace_root, "session-managemenet-testing", "session-management.py"),
            # Input Validation
            "input-validation-testing": os.path.join(self.workspace_root, "input-validation-testing", "input-validation.py"),
            # Error Handling
            "error-handling-testing": os.path.join(self.workspace_root, "error-handling-testing", "error-handling.py"),
            # Weak Cryptography
            "weak-cryptography-testing": os.path.join(self.workspace_root, "testing-for-weak-cryptography", "weak-cryptography.py"),
            # Client-side
            "client-side-testing": os.path.join(self.workspace_root, "client-side-testing", "client-side.py"),
            # Business Logic
            "business-logic-testing": os.path.join(self.workspace_root, "business-logic-testing", "business-logic.py"),
            # Config & Deployment
            "configuration-and-deployment-management": os.path.join(self.workspace_root, "configuration-and-deployment-testing", "configuration-and-deployment.py"),
            # Identity Management
            "identity-management-testing": os.path.join(self.workspace_root, "identity-management-testing", "identity-management.py"),
            # File Upload
            "file-upload-testing": os.path.join(self.workspace_root, "file-upload-testing", "file_upload.py"),
            # API Testing
            "api-testing": os.path.join(self.workspace_root, "api-testing", "api_testing.py"),
        }

        module_path = server_module_map.get(server)
        if not module_path or not os.path.exists(module_path):
            raise NotImplementedError(f"MCP server '{server}' not yet wired or module not found at {module_path}.")

        mod = self._load_module(module_path)
        fn = getattr(mod, tool, None)
        if not callable(fn):
            raise RuntimeError(f"Tool '{tool}' not found in server '{server}' module")

        async def _runner():
            if inspect.iscoroutinefunction(fn):
                return await fn(**args)
            return await asyncio.to_thread(fn, **args)

        return await asyncio.wait_for(_runner(), timeout=timeout)


async def bounded_gather(*aws, limit: int = 5):
    sem = asyncio.Semaphore(limit)

    async def _wrap(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*(_wrap(c) for c in aws), return_exceptions=True)
