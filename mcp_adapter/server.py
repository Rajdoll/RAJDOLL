from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import os
import shlex
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(title="MCP JSON-RPC Adapter", version="0.1.0")


def _load_module(module_path: str):
    if not os.path.exists(module_path):
        raise FileNotFoundError(f"Module file not found: {module_path}")
    spec = importlib.util.spec_from_file_location("_mcp_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class ToolsCallParams(BaseModel):
    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class JsonRpcRequest(BaseModel):
    jsonrpc: str
    id: Optional[int | str]
    method: str
    params: Optional[Dict[str, Any]] = None


def _monkeypatch_module(mod: Any, module_path: str) -> None:
    """
    Make common runtime adjustments so host-developed MCP scripts run inside Docker:
    - Replace execute_wsl_command with a local shell executor (no WSL in Linux containers)
    - Rewrite Windows-specific BASE_OUTPUT_DIR to a container path and recompute derived dirs
    """
    # 1) Replace execute_wsl_command if present
    if hasattr(mod, "execute_wsl_command"):
        async def execute_local_command(command: str, timeout: int = 60, capture_stderr: bool = True) -> Dict[str, Any]:
            try:
                # Run using bash -lc to support pipes and env, without WSL
                proc = await asyncio.create_subprocess_exec(
                    "bash", "-lc", command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    proc.terminate()
                    await proc.wait()
                    return {
                        "success": False,
                        "stdout": "",
                        "stderr": "",
                        "error": f"Command timed out after {timeout}s",
                        "return_code": -1,
                    }

                stdout_str = stdout.decode("utf-8", errors="ignore").strip() if stdout else ""
                stderr_str = stderr.decode("utf-8", errors="ignore").strip() if stderr else ""
                return {
                    "success": proc.returncode == 0,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "error": stderr_str if proc.returncode != 0 else None,
                    "return_code": proc.returncode,
                }
            except Exception as e:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "",
                    "error": f"Command execution error: {str(e)}",
                    "return_code": -1,
                }

        setattr(mod, "execute_wsl_command", execute_local_command)

    # 2) Rewrite Windows paths if detected
    try:
        base_dir = getattr(mod, "BASE_OUTPUT_DIR", None)
        if isinstance(base_dir, str) and base_dir.lower().startswith("/mnt/"):
            new_base = os.path.join(os.path.dirname(module_path), "output")
            os.makedirs(new_base, exist_ok=True)
            setattr(mod, "BASE_OUTPUT_DIR", new_base)
            # Recompute common derived dirs when present
            if hasattr(mod, "SUBRESULT_DIR"):
                setattr(mod, "SUBRESULT_DIR", os.path.join(new_base, "subresult"))
                os.makedirs(getattr(mod, "SUBRESULT_DIR"), exist_ok=True)
            if hasattr(mod, "LOGS_DIR"):
                setattr(mod, "LOGS_DIR", os.path.join(new_base, "logs"))
                os.makedirs(getattr(mod, "LOGS_DIR"), exist_ok=True)
    except Exception:
        # Non-fatal; best-effort adjustments only
        pass

def _resolve_url_aliases(fn: Any, args: Dict[str, Any]) -> Dict[str, Any]:
    """Map URL-like parameters to match what the tool function expects.

    Handles common mismatches between LLM-generated arg names and tool signatures:
    - LLM generates 'url' but tool expects 'domain', 'host', 'base_url', or 'target_url'
    - LLM generates 'domain' but tool expects 'url'
    """
    try:
        sig = inspect.signature(fn)
    except Exception:
        return args

    expected = set(sig.parameters.keys())
    args = dict(args)  # copy so we don't mutate caller's dict

    # Collect available URL-like values
    url_val = args.get("url") or args.get("target_url") or args.get("base_url")
    domain_val = args.get("domain") or args.get("host")

    # url -> domain: pass the FULL url so the tool can parse protocol/port
    if "domain" in expected and "domain" not in args and url_val:
        args["domain"] = url_val

    # url -> host: extract hostname (for tools like TLS that need bare host)
    if "host" in expected and "host" not in args and url_val:
        parsed = urlparse(url_val if "://" in str(url_val) else f"https://{url_val}")
        args["host"] = parsed.hostname or str(url_val)
        # Also map port if tool accepts it and URL has a non-default port
        if "port" in expected and "port" not in args and parsed.port:
            args["port"] = parsed.port

    # url -> base_url
    if "base_url" in expected and "base_url" not in args and url_val:
        args["base_url"] = url_val

    # url -> target_url
    if "target_url" in expected and "target_url" not in args and args.get("url"):
        args["target_url"] = args["url"]

    # domain -> url: construct URL from domain
    if "url" in expected and "url" not in args and domain_val:
        args["url"] = f"https://{domain_val}" if "://" not in str(domain_val) else str(domain_val)

    return args


def _filter_args_for_callable(fn: Any, args: Dict[str, Any]) -> Dict[str, Any]:
    """Filter args to only those accepted by fn unless it accepts **kwargs."""
    try:
        sig = inspect.signature(fn)
    except Exception:
        # Best-effort: if signature can't be determined, pass through.
        return args

    params = sig.parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return args
    return {k: v for k, v in args.items() if k in params}


@app.post("/jsonrpc")
async def jsonrpc_endpoint(req: JsonRpcRequest):
    if req.jsonrpc != "2.0":
        raise HTTPException(status_code=400, detail="Only JSON-RPC 2.0 is supported")

    try:
        if req.method != "tools/call":
            return {"jsonrpc": "2.0", "id": req.id, "error": {"code": -32601, "message": "Method not found"}}

        if not isinstance(req.params, dict):
            return {"jsonrpc": "2.0", "id": req.id, "error": {"code": -32602, "message": "Invalid params"}}

        params = ToolsCallParams(**req.params)
        module_path = os.getenv("MODULE_PATH")
        if not module_path:
            return {"jsonrpc": "2.0", "id": req.id, "error": {"code": -32000, "message": "MODULE_PATH not configured"}}

        mod = _load_module(module_path)
        # Adjust environment for containerized execution
        _monkeypatch_module(mod, module_path)
        fn = getattr(mod, params.name, None)
        if not callable(fn):
            return {"jsonrpc": "2.0", "id": req.id, "error": {"code": -32601, "message": f"Tool not found: {params.name}"}}

        # 🔑 EXTRACT AUTH PARAMETERS: Get auth data from MCPClient
        auth_cookies = params.arguments.get('_auth_cookies')
        auth_headers = params.arguments.get('_auth_headers')
        auth_token = params.arguments.get('_auth_token')
        auth_session = params.arguments.get('auth_session')
        config_arg = params.arguments.get('config')
        
        # Build auth_session from individual auth params if not already provided
        if not auth_session and (auth_cookies or auth_headers or auth_token):
            auth_session = {}
            if auth_cookies:
                auth_session['cookies'] = auth_cookies
            if auth_headers:
                auth_session['headers'] = auth_headers
            if auth_token:
                auth_session['token'] = auth_token
        
        # Remove internal _auth_* params, keep auth_session and config
        filtered_args = {
            k: v for k, v in params.arguments.items()
            if not k.startswith('_auth_')
        }
        
        # Ensure auth_session is included in filtered_args for tools that accept it
        if auth_session:
            filtered_args['auth_session'] = auth_session

        # Resolve URL parameter aliases before filtering
        filtered_args = _resolve_url_aliases(fn, filtered_args)
        call_args = _filter_args_for_callable(fn, filtered_args)

        async def _runner():
            if inspect.iscoroutinefunction(fn):
                return await fn(**call_args)
            # Run sync function off the main loop
            return await asyncio.to_thread(fn, **call_args)

        result = await _runner()
        # Ensure result is JSON-serializable; fallback to string
        try:
            json.dumps(result)
            serializable = result
        except TypeError:
            serializable = json.loads(json.dumps(result, default=str))

        return {"jsonrpc": "2.0", "id": req.id, "result": serializable}

    except Exception as e:
        return {"jsonrpc": "2.0", "id": req.id, "error": {"code": -32001, "message": str(e)}}
