"""
Katana JavaScript Parsing MCP Server - FastAPI HTTP/JSON-RPC Wrapper
Provides endpoint discovery via JavaScript parsing and crawling

Author: Martua Raja Doli Pangaribuan
Institution: Politeknik Siber dan Sandi Negara
Date: January 2, 2026
"""

import asyncio
import contextlib
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Katana MCP Server",
    description="JavaScript parsing and endpoint discovery via Katana",
    version="1.0.0"
)


class KatanaCrawlRequest(BaseModel):
    """Request model for Katana crawling"""
    url: str = Field(..., description="Target URL to crawl")
    depth: int = Field(default=3, description="Crawl depth (1-5)")
    js_parsing: bool = Field(default=True, description="Enable JavaScript parsing")
    headless: bool = Field(default=False, description="Use headless browser for JS execution")
    scope: List[str] = Field(default_factory=list, description="In-scope domains")
    exclude: List[str] = Field(default_factory=list, description="Exclude patterns")
    config: Dict[str, Any] = Field(default_factory=dict, description="Additional config")


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    katana_binary: str
    version: str


def _find_katana_binary() -> Optional[str]:
    """Locate Katana binary in common installation paths"""
    candidates = [
        "/root/go/bin/katana",
        "/usr/local/bin/katana",
        "katana",  # PATH lookup
    ]

    for path in candidates:
        try:
            result = subprocess.run(
                [path, "-version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Found Katana binary at: {path}")
                return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    katana_path = _find_katana_binary()

    if not katana_path:
        raise HTTPException(
            status_code=503,
            detail="Katana binary not found"
        )

    # Get Katana version
    try:
        result = subprocess.run(
            [katana_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception as e:
        logger.warning(f"Could not get Katana version: {e}")
        version = "unknown"

    return HealthResponse(
        status="healthy",
        katana_binary=katana_path,
        version=version
    )


class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 request format"""
    jsonrpc: str = "2.0"
    method: str
    params: Dict[str, Any] = Field(default_factory=dict)
    id: Optional[int] = None


@app.post("/jsonrpc", include_in_schema=False)
async def jsonrpc_handler(request: Request) -> JSONResponse:
    """
    JSON-RPC 2.0 handler for Katana MCP server
    Dispatches to crawl_with_katana method

    CRITICAL: Returns JSONResponse directly to bypass FastAPI auto-validation
    """
    try:
        # Parse raw JSON body
        body = await request.json()
        logger.info(f"[Katana JSON-RPC] Received request: method={body.get('method')}, id={body.get('id')}")

        # Validate JSON-RPC structure
        if "method" not in body:
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid Request - missing method"},
                    "id": body.get("id")
                },
                status_code=200
            )

        method = body.get("method")

        # MCP-style tool invocation compatibility: tools/call
        # Expected params: {"name": "crawl_with_js_parsing", "arguments": {...}}
        if method == "tools/call":
            params = body.get("params", {}) or {}
            tool_name = params.get("name")
            tool_args = params.get("arguments", {}) or {}

            if tool_name not in {"crawl_with_js_parsing", "katana_js_crawl"}:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                        "id": body.get("id"),
                    },
                    status_code=200,
                )

            logger.info(f"[Katana JSON-RPC] tools/call -> {tool_name} args={list(tool_args.keys())}")
            crawl_request = KatanaCrawlRequest(**tool_args)
            result = await crawl_with_katana(crawl_request)

        # Backward-compatible direct method
        elif method == "crawl_with_js_parsing":
            params = body.get("params", {}) or {}
            logger.info(f"[Katana JSON-RPC] Parsing params: {params}")
            crawl_request = KatanaCrawlRequest(**params)
            result = await crawl_with_katana(crawl_request)

        else:
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": body.get("id"),
                },
                status_code=200,
            )

        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "result": result,
                "id": body.get("id")
            },
            status_code=200
        )

    except ValidationError as e:
        logger.error(f"[Katana JSON-RPC] Validation error: {e}")
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32602,
                    "message": f"Invalid params: {str(e)}"
                },
                "id": body.get("id") if 'body' in locals() else None
            },
            status_code=200
        )
    except HTTPException as e:
        # Preserve tool-level failures (including timeouts) as JSON-RPC errors
        error_msg = getattr(e, "detail", None) or str(e)
        logger.error(f"[Katana JSON-RPC] Tool error: {error_msg}")
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": str(error_msg),
                },
                "id": body.get("id") if 'body' in locals() else None,
            },
            status_code=200,
        )
    except Exception as e:
        logger.exception(f"[Katana JSON-RPC] Internal error: {e}")
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                },
                "id": body.get("id") if 'body' in locals() else None
            },
            status_code=200
        )


async def crawl_with_katana(request: KatanaCrawlRequest):
    """
    Crawl target URL with Katana for JavaScript endpoint discovery

    Returns JSON with discovered endpoints, extracted from:
    - HTML links and forms
    - JavaScript files (static analysis)
    - Dynamic JavaScript execution (if headless mode enabled)
    """
    katana_path = _find_katana_binary()

    if not katana_path:
        raise HTTPException(
            status_code=500,
            detail="Katana binary not found"
        )

    # Build Katana command
    cmd = [
        katana_path,
        "-u", request.url,
        "-d", str(request.depth),
        "-jsonl",  # Output as JSON Lines
        "-silent",  # Suppress banner
        "-no-color",  # No color codes
    ]

    # JavaScript parsing options
    if request.js_parsing:
        cmd.append("-jc")  # JavaScript crawling
        cmd.append("-aff")  # Automatic form filling
        cmd.append("-xhr")  # Extract XHR endpoints

    # Headless mode for JavaScript execution
    if request.headless:
        cmd.append("-headless")
        cmd.append("-headless-options")
        cmd.append("--disable-gpu,--disable-dev-shm-usage,--no-sandbox")

    # Scope control
    if request.scope:
        for scope in request.scope:
            cmd.extend(["-field-scope", scope])

    # Exclude patterns
    if request.exclude:
        for pattern in request.exclude:
            cmd.extend(["-exclude", pattern])

    # Additional config
    config = request.config
    timeout = config.get("timeout", 180)
    concurrency = config.get("concurrency", 10)
    rate_limit = config.get("rate_limit", 150)

    cmd.extend(["-c", str(concurrency)])
    cmd.extend(["-rl", str(rate_limit)])

    logger.info(f"Executing Katana: {' '.join(cmd)}")

    proc: Optional[asyncio.subprocess.Process] = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.error(f"Katana scan timed out after {timeout}s; terminating process...")
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
            raise HTTPException(
                status_code=504,
                detail=f"Katana scan timed out after {timeout} seconds",
            )

        if proc.returncode != 0:
            error_msg = (stderr or b"").decode('utf-8', errors='ignore')
            logger.error(f"Katana execution failed: {error_msg}")
            raise HTTPException(
                status_code=500,
                detail=f"Katana scan failed: {error_msg[:500]}"
            )

        # Parse JSONL output
        endpoints = []
        output_lines = (stdout or b"").decode('utf-8', errors='ignore').splitlines()

        for line in output_lines:
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
                endpoints.append(entry)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse JSONL line: {line[:100]}")
                continue

        # Process and categorize endpoints
        categorized = _categorize_endpoints(endpoints)

        # Build response
        response = {
            "status": "success",
            "data": {
                "endpoints": categorized["all"],
                "total_found": len(categorized["all"]),
                "api_endpoints": categorized["api"],
                "js_files": categorized["js"],
                "forms": categorized["forms"],
                "xhr_endpoints": categorized["xhr"],
                "admin_endpoints": categorized["admin"],
                "config": {
                    "depth": request.depth,
                    "js_parsing": request.js_parsing,
                    "headless": request.headless
                }
            }
        }

        logger.info(f"Katana scan complete: {len(categorized['all'])} endpoints found")
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during Katana scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Katana scan error: {str(e)}"
        )


def _categorize_endpoints(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Categorize discovered endpoints by type

    Katana JSONL format:
    {
      "request": {"method": "GET", "endpoint": "http://target/path"},
      "response": {"status_code": 200, "headers": {...}},
      "timestamp": "..."
    }
    """
    categorized = {
        "all": [],
        "api": [],
        "js": [],
        "forms": [],
        "xhr": [],
        "admin": [],
    }

    for entry in endpoints:
        # Extract URL from Katana JSONL structure
        request_data = entry.get("request", {})
        url = request_data.get("endpoint", "")
        method = request_data.get("method", "GET")

        # Extract response data
        response_data = entry.get("response", {})
        status_code = response_data.get("status_code", 0)

        # Get tag/type if available
        endpoint_type = entry.get("tag", "")

        # Skip empty URLs
        if not url:
            continue

        # Normalize entry
        normalized = {
            "url": url,
            "endpoint": url,  # For backward compatibility
            "method": method,
            "source": "katana",
            "type": endpoint_type,
            "status_code": status_code,
        }

        categorized["all"].append(normalized)

        # Categorize by URL pattern
        url_lower = url.lower()

        if "/api/" in url_lower or "/rest/" in url_lower or url.endswith(".json"):
            categorized["api"].append(normalized)

        if url.endswith(".js"):
            categorized["js"].append(normalized)

        if "form" in endpoint_type.lower():
            categorized["forms"].append(normalized)

        if "xhr" in endpoint_type.lower() or "ajax" in url_lower:
            categorized["xhr"].append(normalized)

        if "admin" in url_lower or "dashboard" in url_lower:
            categorized["admin"].append(normalized)

    return categorized


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Katana MCP Server",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "jsonrpc": "/jsonrpc (POST)",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9015)
