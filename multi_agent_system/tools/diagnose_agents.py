"""Diagnostic CLI for zero-finding agents.

Usage (run inside Docker worker container):
  docker exec rajdoll-worker-1 python3 /app/multi_agent_system/tools/diagnose_agents.py
  docker exec rajdoll-worker-1 python3 /app/multi_agent_system/tools/diagnose_agents.py --job-id 5
  docker exec rajdoll-worker-1 python3 /app/multi_agent_system/tools/diagnose_agents.py --agents ClientSideAgent
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure /app is on path when run as a script inside Docker
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

# MCP server names from MCP_SERVER_URLS in docker-compose.yml
ZERO_AGENTS: Dict[str, Dict[str, Any]] = {
    "ClientSideAgent": {
        "server": "client-side-testing",
        "tools_sample": ["test_cors_misconfiguration", "test_clickjacking", "test_dom_xss"],
    },
    "FileUploadAgent": {
        "server": "file-upload-testing",
        "tools_sample": ["test_unrestricted_upload", "test_mime_type_bypass"],
    },
    "APITestingAgent": {
        "server": "api-testing",
        "tools_sample": ["test_graphql_introspection", "test_rest_api_abuse", "test_rate_limiting"],
    },
    "ErrorHandlingAgent": {
        "server": "error-handling-testing",
        "tools_sample": ["probe_for_error_leaks", "check_generic_error_pages"],
    },
    "BusinessLogicAgent": {
        "server": "business-logic-testing",
        "tools_sample": ["test_workflow_bypass", "test_parameter_tampering", "test_data_validation_extremes"],
    },
}

SUGGESTIONS: Dict[str, str] = {
    "CONTAINER_DOWN": "Run: docker ps | grep <server>. If not running: docker compose up -d <service>",
    "TIMEOUT": "Increase TOOL_EXECUTION_TIMEOUT or reduce tool scope",
    "BINARY_MISSING": "Add missing binary to the agent Dockerfile image and rebuild",
    "AUTH_REQUIRED": "Tool needs authenticated session — check auth injection in base_agent.py",
    "TOOL_OK_NO_VULN": "Tool works correctly; target endpoint is not vulnerable to this test",
    "TOOL_FOUND": "Tool is working and found findings",
    "TOOL_BUG": "Tool returned HTTP 500 from MCP server — check tool source for bugs",
    "UNKNOWN": "Inspect raw output manually",
}


def categorize_result(result: Dict[str, Any], elapsed_s: float) -> Dict[str, str]:
    error_str = str(result.get("error") or result.get("raw_output") or "").lower()
    status = result.get("status", "")
    findings = result.get("findings")

    if any(kw in error_str for kw in ("connection refused", "connection error", "connectionrefused")):
        category = "CONTAINER_DOWN"
    elif any(kw in error_str for kw in ("command not found", "no such file", "exit code 127")):
        category = "BINARY_MISSING"
    elif "timed out" in error_str or "timeout" in error_str or elapsed_s >= 10.0:
        category = "TIMEOUT"
    elif status == "error" and "500" in error_str:
        category = "TOOL_BUG"
    elif isinstance(findings, list) and len(findings) > 0:
        category = "TOOL_FOUND"
    elif result.get("vulnerable") is True:
        category = "TOOL_FOUND"
    elif isinstance(findings, list) and len(findings) == 0:
        if "401" in error_str or "403" in error_str:
            category = "AUTH_REQUIRED"
        else:
            category = "TOOL_OK_NO_VULN"
    elif result.get("vulnerable") is False:
        category = "TOOL_OK_NO_VULN"
    else:
        category = "UNKNOWN"

    return {"category": category, "suggestion": SUGGESTIONS.get(category, SUGGESTIONS["UNKNOWN"])}


_FALLBACK_URLS: Dict[str, str] = {
    "client-side-testing":    "http://client-mcp:9008/jsonrpc",
    "file-upload-testing":    "http://fileupload-mcp:9012/jsonrpc",
    "api-testing":            "http://api-testing-mcp:9013/jsonrpc",
    "error-handling-testing": "http://error-mcp:9006/jsonrpc",
    "business-logic-testing": "http://biz-mcp:9009/jsonrpc",
}


def _get_mcp_url(server_name: str) -> str:
    import os
    urls_json = os.getenv("MCP_SERVER_URLS", "{}")
    try:
        urls = json.loads(urls_json)
        if server_name in urls:
            return urls[server_name]
    except Exception:
        pass
    return _FALLBACK_URLS.get(server_name, f"http://{server_name}:9001/jsonrpc")


def _get_target_and_endpoints(job_id: Optional[int]) -> tuple:
    from multi_agent_system.core.db import get_db
    from multi_agent_system.models.models import Job, SharedContext
    with get_db() as db:
        if job_id:
            job = db.query(Job).filter(Job.id == job_id).first()
        else:
            job = db.query(Job).order_by(Job.id.desc()).first()
        if not job:
            return "http://localhost", []
        ctxs = {c.key: c.value for c in
                db.query(SharedContext).filter(SharedContext.job_id == job.id).all()}

    target = ctxs.get("target_url") or ctxs.get("target") or "http://localhost"
    if isinstance(target, dict):
        target = target.get("url", "http://localhost")
    inv = ctxs.get("endpoint_inventory") or {}
    if isinstance(inv, str):
        try:
            inv = json.loads(inv)
        except Exception:
            inv = {}
    eps = [e.get("url", "") for e in inv.get("endpoints", []) if isinstance(e, dict)]
    return str(target), [e for e in eps if e]


async def call_tool(mcp_url: str, tool_name: str, args: Dict[str, Any]) -> tuple:
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(mcp_url, json=payload)
            elapsed = time.perf_counter() - start
            if resp.status_code != 200:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}, elapsed
            data = resp.json()
            result = data.get("result") or data.get("error") or {}
            if isinstance(result, dict) and "data" in result:
                result = result["data"]
            return result if isinstance(result, dict) else {"status": "success", "raw": result}, elapsed
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        return {"status": "error", "error": f"Connection refused: {e}"}, time.perf_counter() - start
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return {"status": "error", "error": "timed out"}, time.perf_counter() - start
    except Exception as e:
        return {"status": "error", "error": str(e)}, time.perf_counter() - start


async def diagnose_agent(
    agent_name: str,
    cfg: Dict[str, Any],
    target: str,
    sample_endpoint: str,
) -> List[Dict[str, Any]]:
    mcp_url = _get_mcp_url(cfg["server"])
    results = []
    for tool_name in cfg["tools_sample"]:
        args = {"url": sample_endpoint or target}
        result, elapsed = await call_tool(mcp_url, tool_name, args)
        cat = categorize_result(result, elapsed)
        snippet = json.dumps(result)[:300]
        results.append({
            "tool": tool_name,
            "elapsed_s": round(elapsed, 2),
            "category": cat["category"],
            "suggestion": cat["suggestion"],
            "snippet": snippet,
        })
    return results


async def main(job_id: Optional[int], agents_filter: Optional[List[str]]) -> None:
    target, endpoints = _get_target_and_endpoints(job_id)
    sample_endpoint = endpoints[0] if endpoints else target
    print(f"\n=== Agent Diagnostic Report (target: {target}) ===\n")

    agents_to_check = {
        k: v for k, v in ZERO_AGENTS.items()
        if not agents_filter or k in agents_filter
    }

    summary: Dict[str, Dict[str, int]] = {}
    for agent_name, cfg in agents_to_check.items():
        print(f"[{agent_name}] -> {cfg['server']}")
        results = await diagnose_agent(agent_name, cfg, target, sample_endpoint)
        counts: Dict[str, int] = {}
        for r in results:
            cat = r["category"]
            counts[cat] = counts.get(cat, 0) + 1
            icon = {"TOOL_FOUND": "v", "TOOL_OK_NO_VULN": "~", "CONTAINER_DOWN": "X",
                    "BINARY_MISSING": "X", "TIMEOUT": "T", "TOOL_BUG": "!", "AUTH_REQUIRED": "A"}.get(cat, "?")
            print(f"  {icon} {r['tool']} [{cat}] ({r['elapsed_s']}s)")
            print(f"      Suggestion: {r['suggestion']}")
            print(f"      Snippet: {r['snippet'][:120]}")
        summary[agent_name] = counts

    print("\n=== Summary ===")
    for agent_name, counts in summary.items():
        parts = [f"{count}x {cat}" for cat, count in counts.items()]
        print(f"  {agent_name}: {', '.join(parts)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Diagnose zero-finding agents")
    parser.add_argument("--job-id", type=int, default=None)
    parser.add_argument("--agents", type=str, default=None,
                        help="Comma-separated agent names")
    args = parser.parse_args()
    agents_filter = [a.strip() for a in args.agents.split(",")] if args.agents else None
    asyncio.run(main(args.job_id, agents_filter))
