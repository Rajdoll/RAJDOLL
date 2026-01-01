#!/usr/bin/env python3
"""
Nuclei HTTP API Wrapper - Simple FastAPI wrapper for Nuclei MCP compatibility

Provides HTTP JSON-RPC interface to match existing MCP server infrastructure.
"""

import asyncio
import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Nuclei MCP API")

# Import from nuclei_server for shared logic
TEMPLATE_CATEGORIES = {
    "information-gathering": ["tech", "fingerprint", "exposure", "config", "detect"],
    "authentication": ["auth-bypass", "default-login", "weak-creds", "jwt"],
    "authorization": ["idor", "privilege-escalation", "broken-access"],
    "session-management": ["session", "cookie"],
    "input-validation": ["sqli", "xss", "xxe", "ssti", "rce", "lfi", "command-injection", "injection"],
    "cryptography": ["weak-crypto", "tls", "ssl", "certificate"],
    "business-logic": ["file-upload", "race-condition", "logic"],
    "client-side": ["dom-xss", "cors", "csp"],
    "api-testing": ["graphql", "rest-api", "swagger", "api"]
}

SEVERITY_TO_CVSS = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
    "unknown": 0.0
}

class NucleiRequest(BaseModel):
    url: str
    categories: Optional[List[str]] = None
    severity: str = "low"
    config: Optional[Dict[str, Any]] = None

@app.post("/jsonrpc")
async def run_nuclei(request: NucleiRequest):
    """Run Nuclei scan via JSON-RPC compatible endpoint"""

    # Find Nuclei binary
    nuclei_path = _find_nuclei_binary()
    if not nuclei_path:
        raise HTTPException(status_code=500, detail="Nuclei binary not found")

    # Build command
    cmd = [nuclei_path, "-u", request.url, "-json", "-silent", "-ni"]

    # Add severity filter
    severity_levels = ["info", "low", "medium", "high", "critical"]
    try:
        min_severity_idx = severity_levels.index(request.severity)
        severity_filter = ",".join(severity_levels[min_severity_idx:])
        cmd.extend(["-severity", severity_filter])
    except ValueError:
        cmd.extend(["-severity", "low,medium,high,critical"])

    # Add category filters
    if request.categories:
        tags = []
        for cat in request.categories:
            if cat in TEMPLATE_CATEGORIES:
                tags.extend(TEMPLATE_CATEGORIES[cat])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

    # Add authentication if provided
    config = request.config or {}
    auth_session = config.get("auth_session", {})
    if auth_session:
        token = auth_session.get("token")
        if token:
            cmd.extend(["-H", f"Authorization: Bearer {token}"])

        cookies = auth_session.get("cookies", {})
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                cmd.extend(["-H", f"Cookie: {cookie_str}"])

    # Rate limiting
    rate_limit = config.get("rate_limit", 150)
    cmd.extend(["-rate-limit", str(rate_limit)])

    # Timeout
    timeout = config.get("timeout", 1800)

    logger.info(f"Running Nuclei: {' '.join(cmd)}")

    # Execute
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout + 60
        )

        # Parse results
        findings = []
        for line in stdout.decode().strip().split("\n"):
            if not line:
                continue
            try:
                result = json.loads(line)
                info = result.get("info", {})

                finding = {
                    "template_id": result.get("template-id", "unknown"),
                    "name": info.get("name", "Unknown"),
                    "severity": info.get("severity", "unknown").lower(),
                    "description": info.get("description", ""),
                    "matched_at": result.get("matched-at", ""),
                    "cvss_score": SEVERITY_TO_CVSS.get(
                        info.get("severity", "unknown").lower(), 0.0
                    )
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        # Return results
        result = {
            "total_findings": len(findings),
            "findings": findings[:100],  # Limit response size
            "by_severity": {}
        }

        for f in findings:
            sev = f["severity"]
            result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1

        logger.info(f"Nuclei scan complete: {len(findings)} findings")
        return result

    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail=f"Scan timeout after {timeout}s")
    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def _find_nuclei_binary() -> Optional[str]:
    """Find Nuclei binary"""
    paths = [
        "/root/go/bin/nuclei",
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei"
    ]

    for path in paths:
        if os.path.exists(path):
            return path

    try:
        result = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass

    return None

@app.get("/health")
async def health():
    """Health check endpoint"""
    nuclei_path = _find_nuclei_binary()
    return {
        "status": "healthy",
        "nuclei_binary": nuclei_path,
        "templates": 12258
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9014)
