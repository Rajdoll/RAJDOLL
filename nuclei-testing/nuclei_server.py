#!/usr/bin/env python3
"""
Nuclei MCP Server - Comprehensive vulnerability scanning with 12,000+ templates

Provides access to Nuclei's extensive vulnerability detection capabilities via MCP protocol.
Supports LLM-guided template selection for adaptive security testing.
"""

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Nuclei template categories (aligned with OWASP WSTG)
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

# Severity to CVSS score mapping
SEVERITY_TO_CVSS = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
    "unknown": 0.0
}

app = Server("nuclei-testing")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available Nuclei scanning tools"""
    return [
        Tool(
            name="run_nuclei_scan",
            description="Run comprehensive Nuclei scan with 12,000+ vulnerability templates. "
                       "Supports category filtering, severity thresholds, and LLM-guided template selection. "
                       "Ideal for broad vulnerability discovery.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g., http://juice-shop:3000)"
                    },
                    "categories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": f"Template categories to run. Options: {list(TEMPLATE_CATEGORIES.keys())}. "
                                     "Leave empty for all categories."
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "description": "Minimum severity threshold (default: low)"
                    },
                    "config": {
                        "type": "object",
                        "description": "Additional configuration",
                        "properties": {
                            "auth_session": {
                                "type": "object",
                                "description": "Authentication session (token, cookies)"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Scan timeout in seconds (default: 1800)"
                            },
                            "rate_limit": {
                                "type": "integer",
                                "description": "Requests per second (default: 150)"
                            },
                            "templates": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific template IDs (LLM-selected)"
                            }
                        }
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="list_nuclei_templates",
            description="List available Nuclei templates by category, severity, or tags. "
                       "Use this for LLM-guided template selection to understand available checks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": f"Template category. Options: {list(TEMPLATE_CATEGORIES.keys())}"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"]
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by specific tags (e.g., ['owasp', 'cve'])"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="run_targeted_nuclei",
            description="Run Nuclei with LLM-selected specific template IDs. "
                       "Use after reconnaissance to target specific vulnerabilities. "
                       "Faster than full scan, ideal for deep-dive testing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "template_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific template IDs to run (e.g., ['CVE-2021-12345', 'jwt-none-alg'])"
                    },
                    "config": {
                        "type": "object",
                        "description": "Auth session and other configs"
                    }
                },
                "required": ["url", "template_ids"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Execute Nuclei tool"""

    if name == "run_nuclei_scan":
        return await run_nuclei_scan(arguments)
    elif name == "list_nuclei_templates":
        return await list_nuclei_templates(arguments)
    elif name == "run_targeted_nuclei":
        return await run_targeted_nuclei(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")

async def run_nuclei_scan(args: Dict[str, Any]) -> list[TextContent]:
    """Run comprehensive Nuclei scan"""
    url = args["url"]
    categories = args.get("categories", [])
    severity = args.get("severity", "low")
    config = args.get("config", {})

    # Find Nuclei binary
    nuclei_path = _find_nuclei_binary()
    if not nuclei_path:
        return [TextContent(
            type="text",
            text=json.dumps({"error": "Nuclei binary not found. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"})
        )]

    # Build Nuclei command
    cmd = [nuclei_path, "-u", url, "-json", "-silent"]

    # Add severity filter
    severity_levels = ["info", "low", "medium", "high", "critical"]
    try:
        min_severity_idx = severity_levels.index(severity)
        severity_filter = ",".join(severity_levels[min_severity_idx:])
        cmd.extend(["-severity", severity_filter])
    except ValueError:
        cmd.extend(["-severity", "low,medium,high,critical"])

    # Add category filters (tags)
    if categories:
        tags = []
        for cat in categories:
            if cat in TEMPLATE_CATEGORIES:
                tags.extend(TEMPLATE_CATEGORIES[cat])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

    # Add authentication
    auth_session = config.get("auth_session", {})
    if auth_session:
        # JWT token
        token = auth_session.get("token")
        if token:
            cmd.extend(["-H", f"Authorization: Bearer {token}"])

        # Cookies
        cookies = auth_session.get("cookies", {})
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            else:
                cookie_str = str(cookies)
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

    # Add rate limiting
    rate_limit = config.get("rate_limit", 150)
    cmd.extend(["-rate-limit", str(rate_limit)])

    # Add timeout
    timeout = config.get("timeout", 1800)
    cmd.extend(["-timeout", str(timeout)])

    # LLM-selected specific templates
    templates = config.get("templates", [])
    if templates:
        for template_id in templates:
            cmd.extend(["-id", template_id])

    # Disable interactsh for faster scanning
    cmd.append("-ni")

    logger.info(f"Running Nuclei: {' '.join(cmd)}")

    # Execute Nuclei
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

        # Parse JSON output
        findings = []
        for line in stdout.decode().strip().split("\n"):
            if not line:
                continue
            try:
                result = json.loads(line)

                # Extract relevant information
                info = result.get("info", {})
                template_id = result.get("template-id", result.get("templateID", "unknown"))

                finding = {
                    "template_id": template_id,
                    "name": info.get("name", "Unknown"),
                    "severity": info.get("severity", "unknown").lower(),
                    "description": info.get("description", ""),
                    "reference": info.get("reference", []),
                    "matched_at": result.get("matched-at", result.get("matched_at", "")),
                    "extracted_results": result.get("extracted-results", []),
                    "curl_command": result.get("curl-command", ""),
                    "matcher_name": result.get("matcher-name", ""),
                    "cvss_score": SEVERITY_TO_CVSS.get(
                        info.get("severity", "unknown").lower(),
                        0.0
                    ),
                    "tags": info.get("tags", [])
                }
                findings.append(finding)

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Nuclei output line: {line[:100]}")
                continue

        # Aggregate results
        result_summary = {
            "total_findings": len(findings),
            "by_severity": {},
            "findings": findings[:100],  # Limit to 100 for MCP response size
            "full_count": len(findings),
            "scan_config": {
                "categories": categories,
                "severity_filter": severity,
                "rate_limit": rate_limit,
                "timeout": timeout
            }
        }

        # Count by severity
        for finding in findings:
            sev = finding["severity"]
            result_summary["by_severity"][sev] = result_summary["by_severity"].get(sev, 0) + 1

        logger.info(f"Nuclei scan complete: {len(findings)} findings")

        return [TextContent(
            type="text",
            text=json.dumps(result_summary, indent=2)
        )]

    except asyncio.TimeoutError:
        logger.error(f"Nuclei scan timeout after {timeout}s")
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "Scan timeout",
                "timeout": timeout,
                "suggestion": "Increase timeout or reduce template scope"
            })
        )]
    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e)})
        )]

async def list_nuclei_templates(args: Dict[str, Any]) -> list[TextContent]:
    """List available Nuclei templates"""
    category = args.get("category")
    severity = args.get("severity")
    tags = args.get("tags", [])

    nuclei_path = _find_nuclei_binary()
    if not nuclei_path:
        return [TextContent(
            type="text",
            text=json.dumps({"error": "Nuclei binary not found"})
        )]

    cmd = [nuclei_path, "-tl", "-silent"]

    # Add category filter via tags
    if category and category in TEMPLATE_CATEGORIES:
        category_tags = TEMPLATE_CATEGORIES[category]
        tags.extend(category_tags)

    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    if severity:
        cmd.extend(["-severity", severity])

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        templates = stdout.decode().strip().split("\n")
        templates = [t for t in templates if t]  # Remove empty lines

        return [TextContent(
            type="text",
            text=json.dumps({
                "count": len(templates),
                "templates": templates[:200],  # Limit for readability
                "category": category,
                "severity": severity,
                "tags": tags
            }, indent=2)
        )]

    except Exception as e:
        logger.error(f"Failed to list templates: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e)})
        )]

async def run_targeted_nuclei(args: Dict[str, Any]) -> list[TextContent]:
    """Run Nuclei with specific template IDs (LLM-selected)"""
    url = args["url"]
    template_ids = args["template_ids"]
    config = args.get("config", {})

    # Reuse run_nuclei_scan with specific template IDs
    return await run_nuclei_scan({
        "url": url,
        "config": {**config, "templates": template_ids}
    })

def _find_nuclei_binary() -> Optional[str]:
    """Find Nuclei binary in common locations"""
    # Check common paths
    paths = [
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        "nuclei"  # Check PATH
    ]

    for path in paths:
        if os.path.exists(path):
            return path

    # Try which command
    try:
        result = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass

    return None

async def main():
    """Run MCP server"""
    logger.info("Starting Nuclei MCP Server...")
    logger.info(f"Nuclei binary: {_find_nuclei_binary()}")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
