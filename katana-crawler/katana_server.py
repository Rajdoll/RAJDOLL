"""
Katana MCP Server - Standard MCP Protocol Implementation
Alternative to HTTP/JSON-RPC wrapper for stdio-based MCP communication

Author: Martua Raja Doli Pangaribuan
Institution: Politeknik Siber dan Sandi Negara
Date: January 2, 2026
"""

import asyncio
import json
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional

# MCP Protocol imports (if available)
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    logging.warning("MCP library not installed. Using HTTP/JSON-RPC mode only.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)


class KatanaMCPServer:
    """Katana MCP Server for JavaScript endpoint discovery"""

    def __init__(self):
        self.katana_binary = self._find_katana_binary()
        if not self.katana_binary:
            raise RuntimeError("Katana binary not found")

        logger.info(f"Katana MCP Server initialized with binary: {self.katana_binary}")

    def _find_katana_binary(self) -> Optional[str]:
        """Locate Katana binary"""
        candidates = [
            "/root/go/bin/katana",
            "/usr/local/bin/katana",
            "katana",
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
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

    async def crawl_with_js_parsing(
        self,
        url: str,
        depth: int = 3,
        js_parsing: bool = True,
        headless: bool = False,
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Crawl target with Katana for JavaScript endpoint discovery

        Args:
            url: Target URL
            depth: Crawl depth (1-5)
            js_parsing: Enable JavaScript file parsing
            headless: Use headless browser for JS execution
            config: Additional configuration (timeout, concurrency, rate_limit)

        Returns:
            Dictionary with discovered endpoints categorized by type
        """
        config = config or {}
        timeout = config.get("timeout", 180)
        concurrency = config.get("concurrency", 10)
        rate_limit = config.get("rate_limit", 150)

        # Build command
        cmd = [
            self.katana_binary,
            "-u", url,
            "-d", str(depth),
            "-jsonl",
            "-silent",
            "-no-color",
            "-c", str(concurrency),
            "-rl", str(rate_limit),
        ]

        if js_parsing:
            cmd.extend(["-jc", "-aff", "-xhr"])

        if headless:
            cmd.extend([
                "-headless",
                "-headless-options",
                "--disable-gpu,--disable-dev-shm-usage,--no-sandbox"
            ])

        logger.info(f"Executing Katana crawl: {url} (depth={depth}, js={js_parsing}, headless={headless})")

        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=timeout
            )

            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"Katana failed: {error_msg}")
                return {
                    "status": "error",
                    "error": f"Katana scan failed: {error_msg[:500]}"
                }

            # Parse JSONL output
            endpoints = []
            for line in stdout.decode('utf-8', errors='ignore').splitlines():
                if not line.strip():
                    continue
                try:
                    endpoints.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            # Categorize endpoints
            categorized = self._categorize_endpoints(endpoints)

            logger.info(f"Katana crawl complete: {len(categorized['all'])} endpoints discovered")

            return {
                "status": "success",
                "endpoints": categorized["all"],
                "total_found": len(categorized["all"]),
                "api_endpoints": categorized["api"],
                "js_files": categorized["js"],
                "forms": categorized["forms"],
                "xhr_endpoints": categorized["xhr"],
                "admin_endpoints": categorized["admin"],
                "scan_config": {
                    "depth": depth,
                    "js_parsing": js_parsing,
                    "headless": headless
                }
            }

        except asyncio.TimeoutError:
            logger.error(f"Katana scan timed out after {timeout}s")
            return {
                "status": "error",
                "error": f"Scan timed out after {timeout} seconds"
            }
        except Exception as e:
            logger.exception(f"Katana scan error: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def quick_endpoint_scan(
        self,
        url: str,
        target_type: str = "api"
    ) -> Dict[str, Any]:
        """
        Quick endpoint scan focused on specific target type

        Args:
            url: Target URL
            target_type: Focus area (api, js, forms, admin)

        Returns:
            Filtered endpoints matching target type
        """
        # Shallow scan with JS parsing
        result = await self.crawl_with_js_parsing(
            url=url,
            depth=2,
            js_parsing=True,
            headless=False,
            config={"timeout": 120}
        )

        if result.get("status") != "success":
            return result

        # Filter by target type
        if target_type == "api":
            filtered = result.get("api_endpoints", [])
        elif target_type == "js":
            filtered = result.get("js_files", [])
        elif target_type == "forms":
            filtered = result.get("forms", [])
        elif target_type == "admin":
            filtered = result.get("admin_endpoints", [])
        else:
            filtered = result.get("endpoints", [])

        return {
            "status": "success",
            "endpoints": filtered,
            "total_found": len(filtered),
            "target_type": target_type
        }

    def _categorize_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize endpoints by type"""
        categorized = {
            "all": [],
            "api": [],
            "js": [],
            "forms": [],
            "xhr": [],
            "admin": [],
        }

        for entry in endpoints:
            url = entry.get("url", "")
            normalized = {
                "url": url,
                "endpoint": entry.get("endpoint", url),
                "method": entry.get("method", "GET"),
                "source": "katana",
                "type": entry.get("tag", ""),
                "status_code": entry.get("status_code", 0),
            }

            categorized["all"].append(normalized)

            url_lower = url.lower()
            if "/api/" in url_lower or "/rest/" in url_lower or url.endswith(".json"):
                categorized["api"].append(normalized)
            if url.endswith(".js"):
                categorized["js"].append(normalized)
            if "form" in normalized["type"].lower():
                categorized["forms"].append(normalized)
            if "xhr" in normalized["type"].lower() or "ajax" in url_lower:
                categorized["xhr"].append(normalized)
            if "admin" in url_lower or "dashboard" in url_lower:
                categorized["admin"].append(normalized)

        return categorized


async def main():
    """Main entry point for MCP stdio server"""
    if not MCP_AVAILABLE:
        logger.error("MCP library not available. Install with: pip install mcp")
        sys.exit(1)

    # Initialize Katana server
    try:
        katana_server = KatanaMCPServer()
    except RuntimeError as e:
        logger.error(f"Failed to initialize Katana server: {e}")
        sys.exit(1)

    # Create MCP server
    server = Server("katana-crawler")

    @server.list_tools()
    async def list_tools() -> List[types.Tool]:
        """List available Katana tools"""
        return [
            types.Tool(
                name="crawl_with_js_parsing",
                description="Crawl target URL with JavaScript parsing to discover hidden endpoints",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "depth": {"type": "integer", "description": "Crawl depth (1-5)", "default": 3},
                        "js_parsing": {"type": "boolean", "description": "Enable JS parsing", "default": True},
                        "headless": {"type": "boolean", "description": "Use headless browser", "default": False},
                        "config": {"type": "object", "description": "Additional config"}
                    },
                    "required": ["url"]
                }
            ),
            types.Tool(
                name="quick_endpoint_scan",
                description="Quick scan focused on specific endpoint type (api, js, forms, admin)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "target_type": {"type": "string", "description": "Focus area", "default": "api"}
                    },
                    "required": ["url"]
                }
            )
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[types.TextContent]:
        """Execute Katana tool"""
        if name == "crawl_with_js_parsing":
            result = await katana_server.crawl_with_js_parsing(**arguments)
        elif name == "quick_endpoint_scan":
            result = await katana_server.quick_endpoint_scan(**arguments)
        else:
            return [types.TextContent(
                type="text",
                text=json.dumps({"status": "error", "error": f"Unknown tool: {name}"})
            )]

        return [types.TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]

    # Run stdio server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    if MCP_AVAILABLE:
        asyncio.run(main())
    else:
        logger.error("MCP library required for stdio server mode")
        logger.info("Use katana_api.py for HTTP/JSON-RPC mode instead")
        sys.exit(1)
