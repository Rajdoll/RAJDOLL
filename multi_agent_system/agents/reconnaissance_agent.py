from __future__ import annotations

import asyncio
import copy
import json
import os
import re
from collections import deque
from typing import Any, ClassVar, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .base_agent import AgentRegistry, BaseAgent
from ..utils.mcp_client import MCPClient
from ..utils.session_manager import SessionManager
from .modules.directory_scanner import DirectoryScanner


@AgentRegistry.register("ReconnaissanceAgent")
class ReconnaissanceAgent(BaseAgent):
    disable_hitl: ClassVar[bool] = True
    # disable_llm_planning: ClassVar[bool] = True  # 🧪 TEST: Re-enabled after fixing JSON mode
    system_prompt: ClassVar[str] = """
You are ReconnaissanceAgent, an autonomous OWASP WSTG-INFO practitioner. Your scope is reconnaissance only.
1. Read shared_context (tech_stack, entry_points, credentials) before planning.
2. Produce a deterministic baseline using the reconnaissance MCP toolchain (fingerprinting, entry points, execution paths, meta files, OSINT).
3. After each tool execution, normalize key artifacts and write them into shared_context so downstream agents never repeat work.
4. Summarize notable risks and, only when justified, request follow-up tools using the provided keys (rerun_security_headers, targeted_entry_point_probe, architecture_deep_dive).
5. Respond with concise JSON (no markdown) describing risk_summary, follow_up_tools, and context_updates.

Operate autonomously without human guidance.
"""

    ENDPOINT_DISCOVERY_TIMEOUT: ClassVar[int] = int(os.getenv("RECON_ENDPOINT_TIMEOUT", "240"))
    MAX_ENDPOINTS: ClassVar[int] = 120
    MAX_JS_FILES: ClassVar[int] = 15

    BASELINE_TOOL_MATRIX: ClassVar[Dict[str, Dict[str, Any]]] = {
        "advanced_technology_fingerprinting": {
            "server": "information-gathering",
            "tool": "advanced_technology_fingerprinting",
            "priority": "CRITICAL",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_technology_fingerprint",
        },
        "fingerprint_web_server": {
            "server": "information-gathering",
            "tool": "fingerprint_web_server",
            "priority": "CRITICAL",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_technology_fingerprint",
        },
        "fingerprint_framework": {
            "server": "information-gathering",
            "tool": "fingerprint_framework",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_technology_fingerprint",
        },
        "fingerprint_application": {
            "server": "information-gathering",
            "tool": "fingerprint_application",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_technology_fingerprint",
        },
        "security_headers_analysis": {
            "server": "information-gathering",
            "tool": "security_headers_analysis",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_security_headers",
        },
        "analyze_webpage_content": {
            "server": "information-gathering",
            "tool": "analyze_webpage_content",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_content_leaks",
        },
        "search_engine_reconnaissance": {
            "server": "information-gathering",
            "tool": "search_engine_reconnaissance",
            "priority": "MEDIUM",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_osint",
        },
        "check_metafiles": {
            "server": "information-gathering",
            "tool": "check_metafiles",
            "priority": "MEDIUM",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_meta_files",
        },
        "identify_entry_points": {
            "server": "information-gathering",
            "tool": "identify_entry_points",
            "priority": "CRITICAL",
            "arg_builder": lambda target, domain: {"domain": domain, "max_pages": 150, "max_depth": 2},
            "handler": "_handle_entry_points",
        },
        "map_execution_paths": {
            "server": "information-gathering",
            "tool": "map_execution_paths",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {"domain": domain, "max_pages": 200, "max_depth": 3},
            "handler": "_handle_execution_paths",
        },
        "run_comprehensive_scan": {
            "server": "information-gathering",
            "tool": "run_comprehensive_scan",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_comprehensive_scan",
            "timeout": 240,
        },
        "map_architecture": {
            "server": "information-gathering",
            "tool": "map_architecture",
            "priority": "MEDIUM",
            "arg_builder": lambda target, domain: {"domain": domain},
            "handler": "_handle_architecture",
        },
        "directory_bruteforce": {
            "server": "local",  # Runs locally, not via MCP
            "tool": "scan_directories",
            "priority": "MEDIUM",  # Downgraded: ffuf is more comprehensive
            "arg_builder": lambda target, domain: {"target_url": target, "depth": 1, "check_extensions": True},
            "handler": "_handle_directory_scan",
            "timeout": 180,
        },
        "dirsearch_scan": {
            "server": "information-gathering",
            "tool": "dirsearch_scan",
            "priority": "CRITICAL",  # CRITICAL: Recursive directory scanning - superior to ffuf
            "arg_builder": lambda target, domain: {
                "target_url": target,
                "recursive": True,
                "recursion_depth": 3,  # Deep recursive scanning
                "extensions": "php,html,json,txt,js,xml,asp,aspx,jsp",
                "threads": 50
            },
            "handler": "_handle_dirsearch_scan",
            "timeout": 600,  # 10 minutes for comprehensive recursive scan
        },
        "discover_endpoints": {
            "server": "local",  # Runs locally using _discover_endpoints
            "tool": "_perform_endpoint_discovery",
            "priority": "HIGH",  # Still important for JavaScript endpoint mining
            "arg_builder": lambda target, domain: {"target": target},
            "handler": "_handle_endpoint_discovery",
            "timeout": 240,
        },
    }

    FOLLOW_UP_TOOL_BUILDERS: ClassVar[Dict[str, Dict[str, str]]] = {
        "rerun_security_headers": {
            "server": "information-gathering",
            "tool": "security_headers_analysis",
            "arg_name": "domain",
            "value_source": "domain",
            "context_key": "security_headers",
        },
        "targeted_entry_point_probe": {
            "server": "information-gathering",
            "tool": "identify_entry_points",
            "arg_name": "domain",
            "value_source": "domain",
            "context_key": "entry_points",
        },
        "architecture_deep_dive": {
            "server": "information-gathering",
            "tool": "map_architecture",
            "arg_name": "domain",
            "value_source": "domain",
            "context_key": "app_architecture",
        },
    }

    def _get_available_tools(self) -> list[str]:
        return list(self.BASELINE_TOOL_MATRIX.keys()) + ["auto_login"]

    def _get_tool_info(self) -> Dict[str, Dict[str, Any]]:
        return {name: {"priority": cfg.get("priority", "MEDIUM")} for name, cfg in self.BASELINE_TOOL_MATRIX.items()}
    
    async def _execute_local_tool(self, tool_name: str, config: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute local (non-MCP) tools like directory scanner"""
        self.log("info", f"Executing local tool: {tool_name}")
        
        if tool_name == "directory_bruteforce":
            scanner = DirectoryScanner(timeout=5, max_concurrent=20)
            try:
                findings = await scanner.scan_directories(
                    target_url=args.get("target_url"),
                    depth=args.get("depth", 1),
                    check_extensions=args.get("check_extensions", True)
                )
                return {
                    "status": "success",
                    "data": findings
                }
            except Exception as exc:
                self.log("error", f"Directory scan failed: {exc}")
                return {
                    "status": "error",
                    "error": str(exc)
                }
        else:
            self.log("warning", f"Unknown local tool: {tool_name}")
            return {
                "status": "error",
                "error": f"Unknown local tool: {tool_name}"
            }

    async def run(self) -> None:
        import sys
        print("🔴🔴🔴 [STDERR TRACE] ReconAgent.run() STARTED", file=sys.stderr, flush=True)

        client = MCPClient()
        target = getattr(self, "_target", None) or self._get_target()
        print(f"🔴 [STDERR TRACE] Target obtained: {target}", file=sys.stderr, flush=True)

        if not target:
            self.log("error", "Target missing; aborting ReconnaissanceAgent")
            print("🔴 [STDERR TRACE] Target missing - ABORTING", file=sys.stderr, flush=True)
            return

        domain = self._domain_from_target(target)
        baseline_snapshot: Dict[str, Any] = {
            "target": target,
            "domain": domain,
            "shared_context_keys": list(self.shared_context.keys()),
        }
        print(f"🔴 [STDERR TRACE] Baseline snapshot created, domain: {domain}", file=sys.stderr, flush=True)

        self.log("info", f"📡 Starting reconnaissance against {target}")
        print("🔴 [STDERR TRACE] About to call log_tool_execution_plan()", file=sys.stderr, flush=True)
        self.log_tool_execution_plan()
        print("🔴 [STDERR TRACE] log_tool_execution_plan() completed", file=sys.stderr, flush=True)

        print("🔴 [STDERR TRACE] About to call _collect_baseline_data()", file=sys.stderr, flush=True)
        await self._collect_baseline_data(client, target, domain, baseline_snapshot)
        self.log("warning", "🔐 [PHASE 4 DEBUG] Baseline data collection COMPLETE")
        print("🔴 [STDERR TRACE] _collect_baseline_data() COMPLETED", file=sys.stderr, flush=True)

        print("🔴 [STDERR TRACE] About to call _perform_endpoint_discovery()", file=sys.stderr, flush=True)
        await self._perform_endpoint_discovery(target, baseline_snapshot)
        self.log("warning", "🔐 [PHASE 4 DEBUG] Endpoint discovery COMPLETE")
        print("🔴 [STDERR TRACE] _perform_endpoint_discovery() COMPLETED", file=sys.stderr, flush=True)

        self.log("warning", "🔐 [PHASE 4 DEBUG] About to call _attempt_auto_login...")
        print("🔴🔴🔴 [STDERR TRACE] About to call _attempt_auto_login()", file=sys.stderr, flush=True)
        await self._attempt_auto_login(target, baseline_snapshot)
        self.log("warning", "🔐 [PHASE 4 DEBUG] _attempt_auto_login call returned")
        print("🔴🔴🔴 [STDERR TRACE] _attempt_auto_login() COMPLETED", file=sys.stderr, flush=True)

        print("🔴 [STDERR TRACE] About to call _post_baseline_analysis()", file=sys.stderr, flush=True)
        await self._post_baseline_analysis(baseline_snapshot, client)
        self.log("warning", "🔐 [PHASE 4 DEBUG] Post-baseline analysis COMPLETE")
        print("🔴 [STDERR TRACE] _post_baseline_analysis() COMPLETED", file=sys.stderr, flush=True)

        self.log("info", "Reconnaissance complete")
        print("🔴🔴🔴 [STDERR TRACE] ReconAgent.run() FINISHED", file=sys.stderr, flush=True)

    async def _collect_baseline_data(self, client: MCPClient, target: str, domain: str, baseline_snapshot: Dict[str, Any]) -> None:
        baseline_snapshot.setdefault("baseline_results", {})
        prior_stack = self.shared_context.get("tech_stack")
        if isinstance(prior_stack, dict):
            baseline_snapshot["tech_stack"] = copy.deepcopy(prior_stack)
        else:
            baseline_snapshot["tech_stack"] = {}

        for tool_name, config in self.BASELINE_TOOL_MATRIX.items():
            if not self.should_run_tool(tool_name):
                self.log("debug", f"Skipping {tool_name} (not in plan or circuit breaker)")
                continue

            arg_builder = config.get("arg_builder") or (lambda _target, d: {"domain": d})
            try:
                args = arg_builder(target, domain)
            except Exception as arg_err:
                self.log("warning", f"Failed to build args for {tool_name}: {arg_err}")
                continue

            # Handle local tools (non-MCP)
            if config["server"] == "local":
                try:
                    result = await self._execute_local_tool(tool_name, config, args)
                except Exception as exc:
                    self.log("warning", f"{tool_name} (local) failed: {exc}")
                    self.record_tool_failure(tool_name, str(exc))
                    continue
            else:
                # Execute via MCP
                try:
                    result = await self.run_tool_with_timeout(
                        client.call_tool(
                            server=config["server"],
                            tool=config.get("tool", tool_name),
                            args=args,
                        ),
                        timeout=config.get("timeout"),
                    )
                except Exception as exc:
                    self.log("warning", f"{tool_name} failed: {exc}")
                    self.record_tool_failure(tool_name, str(exc))
                    continue

            if not isinstance(result, dict) or result.get("status") != "success":
                self.log("warning", f"{tool_name} returned non-success", {"result": result})
                continue

            data = result.get("data", result)
            baseline_snapshot["baseline_results"][tool_name] = data

            handler_name = config.get("handler")
            if handler_name:
                handler = getattr(self, handler_name, None)
                if handler:
                    try:
                        handler(data, baseline_snapshot)
                    except Exception as handler_err:
                        self.log("warning", f"Handler {handler_name} failed", {"error": str(handler_err)})

            self.log("info", f"✓ {tool_name} completed")

    def _handle_technology_fingerprint(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        technologies = data.get("technologies") or {}
        if not isinstance(technologies, dict):
            return

        stack = snapshot.setdefault("tech_stack", {})
        for category, values in technologies.items():
            if not values:
                continue
            existing = set(stack.get(category, []))
            for value in values:
                if isinstance(value, str) and value:
                    existing.add(value)
            stack[category] = sorted(existing)

        if headers := data.get("headers"):
            http_meta = snapshot.setdefault("http_headers", {})
            if isinstance(headers, dict):
                http_meta.update(headers)
                self.write_context("http_headers", http_meta)

        self.write_context("tech_stack", stack)
        confidence = data.get("confidence_score")
        if isinstance(confidence, (int, float)) and confidence >= 70:
            self.add_finding(
                "WSTG-INFO",
                "High-confidence technology fingerprint established",
                severity="info",
                evidence={"score": confidence, "categories": list(stack.keys())}
            )

    def _handle_security_headers(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        payload = {
            "security_headers": data.get("security_headers"),
            "score": data.get("score"),
            "grade": data.get("grade"),
        }
        snapshot["security_headers"] = payload
        self.write_context("security_headers", payload)

        missing = []
        for header, meta in (payload.get("security_headers") or {}).items():
            if not meta.get("present"):
                missing.append(header)
        if missing:
            self.add_finding(
                "WSTG-INFO",
                f"Missing security headers: {', '.join(missing[:5])}",
                severity="medium",
                evidence={"missing": missing[:10]}
            )

    def _handle_content_leaks(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        payload = data.get("information_leakage") or data
        snapshot["content_leaks"] = payload
        self.write_context("content_leaks", payload)

        comment_count = payload.get("comment_count") or len(payload.get("html_comments", []) or [])
        if comment_count:
            self.add_finding(
                "WSTG-INFO",
                f"{comment_count} HTML comments exposed in main page",
                severity="low",
            )
        if payload.get("emails_found"):
            self.add_finding(
                "WSTG-INFO",
                "Email addresses leaked in page source",
                severity="low",
                evidence={"emails": payload["emails_found"][:5]}
            )

    def _handle_osint(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        snapshot["osint"] = data
        self.write_context("osint", data)
        findings = data.get("findings", {})
        if findings.get("admin_panels"):
            self.add_finding(
                "WSTG-INFO",
                "Public OSINT exposed potential admin panels",
                severity="medium",
                evidence={"samples": findings["admin_panels"][:5]}
            )

    def _handle_meta_files(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        metafiles = data.get("metafiles", data)
        snapshot["metafiles"] = metafiles
        self.write_context("metafiles", metafiles)

        robots = (metafiles.get("robots_txt") or {}).get("interesting_findings") or []
        if robots:
            self.add_finding(
                "WSTG-INFO",
                "Robots.txt discloses potentially sensitive paths",
                severity="low",
                evidence={"paths": robots[:5]}
            )

    def _handle_entry_points(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        entry_points = data.get("entry_points") if isinstance(data, dict) else None
        if not entry_points:
            return
        snapshot["entry_points"] = entry_points
        self.write_context("entry_points", entry_points)

        api_endpoints = entry_points.get("api_endpoints") or []
        self.add_finding(
            "WSTG-INFO",
            f"Identified {entry_points.get('urls_found', 0)} entry URLs and {len(api_endpoints)} API endpoints",
            severity="info",
            evidence={"api_samples": api_endpoints[:5]}
        )

    def _handle_execution_paths(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        snapshot["execution_paths"] = data
        self.write_context("execution_paths", data)
        if data.get("hidden_paths"):
            self.add_finding(
                "WSTG-INFO",
                "Hidden workflow paths identified",
                severity="low",
                evidence={"sample": data["hidden_paths"][:5]}
            )

    def _handle_architecture(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        snapshot["app_architecture"] = data
        self.write_context("app_architecture", data)

    def _handle_comprehensive_scan(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        snapshot["comprehensive_scan"] = data
        self.write_context("comprehensive_scan", data)
    
    def _handle_endpoint_discovery(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Handle endpoint discovery results - already processed by _perform_endpoint_discovery"""
        # Data already written to discovered_endpoints by _perform_endpoint_discovery
        # Just update snapshot for consistency
        if isinstance(data, dict):
            snapshot["endpoint_discovery_completed"] = True
            self.log("info", f"✓ Endpoint discovery handler completed")

    def _handle_directory_scan(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process directory bruteforcing results and extract hidden paths"""
        if not isinstance(data, dict):
            return
        
        snapshot["directory_scan"] = data
        self.write_context("directory_scan", data)
        
        # Extract high-value findings
        sensitive_findings = []
        
        # Report sensitive files
        for sensitive_file in data.get('sensitive_files', []):
            self.add_finding(
                "WSTG-INFO-02",
                f"Sensitive file discovered: {sensitive_file['path']}",
                severity="medium",
                evidence={
                    "path": sensitive_file['path'],
                    "status_code": sensitive_file['status_code'],
                    "content_type": sensitive_file.get('content_type', ''),
                    "size": sensitive_file.get('size', 0)
                }
            )
            sensitive_findings.append(sensitive_file['path'])
        
        # Report backup files
        for backup_file in data.get('backup_files', []):
            self.add_finding(
                "WSTG-CONFIG-04",
                f"Backup file found: {backup_file['path']}",
                severity="high",
                evidence={
                    "path": backup_file['path'],
                    "status_code": backup_file['status_code'],
                    "risk": "Backup files may contain sensitive information or source code"
                }
            )
            sensitive_findings.append(backup_file['path'])
        
        # Report directory listings
        for dir_listing in data.get('directory_listings', []):
            self.add_finding(
                "WSTG-CONFIG-04",
                f"Directory listing enabled: {dir_listing['path']}",
                severity="low",
                evidence={
                    "path": dir_listing['path'],
                    "status_code": dir_listing['status_code'],
                    "risk": "Directory listing exposes internal structure"
                }
            )
        
        # Report config files
        for config_file in data.get('config_files', []):
            self.add_finding(
                "WSTG-CONFIG-04",
                f"Configuration file accessible: {config_file['path']}",
                severity="high",
                evidence={
                    "path": config_file['path'],
                    "status_code": config_file['status_code'],
                    "risk": "Configuration files may expose credentials or internal settings"
                }
            )
            sensitive_findings.append(config_file['path'])
        
        # Summary finding
        total_found = data.get('total_found', 0)
        total_checked = data.get('total_checked', 0)
        
        if total_found > 0:
            self.add_finding(
                "WSTG-INFO-07",
                f"Directory bruteforcing discovered {total_found} hidden paths",
                severity="info",
                evidence={
                    "total_checked": total_checked,
                    "total_found": total_found,
                    "api_endpoints": len(data.get('potential_apis', [])),
                    "sensitive_files": len(sensitive_findings),
                    "accessible_paths_sample": [p['path'] for p in data.get('accessible_paths', [])[:10]]
                }
            )
        
        # Share discovered paths with other agents
        all_paths = [p['path'] for p in data.get('accessible_paths', [])]
        self.write_context("hidden_paths", {
            "all_paths": all_paths,
            "sensitive_paths": sensitive_findings,
            "api_paths": [p['path'] for p in data.get('potential_apis', [])],
            "total_discovered": len(all_paths)
        })

    def _handle_ffuf_scan(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process ffuf scan results and add discovered endpoints to shared context"""
        if not isinstance(data, dict) or data.get("status") != "success":
            self.log("warning", "ffuf scan did not return valid data")
            return

        ffuf_data = data.get("data", {})
        snapshot["ffuf_scan"] = ffuf_data
        self.write_context("ffuf_scan", ffuf_data)

        endpoints = ffuf_data.get("endpoints", [])
        total_found = ffuf_data.get("total_found", 0)

        if total_found == 0:
            self.log("info", "ffuf found no additional endpoints")
            return

        # Convert ffuf results to discovered_endpoints format
        discovered_endpoints = []
        for ep in endpoints:
            url = ep.get("url", "")
            path = ep.get("path", "")
            status = ep.get("status", 0)

            # Categorize endpoint
            endpoint_type = "other"
            if "/api/" in path or "/rest/" in path:
                endpoint_type = "api"
            elif "admin" in path.lower():
                endpoint_type = "admin"
            elif "search" in path.lower():
                endpoint_type = "search"

            discovered_endpoints.append({
                "endpoint": path,
                "url": url,
                "method": "GET",  # ffuf tests GET by default
                "status_code": status,
                "type": endpoint_type,
                "source": "ffuf"
            })

        # Merge with existing discovered_endpoints from other sources
        existing_endpoints = self.shared_context.get("discovered_endpoints", {})
        if isinstance(existing_endpoints, dict):
            existing_list = existing_endpoints.get("endpoints", [])
        else:
            existing_list = []

        # Combine and deduplicate
        all_endpoints = existing_list + discovered_endpoints
        unique_endpoints = {ep["endpoint"]: ep for ep in all_endpoints}.values()
        unique_endpoints = list(unique_endpoints)

        # Update shared context with combined endpoints
        payload = {
            "endpoints": unique_endpoints,
            "count": len(unique_endpoints),
            "api_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "api"],
            "admin_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "admin"],
            "search_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "search"],
        }
        self.write_context("discovered_endpoints", payload)
        snapshot["discovered_endpoints"] = payload

        # Add finding
        self.add_finding(
            "WSTG-INFO",
            f"ffuf discovered {total_found} endpoints ({len(payload['api_endpoints'])} API, {len(payload['search_endpoints'])} search)",
            severity="info",
            evidence={
                "total_found": total_found,
                "api_count": len(payload["api_endpoints"]),
                "search_count": len(payload["search_endpoints"]),
                "sample": ffuf_data.get("sample", [])[:10]
            }
        )

        self.log("info", f"✓ ffuf scan found {total_found} endpoints, added to discovered_endpoints")

    def _handle_dirsearch_scan(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process dirsearch scan results with recursive endpoint discovery"""
        if not isinstance(data, dict) or data.get("status") != "success":
            self.log("warning", "dirsearch scan did not return valid data")
            return

        dirsearch_data = data.get("data", {})
        snapshot["dirsearch_scan"] = dirsearch_data
        self.write_context("dirsearch_scan", dirsearch_data)

        total_found = dirsearch_data.get("total_found", 0)

        if total_found == 0:
            self.log("info", "dirsearch found no endpoints (may need different wordlist or extensions)")
            return

        # Extract pre-categorized endpoints from dirsearch output
        endpoints = dirsearch_data.get("endpoints", [])
        api_endpoints_raw = dirsearch_data.get("api_endpoints", [])
        search_endpoints_raw = dirsearch_data.get("search_endpoints", [])
        admin_endpoints_raw = dirsearch_data.get("admin_endpoints", [])

        # Convert dirsearch results to discovered_endpoints format
        discovered_endpoints = []
        for ep in endpoints:
            url = ep.get("url", "")
            path = ep.get("path", "")
            status = ep.get("status", 0)

            # Determine endpoint type (dirsearch already categorized, but double-check)
            endpoint_type = "other"
            path_lower = path.lower()
            if "/api/" in path_lower or "/rest/" in path_lower or path.endswith(".json"):
                endpoint_type = "api"
            elif "admin" in path_lower or "dashboard" in path_lower:
                endpoint_type = "admin"
            elif "search" in path_lower:
                endpoint_type = "search"
            elif "upload" in path_lower or "file" in path_lower:
                endpoint_type = "upload"

            discovered_endpoints.append({
                "endpoint": path,
                "url": url,
                "method": "GET",  # dirsearch tests GET by default, but supports POST
                "status_code": status,
                "type": endpoint_type,
                "source": "dirsearch",
                "size": ep.get("size", 0),
                "redirect": ep.get("redirect")
            })

        # Merge with existing discovered_endpoints from other sources
        existing_endpoints = self.shared_context.get("discovered_endpoints", {})
        if isinstance(existing_endpoints, dict):
            existing_list = existing_endpoints.get("endpoints", [])
        else:
            existing_list = []

        # Combine and deduplicate by endpoint path
        all_endpoints = existing_list + discovered_endpoints
        unique_endpoints = {ep["endpoint"]: ep for ep in all_endpoints}.values()
        unique_endpoints = list(unique_endpoints)

        # Update shared context with combined endpoints
        payload = {
            "endpoints": unique_endpoints,
            "count": len(unique_endpoints),
            "api_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "api"],
            "admin_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "admin"],
            "search_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "search"],
            "upload_endpoints": [ep for ep in unique_endpoints if ep.get("type") == "upload"],
            "stats": dirsearch_data.get("stats", {})
        }
        self.write_context("discovered_endpoints", payload)
        snapshot["discovered_endpoints"] = payload

        # Add finding with detailed stats
        stats = dirsearch_data.get("stats", {})
        self.add_finding(
            "WSTG-INFO",
            f"dirsearch recursively discovered {total_found} endpoints ({len(payload['api_endpoints'])} API, {len(payload['search_endpoints'])} search, {len(payload['admin_endpoints'])} admin)",
            severity="info",
            evidence={
                "total_found": total_found,
                "api_count": len(payload["api_endpoints"]),
                "search_count": len(payload["search_endpoints"]),
                "admin_count": len(payload["admin_endpoints"]),
                "upload_count": len(payload.get("upload_endpoints", [])),
                "sample": dirsearch_data.get("sample", [])[:15],
                "stats": stats
            }
        )

        self.log("info", f"✓ dirsearch recursively found {total_found} endpoints (API: {len(payload['api_endpoints'])}, search: {len(payload['search_endpoints'])}, admin: {len(payload['admin_endpoints'])})")

    async def _perform_endpoint_discovery(self, target: str, baseline_snapshot: Dict[str, Any]) -> None:
        self.log("info", "🔎 Executing custom endpoint discovery crawl")
        try:
            endpoints = await self._discover_endpoints(target)
        except Exception as exc:
            self.log("warning", f"Endpoint discovery failed: {exc}")
            return

        if not endpoints:
            self.log("info", "Endpoint discovery produced no additional targets")
            return

        payload = {
            "endpoints": endpoints,
            "count": len(endpoints),
            "api_endpoints": [ep for ep in endpoints if "/api" in ep["endpoint"] or "/rest" in ep["endpoint"]],
            "admin_endpoints": [ep for ep in endpoints if "admin" in ep["endpoint"].lower()],
        }
        self.write_context("discovered_endpoints", payload)
        baseline_snapshot["discovered_endpoints"] = payload

        self.add_finding(
            "WSTG-INFO",
            f"Discovered {len(endpoints)} candidate endpoints",
            severity="info",
            evidence={"sample": [ep["endpoint"] for ep in endpoints[:10]]}
        )

    async def _discover_endpoints(self, target: str) -> List[Dict[str, Any]]:
        target_url = target if target.startswith(("http://", "https://")) else f"https://{target.lstrip('/')}"
        parsed = urlparse(target_url)
        scheme = parsed.scheme or "https"
        domain = parsed.netloc or parsed.path
        base_domain = domain.split(":")[0]
        base_url = f"{scheme}://{domain}"
        queue = deque([base_url])
        visited: set[str] = set()
        discovered: List[Dict[str, Any]] = []
        js_to_fetch: set[str] = set()
        js_candidates: set[str] = set()
        headers = {
            "User-Agent": "ReconnaissanceAgent/1.0",
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        }
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.ENDPOINT_DISCOVERY_TIMEOUT

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12, headers=headers) as http_client:
            while queue and len(discovered) < self.MAX_ENDPOINTS:
                if loop.time() > deadline:
                    self.log("warning", "Endpoint crawl deadline reached; returning partial results")
                    break

                url = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)

                try:
                    resp = await http_client.get(url)
                except Exception as exc:
                    self.log("debug", "Endpoint request failed", {"url": url, "error": str(exc)})
                    continue

                path = urlparse(url).path or "/"
                entry = {
                    "url": url,
                    "endpoint": path,
                    "status": resp.status_code,
                    "method": "GET",
                    "requires_auth": resp.status_code in (401, 403),
                    "content_type": resp.headers.get("content-type", ""),
                    "source": "crawl",
                }
                if not any(e["url"] == url for e in discovered):
                    discovered.append(entry)

                soup = BeautifulSoup(resp.text, "html.parser")

                for link in soup.find_all("a", href=True):
                    link_url = urljoin(url, link["href"])
                    link_parsed = urlparse(link_url)
                    if (
                        link_parsed.scheme in ("http", "https")
                        and link_parsed.netloc.split(":")[0].endswith(base_domain)
                        and link_url not in visited
                    ):
                        queue.append(link_url)

                for form in soup.find_all("form"):
                    action = form.get("action") or url
                    form_url = urljoin(url, action)
                    action_parsed = urlparse(form_url)
                    if (
                        action_parsed.scheme in ("http", "https")
                        and action_parsed.netloc.split(":")[0].endswith(base_domain)
                    ):
                        queue.append(form_url)

                for script in soup.find_all("script"):
                    src = script.get("src")
                    if src:
                        js_url = urljoin(url, src)
                        if urlparse(js_url).netloc.split(":")[0].endswith(base_domain):
                            js_to_fetch.add(js_url)
                    else:
                        js_candidates.update(self._extract_js_endpoints(script.string or ""))

            for js_url in list(js_to_fetch)[: self.MAX_JS_FILES]:
                if loop.time() > deadline:
                    break
                try:
                    js_resp = await http_client.get(js_url, timeout=6)
                except Exception:
                    continue
                js_candidates.update(self._extract_js_endpoints(js_resp.text))
                if not any(e["url"] == js_url for e in discovered):
                    discovered.append({
                        "url": js_url,
                        "endpoint": urlparse(js_url).path or "/",
                        "status": js_resp.status_code,
                        "method": "GET",
                        "requires_auth": False,
                        "content_type": js_resp.headers.get("content-type", ""),
                        "source": "javascript",
                    })

            meta_paths: List[str] = []
            try:
                robots_resp = await http_client.get(f"{base_url.rstrip('/')}/robots.txt", timeout=6)
                if robots_resp.status_code == 200 and robots_resp.text:
                    for line in robots_resp.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                meta_paths.append(path if path.startswith("/") else f"/{path}")
            except Exception:
                pass

            try:
                sitemap_resp = await http_client.get(f"{base_url.rstrip('/')}/sitemap.xml", timeout=6)
                if sitemap_resp.status_code == 200 and sitemap_resp.text:
                    meta_paths.extend(re.findall(r"<loc>(.*?)</loc>", sitemap_resp.text))
            except Exception:
                pass

            for meta in meta_paths[:50]:
                if loop.time() > deadline:
                    break
                full_url = meta if meta.startswith("http") else f"{base_url.rstrip('/')}{meta if meta.startswith('/') else '/' + meta}"
                full_parsed = urlparse(full_url)
                if full_parsed.netloc and not full_parsed.netloc.split(":")[0].endswith(base_domain):
                    continue
                if any(e["url"] == full_url for e in discovered):
                    continue
                discovered.append({
                    "url": full_url,
                    "endpoint": full_parsed.path or "/",
                    "status": 200,
                    "method": "GET",
                    "requires_auth": False,
                    "content_type": "",
                    "source": "meta",
                })

        if js_candidates and len(discovered) < self.MAX_ENDPOINTS:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=6, headers=headers) as http_client:
                for candidate in list(js_candidates)[: self.MAX_ENDPOINTS]:
                    if loop.time() > deadline or len(discovered) >= self.MAX_ENDPOINTS:
                        break
                    full_url = candidate
                    if not candidate.startswith("http"):
                        full_url = f"{scheme}://{domain}{candidate if candidate.startswith('/') else '/' + candidate}"
                    try:
                        resp = await http_client.get(full_url)
                    except Exception:
                        continue
                    if any(e["url"] == full_url for e in discovered):
                        continue
                    discovered.append({
                        "url": full_url,
                        "endpoint": urlparse(full_url).path or "/",
                        "status": resp.status_code,
                        "method": "GET",
                        "requires_auth": resp.status_code in (401, 403),
                        "content_type": resp.headers.get("content-type", ""),
                        "source": "javascript",
                    })

        return discovered[: self.MAX_ENDPOINTS]

    def _extract_js_endpoints(self, content: str) -> set[str]:
        endpoints: set[str] = set()
        if not content:
            return endpoints

        patterns = [
            r"\"(/(?:api|rest|graphql)[^\"']*)\"",
            r"'(/(?:api|rest|graphql)[^\"']*)'",
            r"fetch\([\"']([^\"']+)[\"']",
            r"axios\.(?:get|post|put|delete|patch)\([\"']([^\"']+)[\"']",
            r"url\s*:\s*[\"']([^\"']+)[\"']",
            r"endpoint\s*:\s*[\"']([^\"']+)[\"']",
            r"\$http\.(?:get|post|put|delete)\([\"']([^\"']+)[\"']",
            r"http\.(?:get|post|put|delete)\([\"']([^\"']+)[\"']",
            r"HttpClient\.(?:get|post|put|delete)\([\"']([^\"']+)[\"']",
            r"[\"'](/[a-zA-Z0-9_/-]+/search[^\"']*)[\"']",
            r"[\"'](/[a-zA-Z0-9_/-]+/products[^\"']*)[\"']",
            r"[\"'](/[a-zA-Z0-9_/-]+/users?[^\"']*)[\"']",
            r"[\"'](/[a-zA-Z0-9_/-]+/orders?[^\"']*)[\"']",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, content, re.IGNORECASE):
                if isinstance(match, tuple):
                    match = match[-1]
                if not match:
                    continue
                if not match.startswith("http") and not match.startswith("/"):
                    match = f"/{match}"
                endpoints.add(match)
        return endpoints

    async def _attempt_auto_login(self, target: str, baseline_snapshot: Dict[str, Any]) -> None:
        import sys
        print("🟣🟣🟣 [AUTOLOGIN TRACE] _attempt_auto_login() ENTERED", file=sys.stderr, flush=True)
        print(f"🟣 [AUTOLOGIN TRACE] Target: {target}", file=sys.stderr, flush=True)

        self.log("warning", "🔐 [PHASE 4 DEBUG] _attempt_auto_login STARTED")
        self.log("warning", f"🔐 [PHASE 4 DEBUG] Target: {target}")

        try:
            print("🟣 [AUTOLOGIN TRACE] About to initialize SessionManager...", file=sys.stderr, flush=True)
            self.log("warning", "🔐 [PHASE 4 DEBUG] Initializing SessionManager...")
            session_mgr = SessionManager(target)
            print(f"🟣 [AUTOLOGIN TRACE] SessionManager created: {type(session_mgr)}", file=sys.stderr, flush=True)
            self.log("warning", f"🔐 [PHASE 4 DEBUG] SessionManager created: {type(session_mgr)}")
        except Exception as exc:
            self.log("error", f"🔐 [PHASE 4 DEBUG] SessionManager init FAILED: {exc}")
            import traceback
            self.log("error", f"🔐 [PHASE 4 DEBUG] Traceback: {traceback.format_exc()}")
            return

        try:
            print("🟣 [AUTOLOGIN TRACE] About to call session_mgr.auto_login() with 120s timeout...", file=sys.stderr, flush=True)
            self.log("warning", "🔐 [PHASE 4 DEBUG] Calling session_mgr.auto_login()...")
            results = await self.run_tool_with_timeout(session_mgr.auto_login(), timeout=120)
            print(f"🟣 [AUTOLOGIN TRACE] auto_login() returned: {type(results)}", file=sys.stderr, flush=True)
            self.log("warning", f"🔐 [PHASE 4 DEBUG] Auto-login returned: {type(results)}, keys: {results.keys() if isinstance(results, dict) else 'N/A'}")
        except Exception as exc:
            self.log("error", f"🔐 [PHASE 4 DEBUG] Auto-login coroutine FAILED: {exc}")
            import traceback
            self.log("error", f"🔐 [PHASE 4 DEBUG] Traceback: {traceback.format_exc()}")
            return

        if not isinstance(results, dict):
            return

        baseline_snapshot["auth"] = results
        if results.get("successful_logins"):
            payload = {
                "app_type": results.get("app_type"),
                "sessions": session_mgr.get_session_info(),
                "successful_logins": results["successful_logins"],
            }
            self.write_context("authenticated_sessions", payload)
            self.add_finding(
                "WSTG-ATHN",
                f"Auto-login succeeded for {len(results['successful_logins'])} account(s)",
                severity="info",
                evidence={"users": [acct.get("username") for acct in results["successful_logins"]]}
            )
        else:
            self.log("warning", f"Auto-login failed ({results.get('failed_attempts', 0)} attempts)")

    async def _post_baseline_analysis(self, baseline_snapshot: Dict[str, Any], client: MCPClient) -> None:
        if not getattr(self, "_llm_client", None):
            self.log("warning", "Tiered autonomy analysis skipped - LLM client unavailable")
            return

        prompt = self._build_analysis_prompt(baseline_snapshot)
        follow_up_keys = ", ".join(self.FOLLOW_UP_TOOL_BUILDERS.keys())
        messages = [
            {
                "role": "system",
                "content": (
                    "You are the analytical brain for ReconnaissanceAgent. "
                    "Review deterministic scan data, highlight the riskiest findings, and propose high-signal follow-up MCP tools. "
                    f"Follow-up tool keys available: {follow_up_keys}. "
                    "Respond ONLY with compact JSON using this schema: {"
                    "\"risk_summary\": [\"short bullet\"], "
                    "\"follow_up_tools\": [{\"tool\": \"name\", \"reason\": \"why next\"}], "
                    "\"context_updates\": {\"key\": {...}}"
                    "}. No markdown, no prose, no code fences."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self._llm_client.chat_completion(messages, max_tokens=1200)
        except Exception as e:
            self.log("warning", f"Tiered autonomy summary failed: {e}")
            return

        report = self._parse_llm_json(response)
        if not isinstance(report, dict):
            self.log("warning", "LLM summary not parsed as JSON", {"snippet": str(response)[:200]})
            return

        if report.get("risk_summary"):
            self.add_finding(
                "WSTG-INFO",
                "Recon analytic summary",
                severity="info",
                evidence={"highlights": report["risk_summary"][:5]},
            )
            self.write_context("recon_summary", {"insights": report["risk_summary"]})

        context_updates = report.get("context_updates")
        if isinstance(context_updates, dict):
            for key, value in context_updates.items():
                payload = self._normalize_context_payload(value)
                if payload is not None:
                    self.write_context(key, payload)

        await self._execute_follow_up_tools(report.get("follow_up_tools") or [], client, baseline_snapshot)

    def _build_analysis_prompt(self, baseline_snapshot: Dict[str, Any]) -> str:
        # Compress to fit context limits
        compressed_baseline = self._compress_baseline(baseline_snapshot)
        compressed_context = self._compress_shared_context(self.shared_context or {})
        follow_up_options = ", ".join(self.FOLLOW_UP_TOOL_BUILDERS.keys())
        return (
            "Reconnaissance baseline (COMPRESSED):\n"
            f"{compressed_baseline}\n\n"
            "Shared context from previous agents (COMPRESSED):\n"
            f"{compressed_context}\n\n"
            f"Tasks: 1) Summarize notable risks. 2) Suggest up to 3 follow-up MCP tools using these exact keys: {follow_up_options}. "
            "3) Propose any context_updates that downstream agents will care about (credentials, prioritized entry points, tech stack)."
        )
    
    def _compress_baseline(self, baseline: Dict[str, Any]) -> str:
        """Compress baseline to <1500 tokens"""
        parts = []
        
        # Tech stack (most important - keep full)
        if "fingerprint" in baseline:
            fp = baseline["fingerprint"]
            tech = fp.get("tech_stack", {}) if isinstance(fp, dict) else {}
            if tech:
                parts.append(f"TECH: {json.dumps(tech, indent=None)}")
        
        # Entry points (top 10 only)
        if "entry_points" in baseline:
            eps = baseline["entry_points"].get("endpoints", [])[:10] if isinstance(baseline["entry_points"], dict) else []
            if eps:
                ep_summary = [f"{ep.get('method', 'GET')} {ep.get('endpoint', '/')}" for ep in eps]
                parts.append(f"ENTRY POINTS ({len(eps)} shown): " + ", ".join(ep_summary))
        
        # Meta files
        if "metafiles" in baseline:
            meta = baseline["metafiles"]
            if isinstance(meta, dict):
                found = [k for k, v in meta.items() if isinstance(v, dict) and v.get("found")]
                if found:
                    parts.append(f"META FILES: {', '.join(found)}")
        
        # Auth results
        if "auth" in baseline:
            auth = baseline["auth"]
            if isinstance(auth, dict) and auth.get("successful_logins"):
                users = [acc.get("username") for acc in auth["successful_logins"]]
                parts.append(f"AUTH: Logged in as {', '.join(users[:5])}")
        
        return "\n".join(parts)
    
    def _compress_shared_context(self, ctx: Dict[str, Any]) -> str:
        """Compress shared context to <500 tokens"""
        if not ctx:
            return "Empty"
        
        parts = []
        if "tech_stack" in ctx:
            parts.append(f"TECH: {json.dumps(ctx['tech_stack'], indent=None)[:200]}")
        
        if "entry_points" in ctx:
            ep_count = len(ctx["entry_points"]) if isinstance(ctx["entry_points"], list) else "unknown"
            parts.append(f"ENTRY POINTS: {ep_count} total")
        
        if "authenticated_sessions" in ctx:
            parts.append("SESSIONS: Active")
        
        return " | ".join(parts) if parts else "Minimal context"

    def _parse_llm_json(self, blob: str) -> Dict[str, Any] | None:
        if not blob:
            return None
        candidates = [blob.strip()]
        stripped = self._strip_code_fences(blob)
        if stripped != blob:
            candidates.append(stripped)
        json_block = self._extract_first_json_block(blob)
        if json_block:
            candidates.append(json_block)
        if stripped != blob:
            json_block_2 = self._extract_first_json_block(stripped)
            if json_block_2:
                candidates.append(json_block_2)
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except Exception:
                continue
        return None

    def _strip_code_fences(self, text: str) -> str:
        trimmed = text.strip()
        if trimmed.startswith("```"):
            lines = trimmed.splitlines()
            lines = lines[1:] if len(lines) > 1 else []
            while lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            return "\n".join(lines).strip()
        return trimmed

    def _extract_first_json_block(self, text: str) -> str | None:
        for opener, closer in (("{", "}"), ("[", "]")):
            starts = [idx for idx, ch in enumerate(text) if ch == opener]
            for start in starts:
                depth = 0
                for idx in range(start, len(text)):
                    char = text[idx]
                    if char == opener:
                        depth += 1
                    elif char == closer:
                        depth -= 1
                        if depth == 0:
                            candidate = text[start:idx + 1]
                            try:
                                json.loads(candidate)
                                return candidate
                            except Exception:
                                break
        return None

    def _normalize_context_payload(self, value: Any) -> Dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        return {"value": value}

    async def _execute_follow_up_tools(self, follow_ups: List[Dict[str, Any]], client: MCPClient, baseline_snapshot: Dict[str, Any]) -> None:
        if not follow_ups:
            self.log("info", "LLM analysis did not request follow-up MCP tools")
            return

        max_runs = 3
        for follow in follow_ups[:max_runs]:
            tool_key = follow.get("tool")
            if not tool_key or tool_key not in self.FOLLOW_UP_TOOL_BUILDERS:
                continue
            builder = self.FOLLOW_UP_TOOL_BUILDERS[tool_key]
            arg_value = self._resolve_value_source(builder.get("value_source"), baseline_snapshot)
            if arg_value is None:
                self.log("debug", "Skipping follow-up due to missing argument", {"tool": tool_key})
                continue
            args = {builder["arg_name"]: arg_value}
            try:
                result = await self.run_tool_with_timeout(
                    client.call_tool(
                        server=builder["server"],
                        tool=builder["tool"],
                        args=args,
                    )
                )
            except Exception as e:
                self.log("warning", f"Follow-up tool {tool_key} failed: {e}")
                self.record_tool_failure(tool_key, str(e))
                continue

            if not isinstance(result, dict) or result.get("status") != "success":
                self.log("warning", f"Follow-up tool {tool_key} returned non-success status", {"status": result})
                continue

            context_key = builder.get("context_key") or f"{tool_key}_followup"
            payload = result.get("data") if isinstance(result, dict) else result
            if not isinstance(payload, dict):
                payload = {"value": payload}
            self.write_context(context_key, payload)
            self.add_finding(
                "WSTG-INFO",
                f"Follow-up tool executed: {tool_key}",
                severity="info",
                evidence={"reason": follow.get("reason"), "context_key": context_key}
            )

    def _resolve_value_source(self, source: Optional[str], baseline_snapshot: Dict[str, Any]) -> Any:
        if not source:
            return None
        if source == "domain":
            return baseline_snapshot.get("domain")
        if source == "target":
            return baseline_snapshot.get("target")
        if source.startswith("context."):
            ctx_key = source.split(".", 1)[1]
            return self.shared_context.get(ctx_key)
        return baseline_snapshot.get(source)

    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None

    def _domain_from_target(self, target: str) -> str:
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                return parsed.netloc
            return target.split("/")[0]
        except Exception:
            return target
