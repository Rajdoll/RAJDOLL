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


async def build_endpoint_inventory(
    hostname: str,
    endpoints: list[dict],
    classifier,
    captured_ids: dict | None = None,
    phase_stats: dict | None = None,
) -> dict:
    """Compose the final endpoint_inventory payload.

    1. Assign stable ids ep_001..ep_NNN.
    2. Resolve {id}-style placeholders using captured_ids.
    3. LLM-classify (cache-aware).
    4. Build the by_tag index.
    """
    from ..core.endpoint_inventory import build_inventory, resolve_placeholders

    captured_ids = captured_ids or {}

    # 1. Assign ids
    numbered = []
    for idx, ep in enumerate(endpoints, start=1):
        new = dict(ep)
        new.setdefault("id", f"ep_{idx:03d}")
        numbered.append(new)

    # 2. Resolve placeholders
    resolved = resolve_placeholders(numbered, captured_ids)

    # 3. Classify
    tagged = await classifier.classify(hostname, resolved)

    # 4. Build inventory
    return build_inventory(tagged, stats={"by_phase": phase_stats or {}})


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

    def _brief_tool_result(self, result: Any) -> str:
        """Summarize a tool result for human-readable logs (safe for None/odd types)."""
        if result is None:
            return "type=None"
        if isinstance(result, dict):
            status = result.get("status")
            error = result.get("error") or result.get("message") or result.get("detail")
            keys = list(result.keys())
            key_preview = keys[:10]
            error_str = ""
            if isinstance(error, str) and error.strip():
                error_str = error.strip()[:160]
            return (
                f"type=dict status={status!r}"
                + (f" error={error_str!r}" if error_str else "")
                + f" keys={key_preview!r}"
            )
        if isinstance(result, str):
            sample = result.strip().replace("\n", " ")
            return f"type=str len={len(result)} sample={sample[:160]!r}"
        if isinstance(result, list):
            return f"type=list len={len(result)}"
        return f"type={type(result).__name__}"

    @staticmethod
    def _is_http_200(item: Dict[str, Any]) -> bool:
        try:
            return int(item.get("status_code", 0)) == 200
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _recon_noise_meta(proof_type: str = "heuristic") -> Dict[str, Any]:
        return {
            "proof_type": proof_type,
            "impact_class": "supporting_context",
            "_meta": {
                "finding_state": "lead",
                "reportability_status": "needs_validation",
                "evidence_quality": "weak",
                "proof_type": proof_type,
                "impact_class": "supporting_context",
            },
        }

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
        "feroxbuster_scan": {
            "server": "information-gathering",
            "tool": "feroxbuster_scan",
            "priority": "CRITICAL",  # CRITICAL: 8-10x faster than dirsearch (Rust-based async)
            "arg_builder": lambda target, domain: {
                "target_url": target,
                "depth": 3,  # Recursive depth
                "extensions": "php,html,json,txt,js,xml,asp,aspx,jsp",
                "threads": 50,
                "timeout": 300  # 5 minutes (vs 10 min for dirsearch)
            },
            "handler": "_handle_feroxbuster_scan",
            "timeout": 360,  # 6 minutes total timeout
        },
        "ffuf_directory_scan": {
            "server": "information-gathering",
            "tool": "ffuf_directory_scan",
            "priority": "HIGH",  # HIGH: Parameter fuzzing & hidden file discovery
            "arg_builder": lambda target, domain: {
                "target_url": target,
                "wordlist": None,  # Auto-select
                "extensions": "php,html,json,txt,js,xml,bak,old,zip",
                "filter_status": "404,403",
                "threads": 40,
                "timeout": 180
            },
            "handler": "_handle_ffuf_scan",
            "timeout": 240,
        },
        "dirsearch_scan_legacy": {
            "server": "information-gathering",
            "tool": "dirsearch_scan",
            "priority": "LOW",  # LEGACY: Replaced by feroxbuster (kept as backup)
            "arg_builder": lambda target, domain: {
                "target_url": target,
                "recursive": True,
                "recursion_depth": 3,
                "extensions": "php,html,json,txt,js,xml,asp,aspx,jsp",
                "threads": 50
            },
            "handler": "_handle_dirsearch_scan",
            "timeout": 600,
        },
        "discover_endpoints": {
            "server": "local",  # Runs locally using _discover_endpoints
            "tool": "_perform_endpoint_discovery",
            "priority": "HIGH",  # Still important for JavaScript endpoint mining
            "arg_builder": lambda target, domain: {"target": target},
            "handler": "_handle_endpoint_discovery",
            "timeout": 240,
        },
        "rest_endpoint_discovery": {
            "server": "information-gathering",
            "tool": "discover_rest_endpoints",
            "priority": "HIGH",
            "arg_builder": lambda target, domain: {
                "target_url": target,
                "existing_endpoints": [],
            },
            "timeout": 60,
        },
        "katana_js_crawl": {
            "server": "katana-crawler",
            "tool": "crawl_with_js_parsing",
            "priority": "HIGH",  # Non-headless: fast, no Chromium timeout. REST discoverer handles API depth.
            "arg_builder": lambda target, domain: {
                "url": target,
                "depth": 3,
                "js_parsing": True,
                "headless": False,  # Non-headless: fast, no Chromium timeout. REST discoverer handles API depth.
                "config": {"timeout": 120, "concurrency": 10, "rate_limit": 150}
            },
            "handler": "_handle_katana_crawl",
            "timeout": 140,
        },
        "analyze_javascript_routes": {
            "server": "information-gathering",
            "tool": "analyze_javascript_routes",
            "priority": "HIGH",  # HIGH: Discovers hidden routes, secrets, API endpoints in JS
            "arg_builder": lambda target, domain: {"url": target},
            "handler": "_handle_js_routes_analysis",
            "timeout": 120,
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
    
    async def _execute_local_tool(
        self,
        tool_name: str,
        config: Dict[str, Any],
        args: Dict[str, Any],
        baseline_snapshot: Dict[str, Any],
    ) -> Dict[str, Any]:
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

        if tool_name == "discover_endpoints":
            target = args.get("target") or args.get("target_url") or args.get("url")
            if not target:
                return {"status": "error", "error": "Missing target for endpoint discovery"}
            timeout = int(config.get("timeout") or 180)
            try:
                await asyncio.wait_for(self._perform_endpoint_discovery(target, baseline_snapshot), timeout=timeout)
            except asyncio.TimeoutError:
                self.log("warning", f"discover_endpoints timed out after {timeout}s; continuing with partial endpoint inventory")
                self.record_tool_failure("discover_endpoints", f"timeout after {timeout}s")
            inventory = self.shared_context.get("endpoint_inventory") or self.shared_context.get("discovered_endpoints")
            return {"status": "success", "data": inventory or {"endpoints": [], "count": 0}}
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

        await self._fallback_js_api_extraction(target, baseline_snapshot)

        print("🔴 [STDERR TRACE] About to call _perform_endpoint_discovery()", file=sys.stderr, flush=True)
        try:
            await asyncio.wait_for(self._perform_endpoint_discovery(target, baseline_snapshot), timeout=3600)
        except asyncio.TimeoutError:
            self.log("warning", "Endpoint discovery timed out after 600s; continuing with partial endpoint inventory")
            self.record_tool_failure("perform_endpoint_discovery", "timeout after 600s")
        self.log("warning", "🔐 [PHASE 4 DEBUG] Endpoint discovery COMPLETE")
        print("🔴 [STDERR TRACE] _perform_endpoint_discovery() COMPLETED", file=sys.stderr, flush=True)

        # Merge auth_discovered_links AFTER all discovery tools — reads live DB state
        # Fills the gap when Katana fails on targets like DVWA (old Apache/PHP apps)
        self._merge_auth_discovered_links(baseline_snapshot)

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

    def _merge_auth_discovered_links(self, baseline_snapshot: Dict[str, Any]) -> None:
        """Merge links extracted from authenticated home page into discovered_endpoints.
        Reads both auth_discovered_links and discovered_endpoints from live DB state
        so the merge sees everything collected by the discovery tools above.
        """
        auth_links_data = self._shared_context_snapshot.get("auth_discovered_links", {})
        urls = auth_links_data.get("urls", []) if isinstance(auth_links_data, dict) else []
        if not urls:
            return
        self.log("info", f"[Recon] Merging {len(urls)} auth_discovered_links into discovered_endpoints")
        # Read live DB state (not stale snapshot) so we see what discovery tools wrote
        existing = self.context_manager.read("discovered_endpoints") or {}
        existing_eps = existing.get("endpoints", []) if isinstance(existing, dict) else []
        existing_urls = {ep.get("url", ep.get("endpoint", "")) for ep in existing_eps}
        new_eps = []
        for url in urls:
            if url not in existing_urls:
                path = url.split("://", 1)[-1].split("/", 1)[-1]
                path = f"/{path}" if not path.startswith("/") else path
                new_eps.append({
                    "url": url, "endpoint": path,
                    "status": 200, "method": "GET",
                    "requires_auth": True, "source": "auth_link"
                })
        all_eps = existing_eps + new_eps
        self.write_context("discovered_endpoints", {"endpoints": all_eps, "count": len(all_eps)})
        self.log("info", f"[Recon] discovered_endpoints now has {len(all_eps)} total endpoints ({len(new_eps)} from auth links)")

    async def _collect_baseline_data(self, client: MCPClient, target: str, domain: str, baseline_snapshot: Dict[str, Any]) -> None:
        baseline_snapshot.setdefault("baseline_results", {})
        prior_stack = self.shared_context.get("tech_stack")
        if isinstance(prior_stack, dict):
            baseline_snapshot["tech_stack"] = copy.deepcopy(prior_stack)
        else:
            baseline_snapshot["tech_stack"] = {}

        # Use a stable, optimized execution order (dict order, with a small override)
        tool_order = list(self.BASELINE_TOOL_MATRIX.keys())
        # Run JS/endpoint discovery earlier so long-running legacy scanners don't block it.
        promote_after = "map_execution_paths" if "map_execution_paths" in tool_order else None
        if promote_after:
            insert_at = tool_order.index(promote_after) + 1
            for promoted in ["discover_endpoints", "katana_js_crawl"]:
                if promoted in tool_order:
                    tool_order.remove(promoted)
                    tool_order.insert(insert_at, promoted)
                    insert_at += 1

        for tool_name in tool_order:
            config = self.BASELINE_TOOL_MATRIX[tool_name]
            if not self.should_run_tool(tool_name):
                self.log("debug", f"Skipping {tool_name} (not in plan or circuit breaker)")
                continue

            arg_builder = config.get("arg_builder") or (lambda _target, d: {"domain": d})
            try:
                args = arg_builder(target, domain)
            except Exception as arg_err:
                self.log("warning", f"Failed to build args for {tool_name}: {arg_err}")
                continue

            # Inject auth cookies into Katana so it crawls authenticated paths
            if tool_name == "katana_js_crawl":
                auth = self.get_auth_session() or {}
                if auth.get("cookies"):
                    cookies_str = "; ".join(f"{k}={v}" for k, v in auth["cookies"].items())
                    args["cookies"] = cookies_str
                    self.log("info", f"[Recon] Injecting auth cookies into Katana: {list(auth['cookies'].keys())}")

            # Handle local tools (non-MCP)
            if config["server"] == "local":
                try:
                    result = await self._execute_local_tool(tool_name, config, args, baseline_snapshot)
                except Exception as exc:
                    self.log("warning", f"{tool_name} (local) failed: {exc}")
                    self.record_tool_failure(tool_name, str(exc))
                    continue
            else:
                # Execute via MCP
                if tool_name == "katana_js_crawl":
                    result = await self._execute_katana_with_fallback(client, config, args)
                else:
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
                self.log(
                    "warning",
                    f"{tool_name} returned non-success: {self._brief_tool_result(result)}",
                    {"result": result},
                )
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

    async def _execute_katana_with_fallback(
        self,
        client: MCPClient,
        config: Dict[str, Any],
        args: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run Katana crawl with a fallback profile when headless JS crawl times out/fails."""

        def _extract_katana_payload(result: Any) -> Optional[Dict[str, Any]]:
            """Best-effort extraction of the Katana payload across wrapper shapes."""
            if not isinstance(result, dict):
                return None

            # Shape A (Katana server): {status: success, data: {...}}
            if result.get("status") == "success" and isinstance(result.get("data"), dict):
                return result["data"]

            # Shape B (MCP wrapper): {status: success, data: {status: success, data: {...}}}
            nested = result.get("data")
            if isinstance(nested, dict) and nested.get("status") == "success" and isinstance(nested.get("data"), dict):
                return nested["data"]

            # Shape C (already-unwrapped payload): {endpoints: [...], total_found: N, ...}
            if "endpoints" in result or "total_found" in result:
                return result

            return None

        def _katana_payload_is_useful(payload: Optional[Dict[str, Any]]) -> bool:
            if not isinstance(payload, dict):
                return False
            endpoints = payload.get("endpoints")
            total_found = payload.get("total_found")
            if isinstance(total_found, int) and total_found > 0:
                return True
            if isinstance(endpoints, list) and len(endpoints) > 0:
                return True
            return False

        async def _run_katana(run_args: Dict[str, Any], timeout: Optional[int]) -> Dict[str, Any]:
            return await self.run_tool_with_timeout(
                client.call_tool(
                    server=config["server"],
                    tool=config.get("tool", "crawl_with_js_parsing"),
                    args=run_args,
                ),
                timeout=timeout,
            )

        # Primary attempt (as configured)
        try:
            primary_result = await _run_katana(args, config.get("timeout"))
        except Exception as exc:
            err = str(exc).strip() or exc.__class__.__name__
            primary_result = {"status": "error", "error": err}
            self.log("warning", f"katana_js_crawl primary attempt failed: {err}")
            self.record_tool_failure("katana_js_crawl", err)

        if isinstance(primary_result, dict) and primary_result.get("status") == "success":
            payload = _extract_katana_payload(primary_result)
            # If headless returns an "OK" status but no meaningful endpoints, try a safer fallback.
            if _katana_payload_is_useful(payload):
                return primary_result
            self.log(
                "warning",
                "katana_js_crawl primary returned empty/invalid payload; attempting fallback",
                {"headless": bool(args.get("headless")), "has_payload": bool(payload)},
            )

        # Fallback: disable headless, reduce depth, shorten server-side timeout to avoid long stalls.
        fallback_args = dict(args)
        fallback_args["headless"] = False
        fallback_args["depth"] = min(int(fallback_args.get("depth") or 3), 2)
        fallback_config = dict((fallback_args.get("config") or {}))
        fallback_config.setdefault("timeout", 120)
        fallback_config.setdefault("concurrency", 10)
        fallback_config.setdefault("rate_limit", 150)
        fallback_args["config"] = fallback_config

        try:
            fallback_result = await _run_katana(fallback_args, min(int(config.get("timeout") or 320), 160))
        except Exception as exc:
            err = str(exc).strip() or exc.__class__.__name__
            self.log("warning", f"katana_js_crawl fallback attempt failed: {err}")
            self.record_tool_failure("katana_js_crawl", err)
            return primary_result

        if isinstance(fallback_result, dict) and fallback_result.get("status") == "success":
            self.log("info", "katana_js_crawl fallback succeeded")
            return fallback_result

        self.log("warning", "katana_js_crawl fallback returned non-success", {"result": fallback_result})
        return primary_result

        self.log("info", "Retrying Katana crawl without headless JS execution")
        try:
            return await _run_katana(fallback_args, timeout=min(int(config.get("timeout") or 320), 160))
        except Exception as exc:
            self.log("warning", f"katana_js_crawl fallback attempt failed: {exc}")
            self.record_tool_failure("katana_js_crawl_fallback", str(exc))
            return {"status": "error", "error": str(exc), "fallback": True}

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
                severity="low",
                evidence={
                    "missing": missing[:10],
                    **self._recon_noise_meta("heuristic"),
                }
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
                evidence={
                    "comment_count": comment_count,
                    **self._recon_noise_meta("source_observation"),
                },
            )
        if payload.get("emails_found"):
            self.add_finding(
                "WSTG-INFO",
                "Email addresses leaked in page source",
                severity="low",
                evidence={"emails": payload["emails_found"][:5]}
            )

    @staticmethod
    def _extract_hostname_from_url(url: str) -> str | None:
        """Extract hostname from URL for scope partitioning."""
        if not url:
            return None
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            return (parsed.hostname or "").lower() or None
        except Exception:
            return None

    def _handle_osint(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return

        findings = data.get("findings", {})

        # Layer 3: Partition findings by scope
        from ..core.security_guards import security_guard

        def _partition(items, host_extractor):
            in_scope, out_scope = [], []
            for item in items:
                h = host_extractor(item)
                if h and security_guard.is_host_allowed(h):
                    in_scope.append(item)
                else:
                    out_scope.append(item)
            return in_scope, out_scope

        # Subdomains
        subs_in, subs_out = _partition(
            findings.get("subdomains_found", []), lambda s: s.lower())
        findings["subdomains_found"] = subs_in
        findings["subdomains_out_of_scope"] = subs_out

        # Emails
        emails_in, emails_out = _partition(
            findings.get("emails_found", []),
            lambda e: e.split("@")[-1] if "@" in e else None)
        findings["emails_found"] = emails_in
        findings["emails_out_of_scope"] = emails_out

        # URL fields
        for field in ("exposed_documents", "admin_panels", "directory_listings",
                      "backup_files", "pastebin_mentions"):
            urls_in, urls_out = _partition(
                findings.get(field, []),
                lambda u: self._extract_hostname_from_url(u))
            findings[field] = urls_in
            findings[f"{field}_out_of_scope"] = urls_out

        # Summary
        data["out_of_scope_summary"] = {
            "subdomain_count": len(subs_out),
            "email_count": len(emails_out),
            "url_count": sum(
                len(findings.get(f"{f}_out_of_scope", []))
                for f in ("exposed_documents", "admin_panels",
                          "directory_listings", "backup_files", "pastebin_mentions")
            ),
        }

        snapshot["osint"] = data
        self.write_context("osint", data)

        # Only create findings from in-scope admin panels
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
                evidence={
                    "paths": robots[:5],
                    **self._recon_noise_meta("source_observation"),
                }
            )

    def _handle_entry_points(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        entry_points = data.get("entry_points") if isinstance(data, dict) else None
        if not entry_points:
            return
        snapshot["entry_points"] = entry_points
        self.write_context("entry_points", entry_points)

        api_endpoints = entry_points.get("api_endpoints") or []
        self.log("info", f"Identified {entry_points.get('urls_found', 0)} entry URLs and {len(api_endpoints)} API endpoints")

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
                evidence={
                    "sample": data["hidden_paths"][:5],
                    **self._recon_noise_meta("inventory_only"),
                }
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

        # Well-known disclosure files that are intentionally public — never a backup or
        # sensitive disclosure on their own. Promotions of these to high/medium produce
        # noise (e.g. `/robots.txt` flagged as "Backup file") and pollute auto-validation.
        well_known_public_paths = {
            "/robots.txt",
            "/sitemap.xml",
            "/humans.txt",
            "/security.txt",
            "/.well-known/security.txt",
            "/.well-known/change-password",
            "/favicon.ico",
            "/ads.txt",
        }

        def _is_well_known_public(entry: Dict[str, Any]) -> bool:
            path = str(entry.get("path", "")).lower()
            return path in well_known_public_paths

        # Extract high-value findings
        sensitive_findings = []

        # Report sensitive files
        for sensitive_file in data.get('sensitive_files', []):
            if not self._is_http_200(sensitive_file):
                continue
            if _is_well_known_public(sensitive_file):
                self.add_finding(
                    "WSTG-INFO-02",
                    f"Well-known public file present: {sensitive_file['path']}",
                    severity="info",
                    evidence={
                        "path": sensitive_file['path'],
                        "status_code": sensitive_file['status_code'],
                        "proof_type": "inventory_only",
                        "impact": "Standard disclosure file — informational only",
                    },
                )
                continue
            self.add_finding(
                "WSTG-INFO-02",
                f"Sensitive file discovered: {sensitive_file['path']}",
                severity="medium",
                evidence={
                    "path": sensitive_file['path'],
                    "status_code": sensitive_file['status_code'],
                    "content_type": sensitive_file.get('content_type', ''),
                    "size": sensitive_file.get('size', 0),
                    "proof_type": "accessible_file",
                    "impact": "Sensitive file returned HTTP 200 and may disclose internal metadata"
                }
            )
            sensitive_findings.append(sensitive_file['path'])

        # Report backup files
        for backup_file in data.get('backup_files', []):
            if not self._is_http_200(backup_file):
                continue
            if _is_well_known_public(backup_file):
                self.add_finding(
                    "WSTG-CONF-04",
                    f"Well-known public file present: {backup_file['path']}",
                    severity="info",
                    evidence={
                        "path": backup_file['path'],
                        "status_code": backup_file['status_code'],
                        "proof_type": "inventory_only",
                        "impact": "Standard disclosure file — not a backup",
                    },
                )
                continue
            self.add_finding(
                "WSTG-CONF-04",
                f"Backup file found: {backup_file['path']}",
                severity="high",
                evidence={
                    "path": backup_file['path'],
                    "status_code": backup_file['status_code'],
                    "risk": "Backup files may contain sensitive information or source code",
                    "proof_type": "accessible_file",
                    "impact": "Backup file returned HTTP 200 and may disclose source or configuration data"
                }
            )
            sensitive_findings.append(backup_file['path'])
        
        # Report directory listings
        for dir_listing in data.get('directory_listings', []):
            if not self._is_http_200(dir_listing):
                continue
            self.add_finding(
                "WSTG-CONF-04",
                f"Directory listing enabled: {dir_listing['path']}",
                severity="low",
                evidence={
                    "path": dir_listing['path'],
                    "status_code": dir_listing['status_code'],
                    "risk": "Directory listing exposes internal structure",
                    "proof_type": "directory_listing",
                    "impact": "Directory index returned HTTP 200 and exposes file names"
                }
            )
        
        # Report config files
        for config_file in data.get('config_files', []):
            if not self._is_http_200(config_file):
                continue
            self.add_finding(
                "WSTG-CONF-04",
                f"Configuration file accessible: {config_file['path']}",
                severity="high",
                evidence={
                    "path": config_file['path'],
                    "status_code": config_file['status_code'],
                    "risk": "Configuration files may expose credentials or internal settings",
                    "proof_type": "accessible_file",
                    "impact": "Configuration file returned HTTP 200 and may disclose internal settings"
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
        if not isinstance(data, dict):
            self.log("warning", f"ffuf scan did not return valid data: {self._brief_tool_result(data)}")
            return

        # Accept both shapes:
        # - Wrapper: {status: success, data: {...}}
        # - Payload: {...}
        if data.get("status") == "success" and isinstance(data.get("data"), dict):
            ffuf_data = data["data"]
        else:
            ffuf_data = data
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

        # Merge with existing raw endpoint list — read LIVE DB, not stale snapshot
        existing_raw = self.context_manager.read("discovered_endpoints") or {}
        existing_list = existing_raw.get("endpoints", []) if isinstance(existing_raw, dict) else []

        # Combine and deduplicate
        all_endpoints = existing_list + discovered_endpoints
        unique_endpoints = list({ep["endpoint"]: ep for ep in all_endpoints}.values())

        self.write_context("discovered_endpoints", {"endpoints": unique_endpoints, "count": len(unique_endpoints)})

        api_count = sum(1 for ep in unique_endpoints if ep.get("type") == "api")
        search_count = sum(1 for ep in unique_endpoints if ep.get("type") == "search")

        # Add finding
        self.add_finding(
            "WSTG-INFO",
            f"ffuf discovered {total_found} endpoints ({api_count} API, {search_count} search)",
            severity="info",
            evidence={
                "total_found": total_found,
                "api_count": api_count,
                "search_count": search_count,
                "sample": ffuf_data.get("sample", [])[:10]
            }
        )

        self.log("info", f"✓ ffuf scan found {total_found} endpoints, added to discovered_endpoints")

    def _handle_dirsearch_scan(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process dirsearch scan results with recursive endpoint discovery"""
        if not isinstance(data, dict):
            self.log("warning", f"dirsearch scan did not return valid data: {self._brief_tool_result(data)}")
            return

        # Accept both shapes:
        # - Wrapper: {status: success, data: {...}}
        # - Payload: {...}
        if data.get("status") == "success" and isinstance(data.get("data"), dict):
            dirsearch_data = data["data"]
        else:
            dirsearch_data = data
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

        # Merge with existing raw endpoint list — read LIVE DB, not stale snapshot
        existing_raw = self.context_manager.read("discovered_endpoints") or {}
        existing_list = existing_raw.get("endpoints", []) if isinstance(existing_raw, dict) else []

        # Combine and deduplicate by endpoint path
        all_endpoints = existing_list + discovered_endpoints
        unique_endpoints = list({ep["endpoint"]: ep for ep in all_endpoints}.values())

        self.write_context("discovered_endpoints", {"endpoints": unique_endpoints, "count": len(unique_endpoints)})

        api_count = sum(1 for ep in unique_endpoints if ep.get("type") == "api")
        search_count = sum(1 for ep in unique_endpoints if ep.get("type") == "search")
        admin_count = sum(1 for ep in unique_endpoints if ep.get("type") == "admin")
        upload_count = sum(1 for ep in unique_endpoints if ep.get("type") == "upload")

        # Add finding with detailed stats
        stats = dirsearch_data.get("stats", {})
        self.add_finding(
            "WSTG-INFO",
            f"dirsearch recursively discovered {total_found} endpoints ({api_count} API, {search_count} search, {admin_count} admin)",
            severity="info",
            evidence={
                "total_found": total_found,
                "api_count": api_count,
                "search_count": search_count,
                "admin_count": admin_count,
                "upload_count": upload_count,
                "sample": dirsearch_data.get("sample", [])[:15],
                "stats": stats
            }
        )

        self.log("info", f"✓ dirsearch recursively found {total_found} endpoints (API: {api_count}, search: {search_count}, admin: {admin_count})")

    def _handle_feroxbuster_scan(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process feroxbuster scan results (8-10x faster than dirsearch)"""
        if not isinstance(data, dict):
            self.log("warning", f"feroxbuster scan did not return valid data: {self._brief_tool_result(data)}")
            return

        # Accept both shapes:
        # - Wrapper: {status: success, data: {...}}
        # - Payload: {...}
        if data.get("status") == "success" and isinstance(data.get("data"), dict):
            ferox_data = data["data"]
        else:
            ferox_data = data
        snapshot["feroxbuster_scan"] = ferox_data
        self.write_context("feroxbuster_scan", ferox_data)

        total_found = ferox_data.get("total_found", 0)

        if total_found == 0:
            self.log("info", "feroxbuster found no endpoints")
            return

        # Extract pre-categorized endpoints from feroxbuster output
        endpoints = ferox_data.get("endpoints", [])
        api_endpoints_raw = ferox_data.get("api_endpoints", [])
        search_endpoints_raw = ferox_data.get("search_endpoints", [])
        admin_endpoints_raw = ferox_data.get("admin_endpoints", [])

        # Convert feroxbuster results to discovered_endpoints format
        discovered_endpoints = []
        for ep in endpoints:
            url = ep.get("url", "")
            path = ep.get("path", "")
            status = ep.get("status", 0)

            # Determine endpoint type
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
                "method": "GET",
                "status_code": status,
                "type": endpoint_type,
                "source": "feroxbuster",
                "size": ep.get("size", 0),
                "redirect": ep.get("redirect")
            })

        # Merge with existing raw endpoint list — read LIVE DB, not stale snapshot
        existing_raw = self.context_manager.read("discovered_endpoints") or {}
        existing_list = existing_raw.get("endpoints", []) if isinstance(existing_raw, dict) else []

        # Combine and deduplicate by endpoint path
        all_endpoints = existing_list + discovered_endpoints
        unique_endpoints = list({ep["endpoint"]: ep for ep in all_endpoints}.values())

        self.write_context("discovered_endpoints", {"endpoints": unique_endpoints, "count": len(unique_endpoints)})

        api_count = sum(1 for ep in unique_endpoints if ep.get("type") == "api")
        search_count = sum(1 for ep in unique_endpoints if ep.get("type") == "search")
        admin_count = sum(1 for ep in unique_endpoints if ep.get("type") == "admin")
        upload_count = sum(1 for ep in unique_endpoints if ep.get("type") == "upload")

        # Add finding with detailed stats
        stats = ferox_data.get("stats", {})
        self.add_finding(
            "WSTG-INFO",
            f"feroxbuster (FAST) discovered {total_found} endpoints ({api_count} API, {search_count} search, {admin_count} admin)",
            severity="info",
            evidence={
                "total_found": total_found,
                "api_count": api_count,
                "search_count": search_count,
                "admin_count": admin_count,
                "upload_count": upload_count,
                "sample": ferox_data.get("sample", [])[:15],
                "stats": stats,
                "performance": "8-10x faster than dirsearch"
            }
        )

        self.log("info", f"✓ feroxbuster found {total_found} endpoints in ~60s (API: {api_count}, search: {search_count}, admin: {admin_count})")

    def _handle_katana_crawl(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process Katana JavaScript parsing results and extract endpoints"""
        if not isinstance(data, dict):
            self.log("warning", f"Katana crawl did not return valid data: {self._brief_tool_result(data)}")
            return

        # Accept multiple shapes:
        # - {status: success, data: {...}} (Katana server)
        # - {...} already-unwrapped payload (some MCP client paths)
        # - {status: success, data: {status: success, data: {...}}} (double wrapped)
        # Normalize to the actual payload dict with keys like endpoints/total_found.
        candidate: Any = data
        if data.get("status") == "success" and isinstance(data.get("data"), dict):
            candidate = data["data"]

        # Unwrap nested tool result: {status: success, data: {endpoints...}}
        if (
            isinstance(candidate, dict)
            and candidate.get("status") == "success"
            and isinstance(candidate.get("data"), dict)
        ):
            katana_data = candidate["data"]
        elif isinstance(candidate, dict) and ("endpoints" in candidate or "total_found" in candidate):
            katana_data = candidate
        else:
            self.log("warning", f"Katana crawl did not return valid data: {self._brief_tool_result(candidate)}")
            return

        snapshot["katana_crawl"] = katana_data
        self.write_context("katana_crawl", katana_data)

        total_found = katana_data.get("total_found", 0)

        if total_found == 0:
            self.log("info", "Katana found no additional endpoints")
            return

        # Extract categorized endpoints from Katana output
        endpoints = katana_data.get("endpoints", [])
        api_endpoints_raw = katana_data.get("api_endpoints", [])
        js_files_raw = katana_data.get("js_files", [])
        forms_raw = katana_data.get("forms", [])
        xhr_endpoints_raw = katana_data.get("xhr_endpoints", [])
        admin_endpoints_raw = katana_data.get("admin_endpoints", [])

        # Convert Katana results to discovered_endpoints format
        discovered_endpoints = []
        for ep in endpoints:
            url = ep.get("url", "")
            endpoint_path = ep.get("endpoint", url)

            # Determine endpoint type
            endpoint_type = "other"
            url_lower = url.lower()

            if "/api/" in url_lower or "/rest/" in url_lower or url.endswith(".json"):
                endpoint_type = "api"
            elif url.endswith(".js"):
                endpoint_type = "js_file"
            elif "admin" in url_lower or "dashboard" in url_lower:
                endpoint_type = "admin"
            elif "search" in url_lower:
                endpoint_type = "search"
            elif "xhr" in ep.get("type", "").lower() or "ajax" in url_lower:
                endpoint_type = "xhr"
            elif "form" in ep.get("type", "").lower():
                endpoint_type = "form"

            discovered_endpoints.append({
                "endpoint": endpoint_path,
                "url": url,
                "method": ep.get("method", "GET"),
                "status_code": ep.get("status_code", 0),
                "type": endpoint_type,
                "source": "katana",
            })

        # Merge with existing raw endpoint list — read LIVE DB, not stale snapshot
        existing_raw = self.context_manager.read("discovered_endpoints") or {}
        existing_list = existing_raw.get("endpoints", []) if isinstance(existing_raw, dict) else []

        # Combine and deduplicate by URL
        all_endpoints = existing_list + discovered_endpoints
        unique_endpoints = list({ep["url"]: ep for ep in all_endpoints}.values())

        self.write_context("discovered_endpoints", {"endpoints": unique_endpoints, "count": len(unique_endpoints)})

        api_count = sum(1 for ep in unique_endpoints if ep.get("type") == "api")
        js_count = sum(1 for ep in unique_endpoints if ep.get("type") == "js_file")
        xhr_count = sum(1 for ep in unique_endpoints if ep.get("type") == "xhr")

        self.log("info", f"✓ Katana crawl found {total_found} endpoints via JS parsing (API: {api_count}, JS: {js_count}, XHR: {xhr_count})")

    def _handle_js_routes_analysis(self, data: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """Process JavaScript route analysis results — hidden routes, secrets, API endpoints."""
        if not isinstance(data, dict):
            self.log("warning", f"JS route analysis did not return valid data: {self._brief_tool_result(data)}")
            return

        # Unwrap MCP response envelope (same pattern as _handle_katana_crawl)
        payload = data
        if data.get("status") == "success" and isinstance(data.get("data"), dict):
            payload = data["data"]

        findings = payload.get("findings", [])
        routes = payload.get("routes_discovered", [])
        api_endpoints = payload.get("api_endpoints", [])
        secrets_count = payload.get("secrets_found", 0)
        js_file = payload.get("js_file", "")

        snapshot["js_routes_analysis"] = data
        self.write_context("js_routes_analysis", {
            "hidden_routes": [f for f in findings if f.get("type") == "hidden_route"],
            "api_endpoints": api_endpoints,
            "secrets_found": secrets_count,
            "js_file": js_file,
            "all_routes": routes,
        })

        if findings:
            self.add_finding(
                "WSTG-INFO-06",
                f"JS static analysis: {len(findings)} findings ({len(routes)} routes, {len(api_endpoints)} API endpoints, {secrets_count} secrets)",
                severity="medium" if secrets_count > 0 else "info",
                evidence={
                    "js_file": js_file,
                    "hidden_routes": [f.get("route") for f in findings if f.get("type") == "hidden_route"][:10],
                    "api_endpoints": api_endpoints[:10],
                    "secrets_count": secrets_count,
                    "sample_findings": findings[:5],
                },
            )

        self.log("info", f"✓ JS route analysis: {len(routes)} routes, {len(api_endpoints)} API endpoints, {secrets_count} secrets from {js_file}")

        # Merge discovered API endpoints into discovered_endpoints for downstream agents
        if api_endpoints:
            target = self.shared_context.get("target", "") or self.shared_context.get("target_url", "")
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else target.rstrip("/")

            existing = self.context_manager.read("discovered_endpoints") or {}
            existing_list = existing.get("endpoints", []) if isinstance(existing, dict) else []
            existing_urls = {ep.get("url", "") for ep in existing_list}

            new_eps = []
            for ep_path in api_endpoints:
                full_url = f"{base_url}{ep_path}" if ep_path.startswith("/") else f"{base_url}/{ep_path}"
                if full_url not in existing_urls:
                    new_eps.append({
                        "url": full_url,
                        "endpoint": ep_path,
                        "method": "GET",
                        "status_code": 200,
                        "type": "api",
                        "source": "js_analysis",
                    })

            if new_eps:
                all_eps = existing_list + new_eps
                self.write_context("discovered_endpoints", {"endpoints": all_eps, "count": len(all_eps)})
                self.log("info", f"[JS] Merged {len(new_eps)} API endpoints into discovered_endpoints (total now {len(all_eps)})")

    async def _fallback_js_api_extraction(self, target: str, baseline_snapshot: Dict[str, Any]) -> None:
        """Direct-fetch fallback for when analyze_javascript_routes MCP tool returns empty.

        Fetches main.js (and other likely bundles) from the target, runs the same API-path
        regex, and merges any found paths into discovered_endpoints.  Only activates when
        js_routes_analysis context has zero api_endpoints.
        """
        js_ctx = self.context_manager.read("js_routes_analysis") or {}
        if js_ctx.get("api_endpoints"):
            return  # MCP tool already found endpoints - nothing to do

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else target.rstrip("/")

        api_regex = re.compile(r'["\'](\/?(?:api|rest|graphql)\/[\w/.\-]+)["\']')
        script_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js)["\']', re.IGNORECASE)

        # Step 1: Fetch the page HTML and extract actual <script src="..."> URLs
        js_candidates: list[str] = []
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
                page_resp = await client.get(base_url + "/")
                if page_resp.status_code == 200:
                    for src in script_re.findall(page_resp.text):
                        if src.startswith("http"):
                            continue  # Skip external CDN scripts
                        full = base_url + src if src.startswith("/") else f"{base_url}/{src}"
                        if full not in js_candidates:
                            js_candidates.append(full)
        except Exception as exc:
            self.log("debug", f"[JS fallback] Page fetch for script extraction failed: {exc}")

        # Step 2: Also add any JS files discovered by katana (all, including chunks)
        katana_ctx = self.context_manager.read("katana_crawl") or {}
        for ep in katana_ctx.get("endpoints", []):
            url = ep.get("url", "")
            if url.endswith(".js") and url not in js_candidates:
                js_candidates.append(url)

        if not js_candidates:
            self.log("warning", "[JS fallback] No JS candidates found - discovered_endpoints may be incomplete")
            return

        # Step 3: Download and parse each JS file for API path patterns
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as client:
            for js_url in js_candidates[:8]:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200 or len(resp.text) < 200:
                        continue
                    matches = api_regex.findall(resp.text)
                    if not matches:
                        continue
                    api_endpoints = list(set(matches))
                    self.log("info", f"[JS fallback] {len(api_endpoints)} API endpoints from {js_url}")
                    self.write_context("js_routes_analysis", {
                        "hidden_routes": [],
                        "api_endpoints": api_endpoints,
                        "secrets_found": 0,
                        "js_file": js_url,
                        "all_routes": [],
                        "source": "fallback",
                    })
                    existing = self.context_manager.read("discovered_endpoints") or {}
                    existing_list = existing.get("endpoints", []) if isinstance(existing, dict) else []
                    existing_urls = {ep.get("url", "") for ep in existing_list}
                    new_eps = []
                    for ep_path in api_endpoints:
                        full_url = f"{base_url}{ep_path}" if ep_path.startswith("/") else f"{base_url}/{ep_path}"
                        if full_url not in existing_urls:
                            new_eps.append({
                                "url": full_url, "endpoint": ep_path,
                                "method": "GET", "status_code": 200,
                                "type": "api", "source": "js_fallback",
                            })
                    if new_eps:
                        all_eps = existing_list + new_eps
                        self.write_context("discovered_endpoints", {"endpoints": all_eps, "count": len(all_eps)})
                        self.log("info", f"[JS fallback] Merged {len(new_eps)} API endpoints (total {len(all_eps)})")
                    return  # Done on first successful parse
                except Exception as exc:
                    self.log("debug", f"[JS fallback] Failed to fetch {js_url}: {exc}")

        self.log("warning", "[JS fallback] No API endpoints found in any JS file - discovered_endpoints may be incomplete")

    async def _perform_endpoint_discovery(self, target: str, baseline_snapshot: Dict[str, Any]) -> None:
        self.log("info", "🔎 Executing custom endpoint discovery crawl")
        try:
            endpoints = await self._discover_endpoints(target)
        except Exception as exc:
            self.log("warning", f"Endpoint discovery failed: {exc}; continuing with existing inventory sources")
            endpoints = []

        # Merge with existing discovered_endpoints — do NOT overwrite; other handlers
        # (katana, js_routes_analysis, ffuf, dirsearch) may have already written valuable API paths.
        # Even when the HTML crawler returns nothing (typical for SPAs), R5 tagging must still
        # run on the data produced by other recon tools.
        existing = self.context_manager.read("discovered_endpoints") or {}
        existing_eps = existing.get("endpoints", []) if isinstance(existing, dict) else []
        existing_urls = {ep.get("url", "") for ep in existing_eps}
        new_eps = [ep for ep in (endpoints or []) if ep.get("url", "") not in existing_urls]
        all_eps = existing_eps + new_eps

        self.write_context("discovered_endpoints", {"endpoints": all_eps, "count": len(all_eps)})

        self.log("info", f"Discovered {len(new_eps)} new candidate endpoints ({len(all_eps)} total including prior)")

        # Build endpoint_inventory
        import os as _os
        from pathlib import Path as _Path
        from urllib.parse import urlparse as _urlparse
        from ..utils.endpoint_classifier import LLMEndpointClassifier
        from ..agents.modules.openapi_probe import probe_openapi, probe_graphql_introspection
        from ..agents.modules.ffuf_runner import FfufRunner
        from ..agents.modules.param_miner import mine_params
        from ..utils.simple_llm_client import SimpleLLMClient
        from ..core.config import settings as _settings

        _target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        _hostname = _urlparse(_target_url).hostname or "unknown"

        # R1 extra probes (OpenAPI/Swagger/GraphQL)
        _extra_r1: list[dict] = []
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=10) as _client:
                _extra_r1.extend(await probe_openapi(_target_url, _client))
                _extra_r1.extend(await probe_graphql_introspection(_target_url, _client))
        except Exception as _exc:
            self.log("warning", f"[Recon] R1 extra probes failed: {_exc}")

        # R3+R4 (aggressive mode only) — no sub-timeouts; both tools are self-bounding
        # (finite wordlist ÷ rate_limit). Outer _perform_endpoint_discovery timeout handles hangs.
        _extra_r3: list[dict] = []
        _extra_r4: list[dict] = []
        if _settings.recon_mode == "aggressive":
            _wordlist = _Path(_os.getenv("RECON_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"))
            if _wordlist.exists():
                try:
                    _runner = FfufRunner(rate_per_sec=_settings.recon_fuzz_rps)
                    _extra_r3.extend(await _runner.run(_target_url, _wordlist))
                    _extra_r3.extend(await _runner.run_per_segment(_target_url, _wordlist, seed_endpoints=all_eps + _extra_r1))
                except Exception as _exc:
                    self.log("warning", f"[Recon] R3 ffuf failed: {_exc}")
            _param_wl = _Path(_os.getenv("RECON_PARAM_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"))
            if _param_wl.exists():
                try:
                    import httpx as _httpx
                    async with _httpx.AsyncClient(timeout=10) as _client:
                        await mine_params(_client, all_eps + _extra_r1 + _extra_r3, wordlist=_param_wl, top_n=20, rate_per_sec=5)
                    _extra_r4 = [ep for ep in all_eps + _extra_r1 + _extra_r3 if ep.get("discovered_params")]
                except Exception as _exc:
                    self.log("warning", f"[Recon] R4 param mining failed: {_exc}")

        _merged = all_eps + _extra_r1 + _extra_r3
        _phase_stats = {
            "R1": len(_extra_r1),
            "R2": len(all_eps),
            "R3": len(_extra_r3),
            "R4": len(_extra_r4),
        }

        # R5: LLM classify + write endpoint_inventory
        try:
            _classifier = LLMEndpointClassifier(
                llm_client=SimpleLLMClient(),
                cache_path=_Path("cache/endpoint_classification.json"),
            )
            _inventory = await build_endpoint_inventory(
                hostname=_hostname,
                endpoints=_merged,
                classifier=_classifier,
                captured_ids=self.shared_context.get("captured_ids", {}),
                phase_stats=_phase_stats,
            )
            # Heuristic augmentation: fill gaps from LLM classifier with deterministic
            # OWASP-style rules (path/method/content-type patterns — target-agnostic).
            from ..core.endpoint_inventory import augment_tags_heuristic as _augment, build_inventory as _rebuild_inv
            _endpoints = _inventory.get("endpoints", [])
            _augment(_endpoints)
            _inventory = _rebuild_inv(_endpoints, stats=_inventory.get("stats", {}))
            self.write_context("endpoint_inventory", _inventory)
            _tagged_count = sum(len(v) for v in _inventory["by_tag"].values())
            self.log("info", f"[Recon] endpoint_inventory: {_phase_stats} -> {_tagged_count} tagged endpoints")
        except Exception as _exc:
            self.log("error", f"[Recon] endpoint_inventory build failed: {_exc}")

        # R6: JS bundle analysis (Component B) — gated by USE_FRAMEWORK
        if _settings.use_framework and _settings.use_js_analyzer and getattr(self, "js_bundle_analyzer", None):
            try:
                import httpx as _httpx
                async with _httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as _client:
                    _js_result = await asyncio.wait_for(
                        self.js_bundle_analyzer.analyze(_target_url, _client),
                        timeout=60,
                    )
                _n_routes = len(_js_result.get("routes", []))
                self.write_context("js_bundle_analysis", {"route_count": _n_routes})
                self.log("info", f"[Recon] js_bundle_analysis: {_n_routes} SPA routes found")
                # Add SPA routes to inventory as additional endpoints
                # CRITICAL: read from DB (not stale snapshot) so R5-built tags are preserved
                if _js_result["routes"]:
                    _inventory = self.read_context("endpoint_inventory") or self.shared_context.get("endpoint_inventory") or {}
                    for _route in _js_result["routes"]:
                        _inventory.setdefault("by_tag", {}).setdefault("spa_route", []).append(
                            {"url": _target_url.rstrip("/") + _route["path"],
                             "method": "GET", "framework_hint": _route.get("framework")}
                        )
                    self.write_context("endpoint_inventory", _inventory)
            except Exception as _exc:
                self.log("warning", f"[Recon] JS bundle analysis failed: {_exc}")

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
            self.log("info", f"Recon analytic summary: {report['risk_summary'][:2]}")
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
            self.log("info", f"Follow-up tool executed: {tool_key} (reason: {follow.get('reason', 'N/A')})")

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
