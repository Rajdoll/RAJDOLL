from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Type, ClassVar, Optional
from sqlalchemy.exc import IntegrityError

from ..core.config import settings
from ..core.db import get_db
from ..models.models import JobAgent, AgentEvent, Finding, Job
from ..utils.simple_llm_client import SimpleLLMClient
from ..utils.hitl_manager import HITLManager
from ..utils.agent_runtime import CURRENT_AGENT
from ..utils.mcp_client import MCPClient
from ..utils.shared_context_manager import SharedContextManager

# PHASE 1 IMPROVEMENT: Increased timeouts for comprehensive testing
AGENT_EXECUTION_TIMEOUT = 7200  # 120 minutes (2 hours) for thorough testing (was 3600/60min) - InputValidationAgent needs time for all endpoints!
LLM_PLANNING_TIMEOUT = 300      # 5 minutes for LLM planning
TOOL_EXECUTION_TIMEOUT = 1800   # 30 minutes per tool (was 900/15min) - SQLMap time-based blind SQLi can take 20-30 min!
MAX_LLM_RETRIES = 3             # Maximum LLM retry attempts
MAX_TOOLS_PER_AGENT = 50        # Allow comprehensive testing (was 5)

# FIX #3: Circuit breaker settings
CIRCUIT_BREAKER_FAILURES = 3    # Max failures before circuit opens


class AgentRegistry:
	_registry: ClassVar[dict[str, Type["BaseAgent"]]] = {}

	@classmethod
	def register(cls, name: str):
		def _wrap(agent_cls: Type["BaseAgent"]):
			cls._registry[name] = agent_cls
			agent_cls.agent_name = name
			return agent_cls
		return _wrap

	@classmethod
	def get(cls, name: str) -> Type["BaseAgent"]:
		return cls._registry[name]


@dataclass
class BaseAgent:
	job_id: int
	agent_name: ClassVar[str] = "BaseAgent"
	# Optional agent-specific system prompt (domain expert). Agents may override.
	system_prompt: ClassVar[str] = (
		"You are an OWASP WSTG expert. Plan focused, high-signal tests using MCP tools."
	)
	disable_llm_planning: ClassVar[bool] = False
	disable_hitl: ClassVar[bool] = False
	
	def __post_init__(self):
		"""Initialize agent with optional tool plan from LLM"""
		self.tool_plan: Dict[str, Any] | None = None
		self._tool_failures: Dict[str, int] = {}
		self._shared_context_snapshot: Dict[str, Any] = {}
		self._target: Optional[str] = None
		self._tool_reason_map: Dict[str, str] = {}
		self._tool_arguments_map: Dict[str, Dict[str, Any]] = {}
		self.hitl_manager: Optional[HITLManager] = None
		self._auto_approve_agents = set(getattr(settings, "auto_approve_tool_agents", []))
		self._hitl_overrides: Dict[str, Any] = {}
		self._circuit_breaker_limit = CIRCUIT_BREAKER_FAILURES  # Use constant
		self._llm_retry_count = 0  # Track LLM retries
		self._mcp_client: Optional[MCPClient] = None
		self.context_manager = SharedContextManager(self.job_id, log_hook=self._context_log_hook)
		self._load_hitl_overrides()
		# Independent LLM client per agent - using simple HTTP-based client
		try:
			self._llm_client = SimpleLLMClient()
			print(f"✓ [{self.agent_name}] SimpleLLMClient initialized successfully")
		except Exception as e:
			self._llm_client = None
			print(f"⚠️  [{self.agent_name}] SimpleLLMClient initialization failed: {e}")
	
	@property
	def shared_context(self) -> Dict[str, Any]:
		"""Access shared context snapshot for this agent"""
		return self._shared_context_snapshot
	
	def set_tool_plan(self, plan: Dict[str, Any]) -> None:
		"""Set the LLM-generated tool plan for this agent
		
		Args:
			plan: Dictionary containing:
				- category: OWASP category (e.g., "WSTG-INPV")
				- tools: List of tool names to execute
				- reasoning: LLM's reasoning for tool selection
				- priority: Testing priority level
		"""
		# Normalize accepted shapes to internal canonical form
		normalized: Dict[str, Any] = {
			"category": plan.get("category", ""),
			"reasoning": plan.get("reasoning", ""),
			"priority": plan.get("priority", "medium"),
		}
		# Accept either a simple list of tool names or an array of dicts with 'tool'
		tools: list[str] = []
		self._tool_reason_map = {}
		self._tool_arguments_map = {}
		if isinstance(plan.get("tools"), list):
			for t in plan["tools"]:
				if isinstance(t, str):
					tools.append(t)
				elif isinstance(t, dict) and t.get("tool"):
					tool_name = str(t["tool"])
					tools.append(tool_name)
					reason = t.get("reason") or t.get("why")
					if reason:
						self._tool_reason_map[tool_name] = str(reason)
					arguments = t.get("arguments")
					if isinstance(arguments, dict):
						self._tool_arguments_map[tool_name] = dict(arguments)
		elif isinstance(plan.get("mcp_tools"), list):
			for t in plan["mcp_tools"]:
				if isinstance(t, dict) and t.get("tool"):
					tool_name = str(t["tool"])
					tools.append(tool_name)
					reason = t.get("reason") or t.get("why")
					if reason:
						self._tool_reason_map[tool_name] = str(reason)
					arguments = t.get("arguments")
					if isinstance(arguments, dict):
						self._tool_arguments_map[tool_name] = dict(arguments)
		normalized["tools"] = tools

		# RESEARCH MODE: Execute ALL tools with LLM-generated arguments
		# Paradigm shift: LLM determines HOW to run tools (arguments/commands), 
		# not WHICH tools to run (comprehensive coverage guaranteed)
		
		# Get available tools - call method to check if subclass overrode it
		available_tools = self._get_available_tools()
		
		# Debug logging to trace execution
		self.log("info", f"🔍 Tool detection: got {len(available_tools)} tools from _get_available_tools()")
		
		# Extract LLM-generated arguments and convert to comprehensive format
		llm_arguments = {}
		comprehensive_tools = []
		
		for tool in tools:
			if isinstance(tool, str):
				# String format - convert to object for ALL available tools
				tool_name = tool
				# If this is one of available tools, ensure we include it with empty args
				if available_tools and tool_name in available_tools:
					comprehensive_tools.append(tool_name)
					llm_arguments[tool_name] = {}  # Empty args, will use defaults
			elif isinstance(tool, dict):
				tool_name = tool.get("tool", "")
				if tool_name:
					comprehensive_tools.append(tool_name)
					# Store LLM-provided arguments
					if "arguments" in tool:
						llm_arguments[tool_name] = tool.get("arguments", {})
						self.log("debug", f"✓ LLM provided arguments for {tool_name}", {
							"arguments": tool.get("arguments")
						})
		
		# COMPREHENSIVE COVERAGE: Ensure ALL available tools are included
		if available_tools:
			# Add any missing tools from available_tools that LLM didn't select
			for avail_tool in available_tools:
				if avail_tool not in comprehensive_tools:
					comprehensive_tools.append(avail_tool)
					llm_arguments[avail_tool] = {}  # Default args
			
			normalized["tools"] = comprehensive_tools
			self.log("info", f"📋 Executing ALL {len(comprehensive_tools)} tools (comprehensive mode)", {
				"comprehensive_tools": comprehensive_tools,
				"llm_selected_count": len(tools),
				"llm_with_arguments": [t for t, args in llm_arguments.items() if args],
				"total_llm_args": len([a for a in llm_arguments.values() if a])
			})
		else:
			# Fallback: use LLM-selected tools
			normalized["tools"] = comprehensive_tools
			self.log("warning", f"⚠️ No available_tools list, using {len(comprehensive_tools)} LLM-selected tools", {
				"tools": comprehensive_tools,
				"agent": self.agent_name
			})
		
		# Preserve LLM-generated arguments for tool execution
		self._tool_arguments_map.update(llm_arguments)
		self.log("info", f"📦 Stored {len([a for a in llm_arguments.values() if a])} LLM argument sets for tools")

		self.tool_plan = normalized
		self.log("info", f"LLM tool plan received (with intelligent coverage)", {
			"category": normalized.get("category"),
			"tools": normalized.get("tools", []),
			"llm_original_count": len(tools),
			"final_count": len(normalized.get("tools", [])),
			"reasoning": normalized.get("reasoning", ""),
			"priority": normalized.get("priority", "medium")
		})

	async def execute(self, target: Optional[str] = None, shared_context: Optional[Dict[str, Any]] = None, job_id: Optional[int] = None) -> None:
		"""Standardized execution entrypoint used by the Orchestrator.

		Steps:
		- snapshot shared_context for context-aware planning
		- ensure target is available (from param or DB)
		- if no tool_plan, ask LLM for adaptive tool selection
		- call self.run() which uses run_tool_with_timeout and should_run_tool
		- on completion, log finish
		"""
		# DEBUG: Log entry to execute
		import sys
		print(f"🚀🚀🚀 DEBUG: {self.agent_name}.execute() CALLED - target={target}, has_tool_plan={bool(self.tool_plan)}, DISABLE_LLM_PLANNING={os.getenv('DISABLE_LLM_PLANNING')}", file=sys.stderr, flush=True)
		self.log("info", f"🚀 {self.agent_name}.execute() CALLED - target={target}, has_tool_plan={bool(self.tool_plan)}, DISABLE_LLM_PLANNING={os.getenv('DISABLE_LLM_PLANNING')}")
		
		if job_id and job_id != self.job_id:
			# Should not happen in normal flow, but align internal id if provided
			self.log("warning", f"execute() called with different job_id={job_id}, keeping self.job_id={self.job_id}")

		# Snapshot shared context
		self._shared_context_snapshot = shared_context or self._aggregate_shared_context()
		self.log("debug", "Shared context snapshot loaded", {"keys": list(self._shared_context_snapshot.keys())})

		# Target resolution
		self._target = target or self._get_target_from_db()
		if not self._target:
			self.log("error", "No target available for agent execution")
			return

		# If no tool plan OR empty tool plan, create one via per-agent LLM planning
		# CRITICAL: Orchestrator Phase 2 may inject empty tool_plan (no owasp_categories),
		# so we MUST check if tools list is empty and trigger per-agent LLM planning
		import sys
		print(f"🔍 {self.agent_name}: Checking tool_plan - exists={bool(self.tool_plan)}, value={self.tool_plan}", file=sys.stderr, flush=True)
		self.log("info", f"🔍 Tool plan check: exists={bool(self.tool_plan)}, type={type(self.tool_plan)}")
		
		if not self.tool_plan or not self.tool_plan.get("tools"):
			print(f"▶▶▶ {self.agent_name}: Entering tool plan creation block (no tool_plan from Orchestrator)", file=sys.stderr, flush=True)
			self.log("info", f"▶▶▶ Entering tool plan creation - tool_plan is empty")
			available_tools = self._get_available_tools()
			print(f"▶▶▶ {self.agent_name}: Got {len(available_tools)} available tools: {available_tools[:5]}", file=sys.stderr, flush=True)
			
			# Check if LLM planning disabled via env var or class attribute
			disable_planning = os.getenv('DISABLE_LLM_PLANNING', 'false').lower() == 'true' or getattr(self, "disable_llm_planning", False)
			print(f"▶▶▶ {self.agent_name}: disable_planning={disable_planning}, has_llm_client={bool(self._llm_client)}", file=sys.stderr, flush=True)

			if disable_planning or not self._llm_client:
				# No LLM planning: Execute ALL available tools for comprehensive coverage
				print(f"🔀 {self.agent_name}: BRANCH 1 - LLM planning disabled path", file=sys.stderr, flush=True)
				self.log("info", f"📋 LLM planning disabled - executing ALL {len(available_tools)} tools")
				self.tool_plan = {
					"tools": available_tools,
					"reasoning": "Comprehensive coverage - all tools executed",
					"priority": "high"
				}
			elif self._llm_client:
				print(f"🔀 {self.agent_name}: BRANCH 2 - LLM planning enabled path", file=sys.stderr, flush=True)
				# LLM planning enabled: Ask LLM for adaptive tool selection
				try:
					# FIX #2: Wrap LLM planning in timeout
					# FIXED: Use print instead of self.log (async deadlock issue)
					print(f"📋 {self.agent_name}: Available tools for LLM planning: {available_tools}", file=sys.stderr, flush=True)

					# Apply LLM planning timeout
					selected = await asyncio.wait_for(
						self._llm_client.select_tools_for_agent(
							agent_name=self.agent_name,
							shared_context=self._shared_context_snapshot,
							available_tools=available_tools,
							system_prompt=getattr(self, "system_prompt", None)
						),
						timeout=LLM_PLANNING_TIMEOUT
					)

					print(f"🧠 {self.agent_name}: LLM selected tools (raw): {selected}", file=sys.stderr, flush=True)
					
					# NEW PARADIGM: Pass LLM response with arguments, let set_tool_plan() handle ALL tools execution
					# LLM provides: tool arguments/commands (HOW to run)
					# set_tool_plan() ensures: ALL available tools executed (WHAT to run)
					self.set_tool_plan({
						"category": "",
						"tools": selected,  # Pass full LLM response with arguments
						"reasoning": "; ".join([t.get("reason", "") for t in selected if isinstance(t, dict)]),
						"priority": "medium",
					})
					print(f"✅ {self.agent_name}: Adaptive tool plan created, {len(selected)} tools selected", file=sys.stderr, flush=True)
					self._llm_retry_count = 0  # Reset on success

				except asyncio.TimeoutError:
					self._llm_retry_count += 1
					print(f"❌ {self.agent_name}: LLM planning timeout after {LLM_PLANNING_TIMEOUT}s (retry {self._llm_retry_count}/{MAX_LLM_RETRIES})", file=sys.stderr, flush=True)
					if self._llm_retry_count >= MAX_LLM_RETRIES:
						print(f"❌ {self.agent_name}: LLM planning failed after max retries, using ALL available tools", file=sys.stderr, flush=True)
						# ENHANCED: Use ALL tools, not just first 3, for maximum coverage
						self.tool_plan = {"tools": available_tools, "reasoning": "Comprehensive fallback - all tools", "priority": "high"}
					else:
						raise  # Retry
				except Exception as e:
					self._llm_retry_count += 1
					print(f"⚠️ {self.agent_name}: LLM tool selection failed (retry {self._llm_retry_count}/{MAX_LLM_RETRIES}): {e}", file=sys.stderr, flush=True)
					if self._llm_retry_count >= MAX_LLM_RETRIES:
						print(f"❌ {self.agent_name}: LLM planning failed after max retries, using ALL available tools", file=sys.stderr, flush=True)
						# ENHANCED: Use ALL tools, not skip, for maximum coverage
						self.tool_plan = {" tools": available_tools, "reasoning": "Comprehensive fallback - all tools", "priority": "high"}
					else:
						raise  # Retry

		# Run agent logic with exception handling
		print(f"🚀 {self.agent_name}: About to call run() method", file=sys.stderr, flush=True)
		token = CURRENT_AGENT.set(self)
		try:
			await self.run()
			self.log("info", "Agent execution completed")
		except Exception as e:
			self.log("error", f"Agent execution failed: {type(e).__name__}: {e}")
			import traceback
			self.log("error", f"Traceback: {traceback.format_exc()}")
			raise  # Re-raise to let orchestrator handle
		finally:
			CURRENT_AGENT.reset(token)
	
	def _get_available_tools(self) -> list[str]:
		"""
		Extract available tool names from agent's run() method.
		Agents can override this to provide custom tool lists.
		"""
		# Default: return empty list (agent will run all tools)
		# Subclasses should override with their actual tool names
		return []

	def log_tool_execution_plan(self):
		"""Log which tools will be executed based on LLM plan and ADAPTIVE_MODE"""
		if getattr(self, "disable_llm_planning", False):
			self.log("info", "🔁 Tiered autonomy active - LLM tool planning disabled for this agent")
			return
		mode = os.getenv('ADAPTIVE_MODE', 'balanced').lower()
		
		# Get tool list and priorities
		available_tools = self._get_available_tools()  # List[str]
		tool_priorities = self._get_tool_info() if hasattr(self, '_get_tool_info') else {}
		
		# Log adaptive mode
		mode_desc = {
			'off': 'OFF - Running ALL tools (maximum detection)',
			'conservative': 'CONSERVATIVE - LLM selects 2-3 tools (maximum efficiency)',
			'balanced': 'BALANCED - CRITICAL tools + LLM selection (default)',
			'aggressive': 'AGGRESSIVE - CRITICAL+HIGH tools + LLM selection (maximum coverage)'
		}
		self.log("info", f"🎯 ADAPTIVE_MODE: {mode_desc.get(mode, mode.upper())}")
		
		if self.tool_plan and self.tool_plan.get("tools"):
			selected_tools = self.tool_plan["tools"]
			reasoning = self.tool_plan.get("reasoning", "No reasoning provided")
			skipped = [t for t in available_tools if t not in selected_tools] if isinstance(available_tools, list) else []
			
			# Count priority-forced tools
			if mode in ['balanced', 'aggressive'] and tool_priorities:
				priority_levels = ['CRITICAL'] if mode == 'balanced' else ['CRITICAL', 'HIGH']
				forced_tools = [t for t, info in tool_priorities.items() 
				               if isinstance(info, dict) and info.get('priority') in priority_levels]
				if forced_tools:
					self.log("info", f"🔒 Priority-forced tools: {', '.join(forced_tools)} ({', '.join(priority_levels)})")
			
			self.log("info", f"🧠 LLM Planning Active - {len(selected_tools)}/{len(available_tools)} tools selected")
			self.log("info", f"✓ Selected tools: {', '.join(selected_tools)}")
			if reasoning:
				self.log("info", f"✓ LLM Reasoning: {reasoning}")
			if skipped:
				self.log("info", f"⚠️  Skipped tools (not in plan): {', '.join(skipped)}")
		else:
			self.log("info", f"⚙️  No LLM plan - running all {len(available_tools)} tools")

	# Shared context helpers
	def read_context(self, key: str) -> dict | None:
		return self.context_manager.read(key)

	def write_context(self, key: str, value: dict) -> None:
		self.context_manager.write(key, value)

	def add_finding(self, category: str, title: str, severity: str = "info", evidence: dict | None = None, details: str | None = None) -> None:
		# Sanitize evidence to prevent unhashable type errors
		if evidence is not None:
			try:
				# Convert evidence to JSON-safe format
				import json
				# Test if evidence is JSON-serializable
				json.dumps(evidence)
			except (TypeError, ValueError) as e:
				# If not serializable, convert to string representation
				evidence = {"raw": str(evidence), "error": f"Evidence not JSON-serializable: {e}"}
		with get_db() as db:
			db.add(Finding(job_id=self.job_id, agent_name=self.agent_name, category=category, title=title, severity=severity, evidence=evidence, details=details))
			try:
				db.commit()
			except IntegrityError:
				# Duplicate finding - skip silently (happens during Celery retries)
				db.rollback()
				import sys
				print(f"⚠️  {self.agent_name}: Duplicate finding skipped: {title}", file=sys.stderr, flush=True)

	def log(self, level: str, message: str, data: dict | None = None) -> None:
		with get_db() as db:
			ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == self.agent_name).one_or_none()
			if not ja:
				return
			db.add(AgentEvent(job_agent_id=ja.id, level=level, message=message, data=data))
			db.commit()

	def get_mcp_client(self) -> MCPClient:
		"""Lazy-load a shared MCP client for agents that need one."""
		if not self._mcp_client:
			self._mcp_client = MCPClient()
		return self._mcp_client

	async def run_tool_with_timeout(self, coro, timeout: int | None = None):
		t = timeout or settings.tool_timeout
		try:
			return await asyncio.wait_for(coro, timeout=t)
		except asyncio.TimeoutError:
			self.log("warning", f"Tool timed out after {t}s")
			return {"status": "error", "message": "timeout"}

	def _normalize_llm_arguments(self, tool_name: str, llm_args: dict) -> dict:
		"""
		Map LLM-generated parameter names to MCP tool signatures.
		Critical for LLM planning: LLM generates 'target_url', MCP expects 'url'.
		"""
		# Common argument mappings across all MCP servers
		MAPPINGS = {
			'target_url': 'url',
			'domain': 'url',
			'endpoint': 'url',
			'target': 'url',
			'test_url': 'url',
			'website': 'url',
			'injection_points': 'parameters',
			'payloads': 'test_strings',
			'test_payloads': 'test_strings',
			'wordlist': 'wordlist_path',
			'dictionary': 'wordlist_path',
		}
		
		normalized = {}
		for llm_key, value in llm_args.items():
			mcp_key = MAPPINGS.get(llm_key, llm_key)  # Use mapping or keep original
			normalized[mcp_key] = value
		
		self.log("debug", f"Normalized LLM args for {tool_name}", {
			"original": llm_args, 
			"normalized": normalized
		})
		return normalized

	async def execute_tool(
		self,
		*,
		server: str,
		tool: str,
		args: Optional[Dict[str, Any]] = None,
		timeout: Optional[int] = None,
		auth_session: Optional[Dict[str, Any]] = None,
	) -> Dict[str, Any] | str:
		"""Centralized helper to run MCP tools with logging and safeguards."""
		if not self.should_run_tool(tool):
			self.log("info", "Skipping tool per plan/limits", {"tool": tool})
			return {"status": "skipped", "message": "filtered"}

		# HITL preparation check (for future HITL activation)
		if not self.disable_hitl and not os.getenv('DISABLE_HITL', 'true').lower() == 'true':
			self.log("info", "HITL enabled - tool execution will require user confirmation", {
				"server": server,
				"tool": tool,
				"args": args
			})
			# TODO: Implement HITL approval flow via HITLManager.request_approval()
			# For now, log only as preparation for future HITL activation

		client = self.get_mcp_client()
		args = dict(args or {})

		# ✅ FIX: Call hook to merge LLM-generated arguments BEFORE execution
		approval = await self._before_tool_execution(server, tool, args)
		if not approval.get("approved", True):
			self.log("warning", "Tool execution blocked by HITL or policy", {"tool": tool})
			return {"status": "blocked", "message": "Execution denied"}

		# ✅ FIX: Use merged arguments from hook (includes LLM args)
		args = approval.get("arguments", args)

		# 🔑 PHASE 3: AUTO-INJECT AUTHENTICATION FROM SHARED CONTEXT
		# This is the CRITICAL FIX for coverage gap - tools need auth to test authenticated endpoints
		if not auth_session:  # Only inject if not explicitly provided
			# Tools that should NOT use authentication (reconnaissance, fingerprinting)
			NO_AUTH_TOOLS = {
				'fingerprint_web_server', 'fingerprint_framework', 'fingerprint_application',
				'advanced_technology_fingerprinting', 'search_engine_reconnaissance',
				'check_metafiles', 'security_headers_analysis', 'analyze_webpage_content',
				'identify_entry_points', 'enumerate_application_admin_interfaces'
			}

			if tool not in NO_AUTH_TOOLS:
				# Load authenticated sessions from SharedContext
				context = self.context_manager.load_all()
				auth_data = context.get('authenticated_sessions', {})

				if auth_data:
					# Extract session from successful_logins array (created by SessionManager)
					# Format: {"successful_logins": [{"username": "...", "token": "...", "cookies": {...}}]}
					successful_logins = auth_data.get('successful_logins', [])

					if successful_logins and len(successful_logins) > 0:
						# Use first successful login (usually admin or user account)
						# Format: {"username": "...", "token": "...", "cookies": {...}, "type": "jwt/cookie"}
						session = successful_logins[0]

						# Inject auth_session into config parameter (MCP tool convention)
						if 'config' not in args:
							args['config'] = {}
						if 'auth_session' not in args.get('config', {}):
							args['config']['auth_session'] = session
							self.log("info", f"🔑 Auto-injected auth session for {tool}", {
								"tool": tool,
								"username": session.get('username', 'unknown'),
								"auth_type": session.get('type', 'unknown'),
								"has_token": bool(session.get('token')),
								"has_cookies": bool(session.get('cookies'))
							})

		# Normalize LLM-generated arguments to MCP signatures
		if args:
			args = self._normalize_llm_arguments(tool, args)

		start = time.perf_counter()
		self.log("info", "Tool execution started", {"server": server, "tool": tool, "final_args": args})
		try:
			result = await self.run_tool_with_timeout(
				client.call_tool(server=server, tool=tool, args=args, timeout=timeout or settings.tool_timeout, auth_session=auth_session),
				timeout=timeout,
			)
		except Exception as exc:
			self.record_tool_failure(tool, str(exc))
			self.log("error", "Tool execution failed", {"tool": tool, "error": str(exc)})
			raise
		else:
			self.reset_tool_failure(tool)
			duration = round(time.perf_counter() - start, 2)
			status = result.get("status") if isinstance(result, dict) else "unknown"

			# 🔍 PHASE 3: DETECT AUTHENTICATION ERRORS (401/403/500)
			# Help diagnose why tools aren't finding vulnerabilities
			if isinstance(result, dict):
				raw_output = result.get('raw_output', '') or result.get('stdout', '')
				stderr = result.get('stderr', '')
				combined_output = f"{raw_output} {stderr}".lower()

				# Check for HTTP authentication error patterns
				auth_error_patterns = [
					'401 unauthorized', '403 forbidden', '500 internal server error',
					'authentication required', 'access denied', 'unauthorized access',
					'login required', 'session expired'
				]

				auth_error_detected = any(pattern in combined_output for pattern in auth_error_patterns)

				if auth_error_detected:
					# Check if auth was actually provided
					has_auth = bool(args.get('config', {}).get('auth_session'))

					if not has_auth:
						self.log("warning", f"⚠️  Auth error detected but no auth provided for {tool}", {
							"tool": tool,
							"server": server,
							"url": args.get('url', 'unknown'),
							"recommendation": "Endpoint may require authentication - consider testing with authenticated session"
						})
					else:
						self.log("warning", f"⚠️  Auth error detected despite auth injection for {tool}", {
							"tool": tool,
							"server": server,
							"url": args.get('url', 'unknown'),
							"has_token": bool(args['config']['auth_session'].get('token')),
							"has_cookies": bool(args['config']['auth_session'].get('cookies')),
							"recommendation": "Auth session may be expired or invalid - check session validity"
						})

			self.log("info", "Tool execution finished", {"tool": tool, "duration_s": duration, "status": status})
			return result

	# Circuit breaker helpers (anti-stuck) + adaptive filtering
	def should_run_tool(self, tool_name: str) -> bool:
		"""Centralized gating logic for MCP tools."""
		import sys

		failures = self._tool_failures.get(tool_name, 0)
		if failures >= self._circuit_breaker_limit:
			self.log("warning", "Circuit breaker: skipping tool due to repeated failures", {"tool": tool_name, "failures": failures})
			print(f"🔴 {self.agent_name}: Tool {tool_name} SKIPPED - Circuit breaker ({failures} failures)", file=sys.stderr, flush=True)
			return False

		# Check environment variable or instance attribute
		if os.getenv('DISABLE_LLM_PLANNING', 'false').lower() == 'true' or getattr(self, "disable_llm_planning", False):
			print(f"✅ {self.agent_name}: Tool {tool_name} APPROVED - LLM planning disabled", file=sys.stderr, flush=True)
			return True

		mode = os.getenv('ADAPTIVE_MODE', 'balanced').lower()
		if mode == 'off':
			print(f"✅ {self.agent_name}: Tool {tool_name} APPROVED - Adaptive mode OFF (all tools)", file=sys.stderr, flush=True)
			return True

		tool_info = {}
		if hasattr(self, '_get_tool_info'):
			info = self._get_tool_info()
			if isinstance(info, dict):
				tool_info = info.get(tool_name, {})
		priority = tool_info.get('priority', 'MEDIUM') if isinstance(tool_info, dict) else 'MEDIUM'
		if mode == 'aggressive' and priority in ['CRITICAL', 'HIGH']:
			print(f"✅ {self.agent_name}: Tool {tool_name} APPROVED - Priority {priority} (aggressive mode)", file=sys.stderr, flush=True)
			return True
		if mode == 'balanced' and priority == 'CRITICAL':
			print(f"✅ {self.agent_name}: Tool {tool_name} APPROVED - Priority CRITICAL (balanced mode)", file=sys.stderr, flush=True)
			return True

		if not self.tool_plan or not self.tool_plan.get("tools"):
			print(f"✅ {self.agent_name}: Tool {tool_name} APPROVED - No LLM plan available", file=sys.stderr, flush=True)
			return True

		in_plan = tool_name in self.tool_plan.get("tools", [])
		if in_plan:
			print(f"✅ {self.agent_name}: Tool {tool_name} APPROVED - In LLM plan", file=sys.stderr, flush=True)
		else:
			print(f"⚠️  {self.agent_name}: Tool {tool_name} SKIPPED - Not in LLM plan (mode={mode}, priority={priority})", file=sys.stderr, flush=True)
		return in_plan

	def record_tool_failure(self, tool_name: str, error: str | None = None) -> None:
		self._tool_failures[tool_name] = self._tool_failures.get(tool_name, 0) + 1
		self.log("warning", "Tool failure recorded", {"tool": tool_name, "count": self._tool_failures[tool_name], "error": error})

	def reset_tool_failure(self, tool_name: str) -> None:
		if tool_name in self._tool_failures:
			self._tool_failures.pop(tool_name, None)

	def _merge_planned_arguments(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
		"""Merge LLM-generated arguments with base arguments for comprehensive testing"""
		base = dict(args or {})
		planned = self._tool_arguments_map.get(tool_name)
		
		if isinstance(planned, dict) and planned:
			merged = dict(base)
			merged.update(planned)
			self.log("info", f"✓ Using LLM arguments for {tool_name}", {
				"base_args": base,
				"llm_args": planned,
				"merged_args": merged
			})
			return merged
		else:
			if self._tool_arguments_map:
				self.log("debug", f"⚠ No LLM arguments for {tool_name}, using base only", {
					"available_llm_args": list(self._tool_arguments_map.keys()),
					"base_args": base
				})
		return base

	async def _before_tool_execution(self, server: str, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
		"""Hook invoked by MCPClient prior to executing a tool.

		Returns a dict with ``approved`` flag and (optionally) sanitized ``arguments``.
		"""
		args = self._merge_planned_arguments(tool_name, args)
		if self.agent_name in self._auto_approve_agents:
			return {"approved": True, "arguments": args}
		if getattr(self, "disable_hitl", False):
			return {"approved": True, "arguments": args}
		if not getattr(settings, "enable_tool_hitl", False):
			return {"approved": True, "arguments": args}

		if not self.hitl_manager:
			self.hitl_manager = HITLManager(self.job_id, overrides=self._hitl_overrides)

		reason = self._tool_reason_map.get(tool_name)
		if not reason and self.tool_plan:
			reason = self.tool_plan.get("reasoning")

		decision = await self.hitl_manager.request_tool_execution(
			agent_name=self.agent_name,
			tool_name=tool_name,
			server=server,
			arguments=args,
			reason=reason,
		)
		if not decision.get("approved", True):
			self.log("warning", "Tool execution blocked by HITL", {"tool": tool_name, "server": server})
		else:
			if decision.get("arguments") and decision["arguments"] != args:
				self.log("info", "Tool arguments overridden by user", {"tool": tool_name})
		return decision

	# Target/context utilities
	def _get_target_from_db(self) -> Optional[str]:
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			return job.target if job else None

	def _aggregate_shared_context(self) -> Dict[str, Any]:
		"""Load all shared context entries for this job into a dict."""
		return self.context_manager.load_all()

	def _load_hitl_overrides(self) -> None:
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			if not job or not isinstance(job.plan, dict):
				return
			options = job.plan.get("options")
			if not isinstance(options, dict):
				return
			overrides: Dict[str, Any] = {}
			if options.get("auto_approve_agents") and isinstance(options.get("auto_approve_agents"), list):
				self._auto_approve_agents.update(str(agent) for agent in options["auto_approve_agents"] if agent)
			if options.get("hitl_enabled") is not None:
				overrides["hitl_enabled"] = bool(options["hitl_enabled"])
			if options.get("enable_tool_hitl") is not None:
				overrides["enable_tool_hitl"] = bool(options["enable_tool_hitl"])
			if overrides:
				self._hitl_overrides = overrides

	def _context_log_hook(self, level: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
		try:
			self.log(level, message, data)
		except Exception:
			pass

