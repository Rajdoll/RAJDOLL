from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Type, ClassVar, Optional, List
from urllib.parse import urlparse
from sqlalchemy.exc import IntegrityError

from ..core.config import settings
from ..core.db import get_db
from ..models.models import JobAgent, AgentEvent, Finding, Job
from ..utils.simple_llm_client import SimpleLLMClient
from ..utils.hitl_manager import HITLManager
from ..utils.agent_runtime import CURRENT_AGENT
from ..utils.mcp_client import MCPClient
from ..utils.shared_context_manager import SharedContextManager
# PHASE 2: New architectural components
from ..utils.knowledge_graph import KnowledgeGraph, Entity, EntityType, RelationType
from ..utils.confidence_scorer import ConfidenceScorer, ConfidenceScore, Evidence, EvidenceType
from ..utils.enrichment_service import EnrichmentService

# Timeouts aligned with job_total_timeout (3600s) to prevent cascading delays
AGENT_EXECUTION_TIMEOUT = 2700  # 45 minutes per agent (leaves room for other phases within 1hr job timeout)
LLM_PLANNING_TIMEOUT = 120      # 2 minutes for LLM planning (Qwen 3-4B responds in 15-60s)
TOOL_EXECUTION_TIMEOUT = 600    # 10 minutes per tool (sufficient for SQLMap; was 1800s which let stuck tools block everything)
MAX_LLM_RETRIES = 1             # No retry on timeout — LM Studio is single-threaded; a 2nd attempt immediately after a 120s timeout wastes another 120s with identical outcome
MAX_TOOLS_PER_AGENT = 50        # Allow comprehensive testing (was 5)

# Global concurrency limit for LLM planning across agents.
# Prevents parallel agent execution from overwhelming a single LLM endpoint (e.g., LM Studio).
_LLM_PLANNING_SEMAPHORE = asyncio.Semaphore(int(os.getenv("LLM_PLANNING_CONCURRENCY", "2")))

# FIX #3: Circuit breaker settings
CIRCUIT_BREAKER_FAILURES = 3    # Max failures before circuit opens

# URL argument names checked for host scope enforcement in _before_tool_execution()
URL_ARG_NAMES = ("url", "target_url", "target", "base_url", "domain", "host")


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
		
		# PHASE 2: Initialize Knowledge Graph and Confidence Scorer
		self._knowledge_graph: Optional[KnowledgeGraph] = None
		self._confidence_scorer = ConfidenceScorer()
		self._current_tool_evidences: List[Evidence] = []  # Track evidence during tool execution
		
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

	# ====================================================================
	# HITL Live Execution Monitor — broadcast status & check signals
	# ====================================================================

	def broadcast_execution_status(self, status: Dict[str, Any]) -> None:
		"""Write structured execution state to SharedContext for dashboard consumption."""
		from datetime import datetime as _dt
		status.setdefault("agent", self.agent_name)
		status.setdefault("timestamp", _dt.utcnow().isoformat())
		try:
			self.context_manager.write("execution_status", status)
		except Exception:
			pass  # non-critical, never block agent execution

	def check_hitl_signal(self) -> Optional[Dict[str, Any]]:
		"""Read and consume a pending HITL intervention signal (if any).

		Returns the signal dict and clears it from SharedContext so it is
		processed only once.  Returns ``None`` when no signal is pending.
		"""
		try:
			signal = self.context_manager.read("hitl_intervention")
			if signal:
				# Clear after reading so agent doesn't re-process it
				self.context_manager.write("hitl_intervention", None)
				self.log("warning", f"HITL intervention received: {signal.get('action')}", signal)
				return signal
		except Exception:
			pass
		return None

	def get_auth_session(self) -> Optional[Dict[str, Any]]:
		"""
		Get authenticated session from shared_context for use with MCP tools.
		
		The AuthenticationAgent performs login and stores session data in shared_context.
		Other agents can use this method to retrieve auth headers/cookies for their requests.
		
		Returns:
			Dict with cookies, headers, token if available, else None
		"""
		auth_data = self._shared_context_snapshot.get("authenticated_session")
		if not auth_data or not auth_data.get("logged_in"):
			return None
		
		return {
			"cookies": auth_data.get("cookies", {}),
			"headers": auth_data.get("headers", {}),
			"token": auth_data.get("jwt_token"),
			"username": auth_data.get("username"),
		}
	
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

		# Persist canonical plan and merge any LLM-provided args.
		for tool_name, args in llm_arguments.items():
			if isinstance(args, dict) and args:
				self._tool_arguments_map[tool_name] = args
		self.tool_plan = normalized
		return

	async def execute(self, target: str = None, shared_context: Dict[str, Any] = None):
		"""Execute this agent with shared context from the orchestrator."""
		import sys
		self._target = target or self._get_target_from_db()
		self._shared_context_snapshot = shared_context or {}

		# If no tool plan OR empty tool plan, create one via per-agent LLM planning
		# CRITICAL: Orchestrator Phase 2 may inject empty tool_plan (no owasp_categories),
		# so we MUST check if tools list is empty and trigger per-agent LLM planning
		print(
			f"🔍 {self.agent_name}: Checking tool_plan - exists={bool(self.tool_plan)}, value={self.tool_plan}",
			file=sys.stderr,
			flush=True,
		)
		self.log("info", f"🔍 Tool plan check: exists={bool(self.tool_plan)}, type={type(self.tool_plan)}")

		# Log planner context if available (cumulative summary + task tree from previous agents)
		cum_summary = self._shared_context_snapshot.get("cumulative_summary", "")
		task_tree_ctx = self._shared_context_snapshot.get("task_tree", "")
		if cum_summary:
			print(f"📋 {self.agent_name}: Received cumulative summary ({len(cum_summary)} chars) from previous agents", file=sys.stderr, flush=True)
		if task_tree_ctx:
			print(f"📋 {self.agent_name}: Received task tree context", file=sys.stderr, flush=True)

		if not self.tool_plan or not self.tool_plan.get("tools"):
			print(
				f"▶▶▶ {self.agent_name}: Entering tool plan creation block (no tool_plan from Orchestrator)",
				file=sys.stderr,
				flush=True,
			)
			self.log("info", "▶▶▶ Entering tool plan creation - tool_plan is empty")
			available_tools = self._get_available_tools()
			print(
				f"▶▶▶ {self.agent_name}: Got {len(available_tools)} available tools: {available_tools[:5]}",
				file=sys.stderr,
				flush=True,
			)

			# Check if LLM planning disabled via env var or class attribute
			disable_planning = os.getenv('DISABLE_LLM_PLANNING', 'false').lower() == 'true' or getattr(self, "disable_llm_planning", False)

			# Tier 2.1: Skip per-agent LLM if orchestrator already ran LLM planning
			# (the orchestrator plan just didn't have tools for THIS agent — use all tools)
			if not disable_planning and getattr(self, "_orchestrator_had_plan", False):
				disable_planning = True
				print(f"⏭️ {self.agent_name}: Skipping per-agent LLM — orchestrator already planned (no tools for this agent)", file=sys.stderr, flush=True)

			# Tier 2.2: Skip LLM planning for agents with <= 5 tools (no value in selection)
			if not disable_planning and len(available_tools) <= 5:
				disable_planning = True
				print(f"⏭️ {self.agent_name}: Skipping LLM — only {len(available_tools)} tools (run all)", file=sys.stderr, flush=True)

			print(
				f"▶▶▶ {self.agent_name}: disable_planning={disable_planning}, has_llm_client={bool(self._llm_client)}",
				file=sys.stderr,
				flush=True,
			)

			if disable_planning or not self._llm_client:
				# No LLM planning: Execute ALL available tools for comprehensive coverage
				print(f"🔀 {self.agent_name}: BRANCH 1 - LLM planning disabled path", file=sys.stderr, flush=True)
				self.log("info", f"📋 LLM planning disabled - executing ALL {len(available_tools)} tools")
				self.tool_plan = {
					"tools": available_tools,
					"reasoning": "Comprehensive coverage - all tools executed",
					"priority": "high",
				}
			else:
				print(f"🔀 {self.agent_name}: BRANCH 2 - LLM planning enabled path", file=sys.stderr, flush=True)
				# Enrich shared_context with cumulative summary for LLM planning
				# This gives the LLM awareness of what previous agents found
				planning_context = dict(self._shared_context_snapshot)
				if cum_summary:
					planning_context["previous_findings_summary"] = cum_summary[-3000:]  # Last 3k chars
				if task_tree_ctx:
					planning_context["testing_status"] = task_tree_ctx
				# Director instructions from pre-agent checkpoint
				director_text = self._shared_context_snapshot.get("director_instructions_text", "")
				if director_text:
					planning_context["director_instructions"] = director_text

				# LLM planning enabled: Ask LLM for adaptive tool selection
				print(f"📋 {self.agent_name}: Available tools for LLM planning: {available_tools}", file=sys.stderr, flush=True)
				selected = None
				last_error: Exception | None = None
				for attempt in range(1, MAX_LLM_RETRIES + 1):
					try:
						await _LLM_PLANNING_SEMAPHORE.acquire()
						try:
							selected = await asyncio.wait_for(
								self._llm_client.select_tools_for_agent(
									agent_name=self.agent_name,
									shared_context=planning_context,
									available_tools=available_tools,
									system_prompt=getattr(self, "system_prompt", None),
								),
								timeout=LLM_PLANNING_TIMEOUT,
							)
						finally:
							_LLM_PLANNING_SEMAPHORE.release()

						print(f"🧠 {self.agent_name}: LLM selected tools (raw): {selected}", file=sys.stderr, flush=True)
						self.set_tool_plan({
							"category": "",
							"tools": selected,
							"reasoning": "; ".join([t.get("reason", "") for t in selected if isinstance(t, dict)]),
							"priority": "medium",
						})
						print(f"✅ {self.agent_name}: Adaptive tool plan created, {len(selected)} tools selected", file=sys.stderr, flush=True)
						self._llm_retry_count = 0
						last_error = None
						break
					except asyncio.TimeoutError as e:
						last_error = e
						self._llm_retry_count += 1
						print(
							f"❌ {self.agent_name}: LLM planning timeout after {LLM_PLANNING_TIMEOUT}s (attempt {attempt}/{MAX_LLM_RETRIES})",
							file=sys.stderr,
							flush=True,
						)
					except Exception as e:
						last_error = e
						self._llm_retry_count += 1
						print(
							f"⚠️ {self.agent_name}: LLM tool selection failed (attempt {attempt}/{MAX_LLM_RETRIES}): {type(e).__name__}: {e}",
							file=sys.stderr,
							flush=True,
						)

				if selected is None:
					reason = "Comprehensive fallback - all tools"
					if last_error is not None:
						reason = f"LLM planning unavailable ({type(last_error).__name__}); {reason}"
					print(f"❌ {self.agent_name}: Using ALL available tools. Reason: {reason}", file=sys.stderr, flush=True)
					self.tool_plan = {"tools": available_tools, "reasoning": reason, "priority": "high"}

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
			raise
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
		import json, sys
		# Sanitize evidence to prevent unhashable type errors
		if evidence is not None:
			try:
				# Convert evidence to JSON-safe format
				json.dumps(evidence)
			except (TypeError, ValueError) as e:
				# If not serializable, convert to string representation
				evidence = {"raw": str(evidence), "error": f"Evidence not JSON-serializable: {e}"}
		with get_db() as db:
			finding = Finding(job_id=self.job_id, agent_name=self.agent_name, category=category, title=title, severity=severity, evidence=evidence, details=details)
			db.add(finding)
			try:
				db.commit()
			except IntegrityError:
				# Duplicate finding - skip silently (happens during Celery retries)
				db.rollback()
				print(f"⚠️  {self.agent_name}: Duplicate finding skipped: {title}", file=sys.stderr, flush=True)
				return
			db.refresh(finding)
			# Enrich finding after successful write — EnrichmentService.enrich() never raises
			enrichment = EnrichmentService.enrich(category, title, severity, evidence or {})
			try:
				db.query(Finding).filter(Finding.id == finding.id).update({
					"explanation": enrichment.explanation,
					"remediation": enrichment.remediation,
					"cwe_id": enrichment.cwe_id,
					"wstg_id": enrichment.wstg_id,
					"cvss_score_v4": enrichment.cvss_score_v4,
					"references": enrichment.references,
					"enrichment_source": enrichment.source,
				})
				db.commit()
			except Exception as enrich_err:
				db.rollback()
				print(f"⚠️  {self.agent_name}: Enrichment DB update failed for '{title}': {enrich_err}", file=sys.stderr, flush=True)

	def add_finding_with_confidence(
		self, 
		category: str, 
		title: str, 
		severity: str = "info", 
		evidence: dict | None = None, 
		details: str | None = None,
		tool_name: str | None = None,
		evidences: List[Evidence] | None = None
	) -> ConfidenceScore:
		"""Add finding with confidence scoring based on evidence.
		
		This enhanced method calculates confidence scores based on:
		- Tool verification success (exploit tools vs scanners)
		- Evidence types (data extracted, error-based, time-based, etc.)
		- Multiple confirmation sources
		
		Args:
			category: OWASP category (e.g., "WSTG-INPV-05")
			title: Finding title
			severity: Severity level (critical/high/medium/low/info)
			evidence: Evidence dictionary
			details: Additional details
			tool_name: Tool that found this vulnerability
			evidences: List of Evidence objects for confidence calculation
			
		Returns:
			ConfidenceScore object with calculated confidence
		"""
		# Calculate confidence score from evidences
		vuln_type = self._infer_vuln_type(category, title)
		
		# Use provided evidences or try to infer from tool results
		evidence_list = evidences or self._current_tool_evidences.copy()
		
		# Add tool-based evidence if tool_name provided
		if tool_name and not evidence_list:
			tool_evidence = self._confidence_scorer.create_tool_evidence(tool_name, evidence or {})
			if tool_evidence:
				evidence_list.append(tool_evidence)
		
		# Calculate confidence
		confidence = self._confidence_scorer.calculate_confidence(vuln_type, evidence_list)
		
		# Enhance evidence dict with confidence metadata
		enhanced_evidence = evidence.copy() if evidence else {}
		enhanced_evidence["_confidence"] = {
			"score": confidence.score,
			"level": confidence.level.value,
			"factors": confidence.contributing_factors,
			"evidence_count": len(confidence.evidences)
		}
		
		# Log confidence calculation
		self.log("info", f"📊 Confidence calculated: {confidence.level.value} ({confidence.score:.2f})", {
			"vuln_type": vuln_type,
			"factors": confidence.contributing_factors[:3]  # Top 3 factors
		})
		
		# Add finding with enhanced evidence
		self.add_finding(category, title, severity, enhanced_evidence, details)
		
		# Clear current tool evidences after use
		self._current_tool_evidences.clear()
		
		# Write to knowledge graph if available
		if self._knowledge_graph:
			self._write_finding_to_knowledge_graph(category, title, severity, confidence)
		
		return confidence

	def _infer_vuln_type(self, category: str, title: str) -> str:
		"""Infer vulnerability type from category and title."""
		title_lower = title.lower()
		category_lower = category.lower()
		
		# Map common patterns to vulnerability types
		mappings = {
			"sql": "sql_injection",
			"sqli": "sql_injection",
			"xss": "xss",
			"cross-site scripting": "xss",
			"csrf": "csrf",
			"cross-site request forgery": "csrf",
			"idor": "idor",
			"insecure direct object": "idor",
			"auth": "authentication_bypass",
			"session": "session_fixation",
			"upload": "file_upload",
			"path traversal": "path_traversal",
			"lfi": "path_traversal",
			"rfi": "path_traversal",
			"command injection": "command_injection",
			"rce": "command_injection",
			"xxe": "xxe",
			"ssrf": "ssrf",
			"information disclosure": "information_disclosure",
			"sensitive data": "information_disclosure",
		}
		
		for pattern, vuln_type in mappings.items():
			if pattern in title_lower or pattern in category_lower:
				return vuln_type
		
		return "unknown"

	def add_evidence_from_tool_result(self, tool_name: str, result: Dict[str, Any]) -> None:
		"""Extract and add evidence from tool execution result.
		
		Call this after each tool execution to accumulate evidence
		for confidence scoring.
		"""
		evidence = self._confidence_scorer.create_tool_evidence(tool_name, result)
		if evidence:
			self._current_tool_evidences.append(evidence)
			self.log("debug", f"📝 Evidence collected from {tool_name}: {evidence.evidence_type.value}")

	def _write_finding_to_knowledge_graph(
		self, 
		category: str, 
		title: str, 
		severity: str,
		confidence: ConfidenceScore
	) -> None:
		"""Write finding to knowledge graph as entity with relationships."""
		if not self._knowledge_graph:
			return
			
		# Create vulnerability entity
		vuln_entity = Entity(
			entity_type=EntityType.VULNERABILITY,
			name=title,
			properties={
				"category": category,
				"severity": severity,
				"confidence_score": confidence.score,
				"confidence_level": confidence.level.value,
				"agent": self.agent_name,
				"job_id": self.job_id
			}
		)
		self._knowledge_graph.add_entity(vuln_entity)
		
		# Create FINDING entity for detailed tracking
		finding_entity = Entity(
			entity_type=EntityType.FINDING,
			name=f"{self.agent_name}:{title}",
			properties={
				"evidence_count": len(confidence.evidences),
				"contributing_factors": confidence.contributing_factors,
				"timestamp": time.time()
			}
		)
		self._knowledge_graph.add_entity(finding_entity)
		
		# Link finding to vulnerability
		self._knowledge_graph.add_relationship(
			finding_entity.entity_id,
			vuln_entity.entity_id,
			RelationType.CONFIRMS
		)
		
		self.log("debug", f"📊 Knowledge graph updated with finding: {title}")

	def set_knowledge_graph(self, kg: KnowledgeGraph) -> None:
		"""Set the knowledge graph instance for this agent.
		
		Called by orchestrator to share the same KnowledgeGraph across agents.
		"""
		self._knowledge_graph = kg

	def get_knowledge_graph(self) -> Optional[KnowledgeGraph]:
		"""Get the knowledge graph instance."""
		return self._knowledge_graph

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

						# Also pass it down as the explicit auth_session argument so MCPClient
						# can standardize auth propagation when appropriate.
						auth_session = session

						# Inject auth_session into both:
						# - config.auth_session (most MCP tool modules)
						# - auth_session (some tools accept it top-level)
						if 'config' not in args:
							args['config'] = {}
						if 'auth_session' not in args.get('config', {}):
							args['config']['auth_session'] = session
						if 'auth_session' not in args:
							args['auth_session'] = session
							self.log("info", f"🔑 Auto-injected auth session for {tool}", {
								"tool": tool,
								"username": session.get('username', 'unknown'),
								"auth_type": session.get('type', session.get('session_type', 'unknown')),
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

			# Surface non-success tool results (common root cause for "tools ran but 0 findings")
			if isinstance(result, dict) and status not in ("success", "skipped"):
				self.log(
					"warning",
					"Tool returned non-success result",
					{
						"tool": tool,
						"server": server,
						"status": status,
						"message": result.get("message") or result.get("error"),
						"result_keys": list(result.keys()),
					},
				)

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

		# SCOPE ENFORCEMENT: hard-disable subdomain enumeration tools (Layer 2a)
		# Cannot be overridden by Director INCLUDE, LLM planner, or HITL approval.
		from ..core.config import SCOPE_VIOLATION_TOOLS
		if tool_name in SCOPE_VIOLATION_TOOLS:
			self.log("warning", f"[scope] tool '{tool_name}' rejected: in SCOPE_VIOLATION_TOOLS")
			print(f"🚫 {self.agent_name}: Tool {tool_name} BLOCKED — scope violation (subdomain enum disabled)", file=sys.stderr, flush=True)
			return False

		# Director SKIP check — runs before all other checks
		directive_key = f"director_directive_{self.agent_name}"
		directives = self._shared_context_snapshot.get(directive_key, [])
		if directives:
			from ..utils.directive_parser import get_skip_tools
			skip_tools = get_skip_tools(directives)
			if tool_name in skip_tools:
				self.log("info", f"Skipping {tool_name} — Director SKIP instruction")
				print(f"🎯 {self.agent_name}: Tool {tool_name} SKIPPED — Director instruction", file=sys.stderr, flush=True)
				return False

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
		"""Merge LLM-generated arguments with base arguments for comprehensive testing

		WORKAROUND: LLM (Qwen 2.5-7B Q4) generates empty '{}' arguments.
		Auto-generate comprehensive arguments from discovered endpoints.
		"""
		base = dict(args or {})
		planned = self._tool_arguments_map.get(tool_name)

		# Check if LLM provided non-empty arguments
		if isinstance(planned, dict) and planned and any(v for v in planned.values()):
			merged = dict(base)
			merged.update(planned)
			self.log("info", f"✓ Using LLM arguments for {tool_name}", {
				"base_args": base,
				"llm_args": planned,
				"merged_args": merged
			})
			return merged

		# WORKAROUND: Auto-generate comprehensive arguments for common vulnerability tests
		enhanced_args = self._auto_generate_test_arguments(tool_name, base)
		if enhanced_args and enhanced_args != base:
			self.log("info", f"🔧 Auto-generated comprehensive arguments for {tool_name}", {
				"base_args": base,
				"auto_args": enhanced_args
			})
			return enhanced_args

		# Fallback: use base arguments only
		if self._tool_arguments_map:
			self.log("debug", f"⚠ No LLM arguments for {tool_name}, using base only", {
				"available_llm_args": list(self._tool_arguments_map.keys()),
				"base_args": base
			})
		return base

	def _auto_generate_test_arguments(self, tool_name: str, base_args: Dict[str, Any]) -> Dict[str, Any]:
		"""Auto-generate comprehensive test arguments from discovered endpoints

		Bypasses LLM limitation (Qwen 2.5-7B too small for complex JSON generation)
		"""
		# Get discovered endpoints from shared context (from Katana JS crawling)
		context = self._shared_context_snapshot or {}
		endpoints = context.get("entry_points", [])
		if not self._target:
			raise ValueError(
				f"[{self.__class__.__name__}] Target URL not set. "
				"Pass target via POST /api/scans before running agents."
			)
		target_base = self._target

		# Comprehensive payload sets for each vulnerability type
		sql_payloads = [
			"' OR '1'='1--",
			"1' UNION SELECT NULL--",
			"1' AND SLEEP(5)--",
			"admin'--",
			"' OR 1=1--",
		]

		xss_payloads = [
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"<svg onload=alert(1)>",
		]

		# Tool-specific argument generation
		args = dict(base_args)

		if tool_name == "test_sqli":
			# Auto-detect search/query/api endpoints from Katana discovery
			api_endpoints = [ep for ep in endpoints if any(pattern in str(ep).lower() for pattern in ['/api/', '/rest/', 'search', 'query', '?q=', '?id='])]
			if api_endpoints and len(api_endpoints) > 0:
				ep = api_endpoints[0]
				url = ep.get("url") if isinstance(ep, dict) else str(ep)
				# Ensure URL has query parameter
				if '?' not in url:
					url = f"{url}?q=test"
				args.update({
					"url": url,
					"payloads": sql_payloads,
					"injection_types": ["union", "blind", "time-based"],
				})
			else:
				# Fallback: scan base target
				args.update({
					"url": f"{target_base}/?q=test",
					"payloads": sql_payloads,
				})

		elif tool_name == "test_xss_reflected":
			# Auto-detect form/search endpoints from Katana discovery
			form_endpoints = [ep for ep in endpoints if any(param in str(ep).lower() for param in ['search', 'comment', 'feedback', 'form', '?q='])]
			if form_endpoints and len(form_endpoints) > 0:
				ep = form_endpoints[0]
				url = ep.get("url") if isinstance(ep, dict) else str(ep)
				args.update({
					"url": url,
					"payloads": xss_payloads,
					"parameters": ["q", "query", "search", "comment"],
				})
			else:
				args.update({
					"url": f"{target_base}/",
					"payloads": xss_payloads,
				})

		elif tool_name == "test_idor_vulnerability" or tool_name == "test_idor_comprehensive":
			# Auto-detect resource endpoints with IDs from Katana discovery
			id_endpoints = [ep for ep in endpoints if any(param in str(ep).lower() for param in ['/api/', '/rest/', '/id/', 'user/', 'profile/', 'basket', 'item'])]
			if id_endpoints and len(id_endpoints) > 0:
				ep = id_endpoints[0]
				url = ep.get("url") if isinstance(ep, dict) else str(ep)
				# Add /1 if not present
				if not any(char.isdigit() for char in url):
					url = f"{url}/1"
				args.update({
					"url": url,
					"id_range": list(range(1, 21)),  # Test IDs 1-20
					"test_modes": ["sequential", "predictable"],
				})
			else:
				args.update({
					"url": f"{target_base}/api/items/1",
					"id_range": list(range(1, 21)),
				})

		return args if args != base_args else base_args

	@staticmethod
	def _extract_hostname(value: str | None) -> str | None:
		"""Extract hostname from URL or bare hostname string."""
		if not value:
			return None
		try:
			v = str(value)
			parsed = urlparse(v if "://" in v else f"http://{v}")
			return (parsed.hostname or "").lower() or None
		except Exception:
			return None

	async def _before_tool_execution(self, server: str, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
		"""Hook invoked by MCPClient prior to executing a tool.

		Returns a dict with ``approved`` flag and (optionally) sanitized ``arguments``.
		"""
		# SCOPE ENFORCEMENT: reject tool calls targeting out-of-scope hosts (Layer 2b)
		from ..core.security_guards import security_guard
		for arg_name in URL_ARG_NAMES:
			if arg_name not in args:
				continue
			host = self._extract_hostname(str(args[arg_name]))
			if host is None:
				continue
			if not security_guard.is_host_allowed(host):
				self.log("warning", f"[scope] tool '{tool_name}' rejected: arg '{arg_name}'={host!r} not in whitelist")
				print(f"🚫 {self.agent_name}: Tool {tool_name} BLOCKED — host {host!r} not in whitelist", file=sys.stderr, flush=True)
				return {"approved": False, "arguments": args}
		args = self._merge_planned_arguments(tool_name, args)
		# HIGH_RISK Director tool review — fires when hitl_mode == "agent"
		from ..core.config import HIGH_RISK_TOOLS
		if (
			tool_name in HIGH_RISK_TOOLS
			and getattr(settings, "hitl_mode", "off") == "agent"
			and self.agent_name not in self._auto_approve_agents
			and not getattr(self, "disable_hitl", False)
		):
			if not self.hitl_manager:
				self.hitl_manager = HITLManager(self.job_id, overrides=self._hitl_overrides)
			decision = await self.hitl_manager.request_tool_arg_review(
				agent_name=self.agent_name,
				tool_name=tool_name,
				server=server,
				generated_args=args,
			)
			if not decision.get("approved", True):
				self.log("warning", f"HIGH_RISK tool {tool_name} skipped by Director")
				return {"approved": False, "arguments": args}
			return {"approved": True, "arguments": decision.get("arguments", args)}

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

