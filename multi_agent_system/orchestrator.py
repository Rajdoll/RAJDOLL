from __future__ import annotations

import asyncio
import json
import os
from typing import Any, List, Dict, Optional
from datetime import datetime

from .core.config import settings
from .core.db import get_db
from .models.models import Job, JobAgent, JobStatus, AgentStatus
from .agents.base_agent import AgentRegistry, AGENT_EXECUTION_TIMEOUT  # FIX #2: Import timeout
from .utils.llm_planner import LLMPlanner
from .utils.hitl_manager import HITLManager
from .utils.shared_context_manager import SharedContextManager
from . import agents  # noqa: F401  # ensure agent classes are registered


DEFAULT_PLAN: List[Any] = [
	# ===== PHASE 1: SEQUENTIAL CRITICAL PATH =====
	# These MUST run sequentially because they build on each other's findings
	"ReconnaissanceAgent",     # 1. Discover endpoints, tech stack, entry points
	"InputValidationAgent",    # 2. Test discovered endpoints for SQLi, XSS, etc.
	"AuthenticationAgent",     # 3. Test auth using discovered vulnerabilities

	# ===== PHASE 2: PARALLEL INDEPENDENT AGENTS =====
	# These can run in parallel as they don't depend on each other
	{
		"parallel": [
			"AuthorizationAgent",        # Uses auth results for authz testing
			"SessionManagementAgent",    # Tests session security
			"ConfigDeploymentAgent",     # Tests misconfigurations
			"ClientSideAgent",           # Tests client-side vulnerabilities
			"FileUploadAgent",           # Tests file upload security
			"APITestingAgent",           # Tests API-specific issues
			"ErrorHandlingAgent",        # Tests error handling
			"WeakCryptographyAgent",     # Tests crypto weaknesses
			"BusinessLogicAgent",        # Tests business logic flaws
			"IdentityManagementAgent",   # Tests identity management
		]
	},

	# ===== PHASE 3: POST-ANALYSIS (TODO: Add LLM correlation) =====
	# Future: LLM analyzes all findings and suggests additional tests

	# ===== PHASE 4: REPORTING =====
	"ReportGenerationAgent",  # Generate final OWASP WSTG 4.2 report
]

# Mapping agent names to OWASP categories
AGENT_TO_OWASP_MAP = {
	"ReconnaissanceAgent": "WSTG-INFO",
	"ConfigDeploymentAgent": "WSTG-CONF",
	"IdentityManagementAgent": "WSTG-IDNT",
	"AuthenticationAgent": "WSTG-ATHN",
	"AuthorizationAgent": "WSTG-AUTHZ",
	"SessionManagementAgent": "WSTG-SESS",
	"InputValidationAgent": "WSTG-INPV",
	"ErrorHandlingAgent": "WSTG-ERRH",
	"WeakCryptographyAgent": "WSTG-CRYP",
	"BusinessLogicAgent": "WSTG-BUSL",
	"FileUploadAgent": "WSTG-BUSL",  # 🆕 Phase 4.1: File upload (business logic)
	"APITestingAgent": "WSTG-APIT",  # 🆕 Phase 4.2: API security testing
	"ClientSideAgent": "WSTG-CLNT",
	"ReportGenerationAgent": "WSTG-REPORT",  # 🆕 Final: Generate OWASP WSTG 4.2 report
}


class Orchestrator:
	def __init__(self, job_id: int):
		self.job_id = job_id
		self.llm_planner: Optional[LLMPlanner] = None
		self.llm_test_plan: Optional[Dict[str, Any]] = None
		self.shared_context: Dict[str, Any] = {}  # Cache of aggregated shared context
		self.context_manager = SharedContextManager(job_id, log_hook=self._log_context_event)
		self.plan_metadata: Dict[str, Any] = self._load_plan_metadata()
		options = self.plan_metadata.get("options") if isinstance(self.plan_metadata, dict) else {}
		self.hitl_manager = HITLManager(job_id, overrides=options)  # 🆕 HITL support
		self.full_wstg_coverage = bool(options.get("full_wstg_coverage"))
		
		# Initialize LLM planner if API key is configured (OpenAI/Anthropic unified)
		if settings.llm_api_key:
			try:
				self.llm_planner = LLMPlanner()
			except Exception as e:
				print(f"Warning: Failed to initialize LLM planner: {e}")
				print("Falling back to default static plan")
				self.llm_planner = None

	def _update_job_status(self, status: JobStatus):
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			if job:
				job.status = status
				db.commit()

	def _ensure_job_agents(self, plan: List[Any]):
		names: List[str] = []
		for step in plan:
			if isinstance(step, str):
				names.append(step)
			elif isinstance(step, dict) and "parallel" in step:
				names += list(step["parallel"])
		with get_db() as db:
			for n in names:
				if not db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == n).one_or_none():
					db.add(JobAgent(job_id=self.job_id, agent_name=n, status=AgentStatus.pending))
			db.commit()

	def _get_failures(self) -> int:
		with get_db() as db:
			return db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.status == AgentStatus.failed).count()

	def _run_step_sync(self, step: Any, llm_plan_step: Optional[Dict[str, Any]] = None):
		if isinstance(step, str):
			# Extract tool plan for this agent from LLM plan
			tool_plan = None
			if llm_plan_step and "tools" in llm_plan_step:
				tool_plan = llm_plan_step
			self._run_agent_sync(step, tool_plan)
		elif isinstance(step, dict) and "parallel" in step:
			# For parallel execution, we need to match tools to agents
			parallel_tools = {}
			if llm_plan_step and isinstance(llm_plan_step, dict):
				for agent_name in step["parallel"]:
					if agent_name in llm_plan_step:
						parallel_tools[agent_name] = llm_plan_step[agent_name]
			self._run_parallel_sync(step["parallel"], parallel_tools)

	def _run_agent_sync(self, agent_name: str, tool_plan: Optional[Dict[str, Any]] = None):
		# Inline run without Celery for now; Celery task exists for distributed scaling
		try:
			agent_cls = AgentRegistry.get(agent_name)
		except KeyError:
			print(f"[Orchestrator] ERROR: Agent '{agent_name}' not found in registry!")
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name).one()
				ja.status = AgentStatus.failed
				ja.error = f"Agent class not registered: {agent_name}"
				ja.finished_at = datetime.utcnow()
				db.commit()
			return
		
		agent = agent_cls(job_id=self.job_id)
		
		# If LLM provided a tool plan, inject it into the agent
		if tool_plan and hasattr(agent, 'set_tool_plan'):
			agent.set_tool_plan(tool_plan)
		
		loop = self._ensure_event_loop()
		error_message: Optional[str] = None
		try:
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name).one()
				ja.status = AgentStatus.running
				ja.attempts = (ja.attempts or 0) + 1
				ja.started_at = datetime.utcnow()
				db.commit()
			# Build current shared_context snapshot to pass into agent.execute
			shared_ctx = self._aggregate_shared_context()
			target = self._get_target()
			# FIX #2: Use reduced timeout (5 min) to prevent stuck agents
			loop.run_until_complete(asyncio.wait_for(agent.execute(target=target, shared_context=shared_ctx), timeout=AGENT_EXECUTION_TIMEOUT))
			status = AgentStatus.completed
		except asyncio.TimeoutError:
			status = AgentStatus.failed
			error_message = f"Agent timeout after {AGENT_EXECUTION_TIMEOUT}s"
		except Exception as e:
			status = AgentStatus.failed
			error_message = str(e)
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name).one()
				ja.error = str(e)
				db.commit()
		finally:
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name).one()
				ja.status = status
				ja.finished_at = datetime.utcnow()
				if error_message and not ja.error:
					ja.error = error_message
				db.commit()
		self._refresh_shared_context_cache()

	def _run_parallel_sync(self, agent_names: List[str], tools_map: Optional[Dict[str, Dict[str, Any]]] = None):
		loop = self._ensure_event_loop()
		tasks = []
		shared_ctx = self._aggregate_shared_context()
		target = self._get_target()
		for name in agent_names:
			agent_cls = AgentRegistry.get(name)
			agent = agent_cls(job_id=self.job_id)
			
			# Inject tool plan if provided by LLM
			if tools_map and name in tools_map and hasattr(agent, 'set_tool_plan'):
				agent.set_tool_plan(tools_map[name])
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == name).one()
				ja.status = AgentStatus.running
				ja.attempts = (ja.attempts or 0) + 1
				ja.started_at = datetime.utcnow()
				db.commit()
			# FIX #2: Use reduced timeout for parallel agents
			tasks.append(asyncio.wait_for(agent.execute(target=target, shared_context=shared_ctx), timeout=AGENT_EXECUTION_TIMEOUT))
		results = []
		try:
			results = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
		finally:
			# mark completion/failure based on exceptions and set finished_at
			with get_db() as db:
				for idx, name in enumerate(agent_names):
					ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == name).one()
					if isinstance(results[idx], Exception):
						ja.status = AgentStatus.failed
						ja.error = str(results[idx])
					elif ja.status == AgentStatus.running:
						ja.status = AgentStatus.completed
					ja.finished_at = datetime.utcnow()
				db.commit()
		self._refresh_shared_context_cache()

	def _ensure_event_loop(self) -> asyncio.AbstractEventLoop:
		try:
			loop = asyncio.get_event_loop()
			if loop.is_closed():
				raise RuntimeError
		except RuntimeError:
			loop = asyncio.new_event_loop()
			asyncio.set_event_loop(loop)
		return loop

	def _is_job_cancelled(self) -> bool:
		"""Check if the job has been cancelled by user"""
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			if job and job.status == JobStatus.cancelled:
				return True
		return False

	def _build_plan(self) -> List[Any]:
		meta = self.plan_metadata or {}
		sequence = meta.get("sequence") if isinstance(meta, dict) else None
		if isinstance(sequence, list) and sequence:
			return list(sequence)
		legacy = meta.get("llm_execution_plan") if isinstance(meta, dict) else None
		if isinstance(legacy, list) and legacy:
			return list(legacy)
		# Backwards compatibility: plan stored as plain list
		if isinstance(meta, list) and meta:
			return list(meta)
		return list(DEFAULT_PLAN)

	def _load_plan_metadata(self) -> Dict[str, Any]:
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			if not job or job.plan is None:
				return {}
			if isinstance(job.plan, dict):
				return dict(job.plan)
			if isinstance(job.plan, list):
				return {"sequence": list(job.plan)}
		return {}

	def _save_plan_metadata(self, meta: Dict[str, Any]):
		from sqlalchemy.orm.attributes import flag_modified
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			if job:
				job.plan = meta
				flag_modified(job, "plan")
				db.commit()
		self.plan_metadata = dict(meta)

	def _update_plan_sequence(self, sequence: List[Any]):
		meta = self.plan_metadata if isinstance(self.plan_metadata, dict) else {}
		meta = dict(meta)
		meta["sequence"] = sequence
		self._save_plan_metadata(meta)

	def _remove_recon(self, sequence: List[Any]) -> List[Any]:
		result: List[Any] = []
		skipped = False
		for step in sequence:
			if not skipped and step == "ReconnaissanceAgent":
				skipped = True
				continue
			result.append(step)
		return result

	def _get_recon_results(self) -> Optional[Dict[str, Any]]:
		"""Get reconnaissance results from the job's findings"""
		with get_db() as db:
			from .models.models import Finding
			job = db.query(Job).get(self.job_id)
			if not job:
				return None
			
			# Get findings as list of Finding ORM objects
			findings = db.query(Finding).filter(Finding.job_id == self.job_id).all()
			if not findings:
				return None
			
			# Convert Finding objects to serializable dicts
			recon_findings = []
			for f in findings:
				if f.agent_name == "ReconnaissanceAgent":
					recon_findings.append({
						"title": f.title,
						"category": f.category,
						"severity": f.severity,
						"evidence": f.evidence,
						"details": f.details
					})
			
			# Also get shared_context tech stack info
			tech_stack = self.shared_context.get("tech_stack", {})
			entry_points = self.shared_context.get("entry_points", [])
			
			return {
				"findings": recon_findings,
				"tech_stack": tech_stack,
				"entry_points": entry_points,
				"target": job.target
			}

	def _aggregate_shared_context(self) -> Dict[str, Any]:
		"""Load all shared context entries for this job into a dict."""
		return self.context_manager.load_all()

	def _populate_shared_context_from_recon(self):
		"""Populate orchestrator's shared_context from database after reconnaissance.
		
		This loads context data that ReconnaissanceAgent wrote to SharedContext table,
		making it available for _get_recon_results() to include in LLM planning.
		"""
		self._refresh_shared_context_cache()

	def _refresh_shared_context_cache(self) -> None:
		self.shared_context = self._aggregate_shared_context()
		print(f"[Orchestrator] Shared context keys now: {list(self.shared_context.keys())}")

	def _log_context_event(self, level: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
		print(f"[SharedContext:{level.upper()}] {message} :: {data}")

	def _get_target(self) -> Optional[str]:
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			return job.target if job else None

	def _convert_llm_plan_to_execution_plan(self, llm_plan: Dict[str, Any]) -> List[Any]:
		"""Convert LLM testing plan to orchestrator execution plan.

		Accepts multiple shapes:
		- { execution_sequence: [{category: WSTG-XXX, priority: ...}, ...] }
		- { execution_plan: { sequence: ["Agent", {parallel: [...]}, ...] } }
		- Fallback: derive order from owasp_categories by priority.
		"""
		execution_plan: List[Any] = ["ReconnaissanceAgent"]

		# 1) Direct sequence provided
		if isinstance(llm_plan.get("execution_plan"), dict) and isinstance(llm_plan["execution_plan"].get("sequence"), list):
			seq = llm_plan["execution_plan"]["sequence"]
			# Ensure sequence is a list of agent names or parallel blocks
			seen = set(execution_plan)  # Track duplicates
			for item in seq:
				if isinstance(item, str):
					if item not in seen:  # Deduplicate
						execution_plan.append(item)
						seen.add(item)
				elif isinstance(item, dict) and "parallel" in item:
					execution_plan.append({"parallel": list(item["parallel"])})
			return execution_plan

		# 2) Legacy/category-based sequence
		if isinstance(llm_plan.get("execution_sequence"), list):
			seen = set(execution_plan)
			for step in llm_plan["execution_sequence"]:
				category = step.get("category", "")
				# Map OWASP category to agent name
				for agent, owasp in AGENT_TO_OWASP_MAP.items():
					if owasp == category and agent not in seen:
						execution_plan.append(agent)
						seen.add(agent)
						break
			return execution_plan

		# 3) Fallback: derive from owasp_categories by priority
		cats = llm_plan.get("owasp_categories", [])
		if isinstance(cats, list):
			# Priority mapping
			prio_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3}
			def _weight(x):
				return prio_weight.get(x.get("priority", "medium"), 2)
			for item in sorted(cats, key=_weight):
				agent = item.get("agent")
				if agent and agent not in execution_plan:
					execution_plan.append(agent)
		return execution_plan

	def _get_tool_plan_for_agent(self, agent_name: str) -> Optional[Dict[str, Any]]:
		"""Extract tool plan for specific agent from LLM test plan.

		Understands these shapes:
		- owasp_categories: [{ agent, category, mcp_tools: [{tool, reason, arguments}], priority, reasoning }]
		- execution_sequence: [{ category, recommended_tools: [..], ... }]
		"""
		if not self.llm_test_plan:
			return None

		owasp_category = AGENT_TO_OWASP_MAP.get(agent_name)
		# 1) Prefer explicit owasp_categories
		cats = self.llm_test_plan.get("owasp_categories")
		if isinstance(cats, list):
			for item in cats:
				if item.get("agent") == agent_name or (owasp_category and item.get("category") == owasp_category):
					tools = []
					for t in item.get("mcp_tools", []) or []:
						if isinstance(t, dict) and t.get("tool"):
							# CRITICAL FIX: Preserve full tool objects with arguments from LLM
							# This enables execute_tool() to merge comprehensive test cases
							tools.append(t)  # Full object: {tool, reason, arguments}
					return {
						"category": item.get("category", owasp_category or ""),
						"tools": tools,  # List of tool objects with arguments
						"reasoning": item.get("reasoning", ""),
						"priority": item.get("priority", "medium"),
					}

		# 2) Legacy execution_sequence with recommended_tools
		seq = self.llm_test_plan.get("execution_sequence")
		if isinstance(seq, list) and owasp_category:
			for step in seq:
				if step.get("category") == owasp_category:
					return {
						"category": owasp_category,
						"tools": step.get("recommended_tools", []),
						"reasoning": step.get("reasoning", ""),
						"priority": step.get("priority", "medium"),
					}

		return None

	def run(self) -> None:
		self._update_job_status(JobStatus.running)
		self._refresh_shared_context_cache()
		plan_with_recon = self._build_plan()
		self._ensure_job_agents(plan_with_recon)

		# PHASE 1: Always run ReconnaissanceAgent first
		print("[Orchestrator] Phase 1: Running reconnaissance...")
		if self._is_job_cancelled():
			print("[Orchestrator] Job cancelled by user, aborting...")
			return
		self._run_step_sync("ReconnaissanceAgent")
		
		# Populate shared_context from recon results for other agents
		self._populate_shared_context_from_recon()
		plan = self._remove_recon(plan_with_recon)
		
		# PHASE 2: Use LLM to plan testing strategy based on reconnaissance
		# Skip if DISABLE_LLM_PLANNING=true (use fallback plan)
		if self._is_job_cancelled():
			print("[Orchestrator] Job cancelled by user, aborting...")
			return
		
		disable_planning = os.getenv("DISABLE_LLM_PLANNING", "false").lower() == "true"
		
		if self.llm_planner and not disable_planning:
			print("[Orchestrator] Phase 2: LLM analyzing reconnaissance and planning testing strategy...")
			try:
				recon_results = self._get_recon_results()
				if recon_results:
					# Get LLM-generated testing plan with timeout protection (5 minutes max)
					print("[Orchestrator] Calling LLM planner with 300s timeout...")
					from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
					
					with ThreadPoolExecutor(max_workers=1) as executor:
						future = executor.submit(self.llm_planner.plan_testing_strategy, recon_results)
						try:
							self.llm_test_plan = future.result(timeout=300)  # 5 minutes
							print("[Orchestrator] LLM planning completed successfully")
						except FuturesTimeoutError:
							print("[Orchestrator] ERROR: LLM planning timed out after 300s")
							print("[Orchestrator] Falling back to default plan")
							raise TimeoutError("LLM planning exceeded 5 minute timeout")
					
					# Convert LLM plan to execution plan (supports multiple formats)
					llm_execution_plan = self._convert_llm_plan_to_execution_plan(self.llm_test_plan)
					
					print(f"[Orchestrator] LLM test plan keys: {list(self.llm_test_plan.keys())}")
					print(f"[Orchestrator] owasp_categories count: {len(self.llm_test_plan.get('owasp_categories', []))}")
					print(f"[Orchestrator] LLM planned execution: {llm_execution_plan}")
					print(f"[Orchestrator] Testing strategy: {self.llm_test_plan.get('strategy') or self.llm_test_plan.get('testing_strategy', 'N/A')}")
					
					# Save execution plan metadata for downstream consumers
					meta = self.plan_metadata if isinstance(self.plan_metadata, dict) else {}
					meta = dict(meta)
					meta["llm_test_plan"] = self.llm_test_plan
					meta["llm_execution_plan"] = llm_execution_plan
					self._save_plan_metadata(meta)
					
					# Update plan to use LLM-generated sequence
					# Skip ReconnaissanceAgent since it's already done
					plan = llm_execution_plan[1:]
					
					# Validate: If LLM plan too short, merge with missing agents from DEFAULT_PLAN
					if len(plan) < 13:  # Should have 13 agents after removing ReconnaissanceAgent
						print(f"[Orchestrator] Warning: LLM plan incomplete ({len(plan)} agents), merging with default plan")
						default_agents = self._remove_recon(list(DEFAULT_PLAN))
						for agent in default_agents:
							if agent not in plan:
								plan.append(agent)
						print(f"[Orchestrator] Merged plan now has {len(plan)} agents: {plan}")
				else:
					print("[Orchestrator] Warning: No reconnaissance results found, using default plan")
					plan = self._remove_recon(list(DEFAULT_PLAN))
			except Exception as e:
				print(f"[Orchestrator] Error in LLM planning: {e}")
				print("[Orchestrator] Falling back to default plan")
				plan = self._remove_recon(list(DEFAULT_PLAN))  # Fallback only on error
		elif disable_planning:
			print("[Orchestrator] Phase 2: LLM planning disabled (DISABLE_LLM_PLANNING=true), using fallback plan")
			plan = self._remove_recon(list(DEFAULT_PLAN))
		else:
			print("[Orchestrator] LLM planner not available, using default plan")
			plan = self._remove_recon(list(DEFAULT_PLAN))

		# Override with full WSTG coverage if explicitly enabled
		if self.full_wstg_coverage:
			print("[Orchestrator] Full WSTG coverage enabled – overriding with complete agent roster.")
			plan = self._remove_recon(list(DEFAULT_PLAN))

		self._update_plan_sequence(["ReconnaissanceAgent", *plan])

		# PHASE 3: Execute the plan with LLM-selected tools
		print(f"[Orchestrator] Phase 3: Executing testing plan with {len(plan)} steps...")
		for idx, step in enumerate(plan):
			# Check if job was cancelled
			if self._is_job_cancelled():
				print("[Orchestrator] Job cancelled by user, aborting...")
				break
			
			if self._get_failures() >= settings.circuit_breaker_failures:
				print(f"[Orchestrator] Circuit breaker triggered: {self._get_failures()} failures")
				break
			
			print(f"[Orchestrator] Step {idx + 1}/{len(plan)}: {step}")
			
			# Get tool plan for this step
			tool_plan = None
			if isinstance(step, str):
				tool_plan = self._get_tool_plan_for_agent(step)
				if tool_plan:
					print(f"[Orchestrator] LLM selected tools: {tool_plan['tools']}")
			
			self._run_step_sync(step, tool_plan)

		# Aggregation/reporting would go here
		print("[Orchestrator] Testing completed")
		
		# Check if any agents failed and update job status accordingly
		with get_db() as db:
			failed_agents = db.query(JobAgent).filter(
				JobAgent.job_id == self.job_id,
				JobAgent.status == AgentStatus.failed
			).all()
			
			if failed_agents:
				failed_names = [ja.agent_name for ja in failed_agents]
				print(f"[Orchestrator] WARNING: {len(failed_agents)} agent(s) failed: {failed_names}")
				self._update_job_status(JobStatus.failed)
			else:
				print("[Orchestrator] All agents completed successfully")
				self._update_job_status(JobStatus.completed)

