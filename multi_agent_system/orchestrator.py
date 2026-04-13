from __future__ import annotations

import asyncio
import json
import os
from typing import Any, List, Dict, Optional
from datetime import datetime

from .core.config import settings
from .core.db import get_db
from .models.models import Job, JobAgent, JobStatus, AgentStatus, Finding
from .agents.base_agent import AgentRegistry, AGENT_EXECUTION_TIMEOUT  # FIX #2: Import timeout
from .utils.llm_planner import LLMPlanner
from .utils.hitl_manager import HITLManager
from .utils.shared_context_manager import SharedContextManager
from .utils.session_service import create_authenticated_session
from .utils.simple_llm_client import SimpleLLMClient
from .core.task_tree import build_task_tree
from . import agents  # noqa: F401  # ensure agent classes are registered


DEFAULT_PLAN: List[Any] = [
	# ===== FULL SEQUENTIAL EXECUTION =====
	# Planner-Summarizer architecture: each agent runs sequentially so that
	# every subsequent agent receives the cumulative summary + task tree from
	# all predecessors.  This maximises context quality for the local LLM
	# (no semaphore contention, no parallel bottleneck).
	#
	# References:
	#   - PentestGPT (Deng et al.) — Pentesting Task Tree for context tracking
	#   - HackSynth (Muzsai et al.) — Planner + Summarizer loop
	#   - PENTEST-AI (Bianou & Batogna) — sequential Saga Controller pattern
	"ReconnaissanceAgent",        #  1. Discover endpoints, tech stack
	"AuthenticationAgent",        #  2. Test auth mechanisms, obtain creds
	"SessionManagementAgent",     #  3. Analyse session/token handling
	"InputValidationAgent",       #  4. SQLi, XSS, LFI, SSTI, etc.
	"AuthorizationAgent",         #  5. Privilege escalation, IDOR
	"ConfigDeploymentAgent",      #  6. Misconfigurations, HSTS, headers
	"ClientSideAgent",            #  7. DOM XSS, CORS, clickjacking
	"FileUploadAgent",            #  8. File upload vulnerabilities
	"APITestingAgent",            #  9. API-specific issues
	"ErrorHandlingAgent",         # 10. Error disclosure, stack traces
	"WeakCryptographyAgent",      # 11. Weak TLS, crypto flaws
	"BusinessLogicAgent",         # 12. Business logic bypass
	"IdentityManagementAgent",    # 13. User enumeration, registration
	"ReportGenerationAgent",      # 14. Final OWASP WSTG 4.2 report
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

# Auto-correction map for common LLM hallucinations
# FIX: Qwen 2.5-7B Q4 often generates grammatically "better" but incorrect agent names
AGENT_NAME_CORRECTION_MAP = {
	# LLM Hallucination → Correct Name
	"ConfigurationDeploymentAgent": "ConfigDeploymentAgent",
	"ConfigurationAgent": "ConfigDeploymentAgent",
	"ConfigAgent": "ConfigDeploymentAgent",
	"WeakCryptAgent": "WeakCryptographyAgent",
	"CryptographyAgent": "WeakCryptographyAgent",
	"IdentityAgent": "IdentityManagementAgent",
	"ReconAgent": "ReconnaissanceAgent",
	"ValidationAgent": "InputValidationAgent",
	"FileUploadTestAgent": "FileUploadAgent",
	"APIAgent": "APITestingAgent",
	"ReportAgent": "ReportGenerationAgent",
	"AuthAgent": "AuthenticationAgent",
	"AuthzAgent": "AuthorizationAgent",
	"SessionAgent": "SessionManagementAgent",
	"ErrorAgent": "ErrorHandlingAgent",
	"ClientAgent": "ClientSideAgent",
	"BusinessAgent": "BusinessLogicAgent",
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

		# Planner-Summarizer state (HackSynth / PentestGPT pattern)
		self.cumulative_summary: str = ""
		self._llm_summarizer: Optional[SimpleLLMClient] = None
		self._pending_director_directives: Dict[str, list] = {}

		# Timing tracking for scan_timing SharedContext
		self._timing_autologin_s: float = 0.0
		self._timing_llm_planning_s: float = 0.0
		self._timing_summarization_s: float = 0.0
		self._timing_autologin_detail: str = ""
		self._timing_llm_planning_detail: str = ""
		
		# CRITICAL FIX: Write target URL to shared context at initialization
		# This ensures all agents have access to the actual target URL
		target_url = self._get_target()
		if target_url:
			self.context_manager.write("target", target_url)
			self.context_manager.write("target_url", target_url)  # Alias for backward compat
			print(f"[Orchestrator] Target URL written to shared_context: {target_url}")
		
		# Initialize LLM planner if API key is configured (OpenAI/Anthropic unified)
		if settings.llm_api_key:
			try:
				self.llm_planner = LLMPlanner()
			except Exception as e:
				print(f"Warning: Failed to initialize LLM planner: {e}")
				print("Falling back to default static plan")
				self.llm_planner = None

	def _format_exception_message(self, exc: BaseException) -> str:
		"""Return a non-empty, human-usable error string for persistence."""
		# asyncio and built-in TimeoutError stringify to empty.
		if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
			return f"Agent timeout after {AGENT_EXECUTION_TIMEOUT}s"
		msg = str(exc).strip()
		return msg if msg else type(exc).__name__

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

		# If LLM provided a tool plan for THIS agent, inject it
		# and mark that orchestrator already planned (skip per-agent LLM)
		if tool_plan and hasattr(agent, 'set_tool_plan'):
			agent.set_tool_plan(tool_plan)
			agent._orchestrator_had_plan = True
		else:
			agent._orchestrator_had_plan = False

		loop = self._ensure_event_loop()
		error_message: Optional[str] = None
		try:
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name).one()
				ja.status = AgentStatus.running
				ja.attempts = (ja.attempts or 0) + 1
				ja.started_at = datetime.utcnow()
				db.commit()
			# FIX PHASE 0: Refresh context cache BEFORE building snapshot
			self._refresh_shared_context_cache()
			# Build shared_context snapshot and inject planner context (cumulative summary + task tree)
			shared_ctx = self._aggregate_shared_context()
			shared_ctx = self._inject_planner_context(shared_ctx, agent_name=agent_name)
			target = self._get_target()
			loop.run_until_complete(asyncio.wait_for(agent.execute(target=target, shared_context=shared_ctx), timeout=AGENT_EXECUTION_TIMEOUT))
			status = AgentStatus.completed
		except asyncio.TimeoutError as e:
			status = AgentStatus.failed
			error_message = self._format_exception_message(e)
		except Exception as e:
			status = AgentStatus.failed
			error_message = self._format_exception_message(e)
		finally:
			with get_db() as db:
				ja = db.query(JobAgent).filter(JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name).one()
				ja.status = status
				ja.finished_at = datetime.utcnow()
				# Ensure failed agents always have a non-empty error string.
				if status == AgentStatus.failed:
					current = (ja.error or "").strip()
					if not current:
						ja.error = error_message or "Agent failed (no error details)"
				db.commit()
		self._refresh_shared_context_cache()

		# Planner-Summarizer: summarize findings after agent completes
		# Skip for ReportGenerationAgent (it consumes summaries, doesn't produce them)
		if agent_name != "ReportGenerationAgent":
			try:
				self._summarize_agent_and_accumulate(agent_name)
			except Exception as e:
				print(f"[Orchestrator] WARNING: Post-agent summarization failed for {agent_name}: {e}")

	def _run_parallel_sync(self, agent_names: List[str], tools_map: Optional[Dict[str, Dict[str, Any]]] = None):
		loop = self._ensure_event_loop()
		tasks = []
		# FIX PHASE 0: Refresh context cache BEFORE building snapshot for parallel agents
		# This ensures all parallel agents get the latest context from sequential agents (Recon, Auth, Session, InputVal)
		self._refresh_shared_context_cache()
		shared_ctx = self._aggregate_shared_context()
		target = self._get_target()
		for name in agent_names:
			agent_cls = AgentRegistry.get(name)
			agent = agent_cls(job_id=self.job_id)

			# Inject tool plan if provided by LLM
			if tools_map and name in tools_map and hasattr(agent, 'set_tool_plan'):
				agent.set_tool_plan(tools_map[name])
			elif not tools_map or name not in tools_map:
				# No orchestrator tool plan for this agent — skip per-agent LLM planning
				# to avoid 9 agents × 3 retries × 300s timeout bottleneck on LM Studio.
				# Agents will use ADAPTIVE_MODE priority filtering instead.
				agent.disable_llm_planning = True
				print(f"[Orchestrator] {name}: No LLM tool plan — using ADAPTIVE_MODE priority filtering")
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
						exc = results[idx]
						ja.error = self._format_exception_message(exc)
					elif ja.status == AgentStatus.running:
						ja.status = AgentStatus.completed
					# Ensure failed agents always have a non-empty error string.
					if ja.status == AgentStatus.failed:
						current = (ja.error or "").strip()
						if not current:
							ja.error = "Agent failed (no error details)"
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

	def _wait_for_target(self, target: str, max_wait: int = 300, poll: int = 10) -> bool:
		"""Poll target until it responds or max_wait seconds elapse.

		Called before each agent (except Recon and Report) so that a target
		crash mid-scan doesn't silently produce 0-finding agents.

		Returns True if target is reachable, False if max_wait exceeded.
		"""
		import time
		import urllib.request

		try:
			urllib.request.urlopen(target, timeout=5).close()
			return True  # fast path — target already up
		except Exception:
			pass

		print(f"[Orchestrator] ⚠  Target {target} unreachable — waiting up to {max_wait}s for recovery...")
		deadline = time.time() + max_wait
		waited = 0
		while time.time() < deadline:
			time.sleep(poll)
			waited += poll
			try:
				urllib.request.urlopen(target, timeout=5).close()
				print(f"[Orchestrator] ✅ Target {target} recovered after {waited}s — resuming scan")
				return True
			except Exception:
				print(f"[Orchestrator] Still waiting for target... ({waited}s elapsed)")

		print(f"[Orchestrator] WARNING: Target still unreachable after {max_wait}s — proceeding anyway")
		return False

	def _run_pre_agent_checkpoint(
		self,
		agent_name: str,
		agent_index: int,
		plan: list,
	) -> str:
		"""Run PRE-AGENT Director checkpoint. Returns "proceed", "skip_current", or "abort".

		On "proceed", stores directive_commands in self._pending_director_directives[agent_name].
		"""
		if getattr(settings, "hitl_mode", "off") != "agent":
			return "proceed"
		if agent_name in ("ReconnaissanceAgent", "ReportGenerationAgent"):
			return "proceed"

		remaining_after = [
			s for s in plan[agent_index + 1:]
			if isinstance(s, str) and s != agent_name
		]
		planned_tools = []
		tool_plan = self._get_tool_plan_for_agent(agent_name)
		if tool_plan:
			for t in tool_plan.get("tools", []):
				if isinstance(t, str):
					planned_tools.append(t)
				elif isinstance(t, dict) and t.get("tool"):
					planned_tools.append(t["tool"])

		loop = self._ensure_event_loop()
		try:
			result = loop.run_until_complete(
				self.hitl_manager.request_pre_agent_checkpoint(
					next_agent=agent_name,
					agent_index=agent_index,
					planned_tools=planned_tools,
					cumulative_summary=self.cumulative_summary or "",
					remaining_agents=remaining_after,
				)
			)
		except Exception as e:
			print(f"[Orchestrator] WARNING: Pre-agent checkpoint failed: {e}, auto-proceeding")
			return "proceed"

		action = result.get("action", "proceed")
		# Only store directives when the agent will actually run
		if action == "proceed":
			directive_commands = result.get("directive_commands", [])
			if directive_commands:
				self._pending_director_directives[agent_name] = directive_commands
				print(f"[Orchestrator] Director directive for {agent_name}: {directive_commands}")
		return action

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
					# FIX: Auto-correct common LLM hallucinations before validation
					original_name = item
					if item in AGENT_NAME_CORRECTION_MAP:
						item = AGENT_NAME_CORRECTION_MAP[item]
						print(f"[Orchestrator] AUTO-CORRECTED: '{original_name}' → '{item}'")

					# Validate agent name against registry (FIX Bug #2)
					if item not in AgentRegistry._agents:
						print(f"[Orchestrator] WARNING: LLM generated invalid agent name: '{item}' - skipping")
						continue
					if item not in seen:  # Deduplicate
						execution_plan.append(item)
						seen.add(item)
				elif isinstance(item, dict) and "parallel" in item:
					# Validate parallel block agent names
					valid_parallel = []
					for agent in item["parallel"]:
						# FIX: Auto-correct for parallel blocks too
						original_agent = agent
						if agent in AGENT_NAME_CORRECTION_MAP:
							agent = AGENT_NAME_CORRECTION_MAP[agent]
							print(f"[Orchestrator] AUTO-CORRECTED (parallel): '{original_agent}' → '{agent}'")

						if agent in AgentRegistry._agents:
							valid_parallel.append(agent)
						else:
							print(f"[Orchestrator] WARNING: LLM generated invalid agent name in parallel block: '{agent}' - skipping")
					if valid_parallel:
						execution_plan.append({"parallel": valid_parallel})
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

	# ====================================================================
	# Planner-Summarizer: post-agent summarisation & context injection
	# ====================================================================

	def _get_llm_summarizer(self) -> Optional[SimpleLLMClient]:
		"""Lazy-init the LLM client used for agent summarisation."""
		if self._llm_summarizer is None:
			try:
				self._llm_summarizer = SimpleLLMClient()
			except Exception as e:
				print(f"[Orchestrator] WARNING: Cannot init LLM summarizer: {e}")
		return self._llm_summarizer

	def _collect_agent_findings_text(self, agent_name: str) -> str:
		"""Collect all findings for an agent as a text block for the summarizer."""
		with get_db() as db:
			findings = (
				db.query(Finding)
				.filter(Finding.job_id == self.job_id, Finding.agent_name == agent_name)
				.all()
			)
			if not findings:
				return f"{agent_name}: No findings recorded."
			lines = [f"=== {agent_name} Findings ({len(findings)} total) ==="]
			for f in findings:
				sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
				lines.append(f"- [{sev.upper()}] {f.title} (category: {f.category})")
				if f.details:
					lines.append(f"  Details: {f.details[:300]}")
				if f.evidence and isinstance(f.evidence, dict):
					# Include key evidence fields (truncated)
					ev_str = json.dumps(f.evidence, default=str)[:400]
					lines.append(f"  Evidence: {ev_str}")
			return "\n".join(lines)

	def _summarize_agent_and_accumulate(self, agent_name: str) -> None:
		"""After an agent finishes, summarize its findings via LLM and append
		the summary to the cumulative summary string.

		If the LLM is unavailable, falls back to the raw findings text.
		"""
		raw_text = self._collect_agent_findings_text(agent_name)
		task_tree = build_task_tree(self.job_id)
		summarizer = self._get_llm_summarizer()

		summary = raw_text[:1500]  # fallback
		if summarizer:
			import time as _time
			loop = self._ensure_event_loop()
			try:
				_t_sum_start = _time.monotonic()
				summary = loop.run_until_complete(
					asyncio.wait_for(
						summarizer.summarize_agent_findings(agent_name, raw_text, task_tree),
						timeout=300,  # 5 min max for summarization (Qwen 3-4B on 4GB VRAM)
					)
				)
				self._timing_summarization_s += _time.monotonic() - _t_sum_start
				print(f"[Orchestrator] Summarized {agent_name} ({len(summary)} chars)")
			except Exception as e:
				print(f"[Orchestrator] WARNING: LLM summarization failed for {agent_name}: {e}")
				# fallback already set above

		# Accumulate
		self.cumulative_summary += f"\n\n--- {agent_name} ---\n{summary}"
		# Persist to shared context so agents can read it
		self.context_manager.write("cumulative_summary", self.cumulative_summary)
		self.context_manager.write("task_tree", task_tree)

	def _gather_agent_checkpoint_data(self, agent_name: str) -> Dict[str, Any]:
		"""Collect summary data for an agent checkpoint."""
		from .models.models import FindingSeverity
		with get_db() as db:
			findings = (
				db.query(Finding)
				.filter(Finding.job_id == self.job_id, Finding.agent_name == agent_name)
				.all()
			)
			severity_counts: Dict[str, int] = {}
			key_findings = []
			for f in findings:
				sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
				severity_counts[sev] = severity_counts.get(sev, 0) + 1
				if sev in ("critical", "high") and len(key_findings) < 10:
					key_findings.append({
						"title": f.title[:120],
						"severity": sev,
						"wstg": f.category or "",
					})
		return {
			"findings_count": len(findings) if findings else 0,
			"findings_by_severity": severity_counts,
			"key_findings": key_findings,
		}

	def _generate_checkpoint_recommendations(
		self, completed_agent: str, remaining: List[str], checkpoint_data: Dict[str, Any]
	) -> List[Dict[str, Any]]:
		"""Generate recommendations for the next step based on findings so far."""
		recs = []
		if remaining:
			recs.append({
				"agent": remaining[0],
				"reason": f"Next in default execution order",
				"priority": "default",
			})
		# If critical findings exist, suggest related agents
		criticals = checkpoint_data.get("findings_by_severity", {}).get("critical", 0)
		if criticals > 0:
			for agent in remaining:
				if agent == remaining[0]:
					continue
				# Suggest InputValidation if injection found
				if "Injection" in str(checkpoint_data.get("key_findings", [])) and "Input" in agent:
					recs.append({"agent": agent, "reason": "Injection findings suggest deeper input testing", "priority": "high"})
				if "auth" in completed_agent.lower() and "Authorization" in agent:
					recs.append({"agent": agent, "reason": "Auth findings suggest authorization testing", "priority": "high"})
		return recs[:5]

	def _run_final_analysis(self) -> None:
		"""Call LLM to correlate all findings before report generation."""
		summarizer = self._get_llm_summarizer()
		if not summarizer:
			print("[Orchestrator] No LLM summarizer — skipping final analysis")
			return
		task_tree = build_task_tree(self.job_id)
		target = self._get_target() or ""
		loop = self._ensure_event_loop()
		try:
			analysis = loop.run_until_complete(
				asyncio.wait_for(
					summarizer.analyze_all_findings(self.cumulative_summary, task_tree, target),
					timeout=600,  # 10 min for final cross-agent analysis
				)
			)
			print(f"[Orchestrator] Final analysis complete ({len(analysis)} chars)")
			self.context_manager.write("final_analysis", analysis)
			self.context_manager.write("cumulative_summary", self.cumulative_summary)
			self.context_manager.write("task_tree", task_tree)
		except Exception as e:
			print(f"[Orchestrator] WARNING: Final analysis failed: {e}")

	def _build_scope_context_block(self) -> str:
		"""Build scope constraints block for LLM planning context (Layer 1)."""
		from .core.config import SCOPE_VIOLATION_TOOLS
		from .core.security_guards import security_guard
		allowed = ", ".join(sorted(security_guard.whitelist_domains)) or "(none — all hosts allowed)"
		disabled = ", ".join(sorted(SCOPE_VIOLATION_TOOLS))
		return (
			"\n## SCOPE CONSTRAINTS (MANDATORY)\n\n"
			f"**Allowed target hosts:** {allowed}\n"
			"- All url/target_url/target/base_url/domain/host arguments MUST resolve\n"
			"  to one of these hosts (exact match or glob pattern).\n"
			"- Tool calls with hostnames outside this list will be rejected at runtime.\n\n"
			f"**Disabled tools (scope violation — do not select):**\n{disabled}\n"
			"- These tools perform subdomain/host discovery outside research scope.\n"
			"- Selecting them has no effect; they are silently skipped.\n"
		)

	def _inject_planner_context(self, shared_ctx: Dict[str, Any], agent_name: Optional[str] = None) -> Dict[str, Any]:
		"""Inject cumulative summary + task tree + director directives into shared context."""
		from .utils.directive_parser import format_for_llm
		ctx = dict(shared_ctx)
		if self.cumulative_summary:
			ctx["cumulative_summary"] = self.cumulative_summary
		task_tree = build_task_tree(self.job_id)
		if task_tree:
			ctx["task_tree"] = task_tree
		if agent_name:
			directives = self._pending_director_directives.get(agent_name, [])
			if directives:
				ctx[f"director_directive_{agent_name}"] = directives
				ctx["director_instructions_text"] = format_for_llm(directives)
		# Layer 1: Scope enforcement via LLM prompt
		ctx["scope_constraints"] = self._build_scope_context_block()
		return ctx

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
		# Record actual scan start time (not queue time) for accurate duration
		with get_db() as db:
			job = db.query(Job).get(self.job_id)
			if job and not job.started_at:
				job.started_at = datetime.utcnow()
				db.commit()
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
		
		# PHASE 1.5: Attempt auto-login to enable authenticated testing
		# This creates an authenticated session that all subsequent agents can use
		import warnings
		import time as _time
		warnings.warn("[Orchestrator] Phase 1.5: Attempting auto-login for authenticated testing...")
		_t_autologin_start = _time.monotonic()
		try:
			target_url = self._get_target()
			if target_url:
				loop = self._ensure_event_loop()
				# Read per-scan credentials from SharedContext (set by POST /api/scans)
				scan_creds = self.context_manager.read("scan_credentials")
				provided_credentials = None
				if scan_creds and isinstance(scan_creds, dict):
					provided_credentials = [(scan_creds["username"], scan_creds["password"])]

				success, auth_session = loop.run_until_complete(
					create_authenticated_session(target_url, credentials=provided_credentials)
				)
				if success:
					self.context_manager.write("authenticated_session", auth_session)
					warnings.warn(f"[Orchestrator] ✓ Auto-login successful as: {auth_session.get('username')}")
					warnings.warn(f"[Orchestrator]   Auth method: {auth_session.get('auth_method')}")
					warnings.warn(f"[Orchestrator]   JWT token: {'Present' if auth_session.get('jwt_token') else 'None'}")
					self._timing_autologin_detail = f"Logged in as {auth_session.get('username', 'unknown')}"
				else:
					warnings.warn("[Orchestrator] ⚠ Auto-login failed - continuing with unauthenticated testing")
					# Store empty auth session to indicate login was attempted
					self.context_manager.write("authenticated_session", {"logged_in": False, "login_attempted": True})
					self._timing_autologin_detail = "Login attempted but failed"
		except Exception as e:
			import traceback
			warnings.warn(f"[Orchestrator] ⚠ Auto-login error: {e} - continuing with unauthenticated testing")
			warnings.warn(f"[Orchestrator] Traceback: {traceback.format_exc()}")
			self._timing_autologin_detail = f"Error: {str(e)[:80]}"
		finally:
			self._timing_autologin_s = _time.monotonic() - _t_autologin_start
		
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
					
					_t_plan_start = _time.monotonic()
					with ThreadPoolExecutor(max_workers=1) as executor:
						future = executor.submit(self.llm_planner.plan_testing_strategy, recon_results)
						try:
							self.llm_test_plan = future.result(timeout=300)  # 5 minutes
							print("[Orchestrator] LLM planning completed successfully")
						except FuturesTimeoutError:
							print("[Orchestrator] ERROR: LLM planning timed out after 300s")
							print("[Orchestrator] Falling back to default plan")
							raise TimeoutError("LLM planning exceeded 5 minute timeout")
					self._timing_llm_planning_s = _time.monotonic() - _t_plan_start
					self._timing_llm_planning_detail = f"{len(self.llm_test_plan.get('owasp_categories', []))} OWASP categories planned"

					# Save LLM test plan metadata for tool selection
					print(f"[Orchestrator] LLM test plan keys: {list(self.llm_test_plan.keys())}")
					print(f"[Orchestrator] owasp_categories count: {len(self.llm_test_plan.get('owasp_categories', []))}")
					print(f"[Orchestrator] Testing strategy: {self.llm_test_plan.get('strategy') or self.llm_test_plan.get('testing_strategy', 'N/A')}")

					# Save execution plan metadata for downstream consumers
					meta = self.plan_metadata if isinstance(self.plan_metadata, dict) else {}
					meta = dict(meta)
					meta["llm_test_plan"] = self.llm_test_plan
					self._save_plan_metadata(meta)

					# OPTION B (FIX Bug #1 & #3): Use DEFAULT_PLAN parallel structure for Phase 2
					# LLM planning is used ONLY for tool selection, NOT execution order
					print("[Orchestrator] Phase 2: Using DEFAULT_PLAN parallel structure (LLM for tool selection only)")
					plan = self._remove_recon(list(DEFAULT_PLAN))  # Preserves {"parallel": [...]}
					print(f"[Orchestrator] Execution plan: {plan}")
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
		agent_hitl_auto = False  # Set True when user chooses "auto" at a checkpoint
		skip_agents_set: set = set()  # Agents the user chose to skip

		for idx, step in enumerate(plan):
			agent_name = step if isinstance(step, str) else str(step)

			# Check if job was cancelled
			if self._is_job_cancelled():
				print("[Orchestrator] Job cancelled by user, aborting...")
				break

			if self._get_failures() >= settings.circuit_breaker_failures:
				print(f"[Orchestrator] Circuit breaker triggered: {self._get_failures()} failures")
				break

			# Check if user requested to skip this agent
			if agent_name in skip_agents_set:
				print(f"[Orchestrator] Skipping {agent_name} (user requested)")
				with get_db() as db:
					ja = db.query(JobAgent).filter(
						JobAgent.job_id == self.job_id, JobAgent.agent_name == agent_name
					).one_or_none()
					if ja:
						ja.status = AgentStatus.skipped if hasattr(AgentStatus, "skipped") else AgentStatus.failed
						ja.error = "Skipped by user via HITL checkpoint"
						ja.finished_at = datetime.utcnow()
						db.commit()
				continue

			print(f"[Orchestrator] Step {idx + 1}/{len(plan)}: {step}")

			# Get tool plan for this step
			tool_plan = None
			if isinstance(step, str):
				tool_plan = self._get_tool_plan_for_agent(step)
				if tool_plan:
					print(f"[Orchestrator] LLM selected tools: {tool_plan['tools']}")
			elif isinstance(step, dict) and "parallel" in step:
				# Build per-agent tool plans for parallel batch
				tool_plan = {}
				for pname in step["parallel"]:
					agent_plan = self._get_tool_plan_for_agent(pname)
					if agent_plan:
						tool_plan[pname] = agent_plan
						print(f"[Orchestrator] LLM selected tools for {pname}: {agent_plan['tools']}")
				if not tool_plan:
					tool_plan = None  # No plans found for any agent

			# Target health check — wait for target to recover before starting
			# each agent (skip Recon which must always run, and Report which
			# doesn't need the target to be live).
			if isinstance(step, str) and step not in ("ReconnaissanceAgent", "ReportGenerationAgent"):
				target_url = self._get_target()
				if target_url:
					self._wait_for_target(target_url)

			# ── Director PRE-AGENT Checkpoint ──────────────────────────
			if isinstance(step, str) and step not in ("ReconnaissanceAgent", "ReportGenerationAgent") and not agent_hitl_auto:
				pre_action = self._run_pre_agent_checkpoint(step, idx, plan)
				if pre_action == "abort":
					print("[Orchestrator] Director ABORTED scan at pre-agent checkpoint")
					break
				if pre_action == "skip_current":
					print(f"[Orchestrator] Director SKIPPED {step}")
					with get_db() as db:
						ja = db.query(JobAgent).filter(
							JobAgent.job_id == self.job_id, JobAgent.agent_name == step
						).one_or_none()
						if ja:
							ja.status = AgentStatus.skipped if hasattr(AgentStatus, "skipped") else AgentStatus.failed
							ja.error = "Skipped by Director at pre-agent checkpoint"
							ja.finished_at = datetime.utcnow()
							db.commit()
					continue

			self._run_step_sync(step, tool_plan)

			# ── Agent-Level HITL Checkpoint ──────────────────────────────
			# After each agent completes + summarization, pause for user review
			# (skip for ReportGenerationAgent, and if user chose "auto")
			if (
				not agent_hitl_auto
				and isinstance(step, str)
				and step != "ReportGenerationAgent"
				and getattr(settings, "hitl_mode", "off") == "agent"
			):
				remaining = [s for s in plan[idx + 1:] if isinstance(s, str) and s not in skip_agents_set]
				next_agent = remaining[0] if remaining else None
				cp_data = self._gather_agent_checkpoint_data(agent_name)
				recommendations = self._generate_checkpoint_recommendations(agent_name, remaining, cp_data)

				loop = self._ensure_event_loop()
				try:
					result = loop.run_until_complete(
						self.hitl_manager.request_agent_checkpoint(
							completed_agent=agent_name,
							agent_index=idx,
							findings_count=cp_data["findings_count"],
							findings_by_severity=cp_data["findings_by_severity"],
							agent_summary=self.cumulative_summary[-1500:] if self.cumulative_summary else "",
							cumulative_summary=self.cumulative_summary,
							key_findings=cp_data["key_findings"],
							next_agent=next_agent,
							remaining_agents=remaining,
							recommendations=recommendations,
						)
					)
				except Exception as e:
					print(f"[Orchestrator] WARNING: Agent checkpoint failed: {e}, auto-proceeding")
					result = {"action": "proceed"}

				action = result.get("action", "proceed")

				if action == "auto":
					agent_hitl_auto = True
					print("[Orchestrator] User chose AUTO — disabling checkpoints for remaining agents")
				elif action == "abort":
					print("[Orchestrator] User ABORTED scan at checkpoint")
					break
				elif action == "skip_next":
					if next_agent:
						skip_agents_set.add(next_agent)
						print(f"[Orchestrator] User chose to skip next agent: {next_agent}")
				elif action == "reorder":
					override = result.get("next_agent_override")
					if override and override in remaining and override != next_agent:
						# Move the overridden agent to front of remaining
						remaining_copy = list(plan[idx + 1:])
						if override in remaining_copy:
							remaining_copy.remove(override)
							remaining_copy.insert(0, override)
							plan[idx + 1:] = remaining_copy
							print(f"[Orchestrator] User reordered: next agent is now {override}")

				# Apply any skip_agents from user
				user_skips = result.get("skip_agents")
				if isinstance(user_skips, list):
					skip_agents_set.update(user_skips)
			# ── End checkpoint ───────────────────────────────────────────

		# Planner-Summarizer: Run final cross-agent analysis before report generation
		if not self._is_job_cancelled():
			print("[Orchestrator] Running final cross-agent analysis...")
			try:
				self._run_final_analysis()
			except Exception as e:
				print(f"[Orchestrator] WARNING: Final analysis failed: {e}")

		# Write scan timing breakdown to SharedContext for PDF report
		try:
			with get_db() as db:
				agents_db = db.query(JobAgent).filter(JobAgent.job_id == self.job_id).all()
				agent_sum_s = sum(
					(a.finished_at - a.started_at).total_seconds()
					for a in agents_db
					if a.started_at and a.finished_at
				)
			scan_timing = {
				"phases": [
					{
						"name": "Auto-login",
						"duration_s": round(self._timing_autologin_s),
						"detail": self._timing_autologin_detail or "Attempted",
					},
					{
						"name": "LLM Planning",
						"duration_s": round(self._timing_llm_planning_s),
						"detail": self._timing_llm_planning_detail or "Strategy generation",
					},
					{
						"name": "Summarization",
						"duration_s": round(self._timing_summarization_s),
						"detail": f"{len(agents_db)} agents summarized",
					},
					{
						"name": "Agent execution",
						"duration_s": round(agent_sum_s),
						"detail": f"Sum of {len(agents_db)} agent durations",
					},
				],
			}
			self.context_manager.write("scan_timing", scan_timing)
			print(f"[Orchestrator] scan_timing written: autologin={self._timing_autologin_s:.0f}s "
				  f"planning={self._timing_llm_planning_s:.0f}s "
				  f"summarization={self._timing_summarization_s:.0f}s "
				  f"agents={agent_sum_s:.0f}s")
		except Exception as e:
			print(f"[Orchestrator] WARNING: Could not write scan_timing: {e}")

		# Best-effort: ensure report generation runs even if circuit breaker
		# or early loop exit prevented reaching the final report step.
		if not self._is_job_cancelled():
			with get_db() as db:
				report_ja = db.query(JobAgent).filter(
					JobAgent.job_id == self.job_id,
					JobAgent.agent_name == "ReportGenerationAgent",
				).one_or_none()
				report_pending = bool(report_ja and report_ja.status in (AgentStatus.pending, AgentStatus.running))
			if report_pending:
				print("[Orchestrator] ReportGenerationAgent still pending; running it now...")
				self._run_step_sync("ReportGenerationAgent", self._get_tool_plan_for_agent("ReportGenerationAgent"))

		# Aggregation/reporting would go here
		print("[Orchestrator] Testing completed")
		
		# Determine final job status based on agent results
		# The job is "completed" as long as the report was generated.
		# Individual agent failures are expected (tool timeouts, MCP issues)
		# and should not fail the entire scan.
		with get_db() as db:
			failed_agents = db.query(JobAgent).filter(
				JobAgent.job_id == self.job_id,
				JobAgent.status == AgentStatus.failed
			).all()
			report_agent = db.query(JobAgent).filter(
				JobAgent.job_id == self.job_id,
				JobAgent.agent_name == "ReportGenerationAgent",
			).one_or_none()
			report_ok = report_agent and report_agent.status == AgentStatus.completed

			if failed_agents:
				failed_names = [ja.agent_name for ja in failed_agents]
				print(f"[Orchestrator] WARNING: {len(failed_agents)} agent(s) failed: {failed_names}")

			if report_ok or not failed_agents:
				print(f"[Orchestrator] Job completed (report generated, {len(failed_agents)} agent(s) had errors)")
				self._update_job_status(JobStatus.completed)
			else:
				print(f"[Orchestrator] Job failed — report not generated and {len(failed_agents)} agent(s) failed")
				self._update_job_status(JobStatus.failed)

