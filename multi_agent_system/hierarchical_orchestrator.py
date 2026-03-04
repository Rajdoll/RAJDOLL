"""
Hierarchical Multi-Agent Orchestrator

Meta-orchestrator yang mengkoordinasi agent dalam cluster:
- Recon Cluster (Info + Identity)
- Attack Cluster (Input + Auth + Session)
- Logic Cluster (Business + Client + Config)

Berbeda dari flat orchestration, hierarchical approach:
1. Meniru struktur tim pentest profesional
2. Lebih scalable untuk parallel execution
3. Better resource management
4. Cluster-level decision making

Author: RAJDOLL Research Project
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor

from .core.config import settings
from .core.db import get_db
from .models.models import Job, JobAgent, JobStatus, AgentStatus
from .agents.base_agent import AgentRegistry, AGENT_EXECUTION_TIMEOUT
from .utils.llm_planner import LLMPlanner
from .utils.shared_context_manager import SharedContextManager
from .utils.knowledge_graph import KnowledgeGraph, EntityType
from .utils.confidence_scorer import ConfidenceScorer
from .utils.attack_chain_detector import AttackChainDetector


class ClusterType(str, Enum):
    """Types of agent clusters"""
    RECONNAISSANCE = "reconnaissance"
    ATTACK = "attack"
    LOGIC = "logic"
    REPORTING = "reporting"


class ClusterStatus(str, Enum):
    """Status of a cluster"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AgentCluster:
    """
    A cluster of related agents that work together.
    """
    cluster_type: ClusterType
    agents: List[str]
    status: ClusterStatus = ClusterStatus.PENDING
    parallel: bool = True  # Can agents run in parallel?
    dependencies: List[ClusterType] = field(default_factory=list)
    priority: int = 0  # Lower = higher priority
    results: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    
    @property
    def duration_seconds(self) -> float:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.cluster_type.value,
            "agents": self.agents,
            "status": self.status.value,
            "parallel": self.parallel,
            "dependencies": [d.value for d in self.dependencies],
            "priority": self.priority,
            "duration_seconds": self.duration_seconds,
        }


# Default cluster configuration
DEFAULT_CLUSTERS = [
    AgentCluster(
        cluster_type=ClusterType.RECONNAISSANCE,
        agents=["ReconnaissanceAgent", "IdentityManagementAgent"],
        parallel=False,  # Sequential: Recon first, then Identity
        dependencies=[],
        priority=0,
    ),
    AgentCluster(
        cluster_type=ClusterType.ATTACK,
        agents=[
            "AuthenticationAgent",
            "SessionManagementAgent",
            "InputValidationAgent",
            "AuthorizationAgent",
        ],
        parallel=False,  # Sequential: Auth → Session → Input → Authz
        dependencies=[ClusterType.RECONNAISSANCE],
        priority=1,
    ),
    AgentCluster(
        cluster_type=ClusterType.LOGIC,
        agents=[
            "BusinessLogicAgent",
            "FileUploadAgent",
            "APITestingAgent",
            "ClientSideAgent",
            "ConfigDeploymentAgent",
            "ErrorHandlingAgent",
            "WeakCryptographyAgent",
        ],
        parallel=True,  # Can run in parallel
        dependencies=[ClusterType.ATTACK],  # Needs auth/session info
        priority=2,
    ),
    AgentCluster(
        cluster_type=ClusterType.REPORTING,
        agents=["ReportGenerationAgent"],
        parallel=False,
        dependencies=[ClusterType.RECONNAISSANCE, ClusterType.ATTACK, ClusterType.LOGIC],
        priority=3,
    ),
]


class HierarchicalOrchestrator:
    """
    Hierarchical Multi-Agent Orchestrator.
    
    Coordinates agents in clusters for more efficient and scalable execution.
    
    Architecture:
    ```
                    ┌─────────────────────────┐
                    │ HierarchicalOrchestrator │
                    │    (Meta-Coordinator)    │
                    └────────────┬────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
    │  Recon Cluster│    │ Attack Cluster│    │ Logic Cluster │
    │ ┌───────────┐ │    │ ┌───────────┐ │    │ ┌───────────┐ │
    │ │ ReconAgent│ │    │ │ AuthAgent │ │    │ │  BizLogic │ │
    │ │ IdentAgent│ │    │ │SessionAgnt│ │    │ │FileUpload │ │
    │ └───────────┘ │    │ │InputValAgt│ │    │ │ APITesting│ │
    └───────────────┘    │ │ AuthzAgent│ │    │ │ ClientSide│ │
                         │ └───────────┘ │    │ │  Config   │ │
                         └───────────────┘    │ │  Crypto   │ │
                                              │ └───────────┘ │
                                              └───────────────┘
    ```
    
    Usage:
        orchestrator = HierarchicalOrchestrator(job_id=1)
        orchestrator.run()
    """
    
    def __init__(self, job_id: int):
        self.job_id = job_id
        
        # State
        self.clusters: List[AgentCluster] = [
            AgentCluster(**{**c.__dict__}) for c in DEFAULT_CLUSTERS
        ]
        self.shared_context: Dict[str, Any] = {}
        
        # Managers
        self.context_manager = SharedContextManager(job_id, log_hook=self._log_context_event)
        self.kg = KnowledgeGraph(job_id)
        self.scorer = ConfidenceScorer()
        self.chain_detector = AttackChainDetector(job_id, knowledge_graph=self.kg)
        
        # LLM planner for strategic decisions
        self.llm_planner: Optional[LLMPlanner] = None
        if settings.llm_api_key:
            try:
                self.llm_planner = LLMPlanner()
            except Exception as e:
                print(f"Warning: Failed to initialize LLM planner: {e}")
        
        # Execution state
        self._completed_clusters: Set[ClusterType] = set()
        self._failed_agents: Set[str] = set()
        self._total_findings = 0
    
    def _log_context_event(self, level: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Log context events"""
        print(f"[HierarchicalOrch:{level.upper()}] {message} :: {data}")
    
    def _update_job_status(self, status: JobStatus) -> None:
        """Update job status in database"""
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job:
                job.status = status
                db.commit()
    
    def _get_target(self) -> Optional[str]:
        """Get target URL from job"""
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
    
    def _ensure_job_agents(self) -> None:
        """Ensure all agents have JobAgent records"""
        all_agents = []
        for cluster in self.clusters:
            all_agents.extend(cluster.agents)
        
        with get_db() as db:
            for agent_name in all_agents:
                existing = db.query(JobAgent).filter(
                    JobAgent.job_id == self.job_id,
                    JobAgent.agent_name == agent_name
                ).one_or_none()
                
                if not existing:
                    db.add(JobAgent(
                        job_id=self.job_id,
                        agent_name=agent_name,
                        status=AgentStatus.pending
                    ))
            db.commit()
    
    def _refresh_shared_context(self) -> None:
        """Refresh shared context from database"""
        self.shared_context = self.context_manager.load_all()
        print(f"[HierarchicalOrch] Context keys: {list(self.shared_context.keys())}")
    
    def _is_cluster_ready(self, cluster: AgentCluster) -> bool:
        """Check if cluster dependencies are satisfied"""
        for dep in cluster.dependencies:
            if dep not in self._completed_clusters:
                return False
        return True
    
    def _run_agent(self, agent_name: str) -> bool:
        """
        Run a single agent.
        
        Returns:
            True if agent completed successfully, False otherwise
        """
        try:
            agent_cls = AgentRegistry.get(agent_name)
        except KeyError:
            print(f"[HierarchicalOrch] ERROR: Agent '{agent_name}' not found")
            self._mark_agent_failed(agent_name, f"Agent class not registered: {agent_name}")
            return False
        
        agent = agent_cls(job_id=self.job_id)
        
        # Update status to running
        with get_db() as db:
            ja = db.query(JobAgent).filter(
                JobAgent.job_id == self.job_id,
                JobAgent.agent_name == agent_name
            ).one()
            ja.status = AgentStatus.running
            ja.started_at = datetime.utcnow()
            ja.attempts = (ja.attempts or 0) + 1
            db.commit()
        
        # Refresh context before running
        self._refresh_shared_context()
        target = self._get_target()
        
        # Create event loop if needed
        loop = self._ensure_event_loop()
        
        try:
            # Run agent with timeout
            loop.run_until_complete(
                asyncio.wait_for(
                    agent.execute(target=target, shared_context=self.shared_context),
                    timeout=AGENT_EXECUTION_TIMEOUT
                )
            )
            
            # Mark success
            with get_db() as db:
                ja = db.query(JobAgent).filter(
                    JobAgent.job_id == self.job_id,
                    JobAgent.agent_name == agent_name
                ).one()
                ja.status = AgentStatus.completed
                ja.finished_at = datetime.utcnow()
                db.commit()
            
            return True
            
        except asyncio.TimeoutError:
            self._mark_agent_failed(agent_name, f"Timeout after {AGENT_EXECUTION_TIMEOUT}s")
            return False
            
        except Exception as e:
            self._mark_agent_failed(agent_name, str(e))
            return False
    
    def _mark_agent_failed(self, agent_name: str, error: str) -> None:
        """Mark agent as failed"""
        with get_db() as db:
            ja = db.query(JobAgent).filter(
                JobAgent.job_id == self.job_id,
                JobAgent.agent_name == agent_name
            ).one()
            ja.status = AgentStatus.failed
            ja.error = error
            ja.finished_at = datetime.utcnow()
            db.commit()
        
        self._failed_agents.add(agent_name)
    
    def _run_cluster(self, cluster: AgentCluster) -> bool:
        """
        Run all agents in a cluster.
        
        Returns:
            True if cluster completed successfully (at least one agent succeeded)
        """
        print(f"\n{'='*60}")
        print(f"[HierarchicalOrch] Starting cluster: {cluster.cluster_type.value}")
        print(f"[HierarchicalOrch] Agents: {cluster.agents}")
        print(f"[HierarchicalOrch] Mode: {'Parallel' if cluster.parallel else 'Sequential'}")
        print(f"{'='*60}\n")
        
        cluster.status = ClusterStatus.RUNNING
        cluster.started_at = datetime.utcnow()
        
        successes = 0
        
        if cluster.parallel and len(cluster.agents) > 1:
            # Run agents in parallel
            successes = self._run_agents_parallel(cluster.agents)
        else:
            # Run agents sequentially
            for agent_name in cluster.agents:
                # Check if job cancelled
                if self._is_job_cancelled():
                    print(f"[HierarchicalOrch] Job cancelled, stopping cluster")
                    break
                
                print(f"[HierarchicalOrch] Running agent: {agent_name}")
                if self._run_agent(agent_name):
                    successes += 1
                    # Refresh context after each sequential agent
                    self._refresh_shared_context()
                else:
                    print(f"[HierarchicalOrch] Agent {agent_name} failed")
        
        cluster.finished_at = datetime.utcnow()
        
        if successes > 0:
            cluster.status = ClusterStatus.COMPLETED
            self._completed_clusters.add(cluster.cluster_type)
            print(f"[HierarchicalOrch] Cluster {cluster.cluster_type.value} completed. Success: {successes}/{len(cluster.agents)}")
            return True
        else:
            cluster.status = ClusterStatus.FAILED
            print(f"[HierarchicalOrch] Cluster {cluster.cluster_type.value} FAILED. No agents succeeded.")
            return False
    
    def _run_agents_parallel(self, agent_names: List[str]) -> int:
        """
        Run multiple agents in parallel.
        
        Returns:
            Number of successful agents
        """
        loop = self._ensure_event_loop()
        
        async def run_agent_async(agent_name: str) -> bool:
            """Async wrapper for agent execution"""
            try:
                agent_cls = AgentRegistry.get(agent_name)
                agent = agent_cls(job_id=self.job_id)
                
                # Update status
                with get_db() as db:
                    ja = db.query(JobAgent).filter(
                        JobAgent.job_id == self.job_id,
                        JobAgent.agent_name == agent_name
                    ).one()
                    ja.status = AgentStatus.running
                    ja.started_at = datetime.utcnow()
                    ja.attempts = (ja.attempts or 0) + 1
                    db.commit()
                
                # Run with timeout
                await asyncio.wait_for(
                    agent.execute(target=self._get_target(), shared_context=self.shared_context),
                    timeout=AGENT_EXECUTION_TIMEOUT
                )
                
                # Mark success
                with get_db() as db:
                    ja = db.query(JobAgent).filter(
                        JobAgent.job_id == self.job_id,
                        JobAgent.agent_name == agent_name
                    ).one()
                    ja.status = AgentStatus.completed
                    ja.finished_at = datetime.utcnow()
                    db.commit()
                
                return True
                
            except Exception as e:
                self._mark_agent_failed(agent_name, str(e))
                return False
        
        async def run_all():
            tasks = [run_agent_async(name) for name in agent_names]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return sum(1 for r in results if r is True)
        
        return loop.run_until_complete(run_all())
    
    def _ensure_event_loop(self) -> asyncio.AbstractEventLoop:
        """Ensure we have an event loop"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop
    
    def _is_job_cancelled(self) -> bool:
        """Check if job has been cancelled"""
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job and job.status == JobStatus.cancelled
    
    def _optimize_cluster_order(self) -> List[AgentCluster]:
        """
        Use LLM to optimize cluster execution order based on recon results.
        
        Falls back to default priority order if LLM unavailable.
        """
        if not self.llm_planner:
            return sorted(self.clusters, key=lambda c: c.priority)
        
        # Get recon results for strategic planning
        recon_data = {
            "tech_stack": self.shared_context.get("tech_stack", {}),
            "entry_points": self.shared_context.get("entry_points", []),
            "endpoints": len(self.shared_context.get("discovered_endpoints", [])),
        }
        
        # For now, use default order
        # TODO: Implement LLM-based cluster prioritization
        return sorted(self.clusters, key=lambda c: c.priority)
    
    def _detect_attack_chains(self) -> None:
        """Detect attack chains from findings"""
        print("\n[HierarchicalOrch] Detecting attack chains...")
        
        # Load findings from knowledge graph
        vulns = self.kg.query_by_type(EntityType.VULNERABILITY)
        
        for vuln in vulns:
            self.chain_detector.add_vulnerability(
                vuln_type=vuln.properties.get("vulnerability_type", ""),
                location=vuln.name,
                agent_name=vuln.discovered_by,
                severity=vuln.properties.get("severity", "medium"),
            )
        
        chains = self.chain_detector.detect_chains()
        
        if chains:
            print(f"[HierarchicalOrch] Detected {len(chains)} attack chains:")
            for chain in chains:
                print(f"  - {chain.name} ({chain.impact.value})")
    
    def run(self) -> None:
        """
        Main orchestration loop.
        
        Executes clusters in order based on dependencies and priorities.
        """
        print(f"\n{'#'*60}")
        print(f"# HIERARCHICAL ORCHESTRATOR - Job {self.job_id}")
        print(f"# Target: {self._get_target()}")
        print(f"# Clusters: {len(self.clusters)}")
        print(f"{'#'*60}\n")
        
        self._update_job_status(JobStatus.running)
        self._ensure_job_agents()
        
        # Sort clusters by priority (dependencies handled by readiness check)
        ordered_clusters = self._optimize_cluster_order()
        
        for cluster in ordered_clusters:
            # Check if job cancelled
            if self._is_job_cancelled():
                print("[HierarchicalOrch] Job cancelled, stopping execution")
                break
            
            # Check dependencies
            if not self._is_cluster_ready(cluster):
                print(f"[HierarchicalOrch] Cluster {cluster.cluster_type.value} waiting for dependencies")
                cluster.status = ClusterStatus.SKIPPED
                continue
            
            # Run the cluster
            self._run_cluster(cluster)
            
            # Check circuit breaker
            if len(self._failed_agents) >= settings.circuit_breaker_failures:
                print(f"[HierarchicalOrch] Circuit breaker triggered: {len(self._failed_agents)} failures")
                break
        
        # Post-processing
        if not self._is_job_cancelled():
            # Detect attack chains
            self._detect_attack_chains()
            
            # Update job status
            if self._failed_agents and len(self._failed_agents) == sum(len(c.agents) for c in self.clusters):
                self._update_job_status(JobStatus.failed)
            else:
                self._update_job_status(JobStatus.completed)
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self) -> None:
        """Print execution summary"""
        print(f"\n{'='*60}")
        print("EXECUTION SUMMARY")
        print(f"{'='*60}")
        
        for cluster in self.clusters:
            status_emoji = {
                ClusterStatus.COMPLETED: "✅",
                ClusterStatus.FAILED: "❌",
                ClusterStatus.SKIPPED: "⏭️",
                ClusterStatus.PENDING: "⏳",
                ClusterStatus.RUNNING: "🔄",
            }
            
            print(f"\n{status_emoji.get(cluster.status, '❓')} {cluster.cluster_type.value.upper()}")
            print(f"   Status: {cluster.status.value}")
            print(f"   Duration: {cluster.duration_seconds:.1f}s")
            print(f"   Agents: {', '.join(cluster.agents)}")
        
        print(f"\n{'='*60}")
        print(f"Failed agents: {self._failed_agents or 'None'}")
        print(f"Knowledge graph entities: {len(self.kg.get_all_entities())}")
        print(f"Attack chains detected: {len(self.chain_detector.get_all_chains())}")
        print(f"{'='*60}\n")
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get status of all clusters"""
        return {
            "clusters": [c.to_dict() for c in self.clusters],
            "completed": [c.value for c in self._completed_clusters],
            "failed_agents": list(self._failed_agents),
        }


# Factory function
def create_hierarchical_orchestrator(job_id: int) -> HierarchicalOrchestrator:
    """Create a new hierarchical orchestrator"""
    return HierarchicalOrchestrator(job_id)


# CLI entry point for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python hierarchical_orchestrator.py <job_id>")
        sys.exit(1)
    
    job_id = int(sys.argv[1])
    orchestrator = HierarchicalOrchestrator(job_id)
    orchestrator.run()
