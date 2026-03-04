"""
ReAct (Reasoning + Acting) Pattern untuk Agent Decision-Making

Implementasi ReAct pattern yang memungkinkan agent untuk:
1. Observe - Mengamati hasil dari aksi sebelumnya
2. Think - Reasoning tentang apa yang harus dilakukan
3. Act - Melakukan aksi (tool call)
4. Loop - Ulangi sampai goal tercapai

Berbeda dari single-shot planning, ReAct memungkinkan
agent untuk adaptif dan recovery dari kegagalan.

Reference: Yao et al., "ReAct: Synergizing Reasoning and Acting in Language Models"

Author: RAJDOLL Research Project
"""

from __future__ import annotations

import asyncio
import json
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Awaitable

from ..utils.simple_llm_client import SimpleLLMClient
from ..utils.knowledge_graph import KnowledgeGraph
from ..utils.confidence_scorer import ConfidenceScorer, ConfidenceScore


class ThoughtType(str, Enum):
    """Types of reasoning in ReAct loop"""
    OBSERVATION = "observation"     # What did I observe?
    REASONING = "reasoning"         # What does this mean?
    PLANNING = "planning"          # What should I do next?
    REFLECTION = "reflection"      # Did that work? What did I learn?
    CONCLUSION = "conclusion"      # Am I done?


class ActionStatus(str, Enum):
    """Status of an action"""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Thought:
    """A single thought in the reasoning chain"""
    thought_type: ThoughtType
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.thought_type.value,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Action:
    """An action to be executed"""
    tool_name: str
    arguments: Dict[str, Any]
    reason: str
    status: ActionStatus = ActionStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "arguments": self.arguments,
            "reason": self.reason,
            "status": self.status.value,
            "result": str(self.result)[:500] if self.result else None,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class Observation:
    """Observation from an action result"""
    action: Action
    interpretation: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    next_actions_suggested: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "interpretation": self.interpretation,
            "findings_count": len(self.findings),
            "suggestions": self.next_actions_suggested,
        }


@dataclass
class ReActStep:
    """A complete step in the ReAct loop"""
    step_number: int
    thought: Thought
    action: Optional[Action]
    observation: Optional[Observation]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "thought": self.thought.to_dict(),
            "action": self.action.to_dict() if self.action else None,
            "observation": self.observation.to_dict() if self.observation else None,
        }


class ReActAgent(ABC):
    """
    Base class for ReAct-style agents.
    
    Implements the observe-think-act loop with LLM-based reasoning.
    
    Usage:
        class SQLInjectionReActAgent(ReActAgent):
            async def get_available_tools(self) -> List[str]:
                return ["run_sqlmap", "test_blind_sqli", "enumerate_database"]
            
            async def execute_tool(self, tool_name: str, arguments: Dict) -> Any:
                # Implementation
                pass
            
            def get_goal_description(self) -> str:
                return "Find and verify SQL injection vulnerabilities"
        
        agent = SQLInjectionReActAgent(job_id=1, target="http://example.com")
        findings = await agent.run()
    """
    
    # Configuration
    MAX_STEPS = 20                    # Maximum ReAct iterations
    MAX_CONSECUTIVE_FAILURES = 3     # Stop after this many failures
    STEP_TIMEOUT = 300               # 5 minutes per step
    
    def __init__(
        self,
        job_id: int,
        target: str,
        shared_context: Optional[Dict[str, Any]] = None,
        llm_client: Optional[SimpleLLMClient] = None,
    ):
        self.job_id = job_id
        self.target = target
        self.shared_context = shared_context or {}
        
        # LLM client for reasoning
        self._llm_client = llm_client or SimpleLLMClient()
        
        # Knowledge graph for context
        self._kg = KnowledgeGraph(job_id)
        
        # Confidence scorer
        self._scorer = ConfidenceScorer()
        
        # ReAct state
        self._steps: List[ReActStep] = []
        self._findings: List[Dict[str, Any]] = []
        self._consecutive_failures = 0
        self._is_goal_achieved = False
        
        # Trace for debugging/analysis
        self._trace: List[Dict[str, Any]] = []
    
    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Name of this agent"""
        pass
    
    @property
    def system_prompt(self) -> str:
        """System prompt for LLM reasoning. Override in subclasses."""
        return f"""You are a security testing agent using the ReAct pattern.
Your goal: {self.get_goal_description()}
Target: {self.target}

You will receive observations from tool executions and must:
1. THINK: Analyze the observation and reason about what it means
2. DECIDE: Choose the next best action or conclude if goal is achieved
3. ACT: Specify the tool and arguments to use

Be thorough but efficient. Stop when you have found vulnerabilities or exhausted reasonable test cases.

Available tools: {', '.join(self._available_tools)}
"""
    
    @abstractmethod
    async def get_available_tools(self) -> List[str]:
        """Return list of available tool names"""
        pass
    
    @abstractmethod
    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool and return result"""
        pass
    
    @abstractmethod
    def get_goal_description(self) -> str:
        """Describe the goal of this agent"""
        pass
    
    async def run(self) -> List[Dict[str, Any]]:
        """
        Main ReAct loop.
        
        Returns:
            List of findings discovered during execution
        """
        print(f"🔄 [{self.agent_name}] Starting ReAct loop", file=sys.stderr)
        
        # Get available tools
        self._available_tools = await self.get_available_tools()
        
        # Initial observation from shared context
        initial_observation = self._create_initial_observation()
        
        step_number = 0
        current_observation: Optional[Observation] = initial_observation
        
        while step_number < self.MAX_STEPS and not self._is_goal_achieved:
            step_number += 1
            
            try:
                # THINK: Generate thought based on observation
                thought = await self._think(current_observation, step_number)
                
                # Check if we're done
                if thought.thought_type == ThoughtType.CONCLUSION:
                    print(f"✅ [{self.agent_name}] Reached conclusion at step {step_number}", file=sys.stderr)
                    self._is_goal_achieved = True
                    self._steps.append(ReActStep(
                        step_number=step_number,
                        thought=thought,
                        action=None,
                        observation=None,
                    ))
                    break
                
                # DECIDE: Choose action based on thought
                action = await self._decide(thought, current_observation)
                
                if action is None:
                    # No more actions to take
                    self._is_goal_achieved = True
                    break
                
                # ACT: Execute the action
                current_observation = await self._act(action)
                
                # Record step
                self._steps.append(ReActStep(
                    step_number=step_number,
                    thought=thought,
                    action=action,
                    observation=current_observation,
                ))
                
                # Check for consecutive failures
                if action.status == ActionStatus.FAILED:
                    self._consecutive_failures += 1
                    if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                        print(f"⚠️ [{self.agent_name}] Too many consecutive failures", file=sys.stderr)
                        break
                else:
                    self._consecutive_failures = 0
                
            except asyncio.TimeoutError:
                print(f"⏰ [{self.agent_name}] Step {step_number} timed out", file=sys.stderr)
                self._consecutive_failures += 1
                
            except Exception as e:
                print(f"❌ [{self.agent_name}] Error in step {step_number}: {e}", file=sys.stderr)
                self._consecutive_failures += 1
        
        print(f"🏁 [{self.agent_name}] ReAct loop completed. Steps: {step_number}, Findings: {len(self._findings)}", file=sys.stderr)
        
        return self._findings
    
    def _create_initial_observation(self) -> Observation:
        """Create initial observation from shared context"""
        # Extract relevant context
        endpoints = self.shared_context.get("discovered_endpoints", [])
        tech_stack = self.shared_context.get("tech_stack", {})
        credentials = self.shared_context.get("credentials", {})
        
        interpretation = f"""Initial state:
- Target: {self.target}
- Discovered endpoints: {len(endpoints) if isinstance(endpoints, list) else 0}
- Tech stack: {json.dumps(tech_stack) if tech_stack else 'Unknown'}
- Credentials available: {'Yes' if credentials else 'No'}
"""
        
        return Observation(
            action=Action(
                tool_name="initial_context",
                arguments={},
                reason="Load shared context",
                status=ActionStatus.SUCCESS,
                result=self.shared_context,
            ),
            interpretation=interpretation,
            next_actions_suggested=["Start with reconnaissance" if not endpoints else "Test discovered endpoints"],
        )
    
    async def _think(self, observation: Optional[Observation], step: int) -> Thought:
        """
        Generate a thought based on the current observation.
        
        Uses LLM to reason about the observation and plan next steps.
        """
        # Build context for LLM
        context = {
            "step": step,
            "goal": self.get_goal_description(),
            "observation": observation.to_dict() if observation else None,
            "findings_so_far": len(self._findings),
            "steps_taken": len(self._steps),
            "available_tools": self._available_tools,
        }
        
        prompt = f"""Based on the current state, reason about what to do next.

Current State:
{json.dumps(context, indent=2)}

Previous steps summary:
{self._get_steps_summary()}

Think step by step:
1. What did the last action reveal?
2. Am I making progress toward the goal?
3. What should I try next, or should I conclude?

Respond in JSON format:
{{
    "thought_type": "reasoning|planning|conclusion",
    "content": "Your reasoning here",
    "should_continue": true/false,
    "suggested_action": "tool_name" or null if concluding
}}
"""
        
        try:
            response = await self._llm_client.chat(
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
            )
            
            # Parse response
            response_text = response.get("content", "") if isinstance(response, dict) else str(response)
            
            # Try to extract JSON
            try:
                # Find JSON in response
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                    thought_type = ThoughtType(parsed.get("thought_type", "reasoning"))
                    content = parsed.get("content", response_text)
                    
                    if not parsed.get("should_continue", True):
                        thought_type = ThoughtType.CONCLUSION
                    
                    return Thought(thought_type=thought_type, content=content)
            except:
                pass
            
            # Fallback: use raw response
            return Thought(thought_type=ThoughtType.REASONING, content=response_text)
            
        except Exception as e:
            # Fallback thought
            return Thought(
                thought_type=ThoughtType.PLANNING,
                content=f"LLM unavailable, using heuristic: Try next tool in sequence"
            )
    
    async def _decide(self, thought: Thought, observation: Optional[Observation]) -> Optional[Action]:
        """
        Decide on an action based on the thought.
        """
        if thought.thought_type == ThoughtType.CONCLUSION:
            return None
        
        # Build decision prompt
        prompt = f"""Based on your thought, decide on the next action.

Your thought: {thought.content}

Available tools: {self._available_tools}

Recent observation: {observation.interpretation if observation else 'None'}

Respond in JSON format:
{{
    "tool": "tool_name",
    "arguments": {{"param": "value"}},
    "reason": "Why this action"
}}

If no more actions needed, respond with {{"tool": null}}
"""
        
        try:
            response = await self._llm_client.chat(
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            
            response_text = response.get("content", "") if isinstance(response, dict) else str(response)
            
            # Parse action
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                tool_name = parsed.get("tool")
                
                if tool_name and tool_name in self._available_tools:
                    return Action(
                        tool_name=tool_name,
                        arguments=parsed.get("arguments", {}),
                        reason=parsed.get("reason", "LLM decision"),
                    )
            
            # Fallback: try next untried tool
            return self._get_fallback_action()
            
        except Exception as e:
            return self._get_fallback_action()
    
    def _get_fallback_action(self) -> Optional[Action]:
        """Get a fallback action when LLM fails"""
        # Get tools we haven't tried yet
        tried_tools = {step.action.tool_name for step in self._steps if step.action}
        untried = [t for t in self._available_tools if t not in tried_tools]
        
        if untried:
            return Action(
                tool_name=untried[0],
                arguments={},
                reason="Fallback: trying next available tool",
            )
        
        return None
    
    async def _act(self, action: Action) -> Observation:
        """
        Execute an action and return the observation.
        """
        start_time = datetime.utcnow()
        
        try:
            # Execute tool
            result = await asyncio.wait_for(
                self.execute_tool(action.tool_name, action.arguments),
                timeout=self.STEP_TIMEOUT
            )
            
            action.status = ActionStatus.SUCCESS
            action.result = result
            action.duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Interpret result
            interpretation, findings = await self._interpret_result(action.tool_name, result)
            
            # Add findings
            for finding in findings:
                self._findings.append(finding)
                # Score the finding
                self._scorer.score_finding(
                    finding_id=finding.get("id", f"finding-{len(self._findings)}"),
                    vulnerability_type=finding.get("type", "UNKNOWN"),
                    tool_used=action.tool_name,
                    tool_output={"result": result},
                    agent_name=self.agent_name,
                )
            
            return Observation(
                action=action,
                interpretation=interpretation,
                findings=findings,
            )
            
        except asyncio.TimeoutError:
            action.status = ActionStatus.FAILED
            action.error = f"Timeout after {self.STEP_TIMEOUT}s"
            action.duration_ms = self.STEP_TIMEOUT * 1000
            
            return Observation(
                action=action,
                interpretation=f"Action timed out after {self.STEP_TIMEOUT} seconds",
            )
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
            action.duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return Observation(
                action=action,
                interpretation=f"Action failed: {e}",
            )
    
    async def _interpret_result(
        self,
        tool_name: str,
        result: Any
    ) -> tuple[str, List[Dict[str, Any]]]:
        """
        Interpret tool result and extract findings.
        
        Override in subclasses for tool-specific interpretation.
        """
        findings = []
        
        # Generic interpretation
        result_str = json.dumps(result) if isinstance(result, (dict, list)) else str(result)
        
        # Look for common vulnerability indicators
        vuln_keywords = {
            "vulnerable": "Potential vulnerability detected",
            "injectable": "Injection point found",
            "exploitable": "Exploitable condition found",
            "success": "Test succeeded",
            "found": "Issue found",
        }
        
        interpretation = f"Tool '{tool_name}' completed. "
        
        for keyword, message in vuln_keywords.items():
            if keyword.lower() in result_str.lower():
                interpretation += f"{message}. "
                findings.append({
                    "type": "POTENTIAL_VULNERABILITY",
                    "tool": tool_name,
                    "indicator": keyword,
                    "raw_result": result_str[:500],
                })
                break
        else:
            interpretation += "No obvious vulnerabilities detected in this result."
        
        return interpretation, findings
    
    def _get_steps_summary(self) -> str:
        """Get summary of steps taken so far"""
        if not self._steps:
            return "No steps taken yet."
        
        summary = []
        for step in self._steps[-5:]:  # Last 5 steps
            action_str = f"{step.action.tool_name}:{step.action.status.value}" if step.action else "no-action"
            summary.append(f"Step {step.step_number}: {step.thought.thought_type.value} → {action_str}")
        
        return "\n".join(summary)
    
    def get_trace(self) -> List[Dict[str, Any]]:
        """Get execution trace for analysis"""
        return [step.to_dict() for step in self._steps]
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings"""
        return self._findings
    
    def get_confidence_summary(self) -> Dict[str, Any]:
        """Get confidence summary for all findings"""
        return self._scorer.to_summary_dict()


class ReActAgentMixin:
    """
    Mixin to add ReAct capabilities to existing agents.
    
    Usage:
        class InputValidationAgent(BaseAgent, ReActAgentMixin):
            async def run(self):
                if self.should_use_react():
                    return await self.run_react()
                else:
                    return await self.run_standard()
    """
    
    # ReAct configuration
    REACT_ENABLED = True
    REACT_MAX_STEPS = 15
    REACT_CONFIDENCE_THRESHOLD = 0.7  # Switch to ReAct if confidence < this
    
    def should_use_react(self) -> bool:
        """Determine if ReAct loop should be used"""
        if not self.REACT_ENABLED:
            return False
        
        # Use ReAct for complex scenarios
        endpoints = self._shared_context_snapshot.get("discovered_endpoints", [])
        
        # Many endpoints = complex target = use ReAct for adaptive testing
        if len(endpoints) > 20:
            return True
        
        # Unknown tech stack = use ReAct for exploration
        tech_stack = self._shared_context_snapshot.get("tech_stack", {})
        if not tech_stack:
            return True
        
        return False
    
    async def run_react(self) -> None:
        """Run agent using ReAct pattern"""
        from .base_agent import CURRENT_AGENT
        
        print(f"🔄 [{self.agent_name}] Using ReAct pattern", file=sys.stderr)
        
        # Initialize ReAct state
        self._react_steps = []
        self._react_findings = []
        step = 0
        max_steps = self.REACT_MAX_STEPS
        
        while step < max_steps:
            step += 1
            
            # OBSERVE
            observation = await self._react_observe()
            
            # THINK
            thought = await self._react_think(observation)
            
            # Check conclusion
            if thought.get("conclude", False):
                break
            
            # ACT
            action = thought.get("action")
            if action:
                result = await self._react_act(action)
                self._react_steps.append({
                    "step": step,
                    "observation": observation,
                    "thought": thought,
                    "action": action,
                    "result": result,
                })
        
        # Save findings
        for finding in self._react_findings:
            self.save_finding(**finding)
    
    async def _react_observe(self) -> Dict[str, Any]:
        """Observe current state"""
        return {
            "findings_count": len(self._react_findings),
            "steps_taken": len(self._react_steps),
            "last_result": self._react_steps[-1]["result"] if self._react_steps else None,
        }
    
    async def _react_think(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """Think about next action using LLM"""
        # Simplified - override in actual implementation
        return {
            "conclude": len(self._react_steps) >= self.REACT_MAX_STEPS,
            "action": None,
        }
    
    async def _react_act(self, action: Dict[str, Any]) -> Any:
        """Execute action"""
        tool_name = action.get("tool")
        arguments = action.get("arguments", {})
        
        if hasattr(self, "_mcp_client") and self._mcp_client:
            return await self._mcp_client.call_tool(tool_name, arguments)
        
        return None
