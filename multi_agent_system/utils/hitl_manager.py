"""
HITL (Human-In-The-Loop) Manager

Manages human approval checkpoints during security scanning
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from sqlalchemy import or_

from ..core.config import settings
from ..core.db import get_db
from ..models.models import Job, Finding
from ..models.hitl_models import (
    PlanApproval,
    FindingApproval,
    RiskApproval,
    ToolApproval,
    ToolApprovalPolicy,
    ToolPolicyMode,
    ApprovalStatus,
    AgentCheckpoint,
    CheckpointAction,
)

from ..utils.directive_parser import parse_directive_commands

# Import OpenAI for conversational HITL
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠️ OpenAI not available, conversational HITL disabled")


class HITLManager:
    """
    Manages Human-In-The-Loop approval workflows
    
    Three approval checkpoints:
    1. Plan Approval - After recon, before main execution
    2. Finding Approval - After critical findings detected
    3. Risk Approval - Before dangerous tests
    4. Tool Approval - Before executing each MCP tool (optional, per-user)
    """
    
    def __init__(self, job_id: int, llm_client: Optional[AsyncOpenAI] = None, overrides: Optional[Dict[str, Any]] = None):
        self.job_id = job_id
        self.hitl_enabled = bool(settings.hitl_enabled)
        self.enable_tool_hitl = bool(settings.enable_tool_hitl)
        self.auto_approve_agents: List[str] = list(getattr(settings, "auto_approve_tool_agents", []))
        self._apply_options_dict(self._fetch_job_options())
        self._apply_options_dict(overrides or {})
        
        # Initialize LLM client for conversational HITL
        if OPENAI_AVAILABLE:
            import os
            self.llm = llm_client or AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        else:
            self.llm = None
    
    async def request_plan_approval(
        self, 
        original_plan: Dict[str, Any],
        recon_summary: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Request user approval for execution plan
        
        Args:
            original_plan: LLM-generated strategic plan
            recon_summary: Results from ReconnaissanceAgent
            
        Returns:
            Approved plan (original or modified)
        """
        if not self.hitl_enabled:
            return original_plan
        
        # Calculate risk level and estimated duration
        risk_level = self._calculate_risk_level(original_plan)
        estimated_duration = self._estimate_duration(original_plan)
        
        # Save approval request to database
        with get_db() as db:
            approval = PlanApproval(
                job_id=self.job_id,
                original_plan=original_plan,
                recon_summary=recon_summary,
                risk_level=risk_level,
                estimated_duration=estimated_duration,
                status=ApprovalStatus.pending
            )
            db.add(approval)
            db.commit()
            db.refresh(approval)
            approval_id = approval.id
        
        # Update job status to waiting_approval
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job:
                job.status = "waiting_approval"
                db.commit()
        
        # Wait for user response (polling)
        print(f"🛑 [HITL] Job {self.job_id}: Waiting for plan approval...")
        
        approved_plan = await self._wait_for_plan_approval(approval_id)
        
        print(f"✅ [HITL] Job {self.job_id}: Plan approved, resuming execution")
        
        return approved_plan
    
    async def _wait_for_plan_approval(
        self, 
        approval_id: int,
        poll_interval: int = 2,
        timeout: int = 3600  # 1 hour
    ) -> Dict[str, Any]:
        """
        Poll database for user approval
        
        Args:
            approval_id: ID of PlanApproval record
            poll_interval: Seconds between polls
            timeout: Max wait time in seconds
            
        Returns:
            Approved plan
        """
        elapsed = 0
        
        while elapsed < timeout:
            with get_db() as db:
                approval = db.query(PlanApproval).get(approval_id)
                
                if not approval:
                    raise Exception(f"Plan approval {approval_id} not found")
                
                if approval.status == ApprovalStatus.approved:
                    # Use modified plan if provided, else original
                    return approval.modified_plan or approval.original_plan
                
                elif approval.status == ApprovalStatus.rejected:
                    raise Exception(f"Plan rejected by user: {approval.user_notes}")
                
                elif approval.status == ApprovalStatus.modified:
                    return approval.modified_plan
                
                elif approval.status == ApprovalStatus.skipped:
                    # User chose to skip approval (proceed with original)
                    return approval.original_plan
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        
        # Timeout - auto-approve original plan
        print(f"⚠️ [HITL] Plan approval timeout, auto-approving original plan")
        with get_db() as db:
            approval = db.query(PlanApproval).get(approval_id)
            if approval:
                approval.status = ApprovalStatus.approved
                approval.responded_at = datetime.utcnow()
                approval.user_notes = "Auto-approved after timeout"
                db.commit()
        
        return approval.original_plan
    
    async def request_finding_approval(
        self,
        finding_id: int,
        severity: str
    ) -> bool:
        """
        Request user verification for a finding
        
        Args:
            finding_id: ID of finding to verify
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            True if approved, False if rejected as false positive
        """
        if not self.hitl_enabled:
            return True
        
        # Only request approval for critical/high findings
        if severity.lower() not in ['critical', 'high']:
            return True
        
        with get_db() as db:
            approval = FindingApproval(
                job_id=self.job_id,
                finding_id=finding_id,
                status=ApprovalStatus.pending
            )
            db.add(approval)
            db.commit()
            db.refresh(approval)
            approval_id = approval.id
        
        # Wait for user verification
        return await self._wait_for_finding_approval(approval_id)
    
    async def _wait_for_finding_approval(
        self,
        approval_id: int,
        poll_interval: int = 2,
        timeout: int = 300  # 5 minutes
    ) -> bool:
        """Poll for finding approval"""
        elapsed = 0
        
        while elapsed < timeout:
            with get_db() as db:
                approval = db.query(FindingApproval).get(approval_id)
                
                if approval.status == ApprovalStatus.approved:
                    return not approval.is_false_positive
                
                elif approval.status == ApprovalStatus.rejected:
                    return False
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        
        # Auto-approve after timeout
        return True
    
    async def request_risk_approval(
        self,
        agent_name: str,
        test_name: str,
        risk_type: str,
        risk_description: str
    ) -> bool:
        """
        Request approval for high-risk test
        
        Args:
            agent_name: Name of agent requesting approval
            test_name: Name of risky test
            risk_type: Type of risk (dos, data_modification, account_lockout)
            risk_description: Human-readable description
            
        Returns:
            True if approved, False if rejected
        """
        if not self.hitl_enabled:
            return True
        
        with get_db() as db:
            # Check if user already approved/rejected similar tests
            similar = db.query(RiskApproval).filter(
                RiskApproval.job_id == self.job_id,
                RiskApproval.risk_type == risk_type,
                RiskApproval.skip_all_similar == True
            ).first()
            
            if similar:
                return False  # User already said skip all similar tests
            
            approval = RiskApproval(
                job_id=self.job_id,
                agent_name=agent_name,
                test_name=test_name,
                risk_type=risk_type,
                risk_description=risk_description,
                status=ApprovalStatus.pending
            )
            db.add(approval)
            db.commit()
            db.refresh(approval)
            approval_id = approval.id
        
        return await self._wait_for_risk_approval(approval_id)
    
    async def _wait_for_risk_approval(
        self,
        approval_id: int,
        poll_interval: int = 2,
        timeout: int = 300
    ) -> bool:
        """Poll for risk approval"""
        elapsed = 0
        
        while elapsed < timeout:
            with get_db() as db:
                approval = db.query(RiskApproval).get(approval_id)
                
                if approval.status == ApprovalStatus.approved:
                    return not approval.skip_this_test
                
                elif approval.status == ApprovalStatus.rejected:
                    return False
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        
        # Auto-reject risky tests after timeout (safe default)
        with get_db() as db:
            approval = db.query(RiskApproval).get(approval_id)
            test_name = approval.test_name if approval else "unknown"
            if approval:
                approval.status = ApprovalStatus.rejected
                approval.responded_at = datetime.utcnow()
                db.commit()
        print(f"⚠️ [HITL] Risk approval timeout, skipping test: {test_name}")
        return False

    async def request_tool_execution(
        self,
        agent_name: str,
        tool_name: str,
        server: str,
        arguments: Dict[str, Any],
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request confirmation before executing a specific MCP tool."""
        if not self.hitl_enabled or not self.enable_tool_hitl:
            return {"approved": True, "arguments": arguments}

        batch_key = self._compute_batch_key(agent_name, tool_name, server, arguments)
        existing = self._find_pending_batch(batch_key)
        if existing:
            print(
                f"🌀 [HITL] Job {self.job_id}: Reusing pending approval {existing.id} for {agent_name}.{tool_name}"
            )
            return await self._wait_for_tool_decision(existing.id, tool_name)

        policy = self._match_tool_policy(agent_name, tool_name, server, arguments)
        policy_id: Optional[int] = None
        if policy:
            if policy["mode"] == ToolPolicyMode.auto:
                print(
                    f"⚙️ [HITL] Job {self.job_id}: Policy {policy['id']} auto-approves {agent_name}.{tool_name}"
                )
                return self._record_policy_decision(
                    policy_id=policy["id"],
                    status=ApprovalStatus.approved,
                    agent_name=agent_name,
                    tool_name=tool_name,
                    server=server,
                    arguments=arguments,
                    reason=reason,
                    batch_key=batch_key,
                )

            if policy["mode"] == ToolPolicyMode.block:
                print(
                    f"🚫 [HITL] Job {self.job_id}: Policy {policy['id']} blocks {agent_name}.{tool_name}"
                )
                return self._record_policy_decision(
                    policy_id=policy["id"],
                    status=ApprovalStatus.rejected,
                    agent_name=agent_name,
                    tool_name=tool_name,
                    server=server,
                    arguments=arguments,
                    reason=reason or "Blocked by policy",
                    batch_key=batch_key,
                )

            if policy["mode"] == ToolPolicyMode.batch:
                batch_key = policy["batch_key"]
                policy_id = policy["id"]
                existing = self._find_pending_batch(batch_key)
                if existing:
                    print(
                        f"🗂️ [HITL] Job {self.job_id}: Policy batch {batch_key} already pending as approval {existing.id}"
                    )
                    return await self._wait_for_tool_decision(existing.id, tool_name)

        with get_db() as db:
            approval = ToolApproval(
                job_id=self.job_id,
                agent_name=agent_name,
                tool_name=tool_name,
                server=server,
                arguments=arguments,
                reason=reason,
                batch_key=batch_key,
                policy_id=policy_id,
            )
            db.add(approval)
            db.commit()
            db.refresh(approval)
            approval_id = approval.id

        print(f"🛑 [HITL] Job {self.job_id}: Awaiting approval for {agent_name}.{tool_name}")
        decision = await self._wait_for_tool_decision(approval_id, tool_name)
        return decision

    async def _wait_for_tool_decision(
        self,
        approval_id: int,
        tool_name: str,
        poll_interval: int = 2,
    ) -> Dict[str, Any]:
        """Poll DB until a tool approval is decided or timeout reached."""
        timeout = getattr(settings, "tool_hitl_timeout", 600)
        elapsed = 0

        while elapsed < timeout:
            with get_db() as db:
                approval = db.query(ToolApproval).get(approval_id)
                if not approval:
                    raise Exception(f"Tool approval {approval_id} missing")

                if approval.status == ApprovalStatus.approved:
                    return {
                        "approved": True,
                        "arguments": approval.approved_arguments or approval.arguments,
                    }
                if approval.status == ApprovalStatus.rejected:
                    return {"approved": False}

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        print(f"⚠️ [HITL] Tool approval timeout, auto-approving {tool_name}")
        with get_db() as db:
            approval = db.query(ToolApproval).get(approval_id)
            if approval:
                approval.status = ApprovalStatus.approved
                approval.responded_at = datetime.utcnow()
                approval.auto_decision = True
                approval.user_notes = "Auto-approved after timeout"
                db.commit()
                args = approval.approved_arguments or approval.arguments
            else:
                args = None

        return {"approved": True, "arguments": args}
    
    def _compute_batch_key(
        self,
        agent_name: str,
        tool_name: str,
        server: str,
        arguments: Optional[Dict[str, Any]]
    ) -> str:
        """Generate a deterministic batch key for similar tool requests."""
        args_serialized = json.dumps(arguments or {}, sort_keys=True)
        digest = hashlib.sha256(args_serialized.encode()).hexdigest()[:12]
        server_name = server or "unknown"
        return f"{agent_name}:{tool_name}:{server_name}:{digest}"

    def _find_pending_batch(self, batch_key: Optional[str]) -> Optional[ToolApproval]:
        """Return an existing pending approval for the same batch key if any."""
        if not batch_key:
            return None
        with get_db() as db:
            return db.query(ToolApproval).filter(
                ToolApproval.job_id == self.job_id,
                ToolApproval.batch_key == batch_key,
                ToolApproval.status == ApprovalStatus.pending
            ).first()

    def _match_tool_policy(
        self,
        agent_name: str,
        tool_name: str,
        server: str,
        arguments: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Return the first matching tool approval policy for current job."""
        with get_db() as db:
            policies = db.query(ToolApprovalPolicy).filter(
                ToolApprovalPolicy.tool_name == tool_name,
                or_(
                    ToolApprovalPolicy.job_id == self.job_id,
                    ToolApprovalPolicy.job_id == None
                )
            ).order_by(
                ToolApprovalPolicy.job_id.desc(),
                ToolApprovalPolicy.created_at.desc()
            ).all()

            now = datetime.utcnow()
            for policy in policies:
                if policy.expires_at and policy.expires_at < now:
                    continue
                if policy.agent_name and policy.agent_name != agent_name:
                    continue
                if policy.server and policy.server != server:
                    continue
                if not self._arguments_match_policy(policy.match_arguments, arguments):
                    continue

                policy.last_used_at = now
                db.commit()
                return {
                    "id": policy.id,
                    "mode": policy.mode,
                    "batch_key": f"policy:{policy.id}"
                }
        return None

    def _arguments_match_policy(
        self,
        required_args: Optional[Dict[str, Any]],
        actual_args: Optional[Dict[str, Any]]
    ) -> bool:
        """Ensure provided arguments satisfy policy requirements."""
        if not required_args:
            return True
        if not actual_args:
            return False
        for key, value in required_args.items():
            if key not in actual_args:
                return False
            actual_value = actual_args.get(key)
            if isinstance(value, list):
                if actual_value not in value:
                    return False
            else:
                if actual_value != value:
                    return False
        return True

    def _record_policy_decision(
        self,
        policy_id: int,
        status: ApprovalStatus,
        agent_name: str,
        tool_name: str,
        server: str,
        arguments: Optional[Dict[str, Any]],
        reason: Optional[str],
        batch_key: Optional[str]
    ) -> Dict[str, Any]:
        """Persist an automatic tool decision that came from a policy."""
        with get_db() as db:
            approval = ToolApproval(
                job_id=self.job_id,
                agent_name=agent_name,
                tool_name=tool_name,
                server=server,
                arguments=arguments,
                reason=reason,
                status=status,
                requested_at=datetime.utcnow(),
                responded_at=datetime.utcnow(),
                user_notes="Policy-driven decision",
                approved_arguments=arguments if status == ApprovalStatus.approved else None,
                auto_decision=True,
                batch_key=batch_key,
                policy_id=policy_id
            )
            db.add(approval)
            db.commit()
            args = approval.approved_arguments if status == ApprovalStatus.approved else None

        return {
            "approved": status == ApprovalStatus.approved,
            "arguments": args,
        }
    
    def _calculate_risk_level(self, plan: Dict[str, Any]) -> str:
        """
        Calculate overall risk level for a plan
        
        Returns: low, medium, high
        """
        # Check for high-risk tests
        risky_agents = [
            'InputValidationAgent',  # May trigger DoS
            'BusinessLogicAgent',    # May modify data
            'AuthenticationAgent'    # May lock accounts
        ]
        
        agents = plan.get('agents', [])
        if isinstance(agents, list):
            agent_names = [a if isinstance(a, str) else a.get('name') for a in agents]
        else:
            agent_names = []
        
        risky_count = sum(1 for name in agent_names if name in risky_agents)
        
        if risky_count >= 3:
            return 'high'
        elif risky_count >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _estimate_duration(self, plan: Dict[str, Any]) -> int:
        """
        Estimate scan duration in minutes
        
        Based on number of agents and complexity
        """
        agents = plan.get('agents', [])
        num_agents = len(agents) if isinstance(agents, list) else 10
        
        # Average 2-5 minutes per agent
        return num_agents * 3
    
    # ============================================================
    # CONVERSATIONAL HITL METHODS
    # ============================================================
    
    async def chat_plan_approval(
        self, 
        approval_id: int, 
        user_message: str
    ) -> Dict[str, Any]:
        """
        Process user's conversational input for plan modification
        
        Args:
            approval_id: PlanApproval record ID
            user_message: User's natural language instruction
        
        Returns:
            AI response with modified plan and next steps
        """
        if not OPENAI_AVAILABLE or not self.llm:
            return {
                "error": "Conversational HITL not available (OpenAI not installed)",
                "fallback": "Please use standard approve/reject buttons"
            }
        
        # Get current approval record
        with get_db() as db:
            approval = db.query(PlanApproval).get(approval_id)
            if not approval:
                return {"error": "Approval not found"}
            
            # Build conversation context
            conversation = approval.conversation_history or []
            conversation.append({
                "role": "user",
                "content": user_message,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Prepare system prompt
            recon_summary = approval.recon_summary or {}
            system_prompt = f"""
You are a security testing assistant helping a penetration tester review an execution plan.

CONTEXT:
- Target: {recon_summary.get('target', 'Unknown')}
- Tech Stack: {', '.join(recon_summary.get('tech_stack', []))}
- Original Plan: {json.dumps(approval.original_plan, indent=2)}
- Risk Level: {approval.risk_level}
- Estimated Duration: {approval.estimated_duration} minutes

CONVERSATION HISTORY:
{json.dumps(conversation[:-1], indent=2) if len(conversation) > 1 else "No previous messages"}

USER'S LATEST MESSAGE:
{user_message}

YOUR TASK:
1. Understand user's instruction (skip tests, focus areas, modify scope, ask questions)
2. If modifying plan, explain changes clearly
3. If answering questions, be concise and technical
4. Always provide actionable next steps

RESPONSE FORMAT (JSON):
{{
  "understanding": "Brief summary of what you understood",
  "response": "Your detailed response in Markdown format",
  "changes": ["Change 1", "Change 2"] or null if no changes,
  "modified_plan": {{...}} or null if no modification,
  "impact": {{"time_saved": "X minutes", "risk_level": "low/medium/high"}} or null,
  "requires_confirmation": true/false
}}

IMPORTANT:
- If user says "approve", "yes", "proceed" → Set requires_confirmation=false
- If user asks questions → Set modified_plan=null, just answer
- If modifying plan → Include full modified_plan structure
"""
            
            # Call LLM
            try:
                response = await self.llm.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    response_format={"type": "json_object"}
                )
                
                ai_output = json.loads(response.choices[0].message.content)
                
                # Update conversation history
                conversation.append({
                    "role": "assistant",
                    "content": ai_output.get("response"),
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": ai_output
                })
                
                # Update database
                approval.conversation_history = conversation
                approval.user_instructions = user_message
                approval.ai_interpretation = ai_output
                
                # Auto-apply if AI is confident and user approved
                if not ai_output.get("requires_confirmation"):
                    if ai_output.get("modified_plan"):
                        approval.modified_plan = ai_output["modified_plan"]
                        approval.status = ApprovalStatus.modified
                    else:
                        approval.status = ApprovalStatus.approved
                    approval.responded_at = datetime.utcnow()
                
                db.commit()
                
                return ai_output
                
            except Exception as e:
                print(f"❌ [HITL Chat] LLM error: {e}")
                return {
                    "error": f"AI processing failed: {str(e)}",
                    "fallback": "Please use standard approve/reject buttons"
                }
    
    async def chat_finding_verification(
        self, 
        approval_id: int, 
        user_message: str
    ) -> Dict[str, Any]:
        """
        Answer user's questions about a specific finding
        
        Args:
            approval_id: FindingApproval record ID
            user_message: User's question
        
        Returns:
            AI response with evidence and explanation
        """
        if not OPENAI_AVAILABLE or not self.llm:
            return {"error": "Conversational HITL not available"}
        
        with get_db() as db:
            approval = db.query(FindingApproval).get(approval_id)
            if not approval:
                return {"error": "Approval not found"}
            
            finding = db.query(Finding).get(approval.finding_id)
            if not finding:
                return {"error": "Finding not found"}
            
            # Prepare system prompt
            system_prompt = f"""
You are a security expert explaining a vulnerability finding to a penetration tester.

FINDING DETAILS:
- Type: {finding.category}
- Severity: {finding.severity}
- Title: {finding.title}
- Description: {finding.description}
- Evidence: {json.dumps(finding.evidence, indent=2) if finding.evidence else 'No evidence available'}

USER QUESTION:
{user_message}

YOUR TASK:
Provide a clear, technical answer. Include evidence when relevant.
If user asks to "confirm", "approve", or indicates it's valid → Mark as ready for approval.

RESPONSE FORMAT (JSON):
{{
  "response": "Your detailed answer in Markdown format",
  "evidence_highlighted": {{...}} or null,
  "is_confirmation": true/false (true if user wants to approve)
}}
"""
            
            try:
                response = await self.llm.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    response_format={"type": "json_object"}
                )
                
                ai_output = json.loads(response.choices[0].message.content)
                
                # Update conversation history
                conversation = approval.conversation_history or []
                conversation.extend([
                    {"role": "user", "content": user_message, "timestamp": datetime.utcnow().isoformat()},
                    {"role": "assistant", "content": ai_output["response"], "timestamp": datetime.utcnow().isoformat()}
                ])
                approval.conversation_history = conversation
                
                # Update user questions list
                questions = approval.user_questions or []
                questions.append(user_message)
                approval.user_questions = questions
                
                # Auto-approve if user confirmed
                if ai_output.get("is_confirmation"):
                    approval.status = ApprovalStatus.approved
                    approval.is_false_positive = False
                    approval.responded_at = datetime.utcnow()
                
                db.commit()
                
                return {
                    "ai_response": ai_output["response"],
                    "evidence": finding.evidence,
                    "is_confirmation": ai_output.get("is_confirmation", False)
                }
                
            except Exception as e:
                print(f"❌ [HITL Chat] Finding verification error: {e}")
                return {"error": f"AI processing failed: {str(e)}"}
    
    async def chat_risk_approval(
        self, 
        approval_id: int, 
        user_message: str
    ) -> Dict[str, Any]:
        """
        Discuss alternatives for risky tests
        
        Args:
            approval_id: RiskApproval record ID
            user_message: User's question or concern
        
        Returns:
            AI response with alternatives or explanation
        """
        if not OPENAI_AVAILABLE or not self.llm:
            return {"error": "Conversational HITL not available"}
        
        with get_db() as db:
            approval = db.query(RiskApproval).get(approval_id)
            if not approval:
                return {"error": "Approval not found"}
            
            system_prompt = f"""
You are a security testing expert discussing a high-risk test.

RISKY TEST:
- Test Name: {approval.test_name}
- Agent: {approval.agent_name}
- Risk Type: {approval.risk_type}
- Description: {approval.risk_description}

USER MESSAGE:
{user_message}

YOUR TASK:
If user asks for alternatives, provide SPECIFIC safer alternatives with:
1. Alternative test name
2. Risk level (low/medium/high)
3. Detection effectiveness (same/lower/higher)
4. Why it's safer

If user approves ("yes", "proceed", "approve"), mark as ready.

RESPONSE FORMAT (JSON):
{{
  "response": "Your explanation in Markdown",
  "alternatives": [
    {{"id": 1, "name": "...", "risk": "low", "effectiveness": "high", "why_safer": "..."}},
    ...
  ] or null,
  "is_approval": true/false,
  "is_rejection": true/false
}}
"""
            
            try:
                response = await self.llm.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    response_format={"type": "json_object"}
                )
                
                ai_output = json.loads(response.choices[0].message.content)
                
                # Update conversation history
                conversation = approval.conversation_history or []
                conversation.extend([
                    {"role": "user", "content": user_message, "timestamp": datetime.utcnow().isoformat()},
                    {"role": "assistant", "content": ai_output["response"], "timestamp": datetime.utcnow().isoformat()}
                ])
                approval.conversation_history = conversation
                
                # Store alternatives if suggested
                if ai_output.get("alternatives"):
                    approval.alternative_suggested = ai_output["alternatives"]
                
                # Auto-approve/reject if user decided
                if ai_output.get("is_approval"):
                    approval.status = ApprovalStatus.approved
                    approval.skip_this_test = False
                    approval.responded_at = datetime.utcnow()
                elif ai_output.get("is_rejection"):
                    approval.status = ApprovalStatus.rejected
                    approval.skip_this_test = True
                    approval.responded_at = datetime.utcnow()
                
                db.commit()
                
                return ai_output
                
            except Exception as e:
                print(f"❌ [HITL Chat] Risk approval error: {e}")
                return {"error": f"AI processing failed: {str(e)}"}
    
    # ============================================================
    # AGENT-LEVEL CHECKPOINT (v2 — per-agent HITL)
    # ============================================================

    async def request_agent_checkpoint(
        self,
        completed_agent: str,
        agent_index: int,
        findings_count: int,
        findings_by_severity: Dict[str, int],
        agent_summary: str,
        cumulative_summary: str,
        key_findings: List[Dict[str, Any]],
        next_agent: Optional[str],
        remaining_agents: List[str],
        recommendations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Create an agent-level checkpoint and wait for user decision.

        Called by the orchestrator after each agent completes + summarisation.
        Pauses execution until the user responds via the frontend.

        Returns:
            {
                "action": "proceed" | "skip_next" | "reorder" | "auto" | "abort",
                "next_agent_override": str | None,
                "skip_agents": list | None,
                "user_notes": str | None,
            }
        """
        hitl_mode = getattr(settings, "hitl_mode", "off")
        if hitl_mode != "agent":
            return {"action": "proceed"}

        # Don't checkpoint after the last agent (ReportGenerationAgent)
        if not next_agent and not remaining_agents:
            return {"action": "proceed"}

        with get_db() as db:
            checkpoint = AgentCheckpoint(
                job_id=self.job_id,
                completed_agent=completed_agent,
                agent_sequence_index=agent_index,
                findings_count=findings_count,
                findings_by_severity=findings_by_severity,
                agent_summary=agent_summary,
                cumulative_summary=cumulative_summary,
                key_findings=key_findings[:10] if key_findings else [],
                next_agent=next_agent,
                remaining_agents=remaining_agents,
                recommendations=recommendations,
                action=CheckpointAction.pending,
            )
            db.add(checkpoint)
            db.commit()
            db.refresh(checkpoint)
            checkpoint_id = checkpoint.id

        # Update job status so frontend knows we're waiting
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job:
                job.status = "waiting_checkpoint"
                db.commit()

        print(
            f"🛑 [HITL] Job {self.job_id}: Agent checkpoint after {completed_agent} "
            f"({findings_count} findings). Waiting for user..."
        )

        result = await self._wait_for_agent_checkpoint(checkpoint_id, completed_agent)

        # Restore job status
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job and job.status == "waiting_checkpoint":
                job.status = "running"
                db.commit()

        return result

    async def request_pre_agent_checkpoint(
        self,
        next_agent: str,
        agent_index: int,
        planned_tools: List[str],
        cumulative_summary: str,
        remaining_agents: List[str],
    ) -> Dict[str, Any]:
        """Create a PRE-AGENT checkpoint and wait for director input.

        Called by the orchestrator BEFORE an agent runs. Pauses execution until
        the user approves (with optional directive) or skips/aborts.

        Returns:
            {
                "action": "proceed" | "skip_current" | "abort",
                "directive_commands": list[dict],
                "user_notes": str | None,
            }
        """
        hitl_mode = getattr(settings, "hitl_mode", "off")
        if hitl_mode != "agent":
            return {"action": "proceed", "directive_commands": [], "user_notes": None}

        if next_agent in ("ReconnaissanceAgent", "ReportGenerationAgent"):
            return {"action": "proceed", "directive_commands": [], "user_notes": None}

        with get_db() as db:
            checkpoint = AgentCheckpoint(
                job_id=self.job_id,
                completed_agent="(pre-agent)",
                agent_sequence_index=agent_index,
                next_agent=next_agent,
                remaining_agents=remaining_agents,
                planned_tools=planned_tools,
                cumulative_summary=cumulative_summary,
                checkpoint_type="pre_agent",
                action=CheckpointAction.pending,
            )
            db.add(checkpoint)
            db.commit()
            db.refresh(checkpoint)
            checkpoint_id = checkpoint.id

        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job:
                job.status = "waiting_checkpoint"
                db.commit()

        print(
            f"🎯 [HITL Director] Job {self.job_id}: PRE-AGENT checkpoint "
            f"for {next_agent} (index {agent_index}). Waiting for director..."
        )

        result = await self._wait_for_agent_checkpoint(checkpoint_id, f"pre-{next_agent}")

        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job and job.status == "waiting_checkpoint":
                job.status = "running"
                db.commit()

        directive_commands: List[Dict[str, Any]] = []
        with get_db() as db:
            cp = db.query(AgentCheckpoint).get(checkpoint_id)
            if cp and cp.directive:
                import json as _json
                try:
                    directive_commands = _json.loads(cp.directive)
                except Exception:
                    directive_commands = []

        action = result.get("action", "proceed")
        if action not in ("proceed", "skip_current", "abort"):
            action = "proceed"

        return {
            "action": action,
            "directive_commands": directive_commands,
            "user_notes": result.get("user_notes"),
        }

    async def request_tool_arg_review(
        self,
        agent_name: str,
        tool_name: str,
        server: str,
        generated_args: Dict[str, Any],
        timeout: int = 600,
    ) -> Dict[str, Any]:
        """Pause before a HIGH_RISK tool and allow Director to edit arguments.

        Creates a ToolApproval record (is_high_risk_review=True), waits for the
        user to approve/edit/skip via the API, then returns the final args.

        Returns:
            {"approved": bool, "arguments": dict}
            approved=False means skip this tool entirely.
        """
        hitl_mode = getattr(settings, "hitl_mode", "off")
        if hitl_mode not in ("agent", "tool"):
            return {"approved": True, "arguments": generated_args}

        with get_db() as db:
            approval = ToolApproval(
                job_id=self.job_id,
                agent_name=agent_name,
                tool_name=tool_name,
                server=server,
                arguments=generated_args,
                reason="HIGH_RISK tool — Director review required before execution",
                status=ApprovalStatus.pending,
                is_high_risk_review=True,
            )
            db.add(approval)
            db.commit()
            db.refresh(approval)
            approval_id = approval.id

        print(
            f"⚠️  [HITL Director] Job {self.job_id}: HIGH_RISK tool '{tool_name}' "
            f"paused for Director review (approval_id={approval_id})"
        )

        elapsed = 0
        poll_interval = 2
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            with get_db() as db:
                ap = db.query(ToolApproval).get(approval_id)
                if not ap:
                    break
                if ap.status == ApprovalStatus.pending:
                    continue
                if ap.status in (ApprovalStatus.approved, ApprovalStatus.modified):
                    final_args = ap.approved_arguments or generated_args
                    print(f"✅ [HITL Director] Tool '{tool_name}' approved (args modified: {ap.approved_arguments is not None})")
                    return {"approved": True, "arguments": final_args}
                if ap.status == ApprovalStatus.rejected:
                    print(f"🚫 [HITL Director] Tool '{tool_name}' skipped by Director")
                    return {"approved": False, "arguments": generated_args}

        # Timeout: run as-is
        print(f"⏱️  [HITL Director] Tool '{tool_name}' timeout — running with original args")
        with get_db() as db:
            ap = db.query(ToolApproval).get(approval_id)
            if ap and ap.status == ApprovalStatus.pending:
                ap.status = ApprovalStatus.approved
                ap.approved_arguments = generated_args
                ap.auto_decision = True
                db.commit()
        return {"approved": True, "arguments": generated_args}

    async def _wait_for_agent_checkpoint(
        self,
        checkpoint_id: int,
        agent_name: str,
        poll_interval: int = 2,
        timeout: int = 3600,  # 1 hour max wait
    ) -> Dict[str, Any]:
        """Poll database for user response to agent checkpoint."""
        elapsed = 0

        while elapsed < timeout:
            with get_db() as db:
                cp = db.query(AgentCheckpoint).get(checkpoint_id)
                if not cp:
                    raise Exception(f"Agent checkpoint {checkpoint_id} not found")

                if cp.action != CheckpointAction.pending:
                    action = cp.action.value
                    print(f"✅ [HITL] Job {self.job_id}: User chose '{action}' after {agent_name}")

                    return {
                        "action": action,
                        "next_agent_override": cp.next_agent_override,
                        "skip_agents": cp.skip_agents,
                        "user_notes": cp.user_notes,
                    }

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        # Timeout — auto-proceed
        print(f"⚠️ [HITL] Agent checkpoint timeout after {agent_name}, auto-proceeding")
        with get_db() as db:
            cp = db.query(AgentCheckpoint).get(checkpoint_id)
            if cp:
                cp.action = CheckpointAction.proceed
                cp.responded_at = datetime.utcnow()
                cp.wait_duration_seconds = timeout
                db.commit()

        return {"action": "proceed"}

    def disable_hitl(self):
        """Disable HITL for this job (run fully automated)"""
        self.hitl_enabled = False
        self.enable_tool_hitl = False
	
    def enable_hitl(self):
        """Enable HITL for this job"""
        self.hitl_enabled = bool(settings.hitl_enabled)
        self.enable_tool_hitl = bool(settings.enable_tool_hitl)

    def _fetch_job_options(self) -> Dict[str, Any]:
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            if job and isinstance(job.plan, dict):
                options = job.plan.get("options")
                if isinstance(options, dict):
                    return dict(options)
        return {}

    def _apply_options_dict(self, options: Dict[str, Any] | None):
        if not options:
            return
        if options.get("hitl_enabled") is not None:
            self.hitl_enabled = bool(options["hitl_enabled"])
        if options.get("enable_tool_hitl") is not None:
            self.enable_tool_hitl = bool(options["enable_tool_hitl"])
        if options.get("hitl_mode") is not None:
            mode = str(options["hitl_mode"]).strip().lower()
            if mode in ("off", "agent", "tool"):
                settings.hitl_mode = mode
        if options.get("auto_approve_agents"):
            extra = options.get("auto_approve_agents")
            if isinstance(extra, list):
                self.auto_approve_agents.extend([str(a) for a in extra if str(a)])


# Helper functions for agents to use
async def check_risk_approval(
    job_id: int,
    agent_name: str,
    test_name: str,
    risk_type: str,
    risk_description: str
) -> bool:
    """
    Helper for agents to request risk approval
    
    Example:
        from utils.hitl_manager import check_risk_approval
        
        approved = await check_risk_approval(
            job_id=self.job_id,
            agent_name="InputValidationAgent",
            test_name="XML Bomb (Billion Laughs)",
            risk_type="dos",
            risk_description="May cause server to become unresponsive for up to 30 seconds"
        )
        
        if not approved:
            logger.warning("User rejected risky test, skipping")
            return
    """
    manager = HITLManager(job_id)
    return await manager.request_risk_approval(
        agent_name, test_name, risk_type, risk_description
    )
