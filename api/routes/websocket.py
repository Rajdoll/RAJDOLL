from __future__ import annotations

from fastapi import APIRouter, WebSocket
import asyncio
from datetime import datetime
from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import JobAgent, AgentEvent, SharedContext
from multi_agent_system.models.hitl_models import AgentCheckpoint, CheckpointAction


router = APIRouter()


@router.websocket("/ws/{job_id}")
async def ws_logs(ws: WebSocket, job_id: int):
	"""WebSocket endpoint for real-time log streaming"""
	await ws.accept()
	# Fast-forward past old events so reconnects don't flood the client
	with get_db() as db:
		max_evt = (
			db.query(AgentEvent.id)
			.join(JobAgent, AgentEvent.job_agent_id == JobAgent.id)
			.filter(JobAgent.job_id == job_id)
			.order_by(AgentEvent.id.desc())
			.first()
		)
		last_event_id = max_evt[0] if max_evt else 0
	last_agent_status = {}  # Track last status per agent to avoid spam
	sent_agent_statuses = {}  # Track which agent statuses we've already sent
	last_checkpoint_id = 0  # Avoid sending same checkpoint repeatedly
	last_tool_approval_id = 0  # Avoid sending same HIGH_RISK approval repeatedly
	
	try:
		# Send initial connection message
		await ws.send_json({
			"type": "log",
			"message": "Connected to log stream",
			"level": "success",
			"agent": "SYSTEM"
		})
		
		while True:
			await asyncio.sleep(0.5)  # Poll every 500ms for responsive updates
			
			with get_db() as db:
				# Get new agent events
				events = (
					db.query(AgentEvent)
					.join(JobAgent, AgentEvent.job_agent_id == JobAgent.id)
					.filter(JobAgent.job_id == job_id, AgentEvent.id > last_event_id)
					.order_by(AgentEvent.id.asc())
					.all()
				)
				
				if events:
					for e in events:
						try:
							agent = db.query(JobAgent).get(e.job_agent_id)
							agent_name = agent.agent_name if agent else "SYSTEM"
							
							# Filter duplicate "running" status messages
							if "running" in e.message.lower() and agent:
								current_status = f"{agent_name}:running"
								if current_status == last_agent_status.get(agent_name):
									last_event_id = e.id  # Update event ID but don't send
									continue  # Skip duplicate running message
								last_agent_status[agent_name] = current_status
							else:
								# Update status on any other message
								if agent:
									last_agent_status[agent_name] = e.message[:50]
							
							# Send each event as a log message
							await ws.send_json({
								"type": "log",
								"message": e.message,
								"level": e.level or "info",
								"agent": agent_name,
								"timestamp": e.created_at.isoformat() if e.created_at else datetime.utcnow().isoformat()
							})
						except Exception:
							pass
					
					last_event_id = events[-1].id
				
				# Check agent status changes - ONLY send if status changed
				agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()
				for agent in agents:
					agent_key = f"{agent.agent_name}:{agent.status}"
					if agent_key != sent_agent_statuses.get(agent.agent_name):
						# Status changed, send update
						sent_agent_statuses[agent.agent_name] = agent_key
						if agent.status in ['running', 'completed', 'failed', 'skipped']:
							await ws.send_json({
								"type": "agent_update",
								"agent": agent.agent_name,
								"status": agent.status
							})

				# HITL Live Monitor: broadcast execution_status to dashboard
				try:
					exec_record = db.query(SharedContext).filter(
						SharedContext.job_id == job_id,
						SharedContext.key == "execution_status"
					).one_or_none()
					if exec_record and exec_record.value:
						await ws.send_json({
							"type": "execution_status",
							**exec_record.value
						})
				except Exception:
					pass

				# Agent-Level HITL Checkpoint: notify frontend when waiting
				try:
					pending_cp = db.query(AgentCheckpoint).filter(
						AgentCheckpoint.job_id == job_id,
						AgentCheckpoint.action == CheckpointAction.pending,
					).order_by(AgentCheckpoint.requested_at.desc()).first()
					if pending_cp and pending_cp.id != last_checkpoint_id:
						last_checkpoint_id = pending_cp.id
						cp_type = getattr(pending_cp, "checkpoint_type", "post_agent") or "post_agent"
						if cp_type == "pre_agent":
							await ws.send_json({
								"type": "pre_agent_checkpoint",
								"data": {
									"checkpoint_id": pending_cp.id,
									"next_agent": pending_cp.next_agent,
									"agent_index": pending_cp.agent_sequence_index,
									"planned_tools": pending_cp.planned_tools or [],
									"cumulative_summary": (pending_cp.cumulative_summary or "")[:1000],
									"remaining_agents": pending_cp.remaining_agents or [],
								}
							})
						else:
							await ws.send_json({
								"type": "agent_checkpoint",
								"data": {
									"checkpoint_id": pending_cp.id,
									"completed_agent": pending_cp.completed_agent,
									"agent_index": pending_cp.agent_sequence_index,
									"findings_count": pending_cp.findings_count,
									"findings_by_severity": pending_cp.findings_by_severity or {},
									"agent_summary": (pending_cp.agent_summary or "")[:2000],
									"key_findings": pending_cp.key_findings or [],
									"next_agent": pending_cp.next_agent,
									"remaining_agents": pending_cp.remaining_agents or [],
									"recommendations": pending_cp.recommendations or [],
								}
							})
				except Exception as cp_err:
					import traceback
					print(f"[WS] Checkpoint query error: {cp_err}\n{traceback.format_exc()}")

				# HIGH_RISK Tool Approval: notify Director when tool is paused
				try:
					from multi_agent_system.models.hitl_models import ToolApproval, ApprovalStatus
					pending_ap = db.query(ToolApproval).filter(
						ToolApproval.job_id == job_id,
						ToolApproval.status == ApprovalStatus.pending,
						ToolApproval.is_high_risk_review == True,
					).order_by(ToolApproval.requested_at.desc()).first()
					if pending_ap and pending_ap.id != last_tool_approval_id:
						last_tool_approval_id = pending_ap.id
						await ws.send_json({
							"type": "high_risk_tool_approval",
							"data": {
								"approval_id": pending_ap.id,
								"tool_name": pending_ap.tool_name,
								"agent_name": pending_ap.agent_name,
								"generated_args": pending_ap.arguments or {},
								"reason": pending_ap.reason,
							}
						})
				except Exception:
					pass

	except Exception as e:
		# Connection closed or error
		pass
	finally:
		try:
			await ws.close()
		except RuntimeError:
			pass


@router.websocket("/ws/progress/{job_id}")
async def ws_progress(ws: WebSocket, job_id: int):  # pragma: no cover
	await ws.accept()
	last_event_id = 0
	try:
		while True:
			await asyncio.sleep(1)
			with get_db() as db:
				events = (
					db.query(AgentEvent)
					.join(JobAgent, AgentEvent.job_agent_id == JobAgent.id)
					.filter(JobAgent.job_id == job_id, AgentEvent.id > last_event_id)
					.order_by(AgentEvent.id.asc())
					.all()
				)
				if events:
					payload = []
					for e in events:
						try:
							agent = db.query(JobAgent).get(e.job_agent_id)
							agent_name = agent.agent_name if agent else None
						except Exception:
							agent_name = None
						payload.append({
							"id": e.id,
							"created_at": e.created_at.isoformat(),
							"level": e.level,
							"message": e.message,
							"data": e.data,
							"agent_name": agent_name,
						})
					last_event_id = events[-1].id
					await ws.send_json({"job_id": job_id, "events": payload})
	except Exception:
		pass
	finally:
		try:
			await ws.close()
		except RuntimeError:
			pass
