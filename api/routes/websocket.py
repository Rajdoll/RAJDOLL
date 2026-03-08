from __future__ import annotations

from fastapi import APIRouter, WebSocket
import asyncio
from datetime import datetime
from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import JobAgent, AgentEvent, SharedContext


router = APIRouter()


@router.websocket("/ws/{job_id}")
async def ws_logs(ws: WebSocket, job_id: int):
	"""WebSocket endpoint for real-time log streaming"""
	await ws.accept()
	last_event_id = 0
	last_agent_status = {}  # Track last status per agent to avoid spam
	sent_agent_statuses = {}  # Track which agent statuses we've already sent
	
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
