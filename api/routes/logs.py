"""
WebSocket endpoint for real-time MCP logs streaming
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, Set
import asyncio
import json
import subprocess
from datetime import datetime

# Allowlist of valid short container names (without rajdoll- prefix and -1 suffix)
KNOWN_CONTAINERS = {
    "worker", "input-mcp", "auth-mcp", "authorz-mcp", "session-mcp",
    "confdep-mcp", "info-mcp", "error-mcp", "identity-mcp", "biz-mcp",
    "client-mcp", "crypto-mcp", "fileupload-mcp", "api-testing-mcp",
    "katana-mcp", "db", "redis",
}

router = APIRouter()

# Active WebSocket connections per job_id
active_connections: Dict[int, Set[WebSocket]] = {}

class LogManager:
    """Manages log streaming from Docker containers"""
    
    def __init__(self):
        self.log_tasks: Dict[int, asyncio.Task] = {}
        self.mcp_containers = [
            "rajdoll-input-mcp-1",
            "rajdoll-auth-mcp-1",
            "rajdoll-authz-mcp-1",
            "rajdoll-session-mcp-1",
            "rajdoll-confdep-mcp-1",
            "rajdoll-info-mcp-1",
            "rajdoll-error-mcp-1",
            "rajdoll-identity-mcp-1",
            "rajdoll-biz-mcp-1",
            "rajdoll-client-mcp-1",
            "rajdoll-crypto-mcp-1",
        ]
    
    async def stream_container_logs(self, container_name: str, websocket: WebSocket, job_id: int = None):
        """Stream logs from a Docker container in real-time"""
        try:
            # Start docker logs with follow
            process = await asyncio.create_subprocess_exec(
                "docker", "logs", "-f", "--tail", "50", container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                log_text = line.decode('utf-8', errors='ignore').strip()
                if not log_text:
                    continue
                
                # Parse log line
                log_entry = self._parse_log_line(log_text, container_name)
                
                # Filter by job_id if needed (check if target URL in log)
                if job_id:
                    # Would need to match against job target from DB
                    pass
                
                # Send to WebSocket
                try:
                    await websocket.send_json(log_entry)
                except Exception as e:
                    # Connection closed
                    break
            
        except Exception as e:
            print(f"Error streaming logs from {container_name}: {e}")
    
    def _parse_log_line(self, line: str, container: str) -> dict:
        """Parse log line into structured format"""
        # Example: [2025-10-24 08:00:00] INFO [input-validation-mcp] 🔍 Starting XXE testing
        
        import re
        pattern = r'\[([^\]]+)\]\s+(\w+)\s+\[([^\]]+)\]\s+(.+)'
        match = re.match(pattern, line)
        
        if match:
            timestamp, level, server, message = match.groups()
            return {
                "timestamp": timestamp,
                "level": level,
                "server": server,
                "container": container,
                "message": message,
                "raw": line
            }
        else:
            # Fallback for non-structured logs
            return {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "level": "INFO",
                "server": container.replace("rajdoll-", "").replace("-1", ""),
                "container": container,
                "message": line,
                "raw": line
            }
    
    async def start_streaming(self, websocket: WebSocket, job_id: int = None):
        """Start streaming from all MCP containers"""
        tasks = []
        for container in self.mcp_containers:
            task = asyncio.create_task(
                self.stream_container_logs(container, websocket, job_id)
            )
            tasks.append(task)
        
        # Wait for all tasks (they run indefinitely until connection closes)
        await asyncio.gather(*tasks, return_exceptions=True)

log_manager = LogManager()

@router.websocket("/ws/logs")
async def websocket_logs_all(websocket: WebSocket):
    """Stream logs from all MCP containers"""
    await websocket.accept()
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to MCP logs stream",
            "timestamp": datetime.now().isoformat()
        })
        
        # Start streaming logs
        await log_manager.start_streaming(websocket)
        
    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
        except:
            pass

@router.websocket("/ws/logs/{job_id}")
async def websocket_logs_job(websocket: WebSocket, job_id: int):
    """Stream logs for specific job"""
    await websocket.accept()
    
    # Add to active connections
    if job_id not in active_connections:
        active_connections[job_id] = set()
    active_connections[job_id].add(websocket)
    
    try:
        # Send initial message
        await websocket.send_json({
            "type": "connected",
            "job_id": job_id,
            "message": f"Connected to logs for job {job_id}",
            "timestamp": datetime.now().isoformat()
        })
        
        # Start streaming with job filter
        await log_manager.start_streaming(websocket, job_id)
        
    except WebSocketDisconnect:
        print(f"WebSocket disconnected for job {job_id}")
    except Exception as e:
        print(f"WebSocket error for job {job_id}: {e}")
    finally:
        # Remove from active connections
        if job_id in active_connections:
            active_connections[job_id].discard(websocket)
            if not active_connections[job_id]:
                del active_connections[job_id]

@router.get("/api/logs/recent/{container_name}")
async def get_recent_logs(container_name: str, lines: int = 100):
    """Get recent logs from a container (HTTP endpoint)"""
    if container_name not in KNOWN_CONTAINERS:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail=f"Unknown container '{container_name}'. Valid: {sorted(KNOWN_CONTAINERS)}",
        )
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(lines), f"rajdoll-{container_name}-1"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        logs = result.stdout + result.stderr
        log_lines = logs.strip().split('\n')
        
        # Parse each line
        parsed_logs = []
        for line in log_lines:
            if line.strip():
                parsed = log_manager._parse_log_line(line, container_name)
                parsed_logs.append(parsed)
        
        return {
            "status": "success",
            "container": container_name,
            "lines": len(parsed_logs),
            "logs": parsed_logs
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/api/logs/search")
async def search_logs(query: str, container: str = None, level: str = None):
    """Search logs across containers"""
    if container and container not in KNOWN_CONTAINERS:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail=f"Unknown container '{container}'. Valid: {sorted(KNOWN_CONTAINERS)}",
        )
    try:
        containers = [f"rajdoll-{container}-1"] if container else log_manager.mcp_containers
        
        all_results = []
        for cont in containers:
            result = subprocess.run(
                ["docker", "logs", "--tail", "500", cont],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            logs = (result.stdout + result.stderr).split('\n')
            for line in logs:
                if query.lower() in line.lower():
                    parsed = log_manager._parse_log_line(line, cont)
                    
                    # Filter by level if specified
                    if level and parsed.get("level", "").lower() != level.lower():
                        continue
                    
                    all_results.append(parsed)
        
        return {
            "status": "success",
            "query": query,
            "matches": len(all_results),
            "results": all_results[-100:]  # Last 100 matches
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
