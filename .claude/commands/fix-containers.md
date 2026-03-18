---
description: Diagnose and fix common Docker container issues
allowed-tools: Bash, Read, Grep
---

Diagnose and fix container issues.

**Steps:**

1. **Check all container status:**
   ```bash
   docker-compose ps -a
   docker ps -a --filter "name=juice-shop"
   ```

2. **Identify problems:**
   - Containers with status "Exited" or "Restarting"
   - Missing containers (not started)
   - Containers without network connectivity

3. **Common fixes:**

   **Juice Shop crashed (exit 139/SIGSEGV):**
   ```bash
   docker rm -f juice-shop
   docker run -d --name juice-shop --network rajdoll_default -p 3000:3000 --restart unless-stopped bkimminich/juice-shop
   ```

   **MCP server not responding:**
   ```bash
   docker-compose restart <mcp-server-name>
   docker-compose logs --tail=20 <mcp-server-name>
   ```

   **Worker can't resolve hostnames (DNS issue):**
   ```bash
   docker-compose restart worker
   # Or full network reset:
   docker-compose down && docker-compose up -d
   ```

   **Database connection refused:**
   ```bash
   docker-compose restart db
   docker-compose logs --tail=10 db
   ```

   **Redis connection refused:**
   ```bash
   docker-compose restart redis
   ```

   **Port conflict:**
   ```bash
   lsof -i :<port> | grep LISTEN
   ```

4. **Verify fix:**
   - Re-check container status
   - Test connectivity from worker to target
   - Test MCP server health

**Output format:**
```
🔧 Container Diagnostics

📋 Status:
   ✅ rajdoll-api       Running (Up 2h)
   ✅ rajdoll-worker    Running (Up 2h)
   ✅ rajdoll-db        Running (Up 2h)
   ✅ rajdoll-redis     Running (Up 2h)
   ❌ juice-shop        Exited (139) — SIGSEGV crash
   ✅ info-mcp          Running
   ...

🔴 Issues Found:
   1. juice-shop container crashed (exit code 139)
      → Restarting with --restart unless-stopped

🔧 Fixes Applied:
   1. ✅ juice-shop restarted successfully
      Network: rajdoll_default (172.18.0.X)
      Health: HTTP 200 on port 3000

✅ All services healthy
```
