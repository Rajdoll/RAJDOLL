---
description: Start a penetration test scan and monitor progress
allowed-tools: Bash, Read
---

Start a scan on target: **$1**

**Steps:**
1. Validate target URL format
2. Check if system is ready (docker-compose ps)
3. Start the scan via API:
   ```bash
   curl -X POST http://localhost:8000/api/scans \
     -H "Content-Type: application/json" \
     -d '{"target": "$1"}'
   ```
4. Extract job_id from response
5. Monitor progress for 60 seconds:
   - Show agent status updates
   - Show findings as they appear
   - Show any errors

6. After 60s, provide commands to:
   - Continue monitoring via WebSocket
   - Check current findings
   - Generate report when complete

**Output format:**
```
🎯 Target: $1
📋 Job ID: X
⏱️  Started: <timestamp>

🚀 Progress:
   [09:15:23] ReconnaissanceAgent started
   [09:16:45] Found 25 endpoints
   [09:17:10] InputValidationAgent started
   [09:18:30] 🟠 Finding: [HIGH] SQL Injection in /search
   ...

📊 Current Status:
   Agents completed: X/14
   Findings: X (Critical: X, High: X, Medium: X)

💡 Next steps:
   Monitor live: python test_websocket.py --job-id X
   Check findings: curl http://localhost:8000/api/scans/X/findings
   Generate report: curl http://localhost:8000/api/scans/X/report?format=pdf -o report.pdf
```
