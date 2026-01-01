---
description: Analyze Docker logs to find and fix errors
allowed-tools: Bash(docker:*), Bash(docker-compose:*), Read, Grep
---

Debug the system by analyzing logs:

**Steps:**
1. Get logs from all Docker containers (last 200 lines)
2. Identify error patterns and stack traces
3. Grep for critical keywords: ERROR, CRITICAL, Exception, Traceback
4. Show relevant code sections causing the errors
5. Rank errors by severity (CRITICAL > ERROR > WARNING)
6. Suggest fixes for top 3 errors

**Containers to check:**
- rajdoll-api (FastAPI backend)
- rajdoll-worker (Celery workers)
- rajdoll-db (PostgreSQL)
- rajdoll-redis (Redis cache)

**Output format:**
```
🔴 CRITICAL Errors: X found
   1. [Container] Error message
      File: path/to/file.py:line
      Cause: <analysis>
      Fix: <suggestion>

🟠 ERROR level: Y found
   ...

💡 Quick fixes:
   1. <command or code change>
   2. ...
```
