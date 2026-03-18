---
description: Rebuild modified Docker containers and restart services
allowed-tools: Bash, Read, Grep
---

Rebuild and restart RAJDOLL services after code changes.

**Steps:**

1. **Detect modified files** by checking git status:
   ```bash
   git diff --name-only HEAD
   git diff --name-only --staged
   ```

2. **Map modified files to MCP servers:**
   | File pattern | Container |
   |-------------|-----------|
   | `information-gathering/` | info-mcp |
   | `authentication-testing/` | auth-mcp |
   | `authorization-testing/` | authorz-mcp |
   | `session-managemenet-testing/` | session-mcp |
   | `input-validation-testing/` | input-mcp |
   | `error-handling-testing/` | error-mcp |
   | `testing-for-weak-cryptography/` | crypto-mcp |
   | `client-side-testing/` | client-mcp |
   | `business-logic-testing/` | biz-mcp |
   | `configuration-and-deployment-testing/` | confdep-mcp |
   | `identity-management-testing/` | identity-mcp |
   | `file-upload-testing/` | fileupload-mcp |
   | `api-testing/` | api-testing-mcp |
   | `multi_agent_system/` | worker |
   | `mcp_adapter/` | ALL MCP servers |
   | `api/` | api |

3. **Build only modified containers** (no-cache for reliability):
   ```bash
   docker-compose build --no-cache <detected_services> worker
   ```

4. **Restart services:**
   ```bash
   docker-compose up -d
   ```

5. **Verify health:**
   - Check all containers are running: `docker-compose ps`
   - Verify worker started: `docker-compose logs --tail=5 worker`
   - Check Juice Shop is accessible: `docker exec rajdoll-worker-1 curl -s -o /dev/null -w "%{http_code}" http://juice-shop:3000`

**Output format:**
```
🔧 Rebuild Summary

📦 Modified files:
   - input-validation-testing/input-validation.py
   - multi_agent_system/agents/input_validation_agent.py

🏗️  Rebuilding: worker, input-mcp
   [Building...] ██████████ Done (45s)

✅ Services restarted:
   worker     → Running ✅
   input-mcp  → Running ✅
   juice-shop → Healthy ✅

💡 Ready to scan: /run-scan http://juice-shop:3000
```
