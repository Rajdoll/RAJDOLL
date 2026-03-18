---
description: Check all 14 MCP server connectivity and tool availability
allowed-tools: Bash, Read, Grep
---

Health check all MCP tool servers.

**Steps:**

1. **Check container status:**
   ```bash
   docker-compose ps | grep mcp
   ```

2. **Test each MCP server endpoint** from the worker container:
   For each server, send a simple JSON-RPC ping:
   ```bash
   docker exec rajdoll-worker-1 curl -s -o /dev/null -w "%{http_code}" \
     -X POST http://<server>:<port>/jsonrpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"__health__","arguments":{}}}'
   ```

   **Server list:**
   | Server | Host | Port |
   |--------|------|------|
   | info-mcp | info-mcp | 9001 |
   | auth-mcp | auth-mcp | 9002 |
   | authorz-mcp | authorz-mcp | 9003 |
   | session-mcp | session-mcp | 9004 |
   | input-mcp | input-mcp | 9005 |
   | error-mcp | error-mcp | 9006 |
   | crypto-mcp | crypto-mcp | 9007 |
   | client-mcp | client-mcp | 9008 |
   | biz-mcp | biz-mcp | 9009 |
   | confdep-mcp | confdep-mcp | 9010 |
   | identity-mcp | identity-mcp | 9011 |
   | fileupload-mcp | fileupload-mcp | 9012 |
   | api-testing-mcp | api-testing-mcp | 9013 |
   | katana-mcp | katana-mcp | 9015 |

3. **Count tools per server** by importing the module and counting async functions:
   ```bash
   docker exec rajdoll-worker-1 python3 -c "
   import importlib, inspect, asyncio
   modules = {
       'info-mcp': 'information-gathering.information_gathering',
       'input-mcp': 'input-validation-testing.input-validation',
       ...
   }
   for name, mod_path in modules.items():
       mod = importlib.import_module(mod_path.replace('-', '_').replace('/', '.'))
       tools = [n for n, f in inspect.getmembers(mod, inspect.iscoroutinefunction) if not n.startswith('_')]
       print(f'{name}: {len(tools)} tools')
   "
   ```

4. **Check target accessibility** (Juice Shop):
   ```bash
   docker exec rajdoll-worker-1 curl -s -o /dev/null -w "%{http_code}" http://juice-shop:3000
   ```

**Output format:**
```
🏥 MCP Server Health Check

✅ info-mcp       (9001) → 200 OK  | 12 tools
✅ auth-mcp       (9002) → 200 OK  | 11 tools
✅ authorz-mcp    (9003) → 200 OK  |  6 tools
✅ session-mcp    (9004) → 200 OK  |  7 tools
✅ input-mcp      (9005) → 200 OK  | 24 tools
✅ error-mcp      (9006) → 200 OK  |  5 tools
✅ crypto-mcp     (9007) → 200 OK  |  5 tools
✅ client-mcp     (9008) → 200 OK  | 17 tools
✅ biz-mcp        (9009) → 200 OK  | 15 tools
✅ confdep-mcp    (9010) → 200 OK  | 16 tools
✅ identity-mcp   (9011) → 200 OK  |  8 tools
✅ fileupload-mcp (9012) → 200 OK  |  5 tools
✅ api-testing-mcp(9013) → 200 OK  |  7 tools
❌ katana-mcp     (9015) → TIMEOUT | Check container

🎯 Juice Shop: ✅ Accessible (HTTP 200)
📊 Total: 13/14 servers healthy, 138 tools available
```
