# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Summary

RAJDOLL is a multi-agent penetration testing system that automates web security assessments per OWASP WSTG 4.2. It uses 14 specialized agents coordinated by an orchestrator in a **Planner-Summarizer Sequential** architecture (inspired by HackSynth, PentestGPT, PENTEST-AI). Agents call security tools (SQLMap, Dalfox, Nmap, etc.) via MCP (Model Context Protocol) servers. A local LLM (Qwen 3-4B via LM Studio) generates adaptive tool arguments based on reconnaissance context, with `json_schema` enforcement for structured output.

**Author:** Martua Raja Doli Pangaribuan — Politeknik Siber dan Sandi Negara thesis project.

### Juice Shop Challenge Coverage (Added 2026-03-18)

16 new Juice Shop-specific MCP tools were added to maximize challenge coverage:

| Tool | MCP Server | Agent | Targets |
|------|-----------|-------|---------|
| `test_sqli_login` | input-mcp | InputValidationAgent | Login bypass SQLi (admin/bender/jim) |
| `analyze_javascript_routes` | info-mcp | ReconnaissanceAgent | Hidden routes, secrets in JS files |
| `test_hidden_endpoints` | confdep-mcp | ConfigDeploymentAgent | /ftp, /metrics, /support/logs, etc. |
| `test_registration_mass_assignment` | identity-mcp | IdentityManagementAgent | Admin role injection at registration |
| `test_captcha_and_rate_limit` | biz-mcp | BusinessLogicAgent | Missing rate limiting on login/feedback |
| `test_http_parameter_pollution` | input-mcp | InputValidationAgent | Duplicate param abuse on endpoints |
| `test_user_spoofing` | authorz-mcp | AuthorizationAgent | Feedback/review UserId manipulation |
| `test_open_redirect` | client-mcp | ClientSideAgent | Allowlist bypass (/redirect?to=) |
| `test_2fa_bypass` | auth-mcp | AuthenticationAgent | TOTP brute force, 2FA skip |
| `test_csp_bypass` | client-mcp | ClientSideAgent | CSP analysis + bypass vectors |
| `test_coupon_forgery` | biz-mcp | BusinessLogicAgent | Expired coupons, negative qty |
| `test_npm_vulnerabilities` | confdep-mcp | ConfigDeploymentAgent | Exposed package.json + CVE check |
| `test_redos` | input-mcp | InputValidationAgent | ReDoS payloads on search/login |
| Enhanced null byte bypass | fileupload-mcp | FileUploadAgent | Juice Shop /ftp null byte tricks |

Additionally, `file-upload-testing/file_upload.py` was enhanced with Juice Shop-specific files (package.json.bak, coupons_2013.md.bak, encrypt.pyc, etc.) and proactive null byte testing for the /ftp directory.

## Commands

```bash
# Start all services (API + worker + DB + Redis + 14 MCP servers)
docker-compose up -d

# Rebuild after code changes (worker + all modified MCP servers)
docker-compose build --no-cache worker input-mcp auth-mcp authorz-mcp identity-mcp confdep-mcp client-mcp biz-mcp info-mcp fileupload-mcp && docker-compose up -d

# Clean rebuild (wipe DB volumes)
docker-compose down -v && docker-compose up --build -d

# View worker logs (where agents run)
docker-compose logs -f worker

# Start a scan via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Check scan findings
curl http://localhost:8000/api/scans/1/findings | jq

# Test individual MCP tool from worker container
docker exec rajdoll-worker-1 curl -s -X POST http://input-mcp:9005/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_nosql_injection","arguments":{"url":"http://juice-shop:3000/rest/products/search?q=test"}}}'

# Check LM Studio connection
curl http://localhost:1234/v1/models

# Run tests
pytest multi_agent_system/tests/test_new_architecture.py -v

# Run Celery worker locally (without Docker, needs DB+Redis running)
celery -A multi_agent_system.tasks.celery_app.celery_app worker -l INFO
```

## Architecture

### Planner-Summarizer Sequential Pattern

All 14 agents run **fully sequential** (no parallel batches). After each agent completes, the LLM summarizes findings into a cumulative summary that grows and is passed to the next agent. Before the report agent, `analyze_all_findings()` correlates cross-agent findings.

```
POST /api/scans → security_guard.validate_target()
  → Job record in PostgreSQL (status: queued)
  → Celery task: run_job_task(job_id) via Redis
  → Orchestrator(job_id).run():
      Phase 1:   ReconnaissanceAgent (discovers endpoints, tech stack)
      Phase 1.5: Auto-login via session_service.create_authenticated_session()
      Phase 2:   LLMPlanner.plan_testing_strategy(recon_results) [5-min timeout]
      Phase 3:   For each agent sequentially:
                   → _inject_planner_context(cumulative_summary, task_tree)
                   → agent.execute()
                   → _summarize_agent_and_accumulate(agent_name)
      Phase 4:   _run_final_analysis() — cross-agent correlation
      Phase 5:   ReportGenerationAgent (always runs, even after circuit breaker)
  → WebSocket pushes status updates to frontend
```

### Execution Order (DEFAULT_PLAN)

```
 1. ReconnaissanceAgent      →  Discover endpoints, tech stack, JS route analysis
 2. AuthenticationAgent      →  Test auth mechanisms, 2FA bypass (12 tools)
 3. SessionManagementAgent   →  Session/token handling
 4. InputValidationAgent     →  SQLi, XSS, LFI, SSTI, NoSQL, HPP, ReDoS, login SQLi
 5. AuthorizationAgent       →  Privilege escalation, IDOR, user spoofing (6 tools)
 6. ConfigDeploymentAgent    →  Misconfigs, headers, hidden endpoints, npm vulns (16 tools)
 7. ClientSideAgent          →  DOM XSS, CORS, clickjacking, CSP bypass, open redirect (17 tools)
 8. FileUploadAgent          →  Upload vulns, path traversal, null byte bypass
 9. APITestingAgent          →  API-specific issues
10. ErrorHandlingAgent       →  Error disclosure, stack traces
11. WeakCryptographyAgent    →  Weak TLS, crypto flaws
12. BusinessLogicAgent       →  Business logic bypass, coupon forgery, rate limiting (15 tools)
13. IdentityManagementAgent  →  User enumeration, registration, mass assignment (8 tools)
14. ReportGenerationAgent    →  Final OWASP WSTG 4.2 report
```

### Agent Tool Execution — Critical Data Flow

Every MCP tool call goes through `BaseAgent.execute_tool()`:

```
execute_tool(server, tool, args)
  → should_run_tool()                    # Circuit breaker + ADAPTIVE_MODE gating
  → _before_tool_execution()             # Merges LLM args with base args
      → _merge_planned_arguments()       # Lookup from _tool_arguments_map
      → _auto_generate_test_arguments()  # Fallback if LLM returned empty args
      → HITLManager (if enabled)
  → args = approval["arguments"]
  → Auth injection from shared_context
  → _normalize_llm_arguments()           # Map 'target_url'→'url', etc.
  → MCPClient.call_tool()                # JSON-RPC to MCP server container
```

### LLM Integration (Two Points)

1. **LLMPlanner** (orchestrator level): Called once after recon. Generates strategic plan for all agents. Uses `plan_testing_strategy()`. 5-min timeout.
2. **SimpleLLMClient** (agent level): Called per-agent via `select_tools_for_agent()`. Uses `json_schema` response format for structured output. Strips `<think>` tags. Multi-strategy JSON parsing (direct → strip code fences → extract first balanced block).

**Current LLM**: Qwen 3-4B via LM Studio (fits 4GB VRAM, ~15-20s/call). `json_schema` enforcement ensures arguments are populated (unlike Qwen 2.5-7B which returned empty `{}`).

### MCP Server Architecture

All 14 MCP servers use a single generic adapter (`mcp_adapter/server.py`). Each server is a Docker container running the same adapter image but with a different `MODULE_PATH` environment variable.

The adapter:
- Exposes `POST /jsonrpc` endpoint (JSON-RPC 2.0)
- Dynamically loads the Python module at `MODULE_PATH` via `importlib`
- **`_resolve_url_aliases()`**: Maps LLM-generated `url` param to function-expected `domain`/`host`/`base_url` (solves parameter mismatch)
- **`_filter_args_for_callable()`**: Uses `inspect.signature` to only pass accepted parameters
- Extracts auth session from `_auth_*` prefixed args

**MCP Server → Port mapping** (defined in docker-compose.yml):
| Server | Port | Module |
|--------|------|--------|
| info-mcp | 9001 | information-gathering/information_gathering.py |
| auth-mcp | 9002 | authentication-testing/authentication.py |
| authorz-mcp | 9003 | authorization-testing/authorization.py |
| session-mcp | 9004 | session-managemenet-testing/session-management.py |
| input-mcp | 9005 | input-validation-testing/input-validation.py |
| error-mcp | 9006 | error-handling-testing/error-handling.py |
| crypto-mcp | 9007 | testing-for-weak-cryptography/weak-cryptography.py |
| client-mcp | 9008 | client-side-testing/client-side.py |
| biz-mcp | 9009 | business-logic-testing/business-logic.py |
| confdep-mcp | 9010 | configuration-and-deployment-testing/configuration-and-deployment.py |
| identity-mcp | 9011 | identity-management-testing/identity-management.py |
| fileupload-mcp | 9012 | file-upload-testing/file_upload.py |
| api-testing-mcp | 9013 | api-testing/api_testing.py |
| katana-mcp | 9015 | katana-crawler/katana_server.py (separate Dockerfile) |

Note: `session-managemenet-testing` is a typo in the directory name — preserved intentionally.

### Database Models (PostgreSQL)

Defined in `multi_agent_system/models/models.py` (SQLAlchemy):
- **Job**: Scan job (target, status, plan, timing)
- **JobAgent**: Per-agent status within a job
- **Finding**: Vulnerability finding (title, severity, WSTG ID, evidence, confidence)
- **SharedContext**: Key-value store for inter-agent communication (recon results, entry points, auth sessions)

### Key Configuration

`multi_agent_system/core/config.py` — `Settings` dataclass, reads from env vars:
- `ADAPTIVE_MODE`: `off` (all tools) | `balanced` | `aggressive`
- `REACT_MODE` / `REACT_MAX_ITERATIONS`: Enable iterative ReAct loop per test
- `MIN_TOOLS_PER_AGENT`: Minimum coverage enforcement (default 7)
- `DISABLE_LLM_PLANNING`: Skip LLM, use all tools with defaults

### Key Timeouts

| Constant | Value | Location |
|----------|-------|----------|
| `AGENT_EXECUTION_TIMEOUT` | 2700s (45m) | base_agent.py |
| `TOOL_EXECUTION_TIMEOUT` | 600s (10m) | base_agent.py |
| `LLM_PLANNING_TIMEOUT` | 300s (5m) | base_agent.py |
| `LLM_SUMMARIZATION_TIMEOUT` | 300s (5m) | orchestrator.py |
| `LLM_FINAL_ANALYSIS_TIMEOUT` | 600s (10m) | orchestrator.py |
| `JOB_TOTAL_TIMEOUT` | 14400s (4h) | config.py |

### Job Status Logic

The job is marked `completed` as long as `ReportGenerationAgent` finishes successfully, even if some agents failed (tool timeouts, MCP issues are expected). The job is only `failed` if the report was NOT generated AND agents failed. This logic is enforced in two places:
- `orchestrator.py` — `run()` method, end of Phase 3
- `tasks/tasks.py` — `run_job_task()` (Celery task layer, re-evaluates and overrides)

## Code Patterns

### Adding a New Agent

1. Create `multi_agent_system/agents/my_agent.py` inheriting `BaseAgent` with `@AgentRegistry.register("MyAgent")`
2. Add to `DEFAULT_PLAN` in `orchestrator.py` (sequential list)
3. Add WSTG mapping in `AGENT_TO_OWASP_MAP`
4. If it needs a new MCP server: create the testing module, add service to `docker-compose.yml` with `Dockerfile.mcp-tools` and unique port, add URL to `MCP_SERVER_URLS` JSON

### Adding a New Tool to an MCP Server

Add an async Python function to the server's module file (e.g., `input-validation-testing/input-validation.py`). The MCP adapter auto-discovers functions by name. The function signature defines accepted parameters. Return a dict with `{"status": "success", "data": {...}}`.

Tools accepting `domain` or `host` parameters should use `_parse_target()` helper (where available) to handle both full URLs (`http://host:3000`) and bare hostnames.

### Shared Context Between Agents

```python
# Write (in any agent)
self.context_manager.save({"entry_points": [...], "tech_stack": {...}})

# Read (in any agent — orchestrator refreshes cache before each agent)
context = self.context_manager.load_all()
endpoints = context.get("entry_points", [])
```

### ADAPTIVE_MODE Behavior

- `off`: Every tool in the agent's arsenal runs unconditionally
- `balanced`: CRITICAL-priority tools always run + LLM-selected tools
- `aggressive`: CRITICAL+HIGH priority tools always run + LLM-selected tools

For research evaluation, `off` or `aggressive` is recommended to maximize coverage.

## Known Issues

1. **Session directory typo**: `session-managemenet-testing/` (double 'e') — don't rename, it's referenced in docker-compose.yml. All references are consistent.
2. **Juice Shop auto-login**: Default credentials (`admin@juice-sh.op`/`admin123`) ARE in `session_service.py DEFAULT_CREDENTIALS`. If auto-login fails, check that the Juice Shop container is running (`docker ps | grep juice-shop`). Run with `--restart unless-stopped` for stability.
3. **Thinking models incompatible**: Qwen 3-4B-thinking outputs `<think>` tags that conflict with `json_schema` enforcement. Non-thinking Qwen 3-4B with `json_schema` is the optimal choice for 4GB VRAM.
4. **Orchestrator LLM plan does NOT contain per-agent tools**: The orchestrator's `plan_testing_strategy()` returns `{"strategy": ..., "execution_plan": {"sequence": [agents]}}` — this is a high-level strategy, NOT per-agent tool assignments. The `_orchestrator_had_plan` flag must only be True when `tool_plan` is actually provided to the agent (fixed 2026-03-18 in orchestrator.py). If set True incorrectly, all agents skip their per-agent LLM planning and lose LLM-generated arguments, causing massive recall regression.

## Security Rules

- **Never commit `.env`** — it contains API keys. Use `.env.example` as template.
- Target domains must be whitelisted via `security_guards.py` before scanning.
- All tool executions are audit-logged.
- HITL (Human-in-the-Loop) approval is required for destructive operations when enabled.

## Evaluation Metrics

Target metrics for thesis validation (calculated in `multi_agent_system/evaluation/metrics.py`):
- Precision >= 90%, Recall >= 80%, F1-Score >= 85%
- Task Completion Rate (TCR) >= 70% of WSTG test cases
- Test targets: DVWA (25 known vulns) and OWASP Juice Shop (100+ challenges)
