# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Summary

RAJDOLL is a multi-agent penetration testing system that automates web security assessments per OWASP WSTG 4.2. It uses 14 specialized agents coordinated by an orchestrator, each targeting a specific WSTG category. Agents call security tools (SQLMap, Dalfox, Nmap, etc.) via MCP (Model Context Protocol) servers. An LLM (local via LM Studio or remote via OpenAI) generates adaptive tool arguments based on reconnaissance context.

**Author:** Martua Raja Doli Pangaribuan — Politeknik Siber dan Sandi Negara thesis project.

## Commands

```bash
# Start all services (API + worker + DB + Redis + 14 MCP servers)
docker-compose up -d

# Rebuild after code changes
docker-compose build && docker-compose up -d

# Clean rebuild (wipe DB volumes)
docker-compose down -v && docker-compose up --build -d

# View API logs / worker logs
docker-compose logs -f api
docker-compose logs -f worker

# Run tests
pytest multi_agent_system/tests/test_new_architecture.py -v

# Run with coverage
pytest tests/ --cov=multi_agent_system --cov-report=html

# Start a scan via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Check scan findings
curl http://localhost:8000/api/scans/1/findings | jq

# Validate LLM planning fix
python fix_validation.py

# Check LM Studio connection
curl http://localhost:1234/v1/models

# Run API locally (without Docker, needs DB+Redis running)
uvicorn api.main:app --reload --port 8000

# Run Celery worker locally
celery -A multi_agent_system.tasks.celery_app.celery_app worker -l INFO
```

## Architecture

### Execution Flow

```
POST /api/scans → security_guard.validate_target()
  → Job record in PostgreSQL (status: queued)
  → Celery task: run_job_task(job_id) via Redis
  → Orchestrator(job_id).run():
      Phase 1:   ReconnaissanceAgent (always first, sequential)
      Phase 1.5: Auto-login via session_service.create_authenticated_session()
      Phase 2:   LLMPlanner.plan_testing_strategy(recon_results) [5-min timeout]
      Phase 3:   Execute plan — sequential agents then parallel block
      Phase 4:   ReportGenerationAgent (always runs, even after circuit breaker)
  → WebSocket pushes status updates to frontend
```

### Default Execution Plan

The orchestrator always follows this order regardless of LLM plan (LLM plan only affects *tool selection* within each agent, not execution order):

1. `ReconnaissanceAgent` — sequential
2. `AuthenticationAgent` — sequential
3. `SessionManagementAgent` — sequential
4. `InputValidationAgent` — sequential
5. Batch 1 (parallel): `AuthorizationAgent`, `ConfigDeploymentAgent`, `ClientSideAgent`
6. Batch 2 (parallel): `FileUploadAgent`, `APITestingAgent`, `ErrorHandlingAgent`
7. Batch 3 (parallel): `WeakCryptographyAgent`, `BusinessLogicAgent`, `IdentityManagementAgent`
8. `ReportGenerationAgent` — sequential

### Two Orchestrator Implementations

- **`orchestrator.py`** (production): Flat plan with sequential + parallel blocks
- **`hierarchical_orchestrator.py`** (Phase 2, not default): Groups agents into clusters (RECONNAISSANCE → ATTACK → LOGIC → REPORTING) with dependency tracking, KnowledgeGraph, and AttackChainDetector

### Agent Tool Execution — Critical Data Flow

Every MCP tool call goes through `BaseAgent.execute_tool()`:

```
execute_tool(server, tool, args)
  → should_run_tool()                    # Circuit breaker + ADAPTIVE_MODE gating
  → _before_tool_execution()             # CRITICAL: merges LLM args with base args
      → _merge_planned_arguments()       # Lookup from _tool_arguments_map
      → HITLManager (if enabled)
  → args = approval["arguments"]         # Apply merged args (the Dec 22 fix)
  → Auth injection from shared_context
  → _normalize_llm_arguments()           # Map 'target_url'→'url', etc.
  → MCPClient.call_tool()                # JSON-RPC to MCP server container
```

### Two LLM Integration Points

1. **LLMPlanner** (orchestrator level): Synchronous, called once after recon via ThreadPoolExecutor. Generates strategic plan for all agents. Uses `plan_testing_strategy()`.
2. **SimpleLLMClient** (agent level): Async, called per-agent if orchestrator didn't provide a tool plan. Uses `select_tools_for_agent()`. Semaphore limits to 2 concurrent LLM calls.

Both strip `<think>...</think>` tags (Qwen artifact) and use multi-strategy JSON parsing (direct → strip code fences → extract first balanced block).

### MCP Server Architecture

All 14 MCP servers use a single generic adapter (`mcp_adapter/server.py`). Each server is a Docker container running the same adapter image but with a different `MODULE_PATH` environment variable pointing to its testing module (e.g., `input-validation-testing/input-validation.py`).

The adapter:
- Exposes a single `POST /jsonrpc` endpoint (JSON-RPC 2.0)
- Dynamically loads the Python module at `MODULE_PATH` via `importlib`
- Looks up the tool function by name via `getattr(module, tool_name)`
- Uses `inspect.signature` to filter args, only passing parameters the function accepts
- Extracts auth session from `_auth_*` prefixed args before forwarding

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
- `ADAPTIVE_MODE`: `off` (all tools) | `balanced` | `aggressive` (production default in .env.example)
- `REACT_MODE` / `REACT_MAX_ITERATIONS`: Enable iterative ReAct loop (env on worker)
- `MIN_TOOLS_PER_AGENT`: Minimum coverage enforcement (default 7)
- `DISABLE_LLM_PLANNING`: Skip LLM, use all tools with defaults

### Key Timeouts

| Constant | Value | Location |
|----------|-------|----------|
| `AGENT_EXECUTION_TIMEOUT` | 7200s (2h) | base_agent.py |
| `TOOL_EXECUTION_TIMEOUT` | 1800s (30m) | base_agent.py |
| `LLM_PLANNING_TIMEOUT` | 300s (5m) | base_agent.py |
| `job_total_timeout` | 3600s (1h) | config.py |

## Code Patterns

### Adding a New Agent

1. Create `multi_agent_system/agents/my_agent.py` inheriting `BaseAgent` with `@AgentRegistry.register("MyAgent")`
2. Add to `DEFAULT_PLAN` in `orchestrator.py` (sequential entry or inside `{"parallel": [...]}`)
3. Add WSTG mapping in `AGENT_TO_OWASP_MAP`
4. If it needs a new MCP server: create the testing module, add service to `docker-compose.yml` with `Dockerfile.mcp-tools` and unique port, add URL to `MCP_SERVER_URLS` JSON

### Adding a New Tool to an MCP Server

Add a Python function to the server's module file (e.g., `input-validation-testing/input-validation.py`). The MCP adapter auto-discovers functions by name. The function signature defines accepted parameters. Return a dict with results.

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

1. ~~**ReAct agent method naming mismatch**~~: Fixed — `react_agent.py` now calls `chat_completion()` matching `SimpleLLMClient`. ReAct is Phase 2 code not yet wired into production agents.
2. **Session directory typo**: `session-managemenet-testing/` (double 'e') — don't rename, it's referenced in docker-compose.yml. All references are consistent.
3. ~~**WebSocket disconnection under load**~~: Fixed — `frontend/js/app.js` now has exponential backoff reconnection (up to 5 retries, 1s/2s/4s/8s/16s delays), with guards against reconnecting after terminal scan states.

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
