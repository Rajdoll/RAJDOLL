# CLAUDE.md

## 1. Project Overview

RAJDOLL is a multi-agent web penetration testing system, built as a thesis at Politeknik Siber dan Sandi Negara (author: Martua Raja Doli Pangaribuan). It automates OWASP WSTG 4.2 assessments using 14 specialized agents coordinated by a **Planner-Summarizer Sequential** orchestrator. Agents invoke security tools (SQLMap, Dalfox, Nmap, etc.) via containerized MCP servers. A local LLM (Qwen 3-4B) generates adaptive tool arguments per-agent using `json_schema` enforcement. This is an **authorized security research tool** — all scanning requires explicit target whitelisting.

---

## 2. Tech Stack

- **Backend**: Python 3.11, FastAPI, Celery, PostgreSQL, Redis, SQLAlchemy ORM (no raw SQL)
- **MCP**: 14 Docker containers, single generic adapter (`mcp_adapter/server.py`), JSON-RPC 2.0
- **LLM**: Qwen 3-4B via LM Studio (openai-compatible, port 1234), `json_schema` response format — **not** the thinking variant (incompatible with `json_schema`)
- **Frontend**: Vanilla JS + HTML, WebSocket for live updates — no framework
- **Config**: `multi_agent_system/core/config.py` (`Settings` dataclass, all env vars)
- **NOT used**: Django, Flask, GraphQL, async DB drivers, ORMs other than SQLAlchemy

---

## 3. Architecture

### Scan Flow

```
POST /api/scans {target, credentials?, whitelist_domain?, hitl_mode?}
  → security_guard.validate_target()       # domain must be whitelisted
  → Job (PostgreSQL) → Celery task (Redis)
  → Orchestrator.run():
      Phase 1:   ReconnaissanceAgent
      Phase 1.5: Auto-login (SharedContext["scan_credentials"] → fallback wordlist)
      Phase 2:   LLMPlanner.plan_testing_strategy() [5-min timeout]
      Phase 3:   For each agent sequentially:
                   _inject_planner_context() → agent.execute()
                   → _summarize_agent_and_accumulate()
                   → [if HITL_MODE=agent]: checkpoint → wait for user
      Phase 4:   _run_final_analysis()
      Phase 5:   ReportGenerationAgent (always runs)
  → WebSocket pushes updates to frontend
```

### Agent Execution Order (DEFAULT_PLAN)

```
 1. ReconnaissanceAgent      →  Endpoints, tech stack, JS route analysis
 2. AuthenticationAgent      →  Auth mechanisms, 2FA bypass (12 tools)
 3. SessionManagementAgent   →  Session/token handling
 4. InputValidationAgent     →  SQLi, XSS, LFI, SSTI, NoSQL, HPP, ReDoS (24+ tools)
 5. AuthorizationAgent       →  Privilege escalation, IDOR, user spoofing
 6. ConfigDeploymentAgent    →  Misconfigs, headers, hidden endpoints (16 tools)
 7. ClientSideAgent          →  DOM XSS, CORS, clickjacking, CSP, redirects (17 tools)
 8. FileUploadAgent          →  Upload vulns, path traversal, null byte bypass
 9. APITestingAgent          →  API-specific issues
10. ErrorHandlingAgent       →  Error disclosure, stack traces
11. WeakCryptographyAgent    →  Weak TLS, crypto flaws
12. BusinessLogicAgent       →  Logic bypass, coupon forgery, rate limiting (15 tools)
13. IdentityManagementAgent  →  User enumeration, mass assignment (8 tools)
14. ReportGenerationAgent    →  Final OWASP WSTG 4.2 report
```

### MCP Tool Call Path

```
execute_tool(server, tool, args)
  → should_run_tool()              # Circuit breaker + ADAPTIVE_MODE gating
  → _before_tool_execution()       # LLM args merge, HITLManager approval
  → _normalize_llm_arguments()     # Map 'target_url'→'url', etc.
  → MCPClient.call_tool()          # JSON-RPC to MCP container
```

### MCP Servers

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
| katana-mcp | 9015 | katana-crawler/katana_server.py |

Note: `session-managemenet-testing` typo is intentional — matches docker-compose.yml.

### Key Timeouts

| Constant | Value | File |
|----------|-------|------|
| `JOB_TOTAL_TIMEOUT` | 14400s (4h) | config.py |
| `AGENT_EXECUTION_TIMEOUT` | 2700s (45m) | base_agent.py |
| `TOOL_EXECUTION_TIMEOUT` | 600s (10m) | base_agent.py |
| `LLM_PLANNING_TIMEOUT` | 300s (5m) | base_agent.py |

### Job Status

`queued` → `running` → [`waiting_checkpoint` ↔ `running`] → `completed` | `failed` | `cancelled`

Job is `completed` when `ReportGenerationAgent` finishes, even if other agents had errors. Enforced in both `orchestrator.py` and `tasks/tasks.py`.

`waiting_checkpoint` is set for both PRE-AGENT checkpoints (Director reviews planned tools before agent runs) and POST-AGENT checkpoints (Director reviews findings after agent completes). Both use `AgentCheckpoint`; distinguish by `checkpoint_type` field ("pre_agent" / "post_agent").

---

## 4. Coding Conventions

**Adding an agent**: Extend `BaseAgent`, decorate `@AgentRegistry.register("MyAgent")`, add to `DEFAULT_PLAN` and `AGENT_TO_OWASP_MAP` in `orchestrator.py`. If it needs a new MCP server, add service to `docker-compose.yml` with `Dockerfile.mcp-tools` and a unique port.

**Adding an MCP tool**: Add an async function to the module file. The adapter auto-discovers by name. Return `{"status": "success", "data": {...}}`. Use `_parse_target()` for `domain`/`host` params to handle full URLs and bare hostnames.

**Shared context between agents**:
```python
self.context_manager.save({"key": value})   # write
context = self.context_manager.load_all()    # read (orchestrator refreshes before each agent)
```

**ADAPTIVE_MODE**: `off` = all tools; `balanced` = CRITICAL + LLM-selected; `aggressive` = CRITICAL+HIGH + LLM-selected. Use `off` or `aggressive` for thesis evaluation.

**HITL_MODE**: `off` (default) | `agent` (pause after each agent for review) | `tool` (approve each tool). Set via env var or per-scan `hitl_mode` field. Details: `docs/execution-flow-hitl-v2.md`.

**Director Mode** (HITL v3, active when `hitl_mode == "agent"`): Before each agent (except Recon and Report), the orchestrator creates a PRE-AGENT `AgentCheckpoint` (`checkpoint_type="pre_agent"`). The Director responds via `POST /api/hitl/pre-agent-checkpoint/{id}/respond` with structured directive commands (FOCUS/SKIP/INCLUDE/EXCLUDE/DEPTH/NOTE). Commands are injected into the agent's LLM planning context via `_inject_planner_context()`. SKIP commands also gate `should_run_tool()`. For the 5 `HIGH_RISK_TOOLS` (run_sqlmap, test_xss_dalfox, run_nikto, run_nmap, test_tls_configuration), a `ToolApproval` record (`is_high_risk_review=True`) is created mid-agent; Director edits args or skips via `POST /api/hitl/tool-approval/{id}/director-review`. DB migration required — SQL in `hitl_models.py` comment.

---

## 5. Commands

```bash
# Start all services
docker-compose up -d

# Rebuild after code changes (worker + modified MCP servers)
docker-compose build --no-cache worker input-mcp auth-mcp authorz-mcp identity-mcp \
  confdep-mcp client-mcp biz-mcp info-mcp fileupload-mcp && docker-compose up -d

# Clean rebuild (wipe DB volumes)
docker-compose down -v && docker-compose up --build -d

# View agent logs
docker-compose logs -f worker

# Start Juice Shop scan (credentials → auto-login in Phase 1.5)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000", "credentials": {"username": "admin@juice-sh.op", "password": "admin123"}}'

# Scan VDP target
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://target.bssn.go.id", "whitelist_domain": "target.bssn.go.id", "credentials": {"username": "user@email.com", "password": "pass"}}'

# Check findings
curl http://localhost:8000/api/scans/1/findings | jq

# Test individual MCP tool
docker exec rajdoll-worker-1 curl -s -X POST http://input-mcp:9005/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_nosql_injection","arguments":{"url":"http://juice-shop:3000/rest/products/search?q=test"}}}'

# Check LM Studio
curl http://localhost:1234/v1/models

# Run tests (no Docker needed)
pytest multi_agent_system/tests/test_vdp_generalization.py -v

# Run architecture tests (requires live DB)
pytest multi_agent_system/tests/test_new_architecture.py -v
```

---

## 6. Safe-Change Rules

1. **Never remove or disable existing MCP tools.** Tools fail gracefully on non-matching targets — that's expected and correct. Removal reduces recall.
2. **Never change `_orchestrator_had_plan` logic without running the Juice Shop regression scan.** If set `True` when no `tool_plan` was provided, all agents skip per-agent LLM planning → lose LLM-generated arguments → major recall regression.
3. **Never hardcode target URLs, credentials, or domain names in infrastructure files.** Use `ALLOWED_DOMAINS` / `ADMIN_TOKEN` env vars or request-body injection via SharedContext.
4. **`ReportGenerationAgent` must always run**, even when earlier agents fail. Do not add early-exit logic that bypasses it.
5. **Never add `shell=True` to subprocess calls.** All subprocess calls must use list arguments.
6. **`whitelist_domain` must be appended before `validate_target` is called** in `api/routes/scans.py`. Appending after causes 403 for new domains.
7. **When modifying orchestrator phases**, verify job status transitions stay correct in both `orchestrator.py` and `tasks/tasks.py`.

---

## 7. Known Issues

1. **Session directory typo**: `session-managemenet-testing/` (double 'e') — matches docker-compose.yml exactly, do not rename.
2. **Auto-login flow changed (2026-03-29)**: Credentials are now injected via `POST /api/scans` body → stored in `SharedContext["scan_credentials"]` → read by orchestrator Phase 1.5. `DEFAULT_CREDENTIALS` in `session_service.py` is a generic fallback wordlist (no longer Juice-Shop-specific). If auto-login fails, verify credentials in request body and that the target container is reachable.
3. **Thinking models incompatible**: Qwen 3-4B-thinking outputs `<think>` tags that break `json_schema` enforcement. Use non-thinking Qwen 3-4B only.
4. **`_orchestrator_had_plan` regression risk**: Must be `True` only when `tool_plan` is actually populated. Fixed 2026-03-18 — see `orchestrator.py` comments.
5. **`test_new_architecture.py` baseline failures**: 8 tests require a live DB/Docker environment — expected to fail without containers. Infrastructure tests are in `test_vdp_generalization.py` (15 tests, no DB needed).
6. **Director Mode DB migration applied (2026-04-01)**: `skip_current` added to `checkpointaction` enum (note: PostgreSQL names it without underscore), `checkpoint_type`/`directive`/`planned_tools` added to `agent_checkpoints`, `is_high_risk_review` added to `tool_approvals`. If rebuilding from scratch: SQL is in `hitl_models.py` comment block — use `ALTER TYPE checkpointaction` (not `checkpoint_action`).

---

## 8. Security Rules

- Never commit `.env` — use `.env.example` as the template.
- New scan targets must be whitelisted: pass `whitelist_domain` in the POST body, or add via admin API with `ADMIN_TOKEN`.
- `ADMIN_TOKEN` must be set in env — whitelist management API is disabled if unset (logs warning at startup).
- Container names in `/api/logs/recent/{container_name}` are validated against a `KNOWN_CONTAINERS` allowlist (injection prevention).
- All tool executions are audit-logged in `JobAgent` database records.

---

## 9. Evaluation Metrics

Thesis validation targets (`multi_agent_system/evaluation/metrics.py`):
- Precision ≥ 90%, Recall ≥ 80%, F1-Score ≥ 85%
- TCR ≥ 70% of WSTG test cases

### Latest Results — Job #2 (2026-03-26, OWASP Juice Shop)

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Precision | 100% | ≥ 90% | PASS |
| Recall | 98.2% (56/57) | ≥ 80% | PASS |
| F1-Score | 99.1% | ≥ 85% | PASS |
| TCR | 100% (96/96 WSTG) | ≥ 70% | PASS |
| OWASP Top 10 | 90% (9/10) | ≥ 80% | PASS |
| Scan Time | 1h 5m | ≤ 4h | PASS |
| Agents | 14/14, 0 failures | | PASS |
| Findings | 102 (23 critical, 36 high, 29 medium) | | |

Missed: SSRF (no tool implemented). Full report: `multi_agent_system/evaluation/EVALUATION_REPORT_JOB2.md`

---

## 10. Key Reference Files

| What | Where |
|------|-------|
| Orchestrator phases + HITL flow | `docs/execution-flow-hitl-v2.md` |
| Director Mode design spec | `docs/superpowers/specs/2026-03-31-hitl-director-design.md` |
| Source code audit report (thesis) | `docs/audit/source_code_audit_report.md` |
| VDP expansion design spec | `docs/superpowers/specs/2026-03-29-vdp-expansion-design.md` |
| Evaluation report | `multi_agent_system/evaluation/EVALUATION_REPORT_JOB2.md` |
| DB models | `multi_agent_system/models/models.py`, `hitl_models.py` |
| Config env vars | `multi_agent_system/core/config.py` |
| HIGH_RISK_TOOLS frozenset | `multi_agent_system/core/config.py` (after `settings = Settings()`) |
| Directive command parser | `multi_agent_system/utils/directive_parser.py` |
| Enrichment KB + service | `multi_agent_system/data/enrichment_kb.json`, `utils/enrichment_service.py` |
| PDF report Jinja2 template | `multi_agent_system/templates/report.html.j2` |
| Pre-HITL-v2 backups | `backups/hitl-v1/` |
