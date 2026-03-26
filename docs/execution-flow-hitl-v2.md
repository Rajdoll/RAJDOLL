# RAJDOLL Execution Flow — Planner-Summarizer Sequential with Agent-Level HITL

## Overview

This document describes the complete execution flow of RAJDOLL's multi-agent penetration testing system, including the **Agent-Level HITL (Human-in-the-Loop) Checkpoint** system introduced in HITL v2.

---

## High-Level Flow

```
                    ┌─────────────────────────┐
                    │   POST /api/scans        │
                    │   { target, hitl_mode }   │
                    └────────────┬──────────────┘
                                 │
                    ┌────────────▼──────────────┐
                    │  Security Guard            │
                    │  validate_target()          │
                    │  + audit_logger             │
                    └────────────┬──────────────┘
                                 │
                    ┌────────────▼──────────────┐
                    │  Create Job in PostgreSQL   │
                    │  status: queued             │
                    │  plan: { sequence, options } │
                    └────────────┬──────────────┘
                                 │
                    ┌────────────▼──────────────┐
                    │  Pre-create JobAgent rows   │
                    │  (14 agents, all pending)   │
                    └────────────┬──────────────┘
                                 │
                    ┌────────────▼──────────────┐
                    │  Celery: run_job_task()     │
                    │  → Orchestrator(job_id)     │
                    │     .run()                  │
                    └────────────┬──────────────┘
                                 │
                                 ▼
                    ╔═════════════════════════════╗
                    ║   ORCHESTRATOR PHASES       ║
                    ╚════════════╤════════════════╝
                                 │
              ┌──────────────────▼──────────────────┐
              │            PHASE 1                   │
              │     ReconnaissanceAgent               │
              │  Discover endpoints, tech stack,      │
              │  JS routes, crawl with Katana          │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │          PHASE 1.5                   │
              │     Auto-Login Session                │
              │  create_authenticated_session()       │
              │  → JWT token + cookies saved to       │
              │    SharedContext["authenticated_session"] │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │           PHASE 2                    │
              │     LLM Strategic Planning            │
              │  LLMPlanner.plan_testing_strategy()   │
              │  → High-level strategy for all agents │
              │  (5-min timeout, skip if disabled)    │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │           PHASE 3                    │
              │  Sequential Agent Execution Loop      │
              │  (13 agents after Recon)              │
              │  ┌────────────────────────────────┐  │
              │  │  See detailed flow below ──────┼──┼──► AGENT LOOP
              │  └────────────────────────────────┘  │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │         PHASE 4                      │
              │  Final Cross-Agent Analysis           │
              │  analyze_all_findings() via LLM       │
              │  → Correlate findings across agents   │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │         PHASE 5                      │
              │  ReportGenerationAgent (best-effort)  │
              │  Ensures report runs even if circuit  │
              │  breaker triggered early exit          │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │      Final Status Determination       │
              │  Report OK → job.status = completed   │
              │  Report fail → job.status = failed    │
              └───────────────────────────────────────┘
```

---

## Phase 3: Detailed Agent Execution Loop (with HITL Checkpoints)

This is the core loop where all 13 agents (after Recon) execute sequentially.

```
╔════════════════════════════════════════════════════════════════════╗
║                  PHASE 3: AGENT LOOP                              ║
║                  for idx, agent in enumerate(plan):               ║
╚══════════════════════════╤═════════════════════════════════════════╝
                           │
           ┌───────────────▼───────────────┐
           │    Job cancelled?              │──── Yes ──→ BREAK (exit loop)
           └───────────────┬───────────────┘
                           │ No
           ┌───────────────▼───────────────┐
           │    Circuit breaker triggered?  │──── Yes ──→ BREAK (jump to Phase 4)
           │    (≥5 consecutive failures)   │
           └───────────────┬───────────────┘
                           │ No
           ┌───────────────▼───────────────┐
           │    Agent in skip_agents_set?   │──── Yes ──→ Mark SKIPPED, CONTINUE
           │    (user skipped via HITL)     │
           └───────────────┬───────────────┘
                           │ No
           ┌───────────────▼───────────────┐
           │    Get LLM tool plan for agent │
           │    _get_tool_plan_for_agent()  │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │      _run_step_sync()          │
           │      ┌─────────────────────┐   │
           │      │ _run_agent_sync()   │   │
           │      │  (see next section) │   │
           │      └─────────────────────┘   │
           └───────────────┬───────────────┘
                           │
                           ▼
        ╔══════════════════════════════════════╗
        ║  HITL CHECKPOINT DECISION GATE       ║
        ║                                      ║
        ║  Skip checkpoint if ANY:             ║
        ║  • agent_hitl_auto == True           ║
        ║  • agent == ReportGenerationAgent    ║
        ║  • hitl_mode != "agent"              ║
        ╚═════════════╤════════════════════════╝
                      │
              ┌───────▼───────┐
              │ hitl_mode ==  │
              │  "agent"?     │
              └───┬───────┬───┘
               No │       │ Yes
                  │       │
                  │       ▼
                  │  ┌──────────────────────────────┐
                  │  │  _gather_agent_checkpoint_    │
                  │  │  data()                       │
                  │  │  • Query Finding table        │
                  │  │  • Count by severity          │
                  │  │  • Top 10 critical/high       │
                  │  └──────────────┬───────────────┘
                  │                 │
                  │  ┌──────────────▼───────────────┐
                  │  │  _generate_checkpoint_        │
                  │  │  recommendations()            │
                  │  │  • Next agent suggestion      │
                  │  │  • Priority recommendations   │
                  │  │    based on finding patterns   │
                  │  └──────────────┬───────────────┘
                  │                 │
                  │  ┌──────────────▼───────────────┐
                  │  │  HITLManager.request_agent_   │
                  │  │  checkpoint()                  │
                  │  │  1. Create AgentCheckpoint     │
                  │  │     record in DB               │
                  │  │  2. Set job.status =           │
                  │  │     "waiting_checkpoint"       │
                  │  │  3. Poll DB every 2s           │
                  │  │     (max 1 hour timeout)       │
                  │  │  4. Restore job.status =       │
                  │  │     "running"                  │
                  │  └──────────────┬───────────────┘
                  │                 │
                  │        ┌───────▼────────┐
                  │        │  WAITING FOR    │ ◄─── WebSocket pushes
                  │        │  USER RESPONSE  │      "agent_checkpoint"
                  │        │  (Frontend UI)  │      event to browser
                  │        └───────┬────────┘
                  │                │
                  │      ┌─────────▼─────────┐
                  │      │   User Action      │
                  │      └──┬──┬──┬──┬──┬────┘
                  │         │  │  │  │  │
                  │  ┌──────┘  │  │  │  └──────────┐
                  │  │         │  │  │              │
                  │  ▼         ▼  │  ▼              ▼
                  │ PROCEED  AUTO │ SKIP_NEXT     ABORT
                  │  │       │    │  │              │
                  │  │  Set auto  │  Add next      BREAK
                  │  │  = True    │  agent to      (exit loop)
                  │  │  (no more  │  skip_set
                  │  │  checkpts) │
                  │  │            │
                  │  │            ▼
                  │  │          REORDER
                  │  │            │
                  │  │     Move override agent
                  │  │     to front of remaining
                  │  │     plan[idx+1:]
                  │  │            │
                  │  │            │
                  │  └────┬───────┘
                  │       │
                  └───────┤
                          │
                          ▼
                ┌─────────────────┐
                │ Next iteration   │──→ (back to top of loop)
                └─────────────────┘
```

---

## _run_agent_sync(): Single Agent Execution Detail

```
┌─────────────────────────────────────────────────────────────────┐
│                    _run_agent_sync(agent_name)                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Lookup agent class from     │
              │  AgentRegistry               │
              │  agent = AgentCls(job_id)    │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Inject tool plan?           │
              │  if tool_plan:               │
              │    agent.set_tool_plan()     │
              │    _orchestrator_had_plan=T  │
              │  else:                       │
              │    _orchestrator_had_plan=F  │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Update JobAgent → running   │
              │  started_at = now()          │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Refresh SharedContext cache  │
              │  Build context snapshot       │
              │  Inject planner context:      │
              │  • cumulative_summary         │
              │  • task_tree (PTT)            │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  agent.execute(              │
              │    target=url,               │
              │    shared_context=ctx        │
              │  )                           │
              │  [45-min timeout]            │
              │                              │
              │  ┌────────────────────────┐  │
              │  │  Inside execute():     │  │
              │  │  1. LLM tool selection │  │
              │  │     (if needed)        │  │
              │  │  2. For each tool:     │  │
              │  │     → should_run_tool()│  │
              │  │     → _before_tool()   │  │
              │  │     → MCP call_tool()  │  │
              │  │     → save Finding     │  │
              │  └────────────────────────┘  │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Update JobAgent             │
              │  → completed | failed        │
              │  finished_at = now()         │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Refresh SharedContext cache  │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Planner-Summarizer:         │
              │  _summarize_agent_and_       │
              │  accumulate(agent_name)      │
              │                              │
              │  LLM summarizes this agent's │
              │  findings → appended to      │
              │  cumulative_summary          │
              │  (skip for ReportGenAgent)   │
              └──────────────────────────────┘
```

---

## Agent Tool Execution Detail (BaseAgent.execute_tool)

```
┌────────────────────────────────────────────────────────────┐
│              execute_tool(server, tool, args)               │
└────────────────────────────┬───────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  should_run_tool(tool)       │
              │  • Circuit breaker check     │
              │  • ADAPTIVE_MODE gating      │
              │  • Tool priority check       │
              └──────────┬──────────┬───────┘
                    Pass │          │ Fail → SKIP
                         │
              ┌──────────▼──────────────────┐
              │  _before_tool_execution()    │
              │  • _merge_planned_arguments()│
              │    (LLM args + base args)    │
              │  • _auto_generate_test_args()│
              │    (fallback if LLM empty)   │
              │  • HITL tool approval        │
              │    (if hitl_mode == "tool")  │
              └──────────┬──────────────────┘
                         │
              ┌──────────▼──────────────────┐
              │  Auth injection              │
              │  Extract auth session from   │
              │  shared_context, inject into │
              │  tool arguments              │
              └──────────┬──────────────────┘
                         │
              ┌──────────▼──────────────────┐
              │  _normalize_llm_arguments()  │
              │  Map 'target_url' → 'url'    │
              │  Map 'target' → 'url'        │
              │  etc.                        │
              └──────────┬──────────────────┘
                         │
              ┌──────────▼──────────────────┐
              │  MCPClient.call_tool()       │
              │  JSON-RPC to MCP container   │
              │  [10-min timeout]            │
              └──────────┬──────────────────┘
                         │
              ┌──────────▼──────────────────┐
              │  Process result → Finding    │
              │  Save to PostgreSQL          │
              └─────────────────────────────┘
```

---

## HITL Checkpoint: Frontend ↔ Backend Communication

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Orchestrator    │     │   PostgreSQL      │     │    Frontend      │
│   (Celery worker) │     │                  │     │    (Browser)     │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                         │
         │  1. INSERT              │                         │
         │  AgentCheckpoint        │                         │
         │  action="pending"       │                         │
         ├───────────────────────►│                         │
         │                        │                         │
         │  2. UPDATE Job          │                         │
         │  status=                │                         │
         │  "waiting_checkpoint"   │                         │
         ├───────────────────────►│                         │
         │                        │                         │
         │  3. Poll every 2s       │     WebSocket loop      │
         │  SELECT checkpoint      │     polls every 500ms   │
         │  WHERE action=pending   │◄────────────────────────┤
         │      ...                │                         │
         │      ...                │  4. Push event:         │
         │      ...                │  {"type":               │
         │      ...                │   "agent_checkpoint",   │
         │      ...                │   data: {...}}          │
         │      ...                ├────────────────────────►│
         │      ...                │                         │
         │      ...                │                    ┌────▼────────────┐
         │      ...                │                    │ Show checkpoint │
         │      ...                │                    │ panel:          │
         │      ...                │                    │ • Agent name    │
         │      ...                │                    │ • Severity grid │
         │      ...                │                    │ • Key findings  │
         │      ...                │                    │ • Summary       │
         │      ...                │                    │ • Recommendations│
         │      ...                │                    │ • Action buttons│
         │      ...                │                    └────┬────────────┘
         │      ...                │                         │
         │      ...                │  5. POST /api/hitl/     │
         │      ...                │  agent-checkpoint/      │
         │      ...                │  {id}/respond           │
         │      ...                │  {action: "proceed"}    │
         │      ...                │◄────────────────────────┤
         │      ...                │                         │
         │  6. SELECT checkpoint   │                         │
         │  action != pending      │                         │
         │  → Return result        │                         │
         │◄────────────────────────┤                         │
         │                        │                         │
         │  7. UPDATE Job          │                         │
         │  status="running"       │                         │
         ├───────────────────────►│                         │
         │                        │                         │
         │  8. Process user action │                         │
         │  (proceed/skip/abort/   │                         │
         │   reorder/auto)         │                         │
         │                        │                         │
         │  9. Continue to next    │                         │
         │  agent in loop...       │                         │
         ▼                        ▼                         ▼
```

---

## HITL Mode Comparison

| Feature | `hitl_mode: "off"` | `hitl_mode: "agent"` | `hitl_mode: "tool"` |
|---|---|---|---|
| Execution | Fully automated | Pause after each agent | Pause before each tool |
| Checkpoint | None | AgentCheckpoint in DB | Tool approval in DB |
| User sees | Final report only | Summary + findings after each agent | Individual tool args before execution |
| Granularity | - | 13 decision points (per agent) | 50-100+ decision points (per tool) |
| Use case | Production/batch scans | Thesis evaluation, learning | Deep inspection, sensitive targets |
| Config | `HITL_MODE=off` | `HITL_MODE=agent` | `HITL_MODE=tool` |

---

## User Actions at Agent Checkpoint

| Action | Effect | Use Case |
|---|---|---|
| **Proceed** | Continue to next agent normally | Default — findings look good |
| **Skip Next** | Skip the next agent in sequence | Agent N+1 is irrelevant given findings |
| **Reorder** | Move a specific agent to run next | Prioritize based on current findings |
| **Auto-Proceed** | Disable all future checkpoints | Seen enough, let it finish automatically |
| **Abort** | Stop the scan entirely | Critical issue found, or target is down |

---

## Complete Execution Timeline (Example: Juice Shop Scan)

```
t=0s     POST /api/scans {target: "http://juice-shop:3000", hitl_mode: "agent"}
         → Job #1 created, status: queued
         → Celery task dispatched

t=5s     Phase 1: ReconnaissanceAgent starts
         → Katana crawl, JS route analysis, tech fingerprinting
t=180s   ReconnaissanceAgent completes (52 endpoints, Node.js/Express/Angular)
         → LLM summarizes recon findings
         ┌─────────────────────────────────────────┐
         │  🛑 CHECKPOINT #1                       │
         │  Agent: ReconnaissanceAgent              │
         │  Findings: 5 (2 info, 3 low)            │
         │  Next: AuthenticationAgent               │
         │  Recommendation: Proceed (default order) │
         │  [Proceed] [Skip] [Reorder] [Auto] [Abort]│
         └─────────────────────────────────────────┘
         → User clicks [Proceed]

t=185s   Phase 3: AuthenticationAgent starts
         → test_login_form, test_brute_force, test_2fa_bypass, test_sqli_login
t=420s   AuthenticationAgent completes
         → LLM summarizes: "SQL injection in login, 2FA bypass possible"
         ┌─────────────────────────────────────────┐
         │  🛑 CHECKPOINT #2                       │
         │  Agent: AuthenticationAgent              │
         │  Findings: 8 (2 critical, 3 high, 3 med)│
         │  Key: SQLi login bypass (admin), 2FA skip│
         │  Next: SessionManagementAgent            │
         │  Rec: ⚠ Injection found → InputValidation│
         │       should run soon (high priority)    │
         │  [Proceed] [Skip] [Reorder▼] [Auto] [Abort]│
         └─────────────────────────────────────────┘
         → User clicks [Reorder] → selects InputValidationAgent

t=425s   InputValidationAgent starts (reordered to run next)
         → test_sqli, test_xss, test_nosql_injection, test_ssti, ...
         ...

t=4h     Phase 5: ReportGenerationAgent (no checkpoint, always runs)
         → Final OWASP WSTG 4.2 report generated
         → Job status: completed
```

---

## File Reference

| Component | File | Key Function/Class |
|---|---|---|
| Orchestrator main loop | `multi_agent_system/orchestrator.py` | `Orchestrator.run()` |
| Agent execution | `multi_agent_system/orchestrator.py` | `_run_agent_sync()` |
| Checkpoint insertion | `multi_agent_system/orchestrator.py` | Phase 3 loop (line 846-907) |
| Checkpoint data gathering | `multi_agent_system/orchestrator.py` | `_gather_agent_checkpoint_data()` |
| Checkpoint recommendations | `multi_agent_system/orchestrator.py` | `_generate_checkpoint_recommendations()` |
| HITL checkpoint request | `multi_agent_system/utils/hitl_manager.py` | `request_agent_checkpoint()` |
| HITL checkpoint polling | `multi_agent_system/utils/hitl_manager.py` | `_wait_for_agent_checkpoint()` |
| Checkpoint DB model | `multi_agent_system/models/hitl_models.py` | `AgentCheckpoint` |
| Checkpoint API endpoints | `api/routes/hitl.py` | `GET/POST /api/hitl/agent-checkpoint/...` |
| WebSocket push | `api/routes/websocket.py` | `agent_checkpoint` event type |
| Frontend UI | `frontend/js/app.js` | `showAgentCheckpoint()`, `respondToCheckpoint()` |
| Frontend styles | `frontend/css/styles.css` | `.checkpoint-panel` |
| Config | `multi_agent_system/core/config.py` | `Settings.hitl_mode` |
| Per-scan override | `api/schemas/schemas.py` | `CreateScanRequest.hitl_mode` |
