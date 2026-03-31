# HITL Director Mode — Design Spec
**Date:** 2026-03-31  
**Author:** Martua Raja Doli Pangaribuan  
**Status:** Approved for implementation

---

## 1. Overview

HITL Director Mode extends the existing HITL v2 agent-level checkpoint system with two new capabilities:

1. **PRE-AGENT checkpoint** — Human reviews what an agent is *about to do* and can inject structured directives into the agent's LLM context before it executes.
2. **HIGH_RISK tool argument editing** — For the five most dangerous tools (SQLMap, Dalfox, Nikto, Nmap, testssl), human can view and edit LLM-generated arguments before execution.

**Purpose:** Thesis demonstration of human-directed AI penetration testing. The human acts as a "Director" who steers the scan strategically, not just reviewing results after the fact.

**Activation:** Only when `hitl_mode == "agent"`. No changes to `hitl_mode == "tool"` or `hitl_mode == "off"`.

---

## 2. Architecture

### 2.1 Checkpoint Flow

```
Current HITL v2:
  [Agent runs] → [POST checkpoint: findings review] → [proceed/skip/abort]

Director (new):
  [PRE checkpoint: plan review + directive] → [Agent runs] → [POST checkpoint: unchanged]
                                                     ↑
                                        [HIGH_RISK tool pause: arg edit]
                                        (SQLMap, Dalfox, Nikto, Nmap, testssl)
```

### 2.2 Three Interaction Points

| Point | When | User sees | User can do |
|-------|------|-----------|-------------|
| PRE-AGENT | Before agent starts | Tool plan + cumulative context | Approve / Inject directive / Skip agent / Abort |
| HIGH_RISK tool | Mid-agent, before dangerous tool call | Generated tool arguments | Approve as-is / Edit args / Skip this tool |
| POST-AGENT | After agent finishes | Findings by severity | Proceed / Auto / Skip next / Abort (unchanged) |

### 2.3 Directive Injection Path

```
PRE checkpoint user input
  → parsed directive commands
  → SharedContext["director_directive_{agent_name}"]
  → _inject_planner_context() appends [DIRECTOR INSTRUCTIONS] block to LLM prompt
  → SKIP commands additionally feed should_run_tool() skip set
```

---

## 3. Directive Command Language

Directives use a structured command grammar, validated on both frontend and backend. Free-form text is **not** accepted to prevent ambiguous LLM injection.

### 3.1 Command Reference

| Command | Syntax | Effect |
|---------|--------|--------|
| `FOCUS` | `FOCUS: <path_or_keyword>` | Narrows agent to specific endpoint/pattern |
| `SKIP` | `SKIP: <tool_name>` | Excludes a tool (must match planned tool list) |
| `INCLUDE` | `INCLUDE: <url>` | Adds a specific URL to agent's target scope |
| `EXCLUDE` | `EXCLUDE: <pattern>` | Excludes URL pattern from scope |
| `DEPTH` | `DEPTH: shallow\|normal\|deep` | Sets scan intensity |
| `NOTE` | `NOTE: <free text>` | Injects contextual note into LLM prompt (no action taken) |

### 3.2 Validation Rules

- Command must start with a recognized keyword (case-insensitive)
- `SKIP` value must match a tool name in the agent's planned tool list — frontend shows autocomplete
- `DEPTH` value must be exactly `shallow`, `normal`, or `deep`
- Max 5 commands per directive submission
- Max 200 characters per command line
- Invalid lines highlighted red; submit button disabled until all lines valid

### 3.3 LLM Injection Format

Parsed commands are formatted and appended to the agent's LLM planning context:

```
[DIRECTOR INSTRUCTIONS]
- Focus testing on: /api/admin
- Skip tool: run_sqlmap
- Scan intensity: shallow
- Include target: http://juice-shop:3000/rest/admin/application-configuration
- Note: Admin panel confirmed at /administration — check for unprotected endpoints
```

---

## 4. Data Model

### 4.1 Extended `AgentCheckpoint`

Two new nullable columns added to the existing table (backward compatible):

```python
checkpoint_type: Enum("pre_agent", "post_agent")  # default "post_agent"
directive: Text (nullable)                          # raw user input (stored for audit)
planned_tools: JSON (nullable)                      # tool list shown at PRE checkpoint
```

Migration: `ALTER TABLE agent_checkpoints ADD COLUMN checkpoint_type VARCHAR DEFAULT 'post_agent'; ...`

### 4.2 SharedContext Keys

Written by orchestrator after each PRE-AGENT checkpoint resolves (one key per agent):

```python
# Per-agent keys — written just before that agent executes
SharedContext["director_directive_InputValidationAgent"] = [
    {"cmd": "FOCUS", "value": "/api/admin"},
    {"cmd": "SKIP", "value": "run_sqlmap"},
    {"cmd": "DEPTH", "value": "shallow"},
    {"cmd": "NOTE", "value": "Admin panel at /administration"},
]
SharedContext["director_directive_AuthorizationAgent"] = [
    {"cmd": "INCLUDE", "value": "http://juice-shop:3000/api/Users/1"},
]
```

Key pattern: `"director_directive_{agent_name}"`. Read in `_inject_planner_context()` and `should_run_tool()` using `self.agent_name`.

### 4.3 HIGH_RISK Tool Approvals

No new table. Uses existing `ToolApproval` model from HITL v2. New: HIGH_RISK tool pauses fire even when `hitl_mode == "agent"` (previously only `"tool"`).

`HIGH_RISK_TOOLS` constant (new, in `core/config.py`):

```python
HIGH_RISK_TOOLS: frozenset[str] = frozenset({
    "run_sqlmap",
    "test_xss_dalfox",
    "run_nikto",
    "run_nmap",
    "test_tls_configuration",
})
```

---

## 5. Frontend UI

### 5.1 PRE-AGENT Panel

Triggered by new `"pre_agent_checkpoint"` WebSocket event. Appears before POST-AGENT panel style.

```
┌─────────────────────────────────────────────────────────────────┐
│  🎯 NEXT: InputValidationAgent  [WSTG-INPV]                     │
├─────────────────────────────────────────────────────────────────┤
│  Planned tools (7):                                             │
│  ⚠ run_sqlmap          [HIGH_RISK] — SQL injection              │
│  ⚠ test_xss_dalfox     [HIGH_RISK] — XSS testing               │
│    test_lfi            — Local file inclusion                   │
│    test_ssti           — Template injection                     │
│    test_nosql_injection — NoSQL injection                       │
│    test_hpp            — HTTP parameter pollution               │
│    test_redos          — ReDoS testing                          │
├─────────────────────────────────────────────────────────────────┤
│  Context: 12 findings so far (3 critical, 5 high)               │
│  Prior: AuthAgent found JWT none-bypass on /rest/user/login     │
├─────────────────────────────────────────────────────────────────┤
│  Director instruction (optional):                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ FOCUS: /api/admin                                ✅     │   │
│  │ SKIP: run_sqlmap                                 ✅     │   │
│  │ DEPTH: shallow                                   ✅     │   │
│  └─────────────────────────────────────────────────────────┘   │
│  Commands: FOCUS | SKIP | INCLUDE | EXCLUDE | DEPTH | NOTE [?] │
├─────────────────────────────────────────────────────────────────┤
│  [Approve]  [Approve with directive]  [Skip Agent]  [Abort]     │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 HIGH_RISK Tool Panel

Triggered by `"high_risk_tool_approval"` WebSocket event. Replaces waiting spinner mid-agent.

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚠ HIGH_RISK TOOL: run_sqlmap                                   │
│  Agent: InputValidationAgent                                    │
├─────────────────────────────────────────────────────────────────┤
│  Generated arguments:                                           │
│  {                                                              │
│    "url": "http://juice-shop:3000/rest/user/login",             │
│    "level": 3,                                                  │
│    "risk": 2,                                                   │
│    "technique": "BEUSTQ"                                        │
│  }                                                              │
├─────────────────────────────────────────────────────────────────┤
│  [Run as-is]    [Edit & Run]    [Skip this tool]                │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 POST-AGENT Panel Enhancement

Unchanged behavior. If a directive was active for this agent, shows it greyed out at the bottom:
> *Directive applied: "FOCUS: /api/admin | SKIP: run_sqlmap | DEPTH: shallow"*

### 5.4 New WebSocket Events

| Event | Direction | Payload |
|-------|-----------|---------|
| `pre_agent_checkpoint` | Server → Client | `{checkpoint_id, agent_name, wstg_category, planned_tools, context_summary}` |
| `high_risk_tool_approval` | Server → Client | `{approval_id, tool_name, agent_name, generated_args}` |

### 5.5 New REST Endpoints

| Method | Path | Body | Purpose |
|--------|------|------|---------|
| `POST` | `/api/scans/{job_id}/checkpoints/{checkpoint_id}/directive` | `{action, commands[]}` | Submit PRE-AGENT response |
| `POST` | `/api/scans/{job_id}/tool-approvals/{approval_id}/args` | `{action, args{}}` | Submit HIGH_RISK tool args |

---

## 6. Implementation Touchpoints

| File | Change |
|------|--------|
| `multi_agent_system/models/hitl_models.py` | Add `checkpoint_type`, `directive`, `planned_tools` columns to `AgentCheckpoint` |
| `multi_agent_system/core/config.py` | Add `HIGH_RISK_TOOLS` frozenset |
| `multi_agent_system/orchestrator.py` | Add `_run_pre_agent_checkpoint()` method; call before `_run_step_sync()` |
| `multi_agent_system/agents/base_agent.py` | Read directive from SharedContext in `_inject_planner_context()`; check SKIP in `should_run_tool()`; call `request_tool_arg_review()` in `_before_tool_execution()` |
| `multi_agent_system/utils/hitl_manager.py` | Add `request_pre_agent_checkpoint()` and `request_tool_arg_review()` methods |
| `api/routes/hitl.py` | Add two new endpoints for directive and arg submission |
| `api/websocket.py` | Add `pre_agent_checkpoint` and `high_risk_tool_approval` event types |
| `frontend/index.html` / `frontend/app.js` | PRE-AGENT panel, command validator, HIGH_RISK tool panel |
| `alembic/versions/` | Migration for new `AgentCheckpoint` columns |

---

## 7. Error Handling

- **PRE-AGENT timeout** (user doesn't respond): Default to **Approve with no directive** after 1 hour (same as existing POST-AGENT timeout).
- **Invalid command in directive**: Backend rejects with `400 Bad Request`; frontend prevents submission of invalid lines.
- **HIGH_RISK tool timeout**: Default to **Run as-is** after 10 minutes (operator likely stepped away).
- **SKIP refers to non-planned tool**: Accepted with a warning injected into the LLM note — tool may not run anyway.

---

## 8. Out of Scope

- No LLM validation of directive content (frontend + backend grammar rules are sufficient for thesis scope)
- No directive history/replay across scans
- No directive templates/presets
- `hitl_mode == "tool"` behavior is unchanged (no PRE-AGENT panel in tool mode)
