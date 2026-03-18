# RAJDOLL - Project Context Guide

## Project Overview

**RAJDOLL** (Reconnaissance And Dynamic Offensive LLM-based) is an advanced **multi-agent penetration testing system** that automates comprehensive web application security assessments based on the **OWASP Web Security Testing Guide (WSTG) 4.2**.

### Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR                         │
│  - Job Planning & Coordination                          │
│  - LLM Strategic Planning (optional)                    │
│  - Shared Context Management                            │
└────────────────┬────────────────────────────────────────┘
                 │
        ┌────────┴──────────┐
        │                   │
┌───────▼──────┐    ┌──────▼───────────────────────────┐
│ Recon Agent  │    │  13 Specialized Test Agents      │
│ (Entry Point)│    │  (OWASP WSTG Categories 1-13)    │
└──────────────┘    └──────┬───────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     ┌────────▼─────────┐    ┌─────────▼────────┐
     │  MCP Client      │    │  Report Agent    │
     │  (15 Tools)      │    │  (Analysis+Docs) │
     └──────────────────┘    └──────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| **14 Specialized Agents** | Each agent is an expert in one OWASP WSTG category |
| **LLM-Powered Planning** | Claude/GPT-4/Qwen generates adaptive test strategies |
| **MCP Integration** | Unified protocol for 15+ security tools (SQLMap, Dalfox, etc.) |
| **Planner-Summarizer** | Cumulative context passing between sequential agents |
| **Knowledge Graph** | Entity-relationship tracking for vulnerabilities |
| **Confidence Scoring** | Evidence-based confidence calculation for findings |
| **HITL Support** | Human-in-the-Loop confirmation for aggressive tests |

---

## Technology Stack

### Backend
- **Framework:** FastAPI 0.115.5
- **Language:** Python 3.11+
- **Task Queue:** Celery 5.4.0 + Redis
- **Database:** PostgreSQL 16 (SQLAlchemy 2.0 ORM)
- **LLM Integration:** OpenAI/Anthropic-compatible APIs (via `SimpleLLMClient`)

### MCP Tool Servers
- **Protocol:** Model Context Protocol (MCP) 1.1.2
- **Transport:** JSON-RPC over HTTP
- **15 MCP Servers:** One per OWASP testing category (ports 9001-9015)

### Frontend
- React dashboard (see `frontend/` directory)

---

## Project Structure

```
RAJDOLL/
├── api/                          # FastAPI REST API
│   ├── main.py                   # Application entry point
│   └── routes/                   # API route handlers
│       ├── scans.py              # Scan management endpoints
│       ├── reporting.py          # Report generation
│       ├── results.py            # Finding retrieval
│       ├── websocket.py          # Real-time updates
│       ├── hitl.py               # HITL intervention
│       └── evaluation.py         # Metrics endpoints
├── multi_agent_system/           # Core agent system
│   ├── orchestrator.py           # Sequential agent coordination
│   ├── hierarchical_orchestrator.py  # Alternative orchestration
│   ├── agents/                   # 14 specialized agents
│   │   ├── base_agent.py         # Base class with LLM/MCP integration
│   │   ├── reconnaissance_agent.py
│   │   ├── authentication_agent.py
│   │   ├── input_validation_agent.py
│   │   └── ... (11 more)
│   ├── core/
│   │   ├── config.py             # Settings management
│   │   ├── db.py                 # Database connection
│   │   └── task_tree.py          # Task tracking structure
│   ├── models/
│   │   └── models.py             # SQLAlchemy ORM models
│   ├── utils/
│   │   ├── mcp_client.py         # MCP tool invocation
│   │   ├── simple_llm_client.py  # LLM API wrapper
│   │   ├── shared_context_manager.py  # Inter-agent context
│   │   ├── hitl_manager.py       # Human-in-the-loop
│   │   ├── knowledge_graph.py    # Entity-relationship graph
│   │   ├── confidence_scorer.py  # Evidence-based scoring
│   │   └── llm_planner.py        # Strategic planning
│   └── tasks/                    # Celery task definitions
├── mcp_adapter/
│   └── server.py                 # MCP server wrapper
├── *-testing/                    # 15 MCP tool implementations
│   ├── information-gathering/
│   ├── authentication-testing/
│   ├── input-validation-testing/
│   └── ... (12 more)
├── katana-crawler/               # Web crawler MCP server
├── frontend/                     # React dashboard
├── docker-compose.yml            # Multi-service orchestration
├── Dockerfile                    # Main application image
├── Dockerfile.mcp-tools          # MCP server image
└── requirements.txt              # Python dependencies
```

---

## Agent System

### 14 Specialized Agents (Sequential Execution)

| Order | Agent | OWASP Category | Tools | Description |
|-------|-------|----------------|-------|-------------|
| 1 | ReconnaissanceAgent | WSTG-INFO | 10+ | Discover endpoints, tech stack, JS route analysis |
| 2 | AuthenticationAgent | WSTG-ATHN | 12 | Auth mechanisms, 2FA bypass, JWT analysis |
| 3 | SessionManagementAgent | WSTG-SESS | 7 | Session/token handling |
| 4 | InputValidationAgent | WSTG-INPV | 24+ | SQLi, XSS, LFI, SSTI, NoSQL, HPP, ReDoS, login SQLi |
| 5 | AuthorizationAgent | WSTG-AUTHZ | 6 | Privilege escalation, IDOR, user spoofing |
| 6 | ConfigDeploymentAgent | WSTG-CONF | 16 | Misconfigs, headers, hidden endpoints, npm vulns |
| 7 | ClientSideAgent | WSTG-CLNT | 17 | DOM XSS, CORS, clickjacking, CSP bypass, open redirect |
| 8 | FileUploadAgent | WSTG-BUSL | 5+ | File upload vulns, null byte bypass |
| 9 | APITestingAgent | WSTG-APIT | 7 | API-specific issues |
| 10 | ErrorHandlingAgent | WSTG-ERRH | 5 | Error disclosure, stack traces |
| 11 | WeakCryptographyAgent | WSTG-CRYP | 5 | Weak TLS, crypto flaws |
| 12 | BusinessLogicAgent | WSTG-BUSL | 15 | Logic bypass, coupon forgery, rate limiting |
| 13 | IdentityManagementAgent | WSTG-IDNT | 8 | User enumeration, registration, mass assignment |
| 14 | ReportGenerationAgent | WSTG-REPORT | 1 | Final OWASP WSTG 4.2 report |

### Agent Execution Flow

1. **Orchestrator** initializes job and writes target URL to shared context
2. **ReconnaissanceAgent** runs first, discovers endpoints/tech stack
3. After each agent completes:
   - LLM **summarizes** findings
   - Summary appended to `cumulative_summary`
   - Task tree updated
4. Next agent receives **cumulative context** (summary + task tree)
5. Process repeats until all agents complete
6. **ReportGenerationAgent** produces final OWASP-compliant report

### Base Agent Features

```python
# multi_agent_system/agents/base_agent.py

class BaseAgent:
    # Key capabilities:
    - LLM-based tool selection (adaptive planning)
    - MCP tool execution with arguments
    - Shared context read/write
    - Finding creation with confidence scoring
    - Knowledge graph integration
    - HITL intervention support
    - Circuit breaker for failures
```

---

## Building and Running

### Prerequisites

- **Python:** 3.11+
- **Docker:** 20.10+ & Docker Compose 2.0+
- **API Key:** OpenAI/Anthropic (optional for LLM planning)

### Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your API keys

# 2. Build containers
docker compose build

# 3. Start all services
docker compose up -d

# 4. Check status
docker compose ps

# 5. Access dashboard
# Open http://localhost:8000
```

### Services Started

| Service | Port | Description |
|---------|------|-------------|
| `rajdoll-api` | 8000 | FastAPI backend + frontend |
| `rajdoll-worker` | - | Celery workers for agents |
| `rajdoll-db` | 5432 | PostgreSQL database |
| `rajdoll-redis` | 6379 | Redis cache/broker |
| `*-mcp` (15x) | 9001-9015 | MCP tool servers |

### Starting a Scan

**Via API:**

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Response: {"job_id": 1, "status": "queued"}
```

**Monitor Progress:**

```bash
curl http://localhost:8000/api/scans/1
curl http://localhost:8000/api/scans/1/findings
curl http://localhost:8000/api/scans/1/logs
```

**Generate Report:**

```bash
curl -X POST http://localhost:8000/api/scans/1/report
curl -o report.md http://localhost:8000/api/scans/1/report?format=markdown
```

---

## Key Configuration

### Environment Variables (.env)

```bash
# LLM Configuration
OPENAI_API_KEY=sk-...           # Required for LLM planning
LLM_BASE_URL=http://host.docker.internal:1234/v1  # LM Studio or compatible
LLM_MODEL=qwen2.5-7b-instruct
LLM_PROVIDER=openai

# Adaptive Mode (tool selection strategy)
ADAPTIVE_MODE=aggressive        # off/conservative/balanced/aggressive

# Database (pre-configured in docker-compose.yml)
DATABASE_URL=postgresql+psycopg://rajdoll:rajdoll@db:5432/rajdoll
REDIS_URL=redis://redis:6379/0

# HITL Controls
HITL_ENABLED=true
ENABLE_TOOL_APPROVALS=true
LAB_MODE=false                  # Disables HITL for local testing
```

### Timeout Configuration

```bash
JOB_TOTAL_TIMEOUT=14400         # 4 hours total
AGENT_TIMEOUT=2700              # 45 minutes per agent
TOOL_TIMEOUT=420                # 7 minutes per tool
LLM_PLANNING_TIMEOUT=300        # 5 minutes for LLM planning
```

---

## Development Practices

### Adding a New Agent

1. **Create agent class:**

```python
# multi_agent_system/agents/my_agent.py

from .base_agent import BaseAgent, AgentRegistry

@AgentRegistry.register("MyAgent")
class MyAgent(BaseAgent):
    agent_name = "MyAgent"
    system_prompt = "You are an OWASP WSTG-XXXX expert..."

    async def run(self):
        # Your testing logic here
        tools = self._get_available_tools()
        for tool in tools:
            result = await self.execute_tool(tool)
            if result.get("success"):
                self.add_finding(
                    category="WSTG-XXXX",
                    title="Vulnerability Found",
                    severity="high",
                    evidence=result
                )
```

2. **Register in orchestrator:**

```python
# multi_agent_system/orchestrator.py

DEFAULT_PLAN = [
    "ReconnaissanceAgent",
    "MyAgent",  # Add here
    ...
]

AGENT_TO_OWASP_MAP = {
    "MyAgent": "WSTG-XXXX",
    ...
}
```

3. **Create MCP tool server** (if new tools needed)

### Testing

```bash
# Unit tests
pytest multi_agent_system/tests/

# Integration tests
pytest api/tests/

# Evaluation metrics
python -m multi_agent_system.evaluation.metrics --job-id 1
```

### Code Style

- **Type hints:** Required for all function signatures
- **Docstrings:** Google-style for public APIs
- **Logging:** Use `self.log(level, message, data)` in agents
- **Error handling:** Circuit breaker pattern for failures
- **Async/await:** All I/O operations are async

---

## Database Schema

### Core Tables

| Table | Description |
|-------|-------------|
| `jobs` | Scan jobs (target, status, plan, summary) |
| `job_agents` | Agent execution records (status, timing, errors) |
| `agent_events` | Agent log events (level, message, data) |
| `findings` | Vulnerability findings (severity, evidence, details) |
| `shared_context` | Inter-agent context storage (key-value JSON) |

### Key Models

```python
class Job(Base):
    id, target, status, plan (JSON), summary

class JobAgent(Base):
    id, job_id, agent_name, status, started_at, finished_at, error

class Finding(Base):
    id, job_id, agent_name, category, title, severity, evidence (JSON), details

class ConfidenceLevel(Enum):
    speculative, low, medium, high, confirmed
```

---

## MCP Tool Integration

### Tool Execution Pattern

```python
# Inside agent's run() method

async def run(self):
    tools = self._get_available_tools()  # e.g., ["sqlmap", "dalfox", "ffuf"]

    for tool_name in tools:
        # Get LLM-generated arguments (if any)
        arguments = self._tool_arguments_map.get(tool_name, {})

        # Execute via MCP client
        result = await self.execute_tool(tool_name, arguments)

        # Process result
        if result.get("success"):
            # Add evidence for confidence scoring
            self.add_evidence_from_tool_result(tool_name, result)

            # Create finding
            self.add_finding_with_confidence(
                category="WSTG-INPV-05",
                title="SQL Injection Detected",
                severity="critical",
                evidence=result,
                tool_name=tool_name
            )
```

### Available MCP Tools (by Category)

| Category | Tools |
|----------|-------|
| Information Gathering | subfinder, amass, nmap, whatweb, nikto |
| Authentication | hydra, medusa, custom auth testers |
| Input Validation | sqlmap, dalfox, ffuf, xsstrike |
| ... | ... |

---

## Shared Context System

### Context Keys

| Key | Description | Written By |
|-----|-------------|------------|
| `target` / `target_url` | Target URL | Orchestrator |
| `entry_points` | Discovered endpoints | ReconnaissanceAgent |
| `tech_stack` | Technology detection | ReconnaissanceAgent |
| `authenticated_session` | Login credentials | AuthenticationAgent |
| `cumulative_summary` | Aggregated findings | Orchestrator (LLM) |
| `task_tree` | Testing progress tree | Orchestrator |
| `final_analysis` | Correlation analysis | Orchestrator (LLM) |

### Read/Write Pattern

```python
# Writing context
self.write_context("my_data", {"key": "value"})

# Reading context
data = self.read_context("my_data")
tech_stack = self.shared_context.get("tech_stack", {})
```

---

## LLM Integration

### Planning Modes

| Mode | Description |
|------|-------------|
| **LLM Planning** | LLM selects tools and generates arguments |
| **Static Plan** | Predefined tool execution (DISABLE_LLM_PLANNING=true) |
| **Adaptive Mode** | Priority-based filtering (conservative/balanced/aggressive) |

### LLM Client Usage

```python
# multi_agent_system/utils/simple_llm_client.py

class SimpleLLMClient:
    async def select_tools_for_agent(
        self,
        agent_name: str,
        shared_context: dict,
        available_tools: list[str],
        system_prompt: str = None
    ) -> list[dict]:
        # Returns: [{"tool": "sqlmap", "reason": "...", "arguments": {...}}, ...]
```

### Planner-Summarizer Pattern

```python
# After each agent completes:
summary = await llm.summarize_agent_findings(agent_name, raw_findings, task_tree)
cumulative_summary += f"\n--- {agent_name} ---\n{summary}"
context_manager.write("cumulative_summary", cumulative_summary)
```

---

## Security & Ethics

### Built-in Safeguards

- ✅ **Domain Whitelist:** Only scan approved targets
- ✅ **Authorization Tokens:** Require explicit permission
- ✅ **Rate Limiting:** Prevent DoS on targets
- ✅ **HITL Confirmation:** Human approval before aggressive tests
- ✅ **Audit Logging:** Comprehensive activity logs

### Authorization Flow

```bash
# 1. Add domain to whitelist
curl -X POST http://localhost:8000/api/whitelist \
  -H "X-Admin-Token: admin_token" \
  -d '{"domain": "example.com"}'

# 2. Generate authorization token
curl -X POST http://localhost:8000/api/auth/token \
  -H "X-Admin-Token: admin_token" \
  -d '{"domain": "example.com", "expires_days": 90}'

# 3. Use token in scan request
curl -X POST http://localhost:8000/api/scans \
  -H "X-Auth-Token: your_token" \
  -d '{"target": "https://example.com"}'
```

---

## Evaluation Metrics

### Effectiveness Metrics

| Metric | Target | Calculation |
|--------|--------|-------------|
| **Precision** | ≥90% | TP / (TP + FP) |
| **Recall** | ≥80% | TP / (TP + FN) |
| **F1-Score** | ≥85% | 2 × (Precision × Recall) / (Precision + Recall) |
| **Severity Accuracy** | ≥80% | Correct severity classification |

### Efficiency Metrics

| Metric | Target |
|--------|--------|
| **Time to First Finding (TTFF)** | ≤5 minutes |
| **Total Scan Time** | ≤4 hours (full WSTG) |
| **Speedup vs Manual** | ≥2x faster |

### Coverage Metrics

| Metric | Target |
|--------|--------|
| **Task Completion Rate (TCR)** | ≥70% of WSTG test cases |
| **OWASP Top 10 Coverage** | ≥80% |
| **Attack Surface Coverage** | ≥90% |

---

## Common Tasks

### Debug an Agent

```bash
# Run API in development mode
docker compose up -d db redis
cd api
uvicorn main:app --reload --port 8000

# Run worker with debug logging
celery -A multi_agent_system.tasks.celery_app worker -l DEBUG
```

### View Agent Logs

```bash
curl http://localhost:8000/api/scans/1/logs
# Or via WebSocket for real-time updates
```

### Export Findings

```bash
# All findings
curl http://localhost:8000/api/scans/1/findings

# Filter by severity
curl "http://localhost:8000/api/scans/1/findings?severity=critical"

# Specific finding
curl http://localhost:8000/api/scans/1/findings/5
```

### Cancel a Running Scan

```bash
curl -X POST http://localhost:8000/api/scans/1/cancel
```

---

## Troubleshooting

### LLM Planning Timeout

```
Error: LLM planning timeout after 300s
```

**Solutions:**
- Use faster LLM endpoint (<5s response time)
- Increase `LLM_PLANNING_TIMEOUT` in config
- Set `DISABLE_LLM_PLANNING=true` for static planning

### Agent Stuck Running

```
Agent status: running (no progress for 30+ minutes)
```

**Solutions:**
- Check MCP server health: `docker compose ps`
- Review agent logs: `/api/scans/{id}/logs`
- Adjust `AGENT_TIMEOUT` and `TOOL_TIMEOUT`
- Enable circuit breaker: `CIRCUIT_BREAKER_FAILURES=3`

### MCP Tool Not Found

```
Error: Tool 'sqlmap' not available
```

**Solutions:**
- Verify MCP server is running: `docker compose ps | grep sqlmap`
- Check tool registration in agent's `_get_available_tools()`
- Ensure MCP_SERVER_URLS configured in environment

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | User guide and quick start |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detailed system architecture |
| [SECURITY.md](SECURITY.md) | Security guidelines and ethics |
| [EVALUATION.md](EVALUATION.md) | Metrics and measurement |

---

## Key Design Decisions

1. **Sequential Agent Execution:** Agents run one-at-a-time to enable cumulative context passing (Planner-Summarizer pattern)

2. **LLM for Planning, Not Execution:** LLM selects tools and generates arguments; tools execute deterministically

3. **Shared Context over Direct Communication:** Agents communicate via shared context table, not direct calls

4. **Evidence-Based Confidence:** Findings include confidence scores calculated from evidence types

5. **MCP Abstraction:** All security tools accessed via Model Context Protocol for uniformity

6. **HITL by Default:** Aggressive tests require human approval (can be disabled in LAB_MODE)

---

**Version:** 2.1
**Last Updated:** March 18, 2026
