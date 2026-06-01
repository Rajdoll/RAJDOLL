# RAJDOLL - Multi-Agent Penetration Testing System

**Autonomous OWASP WSTG 4.2 Security Testing with LLM-Powered Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![OWASP WSTG 4.2](https://img.shields.io/badge/OWASP-WSTG%204.2-green)](https://owasp.org/www-project-web-security-testing-guide/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple)](https://modelcontextprotocol.io/)

---

## Demo

https://github.com/user-attachments/assets/e58255f3-b9d9-4217-ba0b-acd2a1c7156d

---

## Overview

**RAJDOLL** (Reconnaissance And Joint Dynamic Offensive LLM-based) is a multi-agent penetration testing system that automates comprehensive web application security assessments based on the OWASP Web Security Testing Guide (WSTG) 4.2.

Built as a D4 thesis project at **Politeknik Siber dan Sandi Negara** using the **Planner-Summarizer Sequential** architecture, inspired by HackSynth, PentestGPT, and PENTEST-AI.

### Key Features

- **13 Specialized Agents** — Each expert in one OWASP WSTG category, running sequentially with cumulative context
- **Local LLM Planning** — Qwen 3-4B via LM Studio generates adaptive tool arguments with `json_schema` enforcement
- **13 MCP Servers** — 157 security tools via Model Context Protocol (JSON-RPC 2.0)
- **96 WSTG Test Cases** — Full coverage across all 11 WSTG testing categories
- **Real-time Monitoring** — WebSocket updates, per-agent status, live findings
- **Professional Reports** — OWASP-compliant PDF/Markdown with cross-agent correlation
- **Ethical Safeguards** — Domain whitelist, rate limiting, HITL confirmation, audit logging
- **Validated Metrics** — Precision 90.55%, Recall 91.23%, F1 90.89%, TCR 88.89% on OWASP Juice Shop (10 benchmark runs)

---

## Architecture

```
POST /api/scans --> SecurityGuard --> Job (PostgreSQL) --> Celery (Redis)
                                                              |
                                                     Orchestrator.run()
                                                              |
Phase 1:   ReconnaissanceAgent -----> Endpoints, JS routes, tech stack
Phase 1.5: Auto-login (session_service) -----> Authenticated session
Phase 2:   LLMPlanner.plan_testing_strategy() -----> Strategic plan
Phase 3:   For each of 13 agents sequentially:
              --> LLM selects tools + generates arguments
              --> Agent executes tools via MCP (JSON-RPC 2.0)
              --> LLM summarizes findings --> cumulative_summary grows
Phase 4:   analyze_all_findings() -----> Cross-agent correlation
Phase 5:   ReportGenerationAgent -----> Final OWASP WSTG 4.2 report
```

### Agent Execution Order

| # | Agent | WSTG Category |
|---|-------|--------------|
| 1 | ReconnaissanceAgent | WSTG-INFO |
| 2 | AuthenticationAgent | WSTG-ATHN |
| 3 | SessionManagementAgent | WSTG-SESS |
| 4 | InputValidationAgent | WSTG-INPV |
| 5 | AuthorizationAgent | WSTG-ATHZ |
| 6 | ConfigDeploymentAgent | WSTG-CONF |
| 7 | ClientSideAgent | WSTG-CLNT |
| 8 | FileUploadAgent | WSTG-BUSL |
| 9 | ErrorHandlingAgent | WSTG-ERRH |
| 10 | WeakCryptographyAgent | WSTG-CRYP |
| 11 | BusinessLogicAgent | WSTG-BUSL |
| 12 | IdentityManagementAgent | WSTG-IDNT |
| 13 | ReportGenerationAgent | — |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker 20.10+ & Docker Compose 2.0+
- LM Studio with Qwen 3-4B (4GB VRAM) or any OpenAI-compatible API
- Linux / macOS / Windows (WSL2)

### Installation

```bash
# 1. Clone
git clone https://github.com/Rajdoll/RAJDOLL.git
cd RAJDOLL

# 2. Configure
cp .env.example .env
nano .env   # set LLM_BASE_URL, DATABASE_URL, REDIS_URL

# 3. Build & launch
docker compose build
docker compose up -d

# 4. Open dashboard
# http://localhost:8000
```

**Required `.env` variables:**

```bash
LLM_PROVIDER=openai
LLM_BASE_URL=http://host.docker.internal:1234/v1   # LM Studio endpoint
LLM_MODEL=qwen3-4b
DATABASE_URL=postgresql+psycopg://rajdoll:rajdoll@db:5432/rajdoll
REDIS_URL=redis://redis:6379/0
ADAPTIVE_MODE=off          # off | balanced | aggressive
USE_FRAMEWORK=true         # enables JSBundleAnalyzer
USE_JS_ANALYZER=true
WHITELIST_DOMAINS=localhost,127.0.0.1,juice-shop
```

---

## Usage

### Start a Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://juice-shop:3000",
    "credentials": {
      "username": "admin@juice-sh.op",
      "password": "admin123"
    }
  }'
# Response: {"job_id": 1, "status": "queued"}
```

### Monitor Progress

```bash
curl http://localhost:8000/api/scans/1           # status + agent progress
curl http://localhost:8000/api/scans/1/findings  # all findings (reportable)
curl "http://localhost:8000/api/scans/1/findings?mode=raw"  # all findings (raw)
```

### Generate Report

```bash
curl -o report.pdf http://localhost:8000/api/scans/1/report/pdf
```

---

## Testing on OWASP Juice Shop

```bash
# Juice Shop is included in docker-compose.yml
docker compose up -d juice-shop

# Start scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://juice-shop:3000",
    "credentials": {"username": "admin@juice-sh.op", "password": "admin123"}
  }'
```

**Expected Results (10 benchmark runs, Qwen3-4B, May 2026):**

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| Precision | 90.55% (±0.27%) | >= 90% | PASS |
| Recall | 91.23% (±0.00%) | >= 80% | PASS |
| F1-Score | 90.89% (±0.14%) | >= 85% | PASS |
| TCR | 88.89% (24/27 WSTG) | >= 70% | PASS |
| Scan Time | ~62 minutes | <= 4h | PASS |

Ground truth: 57 Juice Shop challenge entries across 27 WSTG sub-categories.
Near-zero std dev confirms deterministic behavior with `json_schema` enforcement.

**5 challenges not detected (genuine system limitations):**
- WSTG-SESS-05 (CSRF) — requires browser interaction
- WSTG-ERRH-01 (Error Handling) — Juice Shop does not expose stack traces
- WSTG-ATHN-09 x2 — requires 2FA setup
- WSTG-ATHN-07 — password policy requires UI interaction
- WSTG-CONF-01 (Supply Chain) — server-side package, not visible in HTML

---

## Project Structure

```
RAJDOLL/
├── api/                            # FastAPI backend
│   ├── main.py
│   └── routes/                     # scans, reporting, websocket, hitl
├── multi_agent_system/             # Core multi-agent system
│   ├── orchestrator.py             # Planner-Summarizer Sequential
│   ├── agents/                     # 13 specialized agents
│   │   ├── base_agent.py           # Base class (LLM planning, MCP execution)
│   │   ├── reconnaissance_agent.py
│   │   ├── input_validation_agent.py
│   │   ├── authentication_agent.py
│   │   ├── client_side_agent.py
│   │   ├── business_logic_agent.py
│   │   └── ... (8 more agents)
│   ├── core/
│   │   ├── config.py               # Settings (ADAPTIVE_MODE, USE_FRAMEWORK)
│   │   ├── db.py                   # PostgreSQL
│   │   └── task_tree.py            # WSTG testing status tracker
│   ├── utils/
│   │   ├── simple_llm_client.py    # LLM API (json_schema enforcement)
│   │   ├── session_service.py      # Auto-login
│   │   └── shared_context_manager.py
│   ├── framework/
│   │   └── js_bundle_analyzer.py   # SPA route extraction (WSTG-INFO-06)
│   └── evaluation/
│       ├── compute_metrics.py      # Precision/Recall/F1/TCR
│       └── evaluation_juiceshop_summary.json
├── mcp_adapter/server.py           # Generic MCP adapter (all 13 servers)
├── information-gathering/          # MCP tool modules (one per server)
├── authentication-testing/
├── input-validation-testing/
├── client-side-testing/
├── business-logic-testing/
├── weak-cryptography-testing/
├── ... (7 more testing modules)
├── frontend/                       # React dashboard
├── docker-compose.yml              # 20+ services
├── Dockerfile                      # API/worker image
└── Dockerfile.mcp-tools            # MCP server image
```

---

## Configuration

### LLM

```bash
LLM_PROVIDER=openai
LLM_BASE_URL=http://host.docker.internal:1234/v1   # LM Studio
LLM_MODEL=qwen3-4b                                  # 4GB VRAM
```

LLM is used at two points:
1. **Orchestrator** — `plan_testing_strategy()` after recon (strategic plan)
2. **Per-agent** — `select_tools_for_agent()` with `json_schema` enforcement

### Timeouts

```bash
JOB_TOTAL_TIMEOUT=14400   # 4 hours
AGENT_TIMEOUT=2700         # 45 minutes per agent
TOOL_TIMEOUT=600           # 10 minutes per tool
```

### Adaptive Mode

```bash
ADAPTIVE_MODE=off          # All tools run (recommended for benchmarks)
ADAPTIVE_MODE=balanced     # CRITICAL + HIGH priority tools
ADAPTIVE_MODE=aggressive   # CRITICAL tools only
```

---

## Security & Ethics

**This tool is for AUTHORIZED TESTING ONLY.**

Built-in safeguards:
- Domain whitelist — only scan approved targets
- Rate limiting — prevent DoS on targets
- HITL confirmation — human approval for aggressive tests
- Audit logging — comprehensive activity logs

---

## Evaluation

RAJDOLL uses Precision/Recall/F1/TCR metrics based on OWASP WSTG sub-category ground truth matching. The alias map supports bidirectional WSTG code matching (e.g., WSTG-INPV-01 matches WSTG-CLNT-01 for XSS variants).

```bash
# Run evaluation
python3 multi_agent_system/evaluation/compute_metrics.py \
  --target juiceshop \
  --runs juiceshop_benchmark_run1 juiceshop_benchmark_run2 ...
```

---

## License

MIT License. See [LICENSE](LICENSE).

**DISCLAIMER:** This software is for **AUTHORIZED SECURITY TESTING ONLY**. Unauthorized use is illegal.

---

## Citation

```bibtex
@thesis{pangaribuan2026rajdoll,
  title={Pengembangan Agentic AI dengan Sistem Multi-Agen Berbasis LLM untuk Otomasi
         Pengujian Keamanan Web Berdasarkan Standar OWASP WSTG 4.2 menggunakan
         Model Context Protocol},
  author={Pangaribuan, Martua Raja Doli},
  year={2026},
  school={Politeknik Siber dan Sandi Negara},
  type={D4 Thesis},
  address={Bogor, Indonesia}
}
```

---

**Author:** Martua Raja Doli Pangaribuan
**Institution:** Politeknik Siber dan Sandi Negara
**Version:** 2.3 | **Updated:** May 2026
