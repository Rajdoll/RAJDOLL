# 🤖 RAJDOLL - Multi-Agent Penetration Testing System

**Autonomous OWASP WSTG 4.2 Security Testing with LLM-Powered Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![OWASP WSTG 4.2](https://img.shields.io/badge/OWASP-WSTG%204.2-green)](https://owasp.org/www-project-web-security-testing-guide/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple)](https://modelcontextprotocol.io/)

---

## 📋 Overview

**RAJDOLL** (Reconnaissance And Joint Dynamic Offensive LLM-based) is an advanced multi-agent penetration testing system that automates comprehensive web application security assessments based on the OWASP Web Security Testing Guide (WSTG) 4.2.

Built as a thesis project at **Politeknik Siber dan Sandi Negara** using the **Planner-Summarizer Sequential** architecture (inspired by HackSynth, PentestGPT, and PENTEST-AI).

### Key Features

✨ **14 Specialized Agents** - Each expert in one OWASP WSTG category, running sequentially with cumulative context
🧠 **Local LLM Planning** - Qwen 3-4B via LM Studio generates adaptive tool arguments with `json_schema` enforcement
🔗 **14 MCP Servers** - 130+ security tools via Model Context Protocol (JSON-RPC 2.0)
🎯 **97+ WSTG Test Cases** - Including 16 Juice Shop-specific challenge tools
📊 **Real-time Monitoring** - WebSocket updates, per-agent status, live findings
📄 **Professional Reports** - OWASP-compliant Markdown/PDF with cross-agent correlation
🔐 **Ethical Safeguards** - Domain whitelist, rate limiting, HITL confirmation, audit logging

---

## 🏗️ Architecture

```
POST /api/scans --> SecurityGuard --> Job (PostgreSQL) --> Celery (Redis)
                                                              |
                                                     Orchestrator.run()
                                                              |
Phase 1:   ReconnaissanceAgent -----> Discover endpoints, JS routes, tech stack
Phase 1.5: Auto-login (session_service) -----> Authenticated session for all agents
Phase 2:   LLMPlanner.plan_testing_strategy() -----> Strategic plan [5-min timeout]
Phase 3:   For each of 14 agents sequentially:
              --> Per-agent LLM selects tools + generates arguments
              --> Agent executes tools via MCP (JSON-RPC 2.0)
              --> LLM summarizes findings --> cumulative_summary grows
Phase 4:   analyze_all_findings() -----> Cross-agent correlation
Phase 5:   ReportGenerationAgent -----> Final OWASP WSTG 4.2 report
```

### Agent Execution Order

| # | Agent | Tools | Focus |
|---|-------|-------|-------|
| 1 | ReconnaissanceAgent | 10+ | Endpoints, tech stack, JS route analysis |
| 2 | AuthenticationAgent | 12 | Auth bypass, 2FA, JWT, lockout |
| 3 | SessionManagementAgent | 7 | Session tokens, cookies, fixation |
| 4 | InputValidationAgent | 24+ | SQLi, XSS, LFI, SSTI, NoSQL, HPP, ReDoS |
| 5 | AuthorizationAgent | 6 | IDOR, privesc, user spoofing |
| 6 | ConfigDeploymentAgent | 16 | Misconfigs, hidden endpoints, npm vulns |
| 7 | ClientSideAgent | 17 | DOM XSS, CORS, CSP bypass, open redirect |
| 8 | FileUploadAgent | 5+ | Upload vulns, null byte bypass |
| 9 | APITestingAgent | 7 | API-specific issues |
| 10 | ErrorHandlingAgent | 5 | Error disclosure, stack traces |
| 11 | WeakCryptographyAgent | 5 | Weak TLS, crypto flaws |
| 12 | BusinessLogicAgent | 15 | Logic bypass, coupon forgery, rate limiting |
| 13 | IdentityManagementAgent | 8 | User enumeration, mass assignment |
| 14 | ReportGenerationAgent | 1 | OWASP WSTG 4.2 report |

**For detailed architecture:** See [ARCHITECTURE.md](ARCHITECTURE.md)

---

## 🚀 Quick Start

### Prerequisites

- **Python:** 3.11+
- **Docker:** 20.10+ & Docker Compose 2.0+
- **LLM:** LM Studio with Qwen 3-4B (4GB VRAM) or any OpenAI-compatible API
- **OS:** Linux/macOS/Windows (WSL2)

### Installation

#### 1. Clone Repository

```bash
git clone https://github.com/Rajdoll/RAJDOLL.git
cd rajdoll
```

#### 2. Configure Environment

```bash
cp .env.example .env

# Edit .env file
nano .env
```

**Required Environment Variables:**

```bash
# LLM Configuration (Local LLM via LM Studio — no cloud API needed)
LLM_PROVIDER=openai
LLM_BASE_URL=http://host.docker.internal:1234/v1
LLM_MODEL=qwen3-4b
DISABLE_LLM_PLANNING=false

# Database (pre-configured in docker-compose.yml)
DATABASE_URL=postgresql+psycopg://rajdoll:rajdoll@db:5432/rajdoll

# Redis
REDIS_URL=redis://redis:6379/0

# Adaptive Mode (tool selection strategy)
ADAPTIVE_MODE=off  # off=all tools | balanced | aggressive

# Security
WHITELIST_DOMAINS=localhost,127.0.0.1,juice-shop
```

#### 3. Build & Launch

```bash
# Build containers
docker compose build

# Start all services
docker compose up -d

# Check status
docker compose ps
```

**Services Started:**
- `rajdoll-api`: FastAPI backend (http://localhost:8000)
- `rajdoll-worker`: Celery workers for agent execution
- `rajdoll-db`: PostgreSQL database
- `rajdoll-redis`: Redis cache
- 15x `*-mcp`: MCP tool servers

#### 4. Access Dashboard

Open http://localhost:8000 in your browser.

---

## 🎯 Usage

### 1. Start a Scan

**Via Web UI:**
1. Navigate to http://localhost:8000
2. Enter target URL (e.g., `http://juice-shop:3000`)
3. Configure options (optional)
4. Click "Start Scan"

**Via API:**

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: your_secure_token_here" \
  -d '{
    "target": "http://juice-shop:3000",
    "options": {
      "full_wstg_coverage": true,
      "aggressive_mode": false
    }
  }'

# Response:
# {"job_id": 1, "status": "queued"}
```

### 2. Monitor Progress

**Via Web UI:**
- Real-time WebSocket updates
- Agent status visualization
- Findings appearing in real-time

**Via API:**

```bash
# Check job status
curl http://localhost:8000/api/scans/1

# Get findings
curl http://localhost:8000/api/scans/1/findings

# Get logs
curl http://localhost:8000/api/scans/1/logs
```

### 3. Review Findings

```bash
# List all findings
curl http://localhost:8000/api/scans/1/findings

# Get specific finding
curl http://localhost:8000/api/scans/1/findings/5

# Filter by severity
curl http://localhost:8000/api/scans/1/findings?severity=critical
```

### 4. Generate Report

```bash
# Generate OWASP WSTG report
curl -X POST http://localhost:8000/api/scans/1/report \
  -H "X-Auth-Token: your_secure_token_here"

# Download PDF
curl -o report.pdf http://localhost:8000/api/scans/1/report?format=pdf

# Download Markdown
curl -o report.md http://localhost:8000/api/scans/1/report?format=markdown
```

---

## 🧪 Testing on Vulnerable Apps

### DVWA (Damn Vulnerable Web Application)

```bash
# Run DVWA container
docker run -d -p 8080:80 vulnerables/web-dvwa

# Scan with RAJDOLL
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://host.docker.internal:8080"}'
```

### OWASP Juice Shop

```bash
# Run Juice Shop on the Docker compose network (recommended)
docker run -d --name juice-shop --network rajdoll_default \
  -p 3000:3000 --restart unless-stopped bkimminich/juice-shop

# Scan with RAJDOLL (use internal hostname)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'
```

**Juice Shop Challenge Coverage:**

RAJDOLL includes 16 Juice Shop-specific tools targeting:
- SQL Injection login bypass (admin, bender, jim accounts)
- JavaScript static analysis for hidden routes/secrets
- Hidden endpoint discovery (/ftp, /metrics, /support/logs)
- Mass assignment at registration (admin role injection)
- Null byte bypass for restricted files (package.json.bak, encrypt.pyc)
- Coupon code forgery and negative quantity abuse
- Open redirect with allowlist bypass (crypto wallet URLs)
- 2FA/TOTP bypass testing
- CAPTCHA and rate limiting abuse
- User spoofing on feedback/reviews

**Expected Results:**
- **DVWA:** ~25 vulnerabilities detected (Precision: ~90%, Recall: ~85%)
- **Juice Shop:** 40-60+ vulnerabilities detected across 12 WSTG categories

---

## 📊 Evaluation Metrics

RAJDOLL implements comprehensive evaluation metrics based on academic research standards:

### Effectiveness Metrics
- **Precision:** ≥90% (few false positives)
- **Recall:** ≥80% (comprehensive detection)
- **F1-Score:** ≥85% (balanced performance)
- **Severity Accuracy:** ≥80% (correct classification)

### Efficiency Metrics
- **Time to First Finding (TTFF):** ≤5 minutes
- **Total Scan Time:** ≤4 hours (full WSTG)
- **Speedup vs Manual:** ≥2x faster

### Coverage Metrics
- **Task Completion Rate (TCR):** ≥70% of WSTG test cases
- **OWASP Top 10 Coverage:** ≥80%
- **Attack Surface Coverage:** ≥90%

**For detailed metrics:** See [EVALUATION.md](EVALUATION.md)

---

## 🔐 Security & Ethics

⚠️ **IMPORTANT:** This tool is for **AUTHORIZED TESTING ONLY**.

### Built-in Safeguards

- ✅ **Domain Whitelist:** Only scan approved targets
- ✅ **Authorization Tokens:** Require explicit permission
- ✅ **Rate Limiting:** Prevent DoS on targets
- ✅ **HITL Confirmation:** Human approval before aggressive tests
- ✅ **Audit Logging:** Comprehensive activity logs

### Before Scanning

1. **Obtain written authorization** from system owner
2. **Add domain to whitelist:**
   ```bash
   curl -X POST http://localhost:8000/api/whitelist \
     -H "X-Admin-Token: your_admin_token" \
     -d '{"domain": "example.com"}'
   ```
3. **Generate authorization token:**
   ```bash
   curl -X POST http://localhost:8000/api/auth/token \
     -H "X-Admin-Token: your_admin_token" \
     -d '{
       "domain": "example.com",
       "issued_by": "security@example.com",
       "expires_days": 90
     }'
   ```

**For complete guidelines:** See [SECURITY.md](SECURITY.md)

---

## 🛠️ Configuration

### LLM Configuration

RAJDOLL uses a **local LLM** (no cloud API dependency) via LM Studio:

```bash
# .env file — Local LLM via LM Studio
LLM_PROVIDER=openai                              # OpenAI-compatible API
LLM_BASE_URL=http://host.docker.internal:1234/v1  # LM Studio endpoint
LLM_MODEL=qwen3-4b                               # Fits 4GB VRAM
DISABLE_LLM_PLANNING=false
```

**LLM is used at two points:**
1. **Orchestrator level** — `plan_testing_strategy()`: Strategic plan after recon (5-min timeout)
2. **Agent level** — `select_tools_for_agent()`: Per-agent tool selection with `json_schema` enforcement for structured arguments

**LLM Planning Benefits:**
- Adaptive tool arguments based on reconnaissance context
- Context-aware parameter generation (target-specific payloads)
- ~2x more findings vs static default arguments

### Timeout Configuration

```bash
JOB_TOTAL_TIMEOUT=14400   # 4 hours total scan budget
AGENT_TIMEOUT=2700         # 45 minutes per agent
TOOL_TIMEOUT=600           # 10 minutes per tool
LLM_PLANNING_TIMEOUT=300   # 5 minutes for LLM planning
```

---

## 📂 Project Structure

```
rajdoll/
├── api/                            # FastAPI backend
│   ├── main.py
│   └── routes/                     # scans, reporting, websocket, hitl
├── multi_agent_system/             # Core multi-agent system
│   ├── orchestrator.py             # Planner-Summarizer Sequential coordination
│   ├── agents/                     # 14 specialized agents
│   │   ├── base_agent.py           # Base class (LLM planning, MCP execution)
│   │   ├── reconnaissance_agent.py # JS route analysis, endpoint discovery
│   │   ├── input_validation_agent.py # 24+ tools (SQLi, XSS, HPP, ReDoS...)
│   │   ├── authentication_agent.py # 12 tools (2FA bypass, JWT, lockout...)
│   │   ├── client_side_agent.py    # 17 tools (CSP bypass, open redirect...)
│   │   ├── business_logic_agent.py # 15 tools (coupon forgery, rate limit...)
│   │   └── ... (8 more agents)
│   ├── core/
│   │   ├── config.py               # Settings (ADAPTIVE_MODE, timeouts)
│   │   ├── db.py                   # PostgreSQL connection
│   │   └── task_tree.py            # WSTG testing status tracker
│   ├── utils/
│   │   ├── simple_llm_client.py    # LLM API (json_schema enforcement)
│   │   ├── mcp_client.py           # MCP JSON-RPC client
│   │   ├── session_service.py      # Auto-login (Juice Shop credentials)
│   │   └── shared_context_manager.py
│   └── evaluation/metrics.py       # Precision/Recall/F1 calculation
├── mcp_adapter/server.py           # Generic MCP adapter (all 14 servers)
├── information-gathering/          # 14 MCP tool modules (one per server)
├── authentication-testing/         #   Each is an async Python module
├── input-validation-testing/       #   auto-discovered by mcp_adapter
├── client-side-testing/
├── business-logic-testing/
├── ... (9 more testing modules)
├── katana-crawler/                 # Headless web crawler (separate image)
├── frontend/                       # React dashboard
├── docker-compose.yml              # 20+ services orchestration
├── Dockerfile                      # Main API/worker image
├── Dockerfile.mcp-tools            # MCP server image
├── .claude/commands/               # 12 Claude Code skills
└── README.md
```

---

## 🧑‍💻 Development

### Running in Development Mode

```bash
# Start database only
docker compose up -d db redis

# Run API locally (for debugging)
cd api
uvicorn main:app --reload --port 8000

# Run worker locally
cd multi_agent_system
celery -A tasks worker --loglevel=info
```

### Running Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Evaluation metrics test
python -m multi_agent_system.evaluation.metrics --job-id 1
```

### Adding New Agent

1. **Create agent file:**
   ```python
   # multi_agent_system/agents/my_new_agent.py
   
   from .base_agent import BaseAgent, AgentRegistry
   
   @AgentRegistry.register("MyNewAgent")
   class MyNewAgent(BaseAgent):
       system_prompt = "You are an OWASP WSTG-XXXX expert..."
       
       async def execute(self, target, shared_context):
           # Your testing logic
           pass
   ```

2. **Add to orchestrator:**
   ```python
   # multi_agent_system/orchestrator.py
   
   DEFAULT_PLAN = [
       "ReconnaissanceAgent",
       "MyNewAgent",  # Add here
       ...
   ]
   
   AGENT_TO_OWASP_MAP = {
       "MyNewAgent": "WSTG-XXXX",
       ...
   }
   ```

3. **Create MCP server** (if needed)

---

## 📊 Benchmarks

### Performance Targets

| Metric | Target | Description |
|--------|--------|-------------|
| **Precision** | >= 90% | Few false positives |
| **Recall** | >= 80% | Comprehensive detection |
| **F1-Score** | >= 85% | Balanced performance |
| **TCR** | >= 70% | WSTG test case completion rate |
| **Scan Time** | <= 4 hours | Full WSTG coverage |
| **TTFF** | <= 5 min | Time to first finding |

### Test Targets

- **DVWA**: 25 known vulnerabilities
- **OWASP Juice Shop**: 90 challenges (47 automatable, 43 manual/OSINT)

### Tool Coverage

| Agent | Tools | Key Capabilities |
|-------|-------|-----------------|
| InputValidationAgent | 24+ | SQLi (login bypass), XSS, LFI, SSTI, NoSQL, HPP, ReDoS |
| ClientSideAgent | 17 | DOM XSS, CORS, CSP bypass, open redirect, clickjacking |
| ConfigDeploymentAgent | 16 | Hidden endpoints, npm vulns, HSTS, headers |
| BusinessLogicAgent | 15 | Coupon forgery, rate limiting, cart manipulation |
| AuthenticationAgent | 12 | 2FA bypass, JWT analysis, lockout, default creds |

---

## 🤝 Contributing

We welcome contributions! Areas of interest:

- **New Agents:** Additional OWASP WSTG categories
- **MCP Tools:** Integration with more security tools
- **Evaluation:** Ground truth datasets
- **Documentation:** Tutorials, use cases
- **Bug Reports:** Found an issue? Let us know!

### Contribution Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

**IMPORTANT DISCLAIMER:**
This software is provided for **AUTHORIZED SECURITY TESTING ONLY**. Unauthorized use against systems you do not own or have permission to test is **ILLEGAL** and may result in criminal prosecution. Users assume all responsibility for their actions.

---

## 📚 Citation

If you use RAJDOLL in your research, please cite:

```bibtex
@thesis{pangaribuan2026rajdoll,
  title={Pengembangan Agentic AI dengan Sistem Multi-Agen Berbasis LLM untuk Otomasi Pengujian Keamanan Web Berdasarkan Standar OWASP WSTG 4.2 menggunakan Model Context Protocol},
  author={Pangaribuan, Martua Raja Doli},
  year={2026},
  school={Politeknik Siber dan Sandi Negara},
  type={Thesis},
  address={Bogor, Indonesia}
}
```

---

## 📞 Contact & Support

**Author:** Martua Raja Doli Pangaribuan
**Institution:** Politeknik Siber dan Sandi Negara
**GitHub:** [@Rajdoll](https://github.com/Rajdoll)

---

## 🙏 Acknowledgments

- **OWASP Foundation** - Web Security Testing Guide 4.2
- **Anthropic** - Claude AI and Model Context Protocol
- **OpenAI** - GPT-4 API
- **Security Community** - Open source tools (SQLMap, Dalfox, etc.)
- **Telkom University** - Research support
- **BSSN Indonesia** - Security guidance

---

## 🗺️ Roadmap

### Version 2.0 (Completed)
- [x] Planner-Summarizer Sequential architecture
- [x] 14 specialized agents with 130+ tools
- [x] Local LLM support (Qwen 3-4B, 4GB VRAM)
- [x] MCP adapter with auto-discovery
- [x] HITL live execution monitor

### Version 2.1 (Current - Q1 2026)
- [x] 16 Juice Shop-specific challenge tools
- [x] Orchestrator Tier 2.1 regression fix
- [x] JS static analysis for hidden routes
- [x] 12 Claude Code project skills
- [ ] Final thesis evaluation metrics
- [ ] Coverage matrix compilation

### Version 2.2 (Planned - Q2 2026)
- [ ] Fine-tuned local LLM for pentest planning
- [ ] ReAct loop improvements (iterative testing)
- [ ] API security testing enhancements (GraphQL)
- [ ] Compliance reporting (PCI-DSS, ISO 27001)

---

**Made with ❤️ by Security Researchers, for Security Researchers**

**Version:** 2.1
**Last Updated:** March 18, 2026

