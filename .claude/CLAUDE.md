# Multi-Agent Penetration Testing System dengan MCP (RAJDOLL)

**Research Project:** Pengembangan Agentic AI dengan Sistem Multi-Agen Berbasis LLM untuk Otomasi Pengujian Keamanan Web Berdasarkan Standar OWASP WSTG 4.2 menggunakan Model Context Protocol

**Author:** Martua Raja Doli Pangaribuan (NPM: 2221101809)
**Institution:** Politeknik Siber dan Sandi Negara
**Timeline:** 3 bulan (Jan - Mar 2026)

---

## 🎯 Project Overview

Sistem multi-agent berbasis LLM yang mengotomatisasi penetration testing untuk aplikasi web. Setiap agent adalah specialist untuk kategori OWASP WSTG 4.2 (Information Gathering, Authentication Testing, Input Validation, dll).

### Core Innovation
- **LLM Planning**: LLM generates adaptive tool arguments berdasarkan reconnaissance context
- **Multi-Agent Architecture**: 14 specialized agents dengan domain expertise
- **MCP Integration**: Unified protocol untuk 15+ security tools (SQLmap, Nuclei, Dalfox, etc)
- **Autonomous Testing**: Minimal human intervention, self-correcting execution

### Research Contribution
1. First MCP implementation for security testing automation
2. 1-to-1 agent mapping dengan OWASP WSTG 4.2 categories
3. Context-aware LLM planning untuk adaptive testing
4. Comprehensive evaluation metrics (Precision, Recall, F1-Score, TCR)

---

## 🏗️ Architecture

### System Components
```
┌─────────────────────────────────────────┐
│         ORCHESTRATOR                    │
│  - Job Planning & Coordination          │
│  - LLM Strategic Planning               │
│  - Shared Context Management            │
└────────────┬────────────────────────────┘
             │
    ┌────────┴──────────┐
    │                   │
┌───▼──────┐    ┌──────▼──────────────┐
│ Recon    │    │  13 Test Agents     │
│ Agent    │    │  (WSTG Categories)  │
└──────────┘    └──────┬──────────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
  ┌───────▼────────┐    ┌──────────▼────────┐
  │  MCP Client    │    │  Report Agent     │
  │  (15 Tools)    │    │  (Analysis+Docs)  │
  └────────────────┘    └───────────────────┘
```

### 14 Specialized Agents
1. **ReconnaissanceAgent** (WSTG-INFO) - Information gathering
2. **ConfigDeploymentAgent** (WSTG-CONF) - Configuration testing
3. **IdentityManagementAgent** (WSTG-IDNT) - Identity testing
4. **AuthenticationAgent** (WSTG-ATHN) - Authentication testing
5. **AuthorizationAgent** (WSTG-AUTHZ) - Authorization testing
6. **SessionManagementAgent** (WSTG-SESS) - Session management
7. **InputValidationAgent** (WSTG-INPV) - Injection vulnerabilities
8. **ErrorHandlingAgent** (WSTG-ERRH) - Error handling
9. **WeakCryptographyAgent** (WSTG-CRYP) - Cryptography testing
10. **BusinessLogicAgent** (WSTG-BUSL) - Business logic
11. **ClientSideAgent** (WSTG-CLNT) - Client-side testing
12. **FileUploadAgent** (WSTG-BUSL) - File upload vulnerabilities
13. **APITestingAgent** (WSTG-APIT) - API security
14. **ReportGenerationAgent** - OWASP WSTG 4.2 report generation

### Technology Stack
- **Backend**: Python 3.11+, FastAPI, Celery
- **Database**: PostgreSQL (findings), Redis (cache/queue)
- **LLM**: LM Studio (local) / OpenAI GPT-4o (fallback)
- **MCP Servers**: 15 security tools via MCP protocol
- **Containerization**: Docker Compose
- **Frontend**: React (real-time WebSocket monitoring)

---

## 📂 Code Structure

```
/mnt/d/MCP/RAJDOLL/
├── api/                        # FastAPI backend
│   ├── main.py                 # API entry point
│   ├── routes/                 # API endpoints
│   │   ├── scans.py
│   │   ├── reporting.py
│   │   ├── websocket.py
│   │   └── evaluation.py
│   └── schemas/                # Pydantic models
│
├── multi_agent_system/         # Core multi-agent system
│   ├── orchestrator.py         # Agent coordination
│   ├── agents/                 # 14 specialized agents
│   │   ├── base_agent.py       # Base class (CRITICAL: has LLM merge fix)
│   │   ├── reconnaissance_agent.py
│   │   ├── input_validation_agent.py (69KB - most complex)
│   │   └── ...
│   ├── core/
│   │   ├── config.py           # Settings
│   │   ├── db.py               # Database connection
│   │   └── security_guards.py  # Authorization & rate limiting
│   ├── models/                 # SQLAlchemy models
│   │   └── models.py           # Job, JobAgent, Finding, etc
│   ├── utils/                  # Utilities
│   │   ├── simple_llm_client.py  # LLM client (OpenAI compatible)
│   │   ├── llm_planner.py        # LLM adaptive planning
│   │   ├── mcp_client.py         # MCP protocol client
│   │   ├── hitl_manager.py       # Human-in-the-loop
│   │   └── shared_context_manager.py  # Anti-context-loss
│   └── evaluation/             # Metrics calculation
│       └── metrics.py          # Precision, Recall, F1-Score
│
├── authentication-testing/     # MCP servers (15 total)
├── input-validation-testing/
├── information-gathering/
├── ... (12 more MCP servers)
│
├── frontend/                   # React dashboard
├── docker-compose.yml          # Service orchestration
├── .env                        # Configuration (GITIGNORED!)
└── requirements.txt            # Python dependencies
```

---

## 🔧 Code Standards & Conventions

### Python Code Style
```python
# ✅ Good
async def execute_tool(
    self,
    *,
    server: str,
    tool: str,
    args: Optional[Dict[str, Any]] = None,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute MCP tool with LLM-generated arguments.

    Args:
        server: MCP server name
        tool: Tool name to execute
        args: Base arguments (will be merged with LLM args)
        timeout: Optional timeout override

    Returns:
        Tool execution result dictionary

    Raises:
        ToolExecutionError: If tool fails after retries
    """
    # Implementation with type hints, docstrings, error handling
    pass
```

### Critical Code Patterns

**1. LLM Argument Merging (FIXED!):**
```python
# In base_agent.py execute_tool() method:
# ✅ MUST call _before_tool_execution() to merge LLM args
approval = await self._before_tool_execution(server, tool, args)
args = approval.get("arguments", args)  # Merged args

# Then normalize and execute
if args:
    args = self._normalize_llm_arguments(tool, args)
result = await client.call_tool(server=server, tool=tool, args=args, ...)
```

**2. Shared Context Pattern:**
```python
# Write findings to shared context (all agents can read)
self.context_manager.save({
    "findings": [...],
    "entry_points": [...],
    "tech_stack": {...}
})

# Read shared context from other agents
context = self.context_manager.load_all()
endpoints = context.get("entry_points", [])
```

**3. Error Handling Pattern:**
```python
try:
    result = await self.execute_tool(server="input-validation", tool="test_sqli", ...)
except ToolExecutionError as e:
    self.log("error", f"SQLi test failed: {e}")
    self.record_tool_failure("test_sqli", str(e))
    # Circuit breaker: skip tool if failures > threshold
except asyncio.TimeoutError:
    self.log("error", "Tool timeout - retrying with increased timeout")
    result = await self.execute_tool(..., timeout=timeout * 2)
```

### Testing Standards
- **Unit tests**: pytest, 80%+ coverage target
- **Integration tests**: Docker-based testing
- **Test file structure**: `tests/` mirrors `multi_agent_system/`
- **Fixtures**: Use `conftest.py` for shared fixtures
- **Mocking**: Mock external LLM/MCP calls in tests

---

## 🔒 Security Considerations

### Credentials & Secrets
- ✅ **NEVER** commit `.env` file
- ✅ Use environment variables for all secrets
- ✅ `.env.example` for template only
- ✅ Git pre-commit hook checks for leaked secrets

### Sandboxing
- ✅ Tools run in isolated Docker containers
- ✅ Network segmentation for test targets
- ✅ Rate limiting to prevent DoS
- ✅ Authorization checks before tool execution

### Target Authorization
- ✅ Whitelist approved domains only
- ✅ Require explicit authorization token per scan
- ✅ Audit logging for all tool executions
- ✅ HITL (Human-in-the-Loop) for destructive operations

---

## 🐛 Known Issues & Workarounds

### Issue 1: LLM Planning Arguments Not Applied (FIXED Dec 22, 2024)
**Symptom:** LLM generates intelligent arguments, but tools execute with hardcoded defaults
**Root Cause:** `execute_tool()` didn't call `_before_tool_execution()` hook
**Fix Applied:** Added hook call in `base_agent.py:execute_tool()` (lines 472-479)
**Verification:** Run `python fix_validation.py` - all checks should PASS

### Issue 2: Context Loss in Long Scans
**Symptom:** Later agents don't see findings from earlier agents
**Workaround:** Use `SharedContextManager` with persistence to PostgreSQL
**Status:** Implemented, working in production

### Issue 3: MCP Server Timeout on Large Scans
**Symptom:** SQLmap timeout after 3 minutes
**Workaround:** Increased `TOOL_EXECUTION_TIMEOUT` to 1800s (30 min) in base_agent.py for time-based blind SQLi
**Status:** Fixed (Dec 28, 2024)

### Issue 4: WebSocket Disconnection Under Load
**Symptom:** Frontend loses real-time updates during heavy scans
**Workaround:** Added reconnection logic with exponential backoff
**Status:** Needs testing

### Issue 5: Low Vulnerability Coverage on Juice Shop (FIXED Dec 28, 2024)
**Symptom:** Job ID 3 detected only 36/102 Juice Shop vulnerabilities (35% coverage)
**Root Causes:**
1. ADAPTIVE_MODE=aggressive filtering out tools not in LLM plan
2. Missing MCP server registrations (api-testing, file-upload-testing)
3. Tool configuration gaps (SQLMap/Dalfox no POST body support, no JWT testing, no business logic tests)
**Fixes Applied:**
- Phase 1: Changed ADAPTIVE_MODE to "off", added MCP registrations, increased timeouts → Job ID 1: 38 findings (+2)
- Phase 2: Added POST body support, JSON content-type, auth headers, XXE SVG upload, JWT weakness testing, shopping cart manipulation (~800 lines across 3 files) → Job ID 2: Validating (expected 50-59 findings)
**Status:** Phase 2 complete, validation scan in progress (Job ID 2)

---

## 🧪 Testing Strategy

### Test Targets
1. **DVWA** (Damn Vulnerable Web Application)
   - 25 known vulnerabilities
   - Ground truth for Precision/Recall
2. **OWASP Juice Shop**
   - 100+ challenges
   - Comprehensive OWASP Top 10 coverage
3. **Custom Vulnerable App** (optional)

### Evaluation Metrics

**Primary Metrics (Must Have):**
- **Precision**: TP / (TP + FP) ≥ 90%
- **Recall**: TP / (TP + FN) ≥ 80%
- **F1-Score**: Harmonic mean ≥ 85%
- **Task Completion Rate (TCR)**: Test cases completed / Total WSTG tests ≥ 70%

**Secondary Metrics (Should Have):**
- False Positive Rate ≤ 15%
- Time to First Finding ≤ 5 minutes
- Total Scan Time ≤ 4 hours
- SUS Score (usability) ≥ 68

### Testing Commands
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=multi_agent_system --cov-report=html

# Run specific agent tests
pytest tests/agents/test_input_validation_agent.py -v

# Run in Docker (integration)
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

---

## 🚀 Common Commands

### Development
```bash
# Start all services
docker-compose up -d

# Rebuild after code changes
docker-compose build && docker-compose up -d

# View logs
docker-compose logs -f rajdoll-api
docker-compose logs -f rajdoll-worker

# Stop all services
docker-compose down

# Clean rebuild (remove volumes)
docker-compose down -v && docker-compose up --build -d
```

### Testing
```bash
# Quick validation
python fix_validation.py

# WebSocket monitoring
python test_websocket.py --job-id 1

# Start test scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Check findings
curl http://localhost:8000/api/scans/1/findings | jq

# Generate report
curl http://localhost:8000/api/scans/1/report?format=pdf -o report.pdf
```

### LLM Configuration
```bash
# Check LM Studio connection
curl http://localhost:1234/v1/models

# Test LLM inference
curl http://localhost:1234/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "qwen2.5-7b-instruct-q4_k_m", "messages": [{"role": "user", "content": "Hello"}]}'

# Monitor LLM planning in logs
docker-compose logs rajdoll-api | grep "LLM"
docker-compose logs rajdoll-api | grep "Using LLM arguments"
```

---

## 📊 Research Progress Tracking

### Timeline (3 Months)

**Month 1: Implementation & Debugging (Dec 2024 - Jan 2026)**
- Week 1: ✅ Fix LLM planning bug (Dec 22, 2024)
- Week 2: ✅ Full system testing on DVWA (completed)
- Week 3: ✅ Full system testing on Juice Shop (baseline: 36 findings, identified coverage gaps)
- Week 4: 🔄 IN PROGRESS - Coverage enhancement (Phase 1: ✅ Complete, Phase 2: ✅ Complete, Job ID 2: 🔄 Validating)

**Month 2: Evaluation & UAT (Feb 2026)**
- Week 5: ⏳ Run 30 evaluation scans
- Week 6: ⏳ Calculate metrics (Precision, Recall, F1)
- Week 7: ⏳ UAT with 10-15 practitioners
- Week 8: ⏳ SUS questionnaire analysis

**Month 3: Documentation & Publication (Mar 2026)**
- Week 9: ⏳ Thesis writing (Chapters 1-3)
- Week 10: ⏳ Thesis writing (Chapters 4-6)
- Week 11: ⏳ Thesis revision & review
- Week 12: ⏳ Defense preparation & paper submission

### Current Status (Updated: Dec 28, 2024)
- **Overall Progress**: 97% implementation complete
- **Current Phase**: Phase 2 Coverage Enhancement - COMPLETE ✅
- **Active Validation**: Job ID 2 running (expected 50-59 findings from 38 baseline)
- **Critical Blocker**: NONE
- **Next Milestone**: Phase 3 (endpoint discovery & auth propagation) if coverage <80%
- **Confidence Level**: HIGH (on track for 90%+ coverage target)

---

## 💰 Cost Optimization

### Current LLM Strategy
- **Primary**: LM Studio local (Qwen2.5-7B-Q4) - FREE
- **Backup**: OpenAI GPT-4o - For final validation only
- **Estimated Total Cost**: ~$5-10 (vs $100+ with full GPT-4o)

### Token Budget
- Development iterations: Unlimited (local)
- Final evaluation (30 scans): ~$5
- Emergency GPT-4o fallback: ~$5
- **Total 3-month budget**: $10

---

## 🎯 Success Criteria

### Technical Criteria
- [ ] All 14 agents execute successfully
- [ ] LLM arguments properly merged and applied
- [ ] Precision ≥ 90%, Recall ≥ 80%, F1 ≥ 85%
- [ ] TCR ≥ 70% (WSTG test case coverage)
- [ ] WebSocket real-time monitoring works
- [ ] PDF report generation functional
- [ ] No memory leaks in 4-hour scans

### Research Criteria
- [ ] Novel contribution validated (MCP + WSTG 4.2)
- [ ] Comprehensive evaluation completed
- [ ] Comparison with baseline (ZAP, Nuclei)
- [ ] UAT with practitioners (SUS ≥ 68)
- [ ] Thesis draft complete
- [ ] Paper submitted to conference

---

## 📚 Key Resources

### Documentation
- **OWASP WSTG 4.2**: https://owasp.org/www-project-web-security-testing-guide/v42/
- **MCP Specification**: https://modelcontextprotocol.io/
- **LM Studio Docs**: https://lmstudio.ai/docs
- **Qwen Model**: https://huggingface.co/Qwen/Qwen2.5-7B-Instruct

### Internal Docs
- `LM_STUDIO_SETUP_GUIDE.md` - Complete LM Studio setup for Windows
- `FIX_SUMMARY.md` - LLM planning bug fix documentation
- `ENHANCED_EVALUATION_METRICS.md` - Comprehensive metrics guide
- `README.md` - Project overview & quick start

### Scripts & Tools
- `fix_validation.py` - Validate LLM planning fix
- `test_websocket.py` - WebSocket monitoring test
- `quick_start_after_fix.sh` - One-command validation & startup

---

## 🔄 Version History

### v2.1 (Current - Dec 28, 2024)
- ✅ FIXED: Juice Shop coverage gap (36 → target 90+ findings)
- ✅ Phase 1: ADAPTIVE_MODE configuration, MCP server registrations, timeout increases
- ✅ Phase 2: POST body support (SQLMap/Dalfox), JWT weakness testing, XXE SVG upload, shopping cart business logic (~800 lines)
- ✅ Enhanced: `input-validation-testing/input-validation.py` (POST/JSON/auth support)
- ✅ Enhanced: `testing-for-weak-cryptography/weak-cryptography.py` (JWT algorithm confusion, alg:none bypass, weak secret brute force)
- ✅ Enhanced: `business-logic-testing/business-logic.py` (shopping cart manipulation, negative quantity, IDOR)
- 📝 Status: Validation in progress (Job ID 2)

### v2.0 (Dec 22, 2024)
- ✅ FIXED: LLM planning arguments now properly applied
- ✅ Added: Comprehensive validation scripts
- ✅ Added: LM Studio setup guide
- ✅ Optimized: Cost reduction via local LLM
- 📝 Status: Ready for evaluation phase

### v1.0 (Dec 2024)
- ✅ Initial implementation of 14 agents
- ✅ MCP integration with 15 tools
- ✅ FastAPI backend + WebSocket
- ✅ Docker orchestration
- ❌ Issue: LLM arguments not applied (FIXED in v2.0)

---

## 🆘 Troubleshooting Quick Reference

| Issue | Quick Fix |
|-------|-----------|
| LLM args not applied | `python fix_validation.py` - ensure all ✅ |
| LM Studio timeout | Check GPU layers (35 for RTX 3050) |
| Docker build fails | `docker-compose down -v && docker-compose build --no-cache` |
| WebSocket disconnects | Check `api/routes/websocket.py` reconnection logic |
| Agent stuck | Check logs: `docker-compose logs rajdoll-worker` |
| High memory usage | Reduce `MAX_CONCURRENT_AGENTS` in config |

---

**Last Updated**: December 28, 2024
**Maintained By**: Martua Raja Doli Pangaribuan
**Next Review**: After Job ID 2 validation completes
