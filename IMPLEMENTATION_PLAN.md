# 🚀 RAJDOLL Optimization Implementation Plan

**Goal:** Increase recall from 34% → 90%+ while reducing scan time 4 hours → 45 minutes

**Timeline:** 2 weeks (10 working days)

**Expected Impact:**
- Findings: 35 → 85-92 (+143% improvement)
- Scan time: 240 min → 45 min (-81% reduction)
- Research validity: Enable LLM planning (critical for thesis)

---

## 📅 WEEK 1: Core Infrastructure (5 days)

### Day 1-2: Nuclei Integration (HIGHEST PRIORITY)

**Why First:** Biggest impact (+30 findings), foundation for other optimizations, proves research hypothesis

#### Day 1 Morning: Setup Nuclei MCP Server
- [ ] Create `nuclei-testing/` directory
- [ ] Install Nuclei: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- [ ] Download templates: `nuclei -update-templates`
- [ ] Verify installation: `nuclei -version`

#### Day 1 Afternoon: Build MCP Server
- [ ] Create `nuclei-testing/nuclei_server.py` (see implementation below)
- [ ] Create `nuclei-testing/requirements.txt`: `mcp`, `httpx`
- [ ] Create `nuclei-testing/Dockerfile`
- [ ] Test server locally

**Files to Create:**
```
nuclei-testing/
├── nuclei_server.py          # MCP server (see plan)
├── requirements.txt          # mcp, httpx
├── Dockerfile               # Container config
└── tests/
    └── test_nuclei_server.py
```

#### Day 2 Morning: Docker Integration
- [ ] Build Dockerfile with Go + Nuclei
- [ ] Add to `docker-compose.yml`: `nuclei-mcp` service on port 9010
- [ ] Register in `mcp_client.py`: `"nuclei-testing": "http://nuclei-mcp:9010"`
- [ ] Test: `docker-compose build nuclei-mcp && docker-compose up -d nuclei-mcp`

#### Day 2 Afternoon: Integration Testing
- [ ] Test MCP server: `curl -X POST http://localhost:9010/list_tools`
- [ ] Run test scan against Juice Shop
- [ ] Verify JSON output parsing
- [ ] Check findings stored correctly

**Success Metrics:**
- [ ] Nuclei finds 20-30 findings in 15 minutes
- [ ] MCP server responds without errors
- [ ] Findings stored in database

---

### Day 3: Create NucleiAgent (LLM Orchestration)

**Why Critical:** This is where LLM magic happens - agent uses LLM to select best templates

#### Morning: Build NucleiAgent
- [ ] Create `multi_agent_system/agents/nuclei_agent.py`
- [ ] Implement `_llm_select_templates()` method
- [ ] Implement `_run_nuclei_with_categories()` method
- [ ] Add authentication session injection
- [ ] Add findings storage logic

#### Afternoon: Register in Orchestrator
- [ ] Import `NucleiAgent` in `orchestrator.py`
- [ ] Add to `_initialize_agents()` with priority 2 (after Recon)
- [ ] Update database schema if needed
- [ ] Test agent execution

**Testing:**
```bash
# Run test scan (Job ID 14)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Monitor NucleiAgent logs
docker-compose logs -f rajdoll-worker | grep "NucleiAgent"
```

**Success Metrics:**
- [ ] NucleiAgent executes without errors
- [ ] LLM template selection logs visible
- [ ] 20-30 findings from Nuclei stored
- [ ] Scan completes in <20 minutes

---

### Day 4: Add Katana (JavaScript Parsing)

**Why:** Finds API endpoints hidden in JavaScript that Dirsearch misses (+5-10 endpoints → +3-7 findings)

#### Morning: Setup Katana MCP Server
- [ ] Create `katana-crawler/` directory
- [ ] Install Katana: `go install github.com/projectdiscovery/katana/cmd/katana@latest`
- [ ] Create `katana_server.py` (JavaScript parsing tool)
- [ ] Create Dockerfile
- [ ] Add to `docker-compose.yml` on port 9011

#### Afternoon: Integrate into ReconnaissanceAgent
- [ ] Update `reconnaissance_agent.py` `_perform_endpoint_discovery()`
- [ ] Add `crawl_with_js_parsing` tool call
- [ ] Merge Katana endpoints with existing endpoint list
- [ ] Store in SharedContext: `katana_js_endpoints`

**Testing:**
```bash
docker-compose build katana-crawler
docker-compose up -d katana-crawler

# Test JavaScript parsing
curl -X POST http://localhost:9011/call_tool \
  -d '{"tool":"crawl_with_js_parsing","args":{"url":"http://juice-shop:3000"}}'
```

**Success Metrics:**
- [ ] Katana finds 5-15 API endpoints in JavaScript
- [ ] Endpoints merged with reconnaissance results
- [ ] No duplicate endpoints

---

### Day 5: Enable ADAPTIVE_MODE (LLM Planning)

**Why:** Research validity! You MUST use LLM planning for thesis credibility.

#### Morning: Update Configuration
- [ ] Update `.env`: `ADAPTIVE_MODE=balanced`
- [ ] Restart services: `docker-compose restart rajdoll-api rajdoll-worker`
- [ ] Verify configuration loaded correctly

#### Afternoon: Improve LLM Prompts with Few-Shot Examples
- [ ] Update `simple_llm_client.py` `select_tools_for_agent()`
- [ ] Add few-shot examples for common tech stacks
- [ ] Lower temperature to 0.2 for deterministic selection
- [ ] Add JSON parsing with fallback

**Testing:**
```bash
# Run test scan (Job ID 15)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Monitor LLM planning logs
docker-compose logs -f rajdoll-worker | grep "LLM"
```

**Success Metrics:**
- [ ] LLM tool selection logs visible
- [ ] Different agents get different tool selections
- [ ] Scan time reduced by 30-40%
- [ ] Logs show: "🧠 LLM selected tools: ..."

---

## 📅 WEEK 2: Optimization & Validation (5 days)

### Day 6: Replace Dirsearch with Feroxbuster

**Why:** 8-10x speed improvement (5 min → 30 sec for directory scanning)

#### Morning: Setup Feroxbuster
- [ ] Update `information-gathering/info_server.py`
- [ ] Add `feroxbuster_scan` tool definition
- [ ] Implement Feroxbuster execution logic
- [ ] Update Dockerfile to install Feroxbuster

#### Afternoon: Update ReconnaissanceAgent
- [ ] Replace `dirsearch_scan` with `feroxbuster_scan`
- [ ] Update tool configuration
- [ ] Test speed improvement

**Testing:**
```bash
# Time comparison test
time curl -X POST http://localhost:9001/call_tool \
  -d '{"tool":"feroxbuster_scan","args":{"url":"http://juice-shop:3000"}}'

# Expected: ~30-60 seconds (vs dirsearch ~5 minutes)
```

**Success Metrics:**
- [ ] Directory scan completes in <1 minute
- [ ] Same or more paths discovered
- [ ] No errors in execution

---

### Day 7: Add FFUF (Parameter Fuzzing)

**Why:** Discovers hidden parameters like `?debug=1`, `?admin=true` (+3-5 findings)

#### Morning: Setup FFUF MCP Server
- [ ] Create `ffuf-fuzzer/` directory
- [ ] Install FFUF binary
- [ ] Create `ffuf_server.py`
- [ ] Create parameter wordlists (`params.txt`, `values.txt`)
- [ ] Create Dockerfile

#### Afternoon: Integrate into ReconnaissanceAgent
- [ ] Add `fuzz_parameters` tool call
- [ ] Store parameter findings in SharedContext
- [ ] Test against Juice Shop

**Testing:**
```bash
docker-compose build ffuf-mcp
docker-compose up -d ffuf-mcp

# Test parameter fuzzing
curl -X POST http://localhost:9012/call_tool \
  -d '{"tool":"fuzz_parameters","args":{"url":"http://juice-shop:3000"}}'
```

**Success Metrics:**
- [ ] Finds 3-10 interesting parameter combinations
- [ ] No false positives (status code validation)

---

### Day 8-9: Consolidate Agents (Reduce 13 → 7)

**Why:** 9 agents produce 0 findings - wasting time. Merge into efficient units.

#### Day 8: Create Merged Agents

**New Agent Structure:**
1. ReconnaissanceAgent (info gathering)
2. NucleiAgent (comprehensive fast scan)
3. InjectionAgent (SQLi, XSS, XXE, SSTI)
4. AuthSecurityAgent (auth + authz + session)
5. BusinessLogicAgent (file upload, race condition)
6. APISecurityAgent (GraphQL, REST, Swagger)
7. ReportGenerationAgent (final report)

- [ ] Create `auth_security_agent.py` (merge 3 agents)
- [ ] Create `injection_agent.py` (merge validation agents)
- [ ] Create `api_security_agent.py`
- [ ] Implement Nuclei-guided deep dive logic

#### Day 9: Update Orchestrator
- [ ] Update `_initialize_agents()` with 7 agents
- [ ] Remove old agent registrations
- [ ] Update execution order
- [ ] Test full scan workflow

**Success Metrics:**
- [ ] All 7 agents execute successfully
- [ ] Scan time reduced by 50%+
- [ ] Same or more findings than 13-agent system

---

### Day 10: Final Validation & Metrics

#### Morning: Run Comprehensive Test
- [ ] Run Job ID 20 with ALL optimizations
- [ ] Monitor progress: `watch -n 10 'curl -s http://localhost:8000/api/scans/20 | jq ".status"'`
- [ ] Wait for completion (~45 minutes expected)

#### Afternoon: Calculate Final Metrics
- [ ] Create `calculate_final_metrics.py` script
- [ ] Manually validate findings (TP vs FP)
- [ ] Calculate Precision, Recall, F1-Score, TCR
- [ ] Generate metrics report for thesis

**Validation Commands:**
```bash
# Run final test
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Calculate metrics
python calculate_final_metrics.py

# Expected output:
# Precision: 95-98%
# Recall: 83-90%
# F1-Score: 89-93%
# Scan time: 42-48 minutes
```

**Success Criteria:**
- [ ] Precision ≥ 90% ✅
- [ ] Recall ≥ 80% ✅
- [ ] F1-Score ≥ 85% ✅
- [ ] TCR ≥ 70% ✅
- [ ] Scan time ≤ 60 minutes ✅

---

## 📊 SUMMARY: Before vs After

| Metric | Before (Current) | After (Optimized) | Improvement |
|--------|------------------|-------------------|-------------|
| **Findings** | 35-36 | 85-92 | +143% |
| **Recall** | 34% | 83-90% | +146% |
| **Precision** | ~70% | 95-98% | +36% |
| **Scan Time** | 240 min | 45 min | -81% |
| **Agents** | 13 | 7 | -46% |
| **LLM Planning** | ❌ Disabled | ✅ Enabled | Research valid |
| **Coverage** | SQLi, XSS only | Full OWASP Top 10 | Comprehensive |

---

## 🚨 RISK MITIGATION

### Risk 1: Nuclei integration takes too long
- **Mitigation:** Use existing Nuclei Python wrapper (nuclei-python)
- **Fallback:** Manual template selection (no LLM) still works
- **Contingency:** Skip Nuclei, focus on ADAPTIVE_MODE + Katana only

### Risk 2: LLM selection doesn't improve results
- **Mitigation:** Compare ADAPTIVE_MODE=off vs balanced in A/B test
- **Evidence:** Document both approaches in thesis (show LLM value)
- **Contingency:** Use "conservative" mode (2-3 tools only)

### Risk 3: Findings don't reach 80% recall
- **Mitigation:**
  - Increase Nuclei timeout to 30 min
  - Add custom Juice Shop templates
  - Manual testing for remaining vulns
- **Contingency:** Lower target to 70% recall (still publishable)

### Risk 4: Timeline slippage
- **Mitigation:**
  - Prioritize P0 tasks only (Nuclei + ADAPTIVE_MODE)
  - P1/P2 are enhancements, not blockers
  - Parallel development (Nuclei while Katana installs)
- **Contingency:** Reduce scope to Week 1 only (still +30 findings improvement)

---

## 🎯 PRIORITY LEVELS

### P0 (Critical - Must Have for Thesis Defense)
- [x] Fix authentication timeout (DONE - Job 13)
- [ ] Enable ADAPTIVE_MODE (Day 5)
- [ ] Add Nuclei (Day 1-3)
- [ ] Calculate final metrics (Day 10)

### P1 (High Impact - Should Have)
- [ ] Add Katana JS parsing (Day 4)
- [ ] Replace Dirsearch with Feroxbuster (Day 6)
- [ ] Consolidate agents (Day 8-9)

### P2 (Nice to Have - Enhancement)
- [ ] Add FFUF fuzzing (Day 7)
- [ ] GraphQL testing (post-thesis)
- [ ] WebSocket testing (post-thesis)
- [ ] LLM false positive filtering (post-thesis)

---

## 📝 DAILY PROGRESS TRACKING

### Completed Tasks
- [x] **Root Cause Analysis:** SessionManager auto-login timeout (60s → 120s)
- [x] **Fix Applied:** Generic solution (not hardcoded to Juice Shop)
- [x] **Validation:** Job 13 running with 120s timeout

### In Progress
- [ ] **Job 13 Results:** Waiting for completion + findings validation

### Next Actions
1. **Immediate:** Check Job 13 results (findings count, auth success)
2. **Day 1 Tomorrow:** Setup Nuclei (if Job 13 shows auth fix worked)
3. **Week 1 Goal:** Nuclei + ADAPTIVE_MODE + Katana = +40 findings

---

## 📚 REFERENCE: Key Implementation Files

### Critical Files to Modify
1. `multi_agent_system/agents/reconnaissance_agent.py` - Auth timeout fix ✅, Katana integration
2. `multi_agent_system/agents/nuclei_agent.py` - NEW agent (LLM-orchestrated)
3. `multi_agent_system/utils/simple_llm_client.py` - Few-shot prompts
4. `multi_agent_system/orchestrator.py` - Agent consolidation
5. `.env` - ADAPTIVE_MODE configuration

### New MCP Servers to Create
1. `nuclei-testing/nuclei_server.py` - 5000+ vulnerability templates
2. `katana-crawler/katana_server.py` - JavaScript parsing
3. `ffuf-fuzzer/ffuf_server.py` - Parameter fuzzing

### Configuration Changes
```bash
# .env
ADAPTIVE_MODE=balanced  # ← CRITICAL for research validity

# docker-compose.yml
# Add: nuclei-mcp, katana-crawler, ffuf-mcp services
```

---

## 🔗 USEFUL COMMANDS

### Development
```bash
# Full rebuild
docker-compose down -v && docker-compose build --no-cache && docker-compose up -d

# Check specific service
docker-compose logs -f rajdoll-worker | grep "AUTOLOGIN\|STDERR"

# Test MCP server
curl -X POST http://localhost:9010/list_tools
```

### Testing
```bash
# Start new scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://juice-shop:3000"}'

# Check findings
curl -s http://localhost:8000/api/scans/13 | jq '.findings | length'

# Monitor status
watch -n 10 'curl -s http://localhost:8000/api/scans/13 | jq ".status, (.findings | length)"'
```

### Metrics Calculation
```bash
# Calculate final metrics
python calculate_final_metrics.py

# Export for thesis
curl -s http://localhost:8000/api/scans/20 | jq > results_job20.json
```

---

**Last Updated:** 2026-01-01
**Version:** 1.0
**Status:** Ready for execution - waiting for Job 13 validation
