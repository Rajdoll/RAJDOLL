# 📋 Review & Saran Proposal ICP: Pengembangan Agentic AI untuk Otomasi Pengujian Keamanan Web

**Mahasiswa:** Martua Raja Doli Pangaribuan (2221101809)
**Program Studi:** Rekayasa Keamanan Siber
**Topik:** Pengembangan Agentic AI dengan Sistem Multi-Agen Berbasis LLM untuk Otomasi Pengujian Keamanan Web Berdasarkan Standar OWASP WSTG 4.2 menggunakan Model Context Protocol

**Reviewer:** Claude (Agentic Engineer Skill)
**Tanggal Review:** 3 Desember 2025

---

## ✅ KEKUATAN PROPOSAL

### 1. **Topik Penelitian Sangat Relevan & Timely**
- ✅ Mengangkat isu nyata: 256 celah critical, 405 high, 350 medium (BSSN 2024)
- ✅ Memanfaatkan teknologi cutting-edge (Agentic AI + MCP)
- ✅ Mengisi gap penelitian yang jelas antara PentestGPT, HackSynth, dan PENTEST-AI

### 2. **Fondasi Teoritis Kuat**
- ✅ Literature review komprehensif dan up-to-date
- ✅ Identifikasi gap research yang spesifik
- ✅ Pemilihan OWASP WSTG 4.2 sebagai framework sangat tepat
- ✅ Integrasi MCP sebagai protokol komunikasi inovatif

### 3. **Metodologi Terstruktur**
- ✅ SDLC Waterfall sesuai untuk pengembangan sistem kompleks
- ✅ Multi-agent architecture jelas (11 agen sesuai WSTG categories)
- ✅ Metode evaluasi komprehensif (Completion Rate + Technical Testing + UAT)

---

## ⚠️ AREA YANG PERLU DIPERBAIKI

### 1. **Arsitektur Multi-Agent Perlu Detail Lebih Lanjut**

**Masalah:**
- Diagram flowchart (halaman 7) masih terlalu high-level
- Belum jelas bagaimana koordinasi antar 11 agen
- Tidak dijelaskan mekanisme "anti-stuck" yang disebutkan di hasil

**Saran Perbaikan:**

#### a) **Perjelas Arsitektur Agent**
Tambahkan diagram arsitektur yang menunjukkan:

```
┌─────────────────────────────────────────────────────────┐
│                    SUPERVISOR AGENT                      │
│  (Orchestration, Planning, Result Aggregation)          │
└────────────────┬────────────────────────────────────────┘
                 │
        ┌────────┴──────────┐
        │                   │
┌───────▼──────┐    ┌──────▼───────────────────────────┐
│ Reconnaissance│    │  11 Specialized Test Agents     │
│    Agent      │    │  (WSTG Categories)              │
└───────┬───────┘    └──────┬───────────────────────────┘
        │                   │
        │    ┌──────────────┴─────────┐
        │    │                        │
┌───────▼────▼──────┐      ┌──────────▼─────────┐
│   MCP Client      │      │   Reporting Agent   │
│   (Tool Executor) │      │   (Analysis & Doc)  │
└───────────────────┘      └─────────────────────┘
```

**Tambahkan penjelasan:**
- **Supervisor Agent**: Mengoordinasi workflow, routing tasks, dan aggregasi hasil
- **Reconnaissance Agent**: Entry point, melakukan info gathering
- **11 Specialized Agents**: Masing-masing handle 1 kategori WSTG
- **MCP Client**: Universal interface ke security tools
- **Reporting Agent**: Kompilasi findings dan generate laporan

#### b) **Definisikan Agent Communication Protocol**

Tambahkan bagian tentang **inter-agent communication**:

```yaml
Agent State Schema:
  agent_id: string
  task_status: [pending, in_progress, completed, failed]
  findings: []
  next_agents: []  # Agent mana yang harus dijalankan setelah ini
  dependencies: [] # Agent mana yang harus selesai dulu
  context: {}      # Shared context antar agent
```

**Pattern komunikasi yang disarankan:**
- **Sequential**: Reconnaissance → Config Testing → Auth Testing
- **Parallel**: SQLi scanning + XSS scanning (independent)
- **Conditional**: Jika auth bypass found → skip session testing

#### c) **Jelaskan Mekanisme "Anti-Stuck"**

Tambahkan spesifik tentang handling agent failures:

```python
# Pseudocode mekanisme anti-stuck
class AgentExecutor:
    max_retries: 3
    timeout: 300  # 5 menit per agent

    def execute_with_safeguards(self, agent, task):
        for attempt in range(self.max_retries):
            try:
                result = asyncio.wait_for(
                    agent.execute(task),
                    timeout=self.timeout
                )
                return result
            except TimeoutError:
                # Log timeout, lanjut ke agent berikutnya
                log_and_continue()
            except ContextLossError:
                # Re-inject context dari shared state
                agent.restore_context()

        # Setelah 3x retry gagal, mark as failed dan continue
        mark_failed_and_continue()
```

---

### 2. **Detail Implementasi MCP Masih Kurang**

**Masalah:**
- MCP dijelaskan sebagai protokol komunikasi, tapi tidak detail bagaimana implementasinya
- Tidak ada contoh konkret tool integration via MCP

**Saran Perbaikan:**

#### a) **Tambahkan Contoh MCP Tool Integration**

```python
# Contoh: MCP Server untuk SQLMap
from mcp import Server, Tool

@app.list_tools()
async def list_sqlmap_tools():
    return [
        Tool(
            name="sqlmap_scan",
            description="Detect SQL injection vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "data": {"type": "string"}
                },
                "required": ["url"]
            }
        )
    ]

@app.call_tool()
async def execute_sqlmap(name: str, arguments: dict):
    if name == "sqlmap_scan":
        result = subprocess.run([
            "sqlmap",
            "-u", arguments["url"],
            "--batch",
            "--output-json"
        ], capture_output=True)

        return parse_sqlmap_output(result.stdout)
```

#### b) **Buat Tabel Tool Mapping**

| WSTG Category | Tools via MCP | Agent Responsible |
|---------------|--------------|-------------------|
| Information Gathering | subfinder, amass, nmap | ReconAgent |
| Config & Deployment | nikto, whatweb | ConfigAgent |
| Authentication Testing | hydra, medusa | AuthAgent |
| Input Validation | SQLmap, Dalfox, XSStrike | InputValidationAgent |
| Session Management | burp-extensions | SessionAgent |
| ... | ... | ... |

---

### 3. **Evaluasi Perlu Lebih Spesifik**

**Masalah:**
- Completion Rate metrics bagus, tapi tidak ada baseline comparison
- Target: "10-15 praktisi keamanan siber" → terlalu vague
- Tidak ada acceptance criteria yang jelas

**Saran Perbaikan:**

#### a) **Tambahkan Baseline Comparison**

```
Metrik Evaluasi:
┌──────────────────────┬──────────┬───────────┬──────────┐
│ Metric               │ Baseline │ Target    │ Stretch  │
├──────────────────────┼──────────┼───────────┼──────────┤
│ Task Completion Rate │ N/A      │ ≥70%      │ ≥85%     │
│ False Positive Rate  │ <20%*    │ <15%      │ <10%     │
│ Avg. Time per Test   │ Manual** │ -50%      │ -70%     │
│ SUS Score            │ N/A      │ ≥68 (C)   │ ≥80 (B)  │
└──────────────────────┴──────────┴───────────┴──────────┘

*Berdasarkan rata-rata scanner otomatis (ZAP, Nikto)
**Benchmark: Manual pentest 8-16 jam untuk full WSTG
```

#### b) **Perjelas UAT Respondent Profile**

**Saat ini:** "10-15 praktisi keamanan siber bersertifikasi"

**Sebaiknya:**
```yaml
Target Responden UAT (n=15):
  Kategori 1 (n=5): Security Analyst
    - Sertifikasi: CEH/OSCP
    - Pengalaman: 2-5 tahun
    - Role: Security testing execution

  Kategori 2 (n=5): Penetration Tester
    - Sertifikasi: OSCP/OSCE
    - Pengalaman: 3-7 tahun
    - Role: Manual pentest & tool evaluation

  Kategori 3 (n=5): Security Engineer/Lead
    - Sertifikasi: CISSP/OSCP
    - Pengalaman: 5+ tahun
    - Role: Strategic security assessment

Metode Rekrutmen:
  - Kerjasama dengan BSSN/CyberSecurity Indonesia
  - Rekrutmen via komunitas (OWASP Chapter Indonesia)
```

#### c) **Tambahkan Acceptance Criteria**

```
Sistem dinyatakan LAYAK jika:
✓ TCR ≥ 70% (minimal 70% test case WSTG selesai)
✓ False Positive Rate < 15%
✓ SUS Score ≥ 68 (Grade C: Acceptable)
✓ Semua unit test passed (100% coverage untuk critical paths)
✓ Integration test passed (agent coordination works)
✓ System test passed (end-to-end workflow pada DVWA & Juice Shop)

Sistem dinyatakan EXCELLENT jika:
✓ TCR ≥ 85%
✓ False Positive Rate < 10%
✓ SUS Score ≥ 80 (Grade B: Good)
✓ Performance: Complete full WSTG scan dalam <4 jam
```

---

### 4. **Aspek Keamanan & Etika Perlu Ditambahkan**

**Masalah:**
- Tidak ada pembahasan tentang safeguards untuk mencegah penyalahgunaan
- Tidak ada ethical guidelines untuk automated pentesting

**Saran Perbaikan:**

#### a) **Tambahkan Security Safeguards**

```python
# Security Controls untuk Autonomous Pentest System
class SecurityGuardRails:
    """Prevent misuse of automated pentesting system"""

    def __init__(self):
        self.whitelist_domains = []  # Only test authorized targets
        self.require_authorization_token = True
        self.max_concurrent_scans = 3
        self.rate_limiting = True

    async def validate_target(self, url: str):
        """Validate target is authorized for testing"""
        # Check 1: Domain whitelist
        if not self.is_whitelisted(url):
            raise UnauthorizedTargetError()

        # Check 2: robots.txt + security.txt
        security_policy = await self.check_security_policy(url)
        if security_policy.disallow_scanning:
            raise SecurityPolicyViolation()

        # Check 3: User confirmation
        await self.request_user_confirmation(url)

    async def request_user_confirmation(self, url: str):
        """Human-in-the-loop approval before aggressive testing"""
        print(f"⚠️  CONFIRM: Run aggressive tests on {url}?")
        print("   This will execute SQL injection, XSS, etc.")
        confirmation = input("   Type 'YES' to proceed: ")

        if confirmation != "YES":
            raise UserAbortedError()
```

#### b) **Tambahkan Ethical Guidelines di Proposal**

```markdown
## Pertimbangan Etika & Keamanan

### 1. Authorization Controls
- Sistem hanya akan menguji target yang telah di-whitelist
- Setiap sesi pengujian memerlukan authorization token
- Human-in-the-loop confirmation untuk eksploitasi agresif

### 2. Rate Limiting & Resource Controls
- Max 3 concurrent scans untuk mencegah DoS
- Request throttling sesuai robots.txt
- Auto-stop jika target menunjukkan tanda overload

### 3. Data Protection
- Tidak menyimpan kredensial yang ditemukan
- Enkripsi hasil pengujian at-rest dan in-transit
- Auto-redact sensitive data dalam laporan

### 4. Compliance
- Pengujian hanya pada lingkungan legal (DVWA, Juice Shop)
- Tidak untuk production systems tanpa written authorization
- Logging lengkap untuk audit trail
```

---

### 5. **Tambahkan Risk Mitigation Strategy**

**Saran: Tambahkan Tabel Risk Analysis**

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **LLM Hallucination** (False positives) | High | Medium | - Validation layer dengan rule-based checker<br>- Require evidence untuk setiap finding<br>- Cross-validation antar agent |
| **Context Loss** (Agent stuck) | Medium | High | - Shared state management (Redis)<br>- Timeout + retry mechanism<br>- Context restoration dari logs |
| **Tool Integration Failure** | Medium | High | - Fallback tools (jika SQLmap fail, coba NoSQLMap)<br>- Graceful degradation<br>- Manual fallback option |
| **API Rate Limiting** (LLM provider) | Medium | Medium | - Response caching<br>- Local LLM fallback (Ollama)<br>- Batch processing |
| **Ethical/Legal Issues** | Low | Critical | - Authorization controls<br>- Audit logging<br>- Legal disclaimer |

---

## 📊 SARAN TAMBAHAN UNTUK MENINGKATKAN KUALITAS

### 1. **Tambahkan Novelty Statement yang Lebih Eksplisit**

**Saat ini:** Proposal menyebutkan gap research tapi tidak eksplisit tentang kontribusi unik.

**Tambahkan:**

```markdown
## Kontribusi Penelitian (Scientific Novelty)

Penelitian ini memberikan kontribusi baru sebagai berikut:

1. **Arsitektur Multi-Agent Terspesialisasi untuk Web Security**
   - Pertama kali mengimplementasikan 11 specialized agents yang
     1-to-1 mapping dengan kategori OWASP WSTG 4.2
   - Berbeda dengan PENTEST-AI yang menggunakan framework umum
     MITRE ATT&CK

2. **Integrasi MCP untuk Tool Orchestration**
   - Implementasi pertama MCP protocol untuk security testing automation
   - Menyederhanakan integrasi 15+ security tools dalam single protocol
   - Berbeda dengan PentestGPT yang masih hard-coded tool integration

3. **Context-Aware Agent Coordination**
   - Mekanisme shared state management untuk mencegah context loss
   - Conditional workflow berdasarkan findings dari agent sebelumnya
   - Berbeda dengan HackSynth yang sequential execution

4. **Comprehensive Evaluation Framework**
   - Kombinasi quantitative (Completion Rate) + qualitative (UAT/SUS)
   - Benchmark terhadap aplikasi standar industri (DVWA, Juice Shop)
```

---

### 2. **Tambahkan Expected Limitations & Future Work**

```markdown
## Keterbatasan Penelitian

1. **Cakupan Pengujian Terbatas pada Web Applications**
   - Tidak mencakup mobile apps, IoT, atau API-only services
   - Future work: Extend ke API security testing (OWASP ASVS)

2. **Dependency pada LLM Provider**
   - Memerlukan API key (Anthropic/OpenAI) dengan biaya operasional
   - Future work: Full local LLM implementation untuk production use

3. **Limited Exploit Capability**
   - Fokus pada vulnerability detection, bukan full exploitation
   - Future work: Tambah post-exploitation agent untuk privilege escalation

4. **Bahasa Indonesia Support**
   - Laporan dalam Bahasa Inggris (OWASP standard)
   - Future work: Bilingual reporting (ID + EN)
```

---

### 3. **Perkuat Bagian Implementation Details**

**Tambahkan sub-section di bab 6 (Isi Pokok Bahasan):**

#### **3.1 Technology Stack**

```yaml
Backend:
  Framework: FastAPI (Python 3.11+)
  LLM Integration:
    - Primary: Claude 3.5 Sonnet (Anthropic)
    - Fallback: GPT-4 (OpenAI)
    - Local: Llama 3.1 70B (Ollama)
  MCP: mcp-python SDK
  Task Orchestration: LangGraph
  State Management: Redis
  Database: PostgreSQL (findings storage)

Security Tools (via MCP):
  - Reconnaissance: subfinder, amass, nmap
  - Scanning: nikto, whatweb, wpscan
  - Vulnerability Detection: SQLmap, Dalfox, XSStrike
  - Exploitation: Metasploit (controlled scope)

Frontend:
  Dashboard: React + Tailwind CSS
  Visualization: D3.js (attack graph visualization)
  Real-time Updates: WebSocket

Infrastructure:
  Containerization: Docker Compose
  Orchestration: Docker Swarm / Kubernetes (production)
  Monitoring: Prometheus + Grafana
  Logging: ELK Stack
```

---

### 4. **Tambahkan Timeline yang Lebih Detail**

**Saat ini:** Tidak ada timeline eksplisit.

**Tambahkan Gantt Chart:**

```
Bulan 1-2: Requirements & Design
  ├─ Week 1-2: Literature review lanjutan
  ├─ Week 3-4: Detailed architecture design
  ├─ Week 5-6: MCP tool integration planning
  └─ Week 7-8: Prototype UI/UX design

Bulan 3-4: Implementation Phase 1 (Core Agents)
  ├─ Week 9-10: Reconnaissance Agent + MCP client
  ├─ Week 11-12: 4 Core Testing Agents (Info, Config, Auth, Input)
  └─ Week 13-16: Remaining 7 Specialized Agents

Bulan 5: Implementation Phase 2 (Integration)
  ├─ Week 17-18: Agent coordination & workflow
  ├─ Week 19-20: Dashboard development
  └─ Week 21: Integration testing

Bulan 6: Verification & Evaluation
  ├─ Week 22: Unit & integration testing
  ├─ Week 23: System testing pada DVWA
  ├─ Week 24: System testing pada Juice Shop
  └─ Week 25: UAT dengan praktisi keamanan

Bulan 7: Documentation & Finalization
  ├─ Week 26-27: Thesis writing
  ├─ Week 28: Final evaluation & revision
  └─ Week 29-30: Submission preparation
```

---

## 🎯 REKOMENDASI PRIORITAS

### **High Priority (Must Fix):**
1. ✅ **Detail arsitektur multi-agent** dengan diagram dan communication protocol
2. ✅ **Tambahkan acceptance criteria** yang clear dan measurable
3. ✅ **Jelaskan mekanisme anti-stuck** dan error handling
4. ✅ **Tambahkan security safeguards** untuk mencegah penyalahgunaan

### **Medium Priority (Should Fix):**
5. ✅ **Perjelas MCP implementation** dengan contoh konkret
6. ✅ **Detailkan UAT respondent profile**
7. ✅ **Tambahkan technology stack** dan timeline
8. ✅ **Eksplisit tentang novelty** penelitian

### **Low Priority (Nice to Have):**
9. ✅ Tambahkan expected limitations
10. ✅ Buat comparison table dengan related work
11. ✅ Visualisasi attack graph di dashboard

---

## ✨ KESIMPULAN

**Proposal ini SANGAT SOLID** sebagai foundation untuk penelitian Tugas Akhir. Topik relevan, metodologi jelas, dan gap research terdefinisi dengan baik.

**Kekuatan utama:**
- Problem statement kuat dengan data empiris
- Multi-agent architecture selaras dengan state-of-the-art research
- Evaluation methodology comprehensive

**Yang perlu diperkuat:**
- Detail implementasi arsitektur agent (communication, coordination, anti-stuck)
- Spesifik tentang MCP integration dengan contoh konkret
- Security & ethical considerations
- Acceptance criteria yang measurable

**Rekomendasi:**
Dengan perbaikan di area prioritas tinggi di atas, proposal ini **LAYAK** untuk dilanjutkan ke tahap implementasi. Potensi kontribusi penelitian sangat baik untuk publikasi di konferensi/jurnal keamanan siber.

**Skor Keseluruhan: 8.5/10** ⭐

---

## 📚 REFERENSI TAMBAHAN YANG DISARANKAN

1. **Agentic AI & Multi-Agent Systems:**
   - Wang et al. (2024). "A Survey on Large Language Model based Autonomous Agents"
   - Xi et al. (2023). "The Rise and Potential of Large Language Model Based Agents"

2. **LLM for Security:**
   - Fang et al. (2024). "Large Language Models for Cyber Security"
   - Deng et al. (2024). "PentestGPT: An LLM-empowered Automatic Penetration Testing Tool"

3. **Model Context Protocol:**
   - Anthropic (2024). "Model Context Protocol Specification"
   - MCP Documentation: https://modelcontextprotocol.io/

4. **Web Security Testing:**
   - OWASP Foundation (2020). "Web Security Testing Guide v4.2"
   - Munaiah et al. (2019). "Vulnerability Severity Scoring and Bounties"

---

**End of Review**
