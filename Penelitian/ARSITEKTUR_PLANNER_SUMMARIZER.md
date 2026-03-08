# RAJDOLL: Arsitektur Planner-Summarizer Sequential

## Ringkasan

Dokumen ini menjelaskan arsitektur baru RAJDOLL yang mengadopsi pola **Planner-Summarizer** dari 3 paper referensi untuk mengoptimalkan penggunaan LLM lokal (Qwen 2.5-7B-Instruct Q4_K_M via LM Studio) dalam multi-agent penetration testing.

**Perubahan utama:**
- Eksekusi **full sequential** (tidak ada parallel batch)
- Setiap agent mendapat **2 LLM call**: Plan (sebelum) + Summarize (setelah)
- **Cumulative Summary** diakumulasi dan diteruskan ke agent berikutnya
- **Task Tree** melacak status testing per WSTG category

---

## Dasar Referensi

### 1. PentestGPT (Deng et al., NTU Singapore)
- **Masalah**: LLM kehilangan konteks seiring dialog panjang (context loss)
- **Solusi**: Pentesting Task Tree (PTT) — encode status testing dalam tree structure yang di-translate ke natural language agar LLM bisa reasoning
- **Arsitektur**: 3 modul (Reasoning, Generation, Parsing) yang saling berinteraksi
- **Adopsi**: Task Tree untuk melacak status per WSTG category

### 2. HackSynth (Muzsai et al., ELTE Budapest)
- **Masalah**: Output tool terlalu panjang, menurunkan kualitas LLM planning
- **Solusi**: Summarizer module yang compress output jadi ringkasan padat
- **Arsitektur**: 2 modul (Planner + Summarizer) dalam loop iteratif
- **Adopsi**: Pola Planner-Summarizer per agent, dengan truncation window

### 3. PENTEST-AI (Bianou & Batogna, IEEE CSR 2024)
- **Masalah**: Penetration testing butuh eksekusi sequential (fase bergantung pada hasil fase sebelumnya)
- **Solusi**: Saga Controller pattern — kontrol alur sequential, Key-Value Store untuk shared memory
- **Arsitektur**: 5 worker agents + 4 control agents dalam 3 plane (Worker, Data, Control)
- **Adopsi**: Sequential execution + shared knowledge base (PostgreSQL)

---

## Arsitektur Tingkat Tinggi

```
+======================================================================+
|                    ORCHESTRATOR (Sequential)                          |
|                                                                      |
|  +-------------+     +------------------------------------------+   |
|  |             |     |        SHARED KNOWLEDGE BASE              |   |
|  |  LM Studio  |     |  +--------------------------------------+ |   |
|  |  (Lokal)    |     |  | Task Tree (status per WSTG category) | |   |
|  |             |     |  | Cumulative Summary (dari Summarizer)  | |   |
|  |  Qwen 2.5   |     |  | Entry Points (dari Recon)             | |   |
|  |  7B Q4_K_M  |     |  | Auth Session (dari Auth Agent)        | |   |
|  |             |     |  | Findings[] (dari semua agent)          | |   |
|  |  ~60s/call  |     |  +--------------------------------------+ |   |
|  |             |     |             PostgreSQL + Redis             |   |
|  +------+------+     +-------------------+----------------------+   |
|         |                                |                           |
|         |    LLM dipanggil 2x per agent  |                           |
|         |    +------------------------+  |                           |
|         |    | 1. PLAN  (sebelum)     |  |                           |
|         |    | 2. SUMMARIZE (setelah) |  |                           |
|         |    +------------------------+  |                           |
|         |                                |                           |
|  =======|================================|========================   |
|         |        EXECUTION FLOW          |                           |
|         v                                v                           |
|                                                                      |
|  +--- AGENT 1: ReconnaissanceAgent ----------------------------+    |
|  |  [LLM PLAN] --> [Execute Tools] --> [LLM SUMMARIZE]         |    |
|  |  Output: endpoints, tech stack, entry points                 |    |
|  +---------------------------+---------------------------------+    |
|                              |                                       |
|                              v  summary + task tree update           |
|                                                                      |
|  +--- AGENT 2: AuthenticationAgent ----------------------------+    |
|  |  [LLM PLAN] --> [Execute Tools] --> [LLM SUMMARIZE]         |    |
|  |  Input: recon summary + task tree                            |    |
|  |  Output: auth vulns, creds found, lockout status             |    |
|  +---------------------------+---------------------------------+    |
|                              |                                       |
|                              v  cumulative summary grows             |
|                                                                      |
|  +--- AGENT 3: SessionManagementAgent -------------------------+    |
|  |  [LLM PLAN] --> [Execute Tools] --> [LLM SUMMARIZE]         |    |
|  |  Input: recon + auth summaries + task tree                   |    |
|  +---------------------------+---------------------------------+    |
|                              |                                       |
|                              v                                       |
|                                                                      |
|  +--- AGENT 4: InputValidationAgent ---------------------------+    |
|  |  [LLM PLAN] --> [Execute Tools] --> [LLM SUMMARIZE]         |    |
|  |  Input: 3 previous summaries + task tree                     |    |
|  +---------------------------+---------------------------------+    |
|                              |                                       |
|                              v                                       |
|                                                                      |
|  +--- AGENT 5: AuthorizationAgent -----------------------------+    |
|  +--- AGENT 6: ConfigDeploymentAgent --------------------------+    |
|  +--- AGENT 7: ClientSideAgent --------------------------------+    |
|  +--- AGENT 8: FileUploadAgent --------------------------------+    |
|  +--- AGENT 9: APITestingAgent --------------------------------+    |
|  +--- AGENT 10: ErrorHandlingAgent ----------------------------+    |
|  +--- AGENT 11: WeakCryptographyAgent -------------------------+    |
|  +--- AGENT 12: BusinessLogicAgent ----------------------------+    |
|  +--- AGENT 13: IdentityManagementAgent -----------------------+    |
|                              |                                       |
|                              v  13 agent summaries accumulated       |
|                                                                      |
|  +--- FINAL: ReportGenerationAgent ----------------------------+    |
|  |  [LLM FINAL ANALYSIS]                                       |    |
|  |  Input: FULL cumulative summary + all findings               |    |
|  |  Output: attack chains, false positive removal,              |    |
|  |          confidence scores, prioritized report               |    |
|  +-------------------------------------------------------------+    |
|                                                                      |
+======================================================================+
```

---

## Alur Data Per Agent (Detail)

```
+--------------------------------------------------+
|              SHARED KNOWLEDGE BASE                |
|  (cumulative_summary dari agent-agent sebelumnya) |
|  (task_tree dengan status per WSTG category)      |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
|           LLM CALL 1: PLAN (~60s)                |
|                                                  |
|  System Prompt:                                  |
|    "Kamu adalah {AgentName}, ahli keamanan       |
|    untuk WSTG kategori {category}.               |
|    Berikut hasil testing sebelumnya:             |
|    {cumulative_summary}                          |
|    Status testing: {task_tree}                   |
|    Target: {target_url}                          |
|    Tools tersedia: {available_tools}             |
|                                                  |
|    Pilih tools dan arguments yang paling tepat   |
|    berdasarkan konteks di atas."                 |
|                                                  |
|  LLM Response:                                   |
|    {                                             |
|      "tools": ["test_sqli", "test_xss"],         |
|      "arguments": {                              |
|        "test_sqli": {"url": "/api/Products/1"},  |
|        "test_xss": {"url": "/rest/user/login"}   |
|      },                                          |
|      "reasoning": "SQLite backend terdeteksi     |
|        di recon, endpoint /api/Products menerima |
|        user input tanpa validasi"                |
|    }                                             |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
|          EXECUTE TOOLS (5-30 menit)              |
|                                                  |
|  Agent <--JSON-RPC--> MCP Server Container       |
|                                                  |
|  test_sqli(url="/api/Products/1")                |
|    -> raw output: sqlmap results (~5KB)          |
|                                                  |
|  test_xss(url="/rest/user/login")                |
|    -> raw output: dalfox results (~3KB)          |
|                                                  |
|  test_lfi(url="/api/Products/1")                 |
|    -> raw output: ffuf results (~2KB)            |
|                                                  |
|  (semua raw output disimpan sebagai findings)    |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
|        LLM CALL 2: SUMMARIZE (~60s)              |
|                                                  |
|  System Prompt:                                  |
|    "Rangkum hasil security testing berikut.      |
|    Fokus pada:                                   |
|    1. Vulnerabilities yang ditemukan (severity)  |
|    2. Endpoint yang vulnerable                   |
|    3. Info berguna untuk testing selanjutnya      |
|    Buang noise, pertahankan evidence penting."   |
|                                                  |
|  Input: raw tool outputs (truncated max 3000     |
|         chars per tool, total max 8000 chars)    |
|                                                  |
|  LLM Response:                                   |
|    "InputValidation testing selesai.             |
|    DITEMUKAN:                                    |
|    - SQLi pada /rest/products/search?q= (CRITICAL|
|      , boolean-based blind via parameter 'q')    |
|    - XSS reflected pada /#/search?q= (HIGH)     |
|    TIDAK DITEMUKAN:                              |
|    - LFI: semua path traversal di-sanitize      |
|    CATATAN UNTUK AGENT SELANJUTNYA:              |
|    - /api/Products endpoint menerima JSON tanpa  |
|      validasi, kemungkinan mass assignment"      |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
|         UPDATE KNOWLEDGE BASE                    |
|                                                  |
|  cumulative_summary += "\n\n" + agent_summary    |
|                                                  |
|  task_tree["INPV"] = {                           |
|    "status": "DONE",                             |
|    "vulns_found": 2,                             |
|    "key_findings": ["SQLi on /rest/products",    |
|                     "XSS on /#/search"]          |
|  }                                               |
|                                                  |
|  -> Disimpan ke SharedContext (PostgreSQL)        |
|  -> Tersedia untuk agent BERIKUTNYA              |
+--------------------------------------------------+
```

---

## Task Tree: Format dan Contoh

Task Tree adalah representasi terstruktur dari status testing yang di-encode sebagai teks agar LLM bisa membacanya. Terinspirasi dari Pentesting Task Tree (PTT) di paper PentestGPT.

### Format

```
PENETRATION TESTING STATUS - {target}
======================================

[DONE] WSTG-INFO (Reconnaissance)
  - 47 endpoints discovered
  - Tech: Node.js, Express, Angular, SQLite
  - Key endpoints: /api/Users, /rest/user/login, /api/Products

[DONE] WSTG-ATHN (Authentication) - 3 vulnerabilities
  - CRITICAL: Default admin credentials work (admin@juice-sh.op)
  - HIGH: No account lockout after 10 failed attempts
  - HIGH: /api/Users accessible without authentication

[DONE] WSTG-SESS (Session Management) - 1 vulnerability
  - MEDIUM: JWT token has weak algorithm (HS256, shared secret)

[DONE] WSTG-INPV (Input Validation) - 2 vulnerabilities
  - CRITICAL: SQLi on /rest/products/search?q= (boolean-based blind)
  - HIGH: XSS reflected on /#/search?q=

[PENDING] WSTG-ATHZ (Authorization)
[PENDING] WSTG-CONF (Configuration)
[PENDING] WSTG-CLNT (Client-Side)
[PENDING] WSTG-BUSL (Business Logic)
[PENDING] WSTG-CRYP (Cryptography)
[PENDING] WSTG-ERRH (Error Handling)
[PENDING] WSTG-APIT (API Testing)
[PENDING] WSTG-IDNT (Identity Management)
```

### Peran Task Tree

| Peran | Penjelasan |
|-------|-----------|
| Konteks untuk LLM Plan | LLM melihat apa yang sudah ditemukan dan apa yang belum ditest |
| Mencegah duplikasi | Agent tidak perlu test ulang vulnerability yang sudah ditemukan |
| Membantu prioritas | LLM bisa fokus ke area yang belum tertesting |
| Korelasi lintas agent | LLM bisa hubungkan findings dari agent berbeda |

---

## Cumulative Summary: Mekanisme Akumulasi

```
Setelah Agent 1 (Recon):
  cumulative_summary = recon_summary

Setelah Agent 2 (Auth):
  cumulative_summary = recon_summary + "\n\n" + auth_summary

Setelah Agent 3 (Session):
  cumulative_summary = recon_summary + "\n\n" + auth_summary + "\n\n" + session_summary

...

Setelah Agent 13 (Identity):
  cumulative_summary = gabungan 13 summary
```

### Pengendalian Ukuran

Cumulative summary akan terus bertambah. Untuk menjaga agar tetap dalam context window LLM:

| Mekanisme | Detail |
|-----------|--------|
| Truncation per agent summary | Max 500 token per summary |
| Sliding window | Jika total > 4000 token, kompres summary lama |
| Prioritas informasi | Vulnerability findings selalu dipertahankan, info teknis minor bisa dibuang |

---

## Estimasi Waktu Eksekusi

### Per Agent

```
LLM Plan call:      ~60 detik
Tool execution:     ~5-30 menit (tergantung agent)
LLM Summarize call: ~60 detik
                    ─────────────
Per agent:          ~7-32 menit
```

### Total Scan

| Agent | LLM Plan | Tools | LLM Summarize | Total |
|-------|----------|-------|---------------|-------|
| Reconnaissance | 60s | ~5 min | 60s | ~7 min |
| Authentication | 60s | ~8 min | 60s | ~10 min |
| SessionManagement | 60s | ~8 min | 60s | ~10 min |
| InputValidation | 60s | ~25 min | 60s | ~27 min |
| Authorization | 60s | ~10 min | 60s | ~12 min |
| ConfigDeployment | 60s | ~10 min | 60s | ~12 min |
| ClientSide | 60s | ~10 min | 60s | ~12 min |
| FileUpload | 60s | ~8 min | 60s | ~10 min |
| APITesting | 60s | ~10 min | 60s | ~12 min |
| ErrorHandling | 60s | ~8 min | 60s | ~10 min |
| WeakCryptography | 60s | ~10 min | 60s | ~12 min |
| BusinessLogic | 60s | ~10 min | 60s | ~12 min |
| IdentityManagement | 60s | ~8 min | 60s | ~10 min |
| Report (Final Analysis) | 60s | ~5 min | - | ~6 min |
| **Total** | **~14 min** | **~135 min** | **~13 min** | **~162 min** |

**Total estimasi: sekitar 2 jam 42 menit** (dalam budget 3-4 jam).

---

## Perbandingan dengan Arsitektur Sebelumnya

| Aspek | Arsitektur Lama | Arsitektur Baru |
|-------|----------------|-----------------|
| Eksekusi | 4 sequential + 3 batch parallel | Full sequential (14 agent berurutan) |
| LLM calls | 1 (LLMPlanner) + gagal di parallel | 28 (2 per agent) + 1 final = 29 |
| Konteks antar agent | Minimal (hanya shared_context raw) | Cumulative summary + Task Tree |
| LLM bottleneck | 9 agent rebutan semaphore | Zero contention (1 agent = 1 LLM) |
| Adaptivitas | LLM plan di awal, lalu diabaikan | LLM plan per agent berdasarkan summary kumulatif |
| False positive handling | Tidak ada | LLM Final Analysis di Report agent |
| Waktu total | ~45 menit (tapi sering timeout/gagal) | ~2 jam 42 menit (stabil) |

---

## Keunggulan untuk Thesis

### 1. Measurable LLM Contribution
Bisa diukur secara empiris:
- **Scan A**: Dengan Planner-Summarizer (LLM aktif)
- **Scan B**: Tanpa LLM (`DISABLE_LLM_PLANNING=true`, semua tools jalan dengan default args)
- **Metrik**: Precision, Recall, F1-Score, false positive rate

### 2. Grounded in Literature
Setiap komponen arsitektur merujuk ke paper yang sudah dipublikasikan:
- Task Tree --> PentestGPT (Deng et al.)
- Planner-Summarizer --> HackSynth (Muzsai et al.)
- Sequential + Shared Memory --> PENTEST-AI (Bianou & Batogna)

### 3. Local LLM Feasibility
Membuktikan bahwa LLM lokal 7B parameter cukup untuk:
- Strategic tool selection (bukan brute-force semua tools)
- Finding summarization (compress output untuk agent berikutnya)
- Cross-agent correlation (hubungkan findings dari agent berbeda)

### 4. Novelty
Kombinasi yang belum ada di paper manapun:
- Multi-agent **per OWASP WSTG category** (bukan per penetration testing phase)
- MCP (Model Context Protocol) sebagai interface agent-to-tool
- Local LLM dengan Planner-Summarizer pattern
- 14 specialized agents dengan 140+ security tools

---

## Komponen yang Perlu Diimplementasikan

### 1. Orchestrator Changes
- Ubah `DEFAULT_PLAN` menjadi full sequential (hapus `{"parallel": [...]}`)
- Tambah `_summarize_agent_results()` — panggil LLM setelah agent selesai
- Tambah `_build_task_tree()` — generate task tree dari findings DB
- Tambah `_get_cumulative_summary()` — gabung semua summary sebelumnya
- Inject cumulative summary + task tree ke setiap agent sebelum `run()`

### 2. BaseAgent Changes
- Tambah `self.cumulative_summary` property (diset oleh orchestrator)
- Tambah `self.task_tree` property (diset oleh orchestrator)
- Modifikasi LLM planning prompt untuk include summary + tree

### 3. LLM Client Changes
- Tambah method `summarize_findings(raw_outputs, max_tokens=500)`
- Tambah method `analyze_findings(all_summaries, all_findings)`
- Truncation logic: `new_observation_window_size` (dari HackSynth)

### 4. New: TaskTree Module
- `multi_agent_system/core/task_tree.py`
- Build tree dari DB findings
- Serialize ke natural language string
- Update setelah setiap agent selesai
