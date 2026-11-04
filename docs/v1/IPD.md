# IPD — RAJDOLL v1: Rencana Implementasi

| | |
|---|---|
| Dokumen | Implementation Plan Document (IPD) |
| Acuan | PRD v1.1, TRD v1.1, AFD v1.0, BSD v1.0 |
| Status | Disetujui (v1.0, 4 November 2026) |
| Pelaksana | Claude menulis kode; pemilik proyek me-review dan menyetujui setiap PR |

Dokumen ini berisi urutan pengerjaan, pemetaan kode lama, dan kriteria selesai setiap fase. Tidak ada perkiraan waktu; urutan dan kriteria yang menjadi pegangan.

---

## 1. Pendekatan

1. **Dibangun ulang di repo yang sama.** Sistem baru ditulis sebagai paket baru. Kode lama dipindahkan ke folder `legacy/` sebagai bahan rujukan, lalu dihapus di fase terakhir. Sebelum itu, keadaan repo sekarang ditandai dengan tag `v0-legacy` agar selalu bisa dikembalikan.
2. **Irisan vertikal dulu.** Satu alur utuh (scan → temuan → triase → laporan) dibangun lebih awal dengan satu modul uji dan tanpa LLM (milestone M1). Setelah itu sistem diperlebar: LLM, modul lain, retest. Dengan begitu masalah integrasi ketahuan sejak awal.
3. **Satu fase, satu PR atau lebih.** Setiap fase dikerjakan di branch sendiri dan masuk lewat pull request. PR tidak di-merge tanpa persetujuan Anda. Fase yang besar dipecah menjadi beberapa PR kecil.
4. **Dokumen adalah acuan.** Jika implementasi perlu menyimpang dari PRD/TRD/AFD/BSD, dokumen yang bersangkutan diperbarui di PR yang sama, dan penyimpangannya disebut di deskripsi PR.

### 1.1 Pembagian pengujian

| Jenis uji | Dijalankan di | Oleh |
|---|---|---|
| Uji unit dan uji dengan PostgreSQL | Lingkungan pengembangan Claude | Claude, sebelum PR dibuka |
| Uji yang butuh stack Docker lengkap (container `tools`, egress proxy, aplikasi uji rentan) | Laptop Anda (Windows + Docker Desktop) | Anda, mengikuti langkah "Cara mencoba" di setiap PR |
| Uji dengan LM Studio | Laptop Anda | Anda |

Lingkungan pengembangan Claude tidak menjalankan Docker, jadi bagian yang hanya bisa dibuktikan di laptop disebut jelas di setiap PR.

### 1.2 Isi setiap PR

- Ringkasan perubahan dan kaitannya dengan kebutuhan (misalnya "PRD F-14, AFD A5").
- Hasil uji yang sudah dijalankan Claude.
- **Cara mencoba** di laptop: perintah dan langkah di UI.
- Penyimpangan dari dokumen, jika ada.

## 2. Struktur repo target

```
RAJDOLL/
├── rajdoll/                 paket Python sistem baru (image api dan worker)
│   ├── api/                 aplikasi FastAPI, rute, renderer HTML/HTMX/JSON
│   │   ├── templates/       Jinja2: layout, halaman, potongan
│   │   └── static/          htmx, ekstensi SSE, Pico.css (disimpan lokal)
│   ├── core/                konfigurasi, sesi database, model SQLAlchemy, kriptografi, scope, keamanan
│   ├── services/            logika bisnis: penugasan, scan, temuan, retest, laporan
│   ├── worker/              workflow engine: antrean, tahap, checkpoint, pemulihan
│   ├── modules/             12 modul uji dan registrinya
│   ├── validators/          satu validator per jenis kerentanan
│   ├── llm/                 klien, katalog tugas, skema, pemangkas konteks
│   ├── reporting/           templat laporan Markdown
│   └── data/                katalog WSTG, seed template temuan, payload, pola pengecualian
├── tools/                   image container tools
│   ├── runner/              API /run dan adaptor per tool
│   ├── proxy/               addon mitmproxy (scope, audit, rate limit, deteksi blokir)
│   ├── mcp/                 server MCP (disiapkan untuk v2)
│   └── Dockerfile
├── templates/nuclei/        template nuclei kustom
├── profiles/                profil scan (full.yaml)
├── migrations/              Alembic
├── testapp/                 aplikasi web rentan untuk uji integrasi
├── tests/                   uji unit dan integrasi
├── docs/v1/                 PRD, TRD, AFD, BSD, IPD
├── legacy/                  kode lama (rujukan, dihapus di Fase 11)
├── compose.yaml
├── Dockerfile               image api dan worker
├── pyproject.toml
├── README.md
└── AGENTS.md
```

## 3. Pemetaan kode lama

Keterangan keputusan:
- **Pindahkan:** kode dibawa dan disesuaikan dengan antarmuka baru.
- **Rujukan:** dibaca sebagai acuan, lalu ditulis ulang.
- **Buang:** tidak dibawa.

Logika yang hanya berlaku untuk satu aplikasi uji tertentu tidak dibawa, termasuk dari berkas yang dipindahkan.

### 3.1 Inti dan orkestrasi

| Kode lama | Keputusan | Tujuan / pengganti | Fase |
|---|---|---|---|
| `multi_agent_system/orchestrator.py`, `hierarchical_orchestrator.py`, `tasks/` (Celery) | Buang | `rajdoll/worker/` | 4 |
| `agents/base_agent.py`, `agents/react_agent.py`, `utils/react_loop.py` | Buang | Konsep agen diganti modul uji | — |
| `agents/*_agent.py` (12 agen) | Rujukan | Daftar pengujian dan urutan per kategori untuk `rajdoll/modules/` | 6, 8 |
| `utils/hitl_manager.py`, `directive_parser.py`, `orchestrator_directive.py`, `pause_manager.py`, `shared_context_manager.py`, `toon_encoder.py`, `agent_runtime.py`, `mcp_client.py`, `llm.py` | Buang | Checkpoint dan antrean baru | — |
| `utils/knowledge_graph.py`, `learned_patterns.py`, `attack_chain_detector.py` | Buang | Di luar scope v1 | — |
| `core/task_tree.py`, `slot_registry.py`, `aggressive_mode.py`, `config.py`, `db.py` | Buang | `rajdoll/core/` | 1 |
| `core/security_guards.py` | Rujukan | Pencocokan host dipakai di `rajdoll/core/scope`; bawaan dibalik menjadi tolak | 1, 3 |
| `utils/secret_store.py` | Buang | `rajdoll/core/crypto` | 1 |
| `models/` (14 tabel), `alembic/`, `db/migrations/` | Buang | Skema BSD di `migrations/` | 1 |

### 3.2 Recon, endpoint, dan sesi

| Kode lama | Keputusan | Tujuan | Fase |
|---|---|---|---|
| `agents/modules/` (`ffuf_runner`, `directory_scanner`, `openapi_probe`, `param_miner`, `jsmap_parser`) | Pindahkan | Modul Information Gathering | 5 |
| `framework/js_bundle_analyzer.py` | Pindahkan | Modul Information Gathering | 5 |
| `core/endpoint_inventory.py`, `url_utils.py` | Pindahkan | Normalisasi endpoint | 5 |
| `core/endpoint_tagger.py`, `utils/endpoint_classifier.py` | Pindahkan | Penanda berbasis aturan (jalan cadangan LLM) | 5 |
| `utils/prompts/endpoint_classification.txt` | Rujukan | Prompt tugas `classify_endpoint` | 7 |
| `core/wordlist_catalog.py` | Pindahkan | Pemilihan wordlist recon | 5 |
| `katana-crawler/` | Rujukan | Adaptor katana di `tools` | 3, 5 |
| `utils/session_service.py`, `session_manager.py` | Rujukan | Cek sesi dan auto-login | 3, 9 |

### 3.3 Pengujian dan validasi

| Kode lama | Keputusan | Tujuan | Fase |
|---|---|---|---|
| Modul MCP `*-testing/*.py` (sekitar 17.500 baris di 12 berkas) | Rujukan, dipilah | Cek yang tidak tercakup nuclei ditulis ulang ke antarmuka modul; sisanya diganti template nuclei | 6, 8 |
| `mcp_adapter/server.py` | Buang | `tools/runner` dan `tools/mcp` | 3 |
| `adjudication/`, `utils/differential_verify.py`, `utils/ssti_verify.py`, `framework/semantic_classifier.py` | Pindahkan | `rajdoll/validators/` | 6, 8 |
| `utils/finding_policy.py`, `utils/confidence_scorer.py` | Rujukan | Ambang validator; skor confidence diganti status validasi | 6 |
| `framework/payload_synthesizer.py` | Pindahkan | Tugas LLM `build_input` | 7 |
| `framework/active_flow.py` | Rujukan | Modul Business Logic | 8 |
| `payloads/*.py` (injeksi, SSRF, JWT, IDOR, NoSQL, HPP, upload, race condition, pola sensitif, miskonfigurasi, komponen rentan) | Pindahkan setelah ditinjau | `rajdoll/data/payloads/` | 6, 8 |
| `payloads/juice_shop_payloads.json` | Buang | — | — |

### 3.4 Data, laporan, UI, dan lainnya

| Kode lama | Keputusan | Tujuan | Fase |
|---|---|---|---|
| `data/wstg_v42_catalog.json`, `data/tool_wstg_map.json`, `core/wstg_catalog.py` | Pindahkan | `rajdoll/data/` | 5 |
| `data/enrichment_kb.json` | Pindahkan | Seed `finding_template` (diterjemahkan, ditambah vektor CVSS) | 9 |
| `utils/enrichment_service.py`, `templates/enrichment_prompt.j2` | Buang | Template temuan dan tugas `triage_finding` | — |
| `utils/report_generator.py`, `owasp_report_generator.py`, `report_service.py`, `pdf_generator.py`, `finding_serializer.py`, `templates/report.html.j2`, `agents/report_generation_agent.py` | Rujukan | Struktur bab untuk templat Markdown | 6, 10 |
| `api/` (10 router), `frontend/`, `nginx/` | Buang | `rajdoll/api/` | 1+ |
| `Dockerfile.mcp-tools`, `Dockerfile.client-mcp`, `katana-crawler/Dockerfile` | Rujukan | Cara instalasi tool di `tools/Dockerfile` | 3 |
| `Dockerfile`, `docker-compose.yml` | Buang | `Dockerfile`, `compose.yaml` baru | 0 |
| `evaluation/`, `data/juice_shop_ground_truth.json` | Buang | — | 0 |
| Uji lama (sekitar 100 berkas) | Ikut keputusan kode yang diuji | Uji untuk kode yang dipindahkan ikut dipindahkan dan disesuaikan | — |
| `README.md`, `AGENTS.md` | Tulis ulang | Menjelaskan sistem v1 | 0, 11 |
| `LICENSE`, `.env.example` | Pertahankan / sesuaikan | | 0 |

## 4. Fase pengerjaan

Ringkasan urutan:

```
F0 Persiapan
F1 Fondasi: database, kriptografi, login, kerangka UI
F2 Penugasan, scope, akun
F3 Container tools dan egress proxy
F4 Workflow engine
F5 Recon dan perencanaan
F6 Irisan pertama: Input Validation → temuan → triase → laporan   ◀ M1
F7 Lapisan LLM
F8 Modul uji lainnya                                               ◀ M2
F9 Triase lengkap, temuan manual, WAF
F10 Retest dan laporan lengkap
F11 Pengerasan dan pembersihan                                     ◀ M3 = v1.0
```

### F0. Persiapan

**Tujuan:** repo siap untuk sistem baru tanpa kehilangan kode lama.

Pekerjaan:
- Tag `v0-legacy` pada commit terakhir sebelum perubahan.
- Pindahkan semua kode lama ke `legacy/` (dengan `git mv` agar riwayat tetap ada). Hapus `evaluation/` dan berkas khusus aplikasi uji.
- Buat kerangka struktur di bagian 2, `pyproject.toml` (Python 3.12, dependensi dengan versi pasti), konfigurasi `ruff` dan `pytest`.
- `compose.yaml` dengan empat layanan (isi masih kerangka), port `api` hanya di `127.0.0.1`.
- `.env.example` baru.
- Tulis ulang `AGENTS.md` agar menunjuk ke `docs/v1/` sebagai acuan dan menjelaskan bahwa `legacy/` hanya rujukan. AGENTS.md lama menjelaskan arsitektur 13 agen dan akan menyesatkan sesi pengembangan berikutnya jika dibiarkan.

Kriteria selesai:
- `docker compose up` menyalakan empat layanan dan `GET /health` di `api` menjawab.
- `pytest` dan `ruff` berjalan bersih pada kerangka.

### F1. Fondasi

**Tujuan:** database, enkripsi, dan login berfungsi.

Pekerjaan:
- Model SQLAlchemy dan migrasi Alembic baseline untuk 17 tabel di BSD, termasuk `CHECK`, indeks, dan peran `rajdoll_app` / `rajdoll_tools`.
- Modul kriptografi: pembuatan kunci utama, kunci data per penugasan sebagai berkas, AES-256-GCM dengan AAD, format `_enc`, urutan penghapusan, dan pembersihan berkas kunci yatim.
- Setup awal, login, logout, sesi UI, token CSRF, ganti password.
- Renderer respons: halaman penuh, potongan HTMX, JSON (BSD 10.1).
- Layout dasar UI (navigasi, Pico.css, HTMX), halaman pengaturan aplikasi.

Kriteria selesai:
- Uji unit kriptografi: enkripsi-dekripsi, AAD yang salah ditolak, kunci yang dihapus membuat data tidak terbaca.
- Uji migrasi naik dan turun pada PostgreSQL 16.
- Setup → login → ubah pengaturan → logout berjalan di browser.

### F2. Penugasan, scope, akun

**Tujuan:** AFD A1, A2, dan A11.

Pekerjaan:
- CRUD penugasan, scope (dengan validasi BSD 10.3), akun target (pengurai sesi tempel: header per baris dan string cookie).
- Status penugasan `draft` → `ready`.
- Pengaturan per penugasan.
- Hapus penugasan dengan konfirmasi nama dan urutan penghapusan kunci.
- Halaman Beranda dan tab Ringkasan, Scope & Akun, Pengaturan.

Kriteria selesai:
- Uji service untuk semua aturan validasi scope dan sesi.
- Uji penghapusan: setelah dihapus, baris hilang dan berkas kunci hilang.

### F3. Container tools dan egress proxy

**Tujuan:** tool bisa dijalankan dengan aman, dan semua trafik tercatat serta dibatasi scope.

Pekerjaan:
- `tools/Dockerfile` dengan semua tool di TRD 4.3, versi dikunci (nuclei ≥ 3.10), plus wordlist yang dibutuhkan recon.
- Runner: `POST /run`, `POST /run/{id}/cancel`, `GET /health`, token internal, kerangka adaptor (argumen bertipe, tanpa shell, cek scope, pengurai keluaran).
- Adaptor pertama: httpx (ProjectDiscovery) dan nuclei.
- Egress proxy (addon mitmproxy): penegakan scope, `request_log`, rate limit token bucket, header `X-Rajdoll-Task`, header identitas, CA RAJDOLL.
- Fitur **Uji sesi** dan cek sesi (PRD F-07, sebagian) lewat proxy.
- Kerangka `testapp/`: aplikasi web rentan kecil yang berjalan sebagai layanan tambahan di profil compose khusus uji. Diisi contoh kerentanan bertahap di fase-fase berikutnya.

Kriteria selesai:
- Request ke host di luar scope ditolak proxy dan tercatat `blocked_scope`.
- Menjalankan nuclei lewat `/run` terhadap `testapp` menghasilkan baris audit untuk setiap request.
- Rate limit terbukti membatasi laju (uji dengan banyak request).

### F4. Workflow engine

**Tujuan:** pipeline bisa berjalan, dijeda, dilanjutkan, dan bertahan dari restart.

Pekerjaan:
- Antrean tugas dengan `SELECT … FOR UPDATE SKIP LOCKED`, `LISTEN/NOTIFY`, batas paralel per penugasan.
- Tahap dan transisi status scan (AFD 3.2), status tugas (AFD 3.3), ulang sekali untuk galat sementara.
- Jeda, lanjut, batal; pembatalan tool yang sedang jalan lewat `/run/{id}/cancel`.
- Pemulihan setelah worker mati: tugas `running` milik worker lama kembali ke `pending`.
- Checkpoint: `checkpoint_deadline`, hold, lanjut otomatis.
- Jeda karena sesi kedaluwarsa (AFD A6).
- `scan_event`, endpoint SSE, halaman Monitor scan, tab Scan, profil `full.yaml`.
- Modul tiruan (dummy) untuk menguji pipeline sebelum modul sungguhan ada.

Kriteria selesai:
- Uji: worker dimatikan di tengah tahap pengujian, dinyalakan lagi, dan scan selesai tanpa tugas ganda.
- Uji: checkpoint lanjut otomatis setelah batas waktu; hold menghentikan hitung mundur.
- Monitor menampilkan progres realtime di browser.

### F5. Recon dan perencanaan

**Tujuan:** inventaris endpoint yang lengkap dan checkpoint yang bisa disunting.

Pekerjaan:
- Adaptor katana (termasuk headless), ffuf, nmap.
- Modul Information Gathering: crawling, fuzzing direktori, fingerprint teknologi, port scan, analisis bundle JavaScript, probe OpenAPI, penemuan parameter, deteksi WAF.
- Normalisasi endpoint ke tabel `endpoint` (dedup per penugasan), pengumpulan host di luar scope.
- Perencanaan berbasis aturan: penanda endpoint, pola pengecualian, pemilihan modul per endpoint, perkiraan jumlah request.
- Layar Checkpoint lengkap (AFD A5), termasuk tempel request mentah dari Burp dan tambah ke scope.

Kriteria selesai:
- Recon terhadap `testapp` menemukan semua endpoint yang didaftarkan di aplikasi uji, termasuk yang hanya ada di JavaScript.
- Endpoint `logout` di `testapp` otomatis dikecualikan.

### F6. Irisan pertama ujung ke ujung (M1)

**Tujuan:** satu VA utuh bisa dijalankan, walaupun baru satu modul dan tanpa LLM.

Pekerjaan:
- Antarmuka modul dan registri (TRD 6.1), pembuatan temuan dengan sidik jari, penyimpanan evidence terenkripsi, spesifikasi PoC.
- Adaptor sqlmap, dalfox, commix; nuclei mode DAST.
- Modul **Input Validation**: SQLi, XSS, command injection, SSTI, SSRF (pindahan cek kustom yang relevan dan payload).
- Validator `sqli`, `xss` (Playwright), `cmdi`, `ssti`, `ssrf`, dan validator umum untuk template nuclei (ulangan kedua).
- Tab Temuan versi dasar: daftar, filter, detail, evidence (di-escape, pratinjau di iframe sandbox), salin curl dan request mentah, terima/tolak.
- Laporan VA Markdown versi dasar dan riwayat ekspor.
- `testapp`: contoh untuk setiap jenis kerentanan di atas.

Kriteria selesai (**M1**):
- Dari penugasan baru sampai unduh laporan `.md` bisa dilakukan di laptop terhadap `testapp`.
- Semua contoh kerentanan Input Validation di `testapp` muncul sebagai temuan `confirmed`.
- Laporan hanya berisi temuan yang diterima.

### F7. Lapisan LLM

**Tujuan:** kelima tugas LLM berjalan dengan jalan cadangan yang aman.

Pekerjaan:
- Klien yang kompatibel dengan OpenAI (ringkasan dari klien lama: `json_schema` untuk LM Studio), antrean satu-per-satu, batas waktu, ulang dengan prompt perbaikan, anggaran per scan, pencatatan `llm_call`.
- Pemangkas konteks (TRD 5.3) dan pembungkus konten target (TRD 5.5).
- Tugas `classify_endpoint` (dipasang di perencanaan), `build_input` (dipasang di modul Input Validation), `judge_response`, `verification_step` (mini-loop, TRD 6.4), `triage_finding`.
- Pengaturan LLM dan uji koneksi di UI, indikator di navigasi, peringatan jika memakai API.
- Catatan AI dan riwayat mini-loop di detail temuan.

Kriteria selesai:
- Dengan LLM mati, hasil scan terhadap `testapp` sama dengan M1.
- Dengan LM Studio aktif, endpoint mendapat tanda dari LLM dan temuan "perlu cek manual" melewati mini-loop (maksimal 3 putaran).
- Uji dengan penyedia palsu: keluaran rusak → ulang sekali → jalan cadangan.

### F8. Modul uji lainnya (M2)

Dikerjakan dalam tiga PR berurutan. Setiap modul: pindahkan cek kustom yang relevan dari modul MCP lama, tulis template nuclei untuk yang bisa, tambah validator yang dibutuhkan, tambah contoh di `testapp`.

| PR | Modul | Validator baru |
|---|---|---|
| F8a | Authorization (IDOR dan eskalasi hak dengan dua akun), Session Management, Authentication (JWT, lockout, reset password) | `idor`, `privilege_escalation`, `jwt`, `session` |
| F8b | Configuration & Deployment, Error Handling, Weak Cryptography (testssl.sh), Identity Management | `info_leak`, `misconfig`, `tls` |
| F8c | Client-Side (retire.js, DOM XSS, CORS, clickjacking), File Upload, Business Logic | `dom_xss`, `cors`, `upload`, `business_logic` (sebagian besar menghasilkan "perlu cek manual") |

Kriteria selesai (**M2**):
- Profil Lengkap menjalankan ke-12 modul terhadap `testapp`.
- Setiap contoh kerentanan di `testapp` terdeteksi, dengan status validasi yang sesuai dengan kemampuan validatornya.
- Modul Authorization dilewati dengan alasan jelas jika akun kurang dari dua.

### F9. Triase lengkap, temuan manual, WAF

**Tujuan:** AFD A7 dan A8 lengkap.

Pekerjaan:
- Seed `finding_template` dari `enrichment_kb.json` (diterjemahkan ke Bahasa Indonesia, ditambah vektor CVSS 3.1 dan 4.0); halaman Pustaka template.
- Penyunting CVSS dua versi dengan library `cvss`, severity dihitung dari versi utama.
- Temuan manual, gabungkan duplikat, kirim ulang lewat proxy, pintasan keyboard (Could).
- Deteksi blokir di proxy, penurunan rate otomatis, jeda karena WAF, "lewati modul terdampak", status `blocked` dan penandaan di laporan.
- Auto-login dengan Playwright (Should; bisa ditunda ke setelah v1.0).
- Notifikasi browser (Could).

Kriteria selesai:
- Mode uji di `testapp` yang meniru WAF (mengembalikan 403 untuk pola payload) memicu penurunan rate lalu jeda, dan laporan mencantumkan pengujian yang terblokir.
- Mengubah vektor CVSS mengubah skor dan severity sesuai pengaturan versi utama.

### F10. Retest dan laporan lengkap

**Tujuan:** AFD A9 dan A10 lengkap.

Pekerjaan:
- Alur retest: persiapan (base URL, sesi, pilihan temuan), eksekusi PoC dan validator, hasil per temuan, koreksi, riwayat putaran.
- Laporan VA lengkap (struktur di TRD 11) dan laporan retest.
- Peringatan sebelum ekspor.

Kriteria selesai:
- Uji: temuan di `testapp` diretest setelah kerentanannya dimatikan (mode "sudah diperbaiki") → hasil `fixed`; yang tidak dimatikan → `still_vulnerable`.
- Laporan retest membandingkan putaran 1 dan 2.

### F11. Pengerasan dan pembersihan (M3 = v1.0)

Pekerjaan:
- Tinjauan keamanan: escape konten target, CSRF, header keamanan HTTP, tidak ada `shell=True`, port yang terbuka, hak peran database.
- Uji ketahanan: restart laptop di tengah scan, Docker Desktop dimatikan dan dinyalakan.
- Panduan instalasi Windows (Docker Desktop, WSL2, LM Studio, BitLocker) di `README.md`.
- Hapus folder `legacy/` setelah dipastikan tidak ada lagi yang dirujuk.
- Perbarui `AGENTS.md` dan dokumen v1 sesuai keadaan akhir.
- Tag `v1.0.0`.

Kriteria selesai (**M3**):
- Semua kriteria di PRD bagian 9 (Definisi selesai v1) terpenuhi dan dicoba di laptop Anda.

## 5. Milestone

| Milestone | Setelah fase | Yang bisa Anda lakukan |
|---|---|---|
| **M1** | F6 | Menjalankan VA utuh dengan modul Input Validation, mentriase, dan mengunduh laporan Markdown. Belum ada LLM. |
| **M2** | F8 | Menjalankan VA dengan ke-12 modul dan bantuan LLM lokal. |
| **M3 (v1.0)** | F11 | Semua fitur PRD v1, termasuk retest, penanganan WAF, dan triase lengkap. |

Setelah M1, sistem sudah bisa dicoba pada pekerjaan nyata secara terbatas, sambil fase berikutnya berjalan.

## 6. Aturan pengembangan

| Hal | Aturan |
|---|---|
| Bahasa | Python 3.12, type hint di semua fungsi publik. |
| Gaya kode | `ruff` (lint dan format). |
| Uji | `pytest`. Setiap PR menambah uji untuk perilaku barunya. Logika validator dan pengurai keluaran tool wajib diuji dengan contoh nyata. |
| Skema | Setiap perubahan skema lewat migrasi Alembic, dan BSD diperbarui di PR yang sama. |
| Eksekusi perintah | Tanpa `shell=True`; argumen tool selalu dari parameter bertipe. |
| Rahasia | Tidak ada kunci, token, atau kredensial di repo maupun log. |
| Komentar dan teks | Kode dan komentar dalam bahasa Inggris; teks UI dan laporan dalam bahasa Indonesia. |
| Dependensi | Versi dikunci; tool di image `tools` memakai versi pasti, bukan `latest`. |

## 7. Risiko implementasi

| Risiko | Mitigasi |
|---|---|
| Fitur yang hanya bisa dibuktikan dengan Docker penuh tidak bisa diuji di lingkungan Claude | Logika dipisah dari I/O agar bisa diuji unit; langkah "Cara mencoba" di setiap PR; masalah dari laptop dilaporkan balik dan diperbaiki di PR berikutnya. |
| Cek kustom lama ternyata bergantung pada perilaku satu aplikasi uji | Setiap cek yang dipindahkan harus lolos terhadap contoh di `testapp`, bukan hanya dipindah apa adanya. |
| Image `tools` besar dan lama dibangun | Build bertahap (multi-stage) dan cache layer; tool yang jarang berubah dipasang lebih dulu. |
| Model 4B lambat sehingga scan terasa lama | Anggaran panggilan LLM per scan dan jalan cadangan; LLM tidak pernah menghalangi tahap berjalan. |
| Lingkup bertambah di tengah jalan | Permintaan baru dicatat sebagai kandidat v2 di PRD bagian 10, kecuali Anda memutuskan memasukkannya ke v1. |

## 8. Keputusan tambahan

| No | Pertanyaan | Keputusan |
|---|---|---|
| I1 | Aktifkan CI (GitHub Actions)? | Ya. `.github/` dihapus dari `.gitignore`; workflow menjalankan `ruff` dan `pytest` di setiap PR (F0). |
| I2 | Branch tujuan PR | `main`, dengan setiap fase di branch sendiri. |
