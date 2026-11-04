# BSD — RAJDOLL v1: Skema Backend

| | |
|---|---|
| Dokumen | Backend Schema Document (BSD): skema database dan kontrak API |
| Acuan | PRD v1.1, TRD v1.1, AFD v1.0 |
| Status | Disetujui (v1.0, 4 November 2026) |

---

## 1. Konvensi

| Hal | Ketentuan |
|---|---|
| Bahasa identifier | Nama tabel, kolom, nilai status, dan field API memakai bahasa Inggris. Label di UI dan laporan berbahasa Indonesia. Pemetaan istilah AFD ada di bagian 9. |
| Kunci utama | `id bigint generated always as identity`, kecuali disebut lain. |
| Waktu | `timestamptz`, disimpan dalam UTC, ditampilkan dalam WIB. |
| Status dan jenis | Kolom `text` dengan `CHECK` (bukan tipe `enum` Postgres) agar mudah diubah lewat migrasi. |
| Kolom terenkripsi | Berakhiran `_enc`, bertipe `bytea`. Format: `versi (1 byte) ‖ nonce (12 byte) ‖ ciphertext ‖ tag`. AES-256-GCM dengan kunci data penugasan; AAD = `<engagement_id>:<tabel>:<kolom>`. Isi sebelum dienkripsi selalu JSON atau teks UTF-8. |
| Penghapusan | Fisik (tanpa soft delete). Relasi ke `engagement` memakai `ON DELETE CASCADE`. |
| Migrasi | Alembic saja. v1 dimulai dari baseline baru; data dari sistem lama tidak dipindahkan. |

## 2. Diagram relasi

```
app_user        ui_session        app_setting        finding_template
                                                            │ 0..1
engagement ─┬─< scope_rule                                  │
            ├─< target_account                              │
            ├─< endpoint ◀──────────────────────┐           │
            ├─< scan ─┬─< task                  │ 0..1      │
            │         ├─< scan_event            │           │
            │         └─< retest_result >──┐    │           │
            ├─< finding ◀──────────────────┘────┴───────────┘
            │      └─< evidence
            ├─< llm_call
            ├─< request_log
            └─< report_export

─<  satu ke banyak
```

Kunci data penugasan **tidak** disimpan di database (bagian 7).

## 3. Tabel aplikasi

### 3.1 `app_user`

Hanya satu baris (satu pengguna).

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | `smallint` PK | Selalu `1` (`CHECK (id = 1)`). |
| `password_hash` | `text` | Argon2id. |
| `created_at`, `updated_at` | `timestamptz` | |
| `last_login_at` | `timestamptz` null | |

### 3.2 `ui_session`

Sesi login ke UI RAJDOLL (bukan sesi ke target).

| Kolom | Tipe | Keterangan |
|---|---|---|
| `token_hash` | `text` PK | SHA-256 dari token di cookie; token aslinya tidak disimpan. |
| `csrf_token` | `text` | |
| `created_at`, `last_seen_at`, `expires_at` | `timestamptz` | Berlaku 12 jam (bisa diatur). |

### 3.3 `app_setting`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `key` | `text` PK | |
| `value` | `jsonb` | |
| `updated_at` | `timestamptz` | |

Kunci yang dipakai:

| Kunci | Contoh nilai | Keterangan |
|---|---|---|
| `llm` | `{"enabled": true, "base_url": "http://host.docker.internal:1234/v1", "model": "qwen3-4b", "api_key_enc": null, "thinking": false, "timeout_s": 120}` | `api_key_enc` dienkripsi dengan kunci utama (base64; AAD `app:llm.api_key`). Klien mengirim `api_key` dalam teks biasa (string kosong menghapusnya) dan tidak pernah bisa mengisi `api_key_enc` langsung; nilainya tidak pernah dikembalikan. `enabled = false`: setiap tugas LLM memakai jalan cadangan (F7). |
| `llm_budget_per_scan` | `400` | Batas panggilan LLM per scan. |
| `cvss_primary` | `"3.1"` | `"3.1"`, `"4.0"`, atau `"both"`. |
| `defaults` | `{"rate_limit_rps": 10, "concurrency": 2, "checkpoint_enabled": true, "checkpoint_timeout_min": 15, "evidence_max_bytes": 1048576, "oob_enabled": false}` | Nilai bawaan untuk penugasan baru. |
| `block_detection` | `{"window_s": 60, "throttle_ratio": 0.3, "pause_ratio": 0.6, "pause_after_s": 180}` | Ambang deteksi blokir. |
| `excluded_patterns` | `["logout", "signout", "delete", "remove", "destroy", "reset", "change-password", "deactivate"]` | Pola endpoint berisiko (PRD F-46). |

## 4. Tabel penugasan

### 4.1 `engagement`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `name` | `text` not null | Nama aplikasi. |
| `organization` | `text` null | Instansi. |
| `target_url` | `text` not null | |
| `notes` | `text` null | Misalnya nomor surat tugas. |
| `start_date`, `end_date` | `date` null | |
| `status` | `text` | `draft`, `ready`, `active`, `done`. |
| `key_id` | `uuid` not null unique | Nama berkas kunci data di volume `secrets`. |
| `settings` | `jsonb` | Menimpa `defaults` dan `block_detection`, plus `identity_header` (misalnya `{"name": "X-VA-Team", "value": "..."}`). |
| `session_check_url` | `text` null | |
| `session_check_marker` | `text` null | Teks penanda login. |
| `created_at`, `updated_at` | `timestamptz` | |

Constraint (`CHECK`): `end_date >= start_date` jika keduanya terisi.

### 4.2 `scope_rule`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `pattern` | `text` | Host atau wildcard, misalnya `app.instansi.test`, `*.instansi.test`. Tanpa skema dan path. |
| `created_at` | `timestamptz` | |

Unik: `(engagement_id, pattern)`.

### 4.3 `target_account`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `label` | `text` | "Akun A", "Akun B", dan seterusnya. |
| `auth_method` | `text` | `pasted`, `auto_login`. |
| `session_enc` | `bytea` null | JSON `{"cookies": {...}, "headers": {...}}`. |
| `credentials_enc` | `bytea` null | JSON `{"username", "password", "login_url", "selectors": {...}}` untuk auto-login. |
| `session_status` | `text` | `unknown`, `valid`, `invalid`. |
| `session_checked_at` | `timestamptz` null | |
| `created_at`, `updated_at` | `timestamptz` | |

Unik: `(engagement_id, label)`.

### 4.4 `endpoint`

Inventaris endpoint dikumpulkan per penugasan dan bertambah dari setiap scan.

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `method` | `text` | |
| `scheme` | `text` default `https` | `http` atau `https` (migrasi `0003`). |
| `host` | `text` | Nama host, ditambah port jika bukan port bawaan scheme (`testapp:8080`). |
| `path_template` | `text` | Path yang dinormalisasi, misalnya `/api/users/{id}`. |
| `query_params` | `text[]` | Nama parameter query. |
| `body_params` | `jsonb` | `[{"name": "qty", "type": "number", "location": "json"}]`. |
| `content_type` | `text` null | |
| `source` | `text` | `crawl`, `fuzz`, `js`, `openapi`, `manual`, `burp_paste`. `openapi` (dari spesifikasi API, belum tentu teramati langsung) ditambahkan di migrasi `0003`. |
| `sample_request_enc` | `bytea` null | Contoh request mentah. |
| `tags` | `text[]` | Taksonomi (F5b, `rajdoll/services/tagging.py`): `idor_candidate`, `admin`, `auth`, `registration`, `password_reset`, `profile`, `upload`, `price`, `state_change`, `has_params`, `redirect_param`, `file_param`, `api`, `graphql`, `hidden`. |
| `tag_source` | `text` | `rule`, `llm`, `user`. Tanda `rule` dihitung ulang setiap kali parameter endpoint bertambah; tanda `user` (disunting asesor) tidak pernah ditimpa. |
| `excluded` | `boolean` default `false` | |
| `exclude_reason` | `text` null | Misalnya `pattern:logout` atau `user`. |
| `first_seen_scan_id`, `last_seen_scan_id` | FK → `scan` null | |
| `created_at`, `updated_at` | `timestamptz` | |

Unik: `(engagement_id, method, host, path_template)`.

Catatan implementasi (F5a): normalisasi path di `rajdoll/services/inventory.py`: segmen angka menjadi `{id}`, UUID menjadi `{uuid}`, hex panjang menjadi `{hash}`, gaya Express `:nama` menjadi `{nama}`; garis miring ganda dan di akhir dibuang. File statis (gambar, font, CSS, source map) tidak disimpan; JavaScript tetap disimpan. Endpoint baru yang path atau nama parameternya mengandung pola pengecualian (`excluded_patterns` di pengaturan, misalnya `logout`) langsung disimpan dengan `excluded = true` dan `exclude_reason = 'pattern:<pola>'`; keputusan asesor pada endpoint yang sudah ada tidak ditimpa. Host di luar scope tidak disimpan, tetapi dihitung di `scan.recon_summary.out_of_scope_hosts`.

## 5. Tabel pipeline

### 5.1 `scan`

Dipakai untuk scan biasa dan putaran retest.

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `kind` | `text` | `scan`, `retest`. |
| `number` | `int` | Nomor urut per penugasan dan jenis (scan #1, #2; retest putaran 1, 2). Unik `(engagement_id, kind, number)`. |
| `profile` | `text` null | `full`, `custom`. Null untuk retest. |
| `modules` | `text[]` | Modul aktif. |
| `status` | `text` | `queued`, `running`, `awaiting_checkpoint`, `paused`, `completed`, `cancelled`, `failed`. |
| `stage` | `text` null | `recon`, `planning`, `testing`, `validation`, `ai_triage`, `retest`. |
| `paused_reason` | `text` null | `manual`, `session_expired`, `waf_blocked`. |
| `checkpoint_deadline` | `timestamptz` null | Null jika checkpoint ditahan (sedang disunting) atau tidak berlaku. |
| `checkpoint_resolution` | `text` null | `user_continued`, `auto_continued`, `disabled`. |
| `base_url` | `text` null | Untuk retest jika alamat clone berubah. |
| `settings_snapshot` | `jsonb` | Pengaturan efektif saat scan dimulai, termasuk rate limit yang sedang berlaku (bisa diturunkan saat blokir). |
| `llm_snapshot` | `jsonb` | `{"enabled", "base_url", "model", "is_local", "thinking", "timeout_s", "budget"}` saat scan dimulai; scan memakai LLM yang dilihat asesor saat memulai (F7). |
| `recon_summary` | `jsonb` null | Ditulis modul selama recon: `{"technologies": [{"name", "version"}], "servers": [..], "waf": {"detected", "name", "evidence", "blocks_attacks"}, "open_ports": [{"port", "protocol", "service", "product", "version"}], "api_specs": [url], "out_of_scope_hosts": {"host": jumlah}, "estimated_requests"}`. Di API checkpoint, `out_of_scope_hosts` ditampilkan sebagai `[{"host", "count"}]` dan digabung dengan host yang ditolak proxy di `request_log`. |
| `stats` | `jsonb` | Cache angka untuk monitor: total request, ditolak scope, dicurigai blokir, laju saat ini, temuan per status. |
| `error` | `text` null | |
| `created_at`, `started_at`, `finished_at` | `timestamptz` | |

Constraint (`CHECK`):
- `kind = 'scan'` wajib punya `profile`; `kind = 'retest'` wajib tanpa `profile`.
- `status = 'paused'` jika dan hanya jika `paused_reason` terisi.

### 5.2 `task`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `scan_id` | FK → `scan` cascade | |
| `stage` | `text` | Sama dengan `scan.stage`. |
| `module` | `text` | Misalnya `input_validation`. |
| `engine` | `text` | Misalnya `nuclei`, `sqlmap`, `custom:jwt`, `validator:sqli`, `llm:classify_endpoint`. |
| `target` | `jsonb` | `{"endpoint_ids": [..], "parameter": "q", "finding_id": null, "account": "Akun B"}`. |
| `params` | `jsonb` | Parameter tool atau cek. |
| `status` | `text` | `pending`, `running`, `done`, `failed`, `skipped`, `blocked`. |
| `attempt` | `smallint` default 0 | Jumlah percobaan. Naik saat diambil worker; turun lagi bila tugas dihentikan karena jeda atau worker berhenti dengan baik. |
| `locked_by` | `text` null | ID proses worker (`host:pid:acak`). |
| `locked_at`, `started_at`, `finished_at` | `timestamptz` null | |
| `result_summary` | `jsonb` null | Ringkasan hasil (jumlah kandidat, endpoint baru). |
| `raw_output_enc` | `bytea` null | Keluaran mentah tool, dipotong pada batas ukuran. |
| `error` | `text` null | |
| `created_at` | `timestamptz` | |

Indeks: `(scan_id, status)`, dan indeks parsial `(created_at) WHERE status = 'pending'` untuk pengambilan antrean.

Catatan implementasi (F4): `locked_at` berfungsi sebagai *lease*. Worker yang menjalankan tugas memperbaruinya setiap putaran (bawaan 5 detik). Tugas `running` yang `locked_at`-nya lebih tua dari batas lease (bawaan 60 detik, `RAJDOLL_WORKER_LEASE_SECONDS`) dianggap milik worker yang mati dan dikembalikan ke `pending`; setelah 3 percobaan, tugas ditandai `failed`. Selain trigger `scan_events`, layanan scan mengirim `NOTIFY rajdoll_worker` saat scan dimulai, dijeda, dilanjutkan, dibatalkan, atau checkpoint dilanjutkan, agar worker langsung bereaksi tanpa menunggu polling.

### 5.3 `scan_event`

Sumber data untuk log, notifikasi, dan SSE.

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `scan_id` | FK → `scan` cascade | |
| `ts` | `timestamptz` | |
| `level` | `text` | `info`, `warning`, `error`. |
| `type` | `text` | `stage_changed`, `task_finished`, `finding_created`, `checkpoint_waiting`, `paused`, `resumed`, `session_expired`, `block_suspected`, `block_sustained`, `rate_reduced`, `completed`, `failed`, `cancelled`, `notice`. `cancelled` dan `notice` (pesan informasi, misalnya modul yang belum tersedia atau log modul) ditambahkan di migrasi `0002`. |
| `message` | `text` | Pesan berbahasa Indonesia untuk UI. |
| `data` | `jsonb` null | |

Indeks: `(scan_id, id)`. Trigger `scan_event_notify` menjalankan `pg_notify('scan_events', '<scan_id>:<id>')` untuk setiap insert, siapa pun yang menulisnya (termasuk peran `rajdoll_tools`).

## 6. Tabel temuan dan pendukung

### 6.1 `finding`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `fingerprint` | `text` | SHA-256 dari `module ‖ vuln_type ‖ method ‖ host ‖ path_template ‖ parameter`. Temuan manual: `manual:<uuid>`. Unik `(engagement_id, fingerprint)`. |
| `title` | `text` | |
| `vuln_type` | `text` | Misalnya `sqli`, `xss_reflected`, `idor`, `info_leak`. Menentukan validator dan template. |
| `module` | `text` | |
| `wstg_id` | `text` null | Misalnya `WSTG-ATHZ-04`. |
| `cwe_id` | `text` null | Misalnya `CWE-639`. |
| `endpoint_id` | FK → `endpoint` null | Null untuk temuan manual yang tidak terkait endpoint di inventaris. |
| `parameter` | `text` null | |
| `severity` | `text` | `critical`, `high`, `medium`, `low`, `info`. Dihitung dari skor CVSS versi utama; diisi manual hanya jika tidak ada vektor CVSS. |
| `cvss31_vector`, `cvss40_vector` | `text` null | |
| `cvss31_score`, `cvss40_score` | `numeric(3,1)` null | Selalu dihitung dari vektor. |
| `validation` | `text` | `confirmed`, `needs_manual_check`, `manual`. |
| `decision` | `text` default `pending` | `pending`, `accepted`, `rejected`. |
| `decision_reason` | `text` null | Wajib jika `rejected`. |
| `decided_at` | `timestamptz` null | |
| `retest_result` | `text` default `not_tested` | `not_tested`, `fixed`, `still_vulnerable`, `untestable`, `needs_manual_retest`. Salinan hasil putaran retest terakhir. |
| `description`, `impact`, `recommendation` | `text` | Awalnya dari template, bisa disunting. |
| `references` | `jsonb` | Daftar tautan. |
| `template_id` | FK → `finding_template` null | |
| `poc_spec_enc` | `bytea` null | Lihat 6.2. |
| `llm_notes_enc` | `bytea` null | JSON `{"explanation", "impact", "fix", "manual_test_suggestions": [..], "possible_duplicates": [<id temuan>], "verification_rounds": [{"round", "requests": [{"method", "path", "status" \| "skipped"}], "base_value", "reasoning", "validator_note", "confirmed"}]}`. Putaran baru ditambahkan; kunci lain diganti oleh triase terakhir (F7b). |
| `merged_into_id` | FK → `finding` null | Diisi jika digabung ke temuan lain; temuan ini disembunyikan dari daftar dan laporan. |
| `first_scan_id`, `last_scan_id` | FK → `scan` null | |
| `created_at`, `updated_at` | `timestamptz` | |

Pemetaan severity dari skor (sama untuk CVSS 3.1 dan 4.0): 9.0–10.0 `critical`, 7.0–8.9 `high`, 4.0–6.9 `medium`, 0.1–3.9 `low`, 0.0 `info`.

Aturan konsistensi:
- `validation = 'manual'` ⇒ `decision = 'accepted'` saat dibuat (service layer).
- `retest_result <> 'not_tested'` ⇒ `decision = 'accepted'` (`CHECK`). Mengubah keputusan dari `accepted` harus mengembalikan `retest_result` ke `not_tested` lebih dulu.
- `decision = 'rejected'` ⇒ `decision_reason` tidak kosong (`CHECK`).
- `cvss31_score` dan `cvss40_score` di antara 0 dan 10 (`CHECK`).

Indeks: `(engagement_id, decision, severity)`, `(engagement_id, validation)`.

### 6.2 Isi `poc_spec_enc`

```json
{
  "method": "GET",
  "path": "/api/users/1001",
  "query": {"expand": "profile"},
  "headers": {"Accept": "application/json"},
  "body": null,
  "body_encoding": "none",
  "account": "Akun B",
  "validator": "idor",
  "validator_params": {"owner_account": "Akun A", "compare_fields": ["email", "nip"]}
}
```

Path disimpan relatif; host diambil dari endpoint temuan (atau `target_url` jika temuan tidak terkait endpoint), atau dari `scan.base_url` saat retest. Sesi akun diambil dari `target_account` saat dijalankan, tidak disimpan di PoC.

Untuk temuan Authorization, `account` adalah akun yang sesinya dipakai untuk mengirim PoC. `idor`: `validator_params` berisi `parameter`, `location` (`path` atau `query`), `owner_account` (pemilik objek), `control_path` dan `control_query` (objek pembanding milik akun pengirim, atau objek yang tidak ada). `privilege_escalation`: `privileged_account` dan `reference_path` (fungsi admin yang menolak akun pengirim; `null` jika kandidat hanya berdasarkan penilaian LLM). Detail temuan dan laporan menampilkan akun yang harus dipakai.

Untuk temuan JWT (`jwt_signature_not_verified`, `jwt_alg_none`, `jwt_weak_secret`), `headers` berisi token palsu yang diterima dan `account` adalah akun yang tokennya diubah; `validator_params` berisi `location` (`header` atau `cookie`), `name`, `protected_path`, serta `variant` (`alg: none`) atau `secret` dan `forged_accepted` (secret lemah). `weak_lockout`: `body` berisi username acak dan password salah; `validator_params` berisi `user_field`, `password_field`, `other_fields`, `csrf_field`, dan `attempts`. `cookie_flags`: `account` (`null` jika cookie dibuat tanpa sesi) dan `validator_params` berisi `cookie` dan `missing`. Untuk temuan Configuration & Deployment: `sensitive_file`, `backup_file`, `debug_exposed` dari nuclei membawa `validator_params` `source = "nuclei_template"`, `template`, dan `template_id`; cadangan dari cek RAJDOLL membawa `source = "backup"`, `original_path`, dan `suffix`. `missing_security_headers` membawa `missing`, `version_disclosure` membawa `header`, dan PoC `http_trace` memakai metode `TRACE`. `error_disclosure` dari parameter memakai bentuk PoC Input Validation dengan nilai uji, `base`, dan `patterns`; dari halaman tidak ditemukan membawa `source = "not_found"` dan `patterns`. Temuan TLS (`weak_tls_protocol`, `weak_cipher`, `certificate_problem`, `tls_vulnerability`) membawa `source = "sslyze"`, `host`, `port`, dan `details`; evidence-nya ringkasan hasil SSLyze, bukan pasangan request/response HTTP. `cleartext_credentials` membawa `body_params` endpoint login.

Untuk temuan Input Validation, `query` dan `body` berisi request dengan payload deteksi, dan `validator_params` berisi `parameter`, `location` (`query`, `form`, `json`, `multipart`), `base` (nilai normal yang dipakai saat deteksi), serta rincian teknik (misalnya `technique`, `syntax`, `separator`).

### 6.3 `evidence`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `finding_id` | FK → `finding` cascade | |
| `scan_id` | FK → `scan` null | Scan atau putaran retest asal evidence. |
| `kind` | `text` | `detection`, `validation`, `verification_round`, `resend`, `retest`, `manual`. |
| `sequence` | `int` | Urutan tampil dalam satu temuan. |
| `request_enc` | `bytea` | Request mentah. |
| `response_enc` | `bytea` null | Response mentah, dipotong pada `evidence_max_bytes`. |
| `response_status` | `int` null | |
| `truncated` | `boolean` | |
| `note` | `text` null | |
| `created_at` | `timestamptz` | |

### 6.4 `retest_result`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `scan_id` | FK → `scan` (kind = `retest`) cascade | |
| `finding_id` | FK → `finding` cascade | |
| `auto_result` | `text` null | Hasil otomatis: `fixed`, `still_vulnerable`, `untestable`, `needs_manual_retest`. |
| `result` | `text` | Hasil akhir; sama dengan `auto_result` kecuali dikoreksi. |
| `corrected` | `boolean` default `false` | |
| `note` | `text` null | |
| `created_at`, `updated_at` | `timestamptz` | |

Unik: `(scan_id, finding_id)`. Setiap perubahan `result` pada putaran terbaru disalin ke `finding.retest_result`.

### 6.5 `finding_template`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `vuln_type` | `text` unique | |
| `title` | `text` | |
| `wstg_id`, `cwe_id` | `text` null | |
| `description`, `impact`, `recommendation` | `text` | Bahasa Indonesia. |
| `references` | `jsonb` | |
| `cvss31_vector`, `cvss40_vector` | `text` null | Vektor bawaan. |
| `default_severity` | `text` | Dipakai jika tidak ada vektor. |
| `is_builtin` | `boolean` | Template bawaan; bisa disunting, dan bisa dikembalikan ke isi awal. |
| `created_at`, `updated_at` | `timestamptz` | |

Isi awal dipindahkan dari `multi_agent_system/data/enrichment_kb.json` lalu diterjemahkan dan dilengkapi vektor CVSS.

### 6.6 `llm_call`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `scan_id` | FK → `scan` null | |
| `task_kind` | `text` | `classify_endpoint`, `build_input`, `judge_response`, `verification_step`, `triage_finding`. |
| `finding_id`, `endpoint_id` | FK null | Untuk penelusuran dari temuan (PRD F-37). |
| `model` | `text` | |
| `is_local` | `boolean` | |
| `prompt_enc`, `output_enc` | `bytea` | |
| `status` | `text` | `ok`, `schema_retry_ok`, `schema_error`, `timeout`, `error`, `skipped_budget`. Tidak ada baris jika LLM dimatikan atau server sedang dianggap tidak terjangkau (lihat TRD 5.4). |
| `tokens_in`, `tokens_out`, `duration_ms` | `int` null | |
| `created_at` | `timestamptz` | |

### 6.7 `request_log` (audit)

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `scan_id` | FK → `scan` null | |
| `task_id` | `bigint` null | Tanpa FK agar insert cepat. |
| `ts` | `timestamptz` | |
| `kind` | `text` | `http` (termasuk tunnel `CONNECT` SSLyze yang diteruskan tanpa didekripsi), `tool_exec` (nmap). |
| `tool` | `text` | |
| `method` | `text` null | |
| `url` | `text` | Untuk `tool_exec`: target dan ringkasan argumen. |
| `host` | `text` | |
| `status` | `int` null | |
| `response_bytes` | `int` null | |
| `duration_ms` | `int` null | |
| `outcome` | `text` | `forwarded`, `blocked_scope`, `block_suspected`, `error`. |

Indeks: `(scan_id, ts)`, `(engagement_id, outcome)`. Volume diperkirakan puluhan ribu baris per scan; tidak dipartisi di v1. Tidak dienkripsi (keputusan TRD 8.1).

### 6.8 `report_export`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | PK | |
| `engagement_id` | FK → `engagement` | |
| `kind` | `text` | `va`, `retest`. |
| `retest_scan_id` | FK → `scan` null | Wajib jika `kind = 'retest'`. |
| `finding_count` | `int` | |
| `warnings` | `jsonb` | Misalnya jumlah temuan belum diputuskan, pengujian terblokir. |
| `content_enc` | `bytea` | Isi Markdown. |
| `created_at` | `timestamptz` | |

## 7. Kunci enkripsi

| Kunci | Lokasi | Keterangan |
|---|---|---|
| Kunci utama | `secrets/master.key` di volume `secrets` | 32 byte acak, dibuat saat instalasi pertama. |
| Kunci data penugasan | `secrets/engagements/<key_id>.key` | 32 byte acak, disimpan terbungkus (dienkripsi) dengan kunci utama. |
| Kunci untuk `app_setting` | Kunci utama langsung | Hanya untuk `llm.api_key_enc`. |

Kunci data penugasan disimpan di volume `secrets`, **bukan di database**, agar salinan atau backup database tidak pernah berisi kuncinya.

**Urutan penghapusan penugasan:**
1. Hapus berkas `secrets/engagements/<key_id>.key`. Sejak titik ini semua data terenkripsi penugasan tidak bisa dibaca.
2. Hapus baris `engagement` (cascade ke semua tabel terkait).
3. Saat aplikasi menyala, berkas kunci tanpa baris `engagement` yang sesuai (sisa dari proses yang terputus) dihapus otomatis.

## 8. Peran database

| Peran | Dipakai oleh | Hak |
|---|---|---|
| `rajdoll_app` | `api`, `worker`, migrasi | Pemilik skema, semua hak. |
| `rajdoll_tools` | Egress proxy di `tools` | `SELECT` pada `task`, `scan`, `scope_rule`, `engagement` (kolom `id`, `settings`); `INSERT` pada `request_log` dan `scan_event`. |

Dengan pembatasan ini, container `tools` tidak bisa membaca temuan, evidence, atau sesi.

Peran `rajdoll_tools` dibuat oleh migrasi baseline tanpa `LOGIN`. Langkah bootstrap di `api` mengaktifkan login dengan password dari `TOOLS_DB_PASSWORD` (`.env`) setiap kali container menyala; `api` adalah satu-satunya layanan yang menerima password ini selain `tools`.

## 9. Pemetaan istilah AFD

| AFD (UI) | Skema |
|---|---|
| Penugasan: draf, siap, aktif, selesai | `engagement.status`: `draft`, `ready`, `active`, `done` |
| Scan: antre | `scan.status = queued` |
| Scan: recon, perencanaan, pengujian, validasi, triase AI | `status = running`, `stage` = `recon`, `planning`, `testing`, `validation`, `ai_triage` |
| Scan: menunggu checkpoint | `status = awaiting_checkpoint`, `stage = planning` |
| Scan: dijeda | `status = paused`, `stage` tetap, `paused_reason` diisi |
| Scan: selesai, dibatalkan, gagal | `status` = `completed`, `cancelled`, `failed` |
| Tugas: pending … blocked | `task.status` dengan nama yang sama |
| Temuan `validasi`: terkonfirmasi, perlu cek manual, manual | `finding.validation`: `confirmed`, `needs_manual_check`, `manual` |
| Temuan `keputusan`: belum, diterima, ditolak | `finding.decision`: `pending`, `accepted`, `rejected` |
| Temuan `hasil_retest`: belum, diperbaiki, masih rentan, tidak bisa diuji, perlu retest manual | `finding.retest_result`: `not_tested`, `fixed`, `still_vulnerable`, `untestable`, `needs_manual_retest` |
| Putaran retest: persiapan | Belum ada baris `scan`; data hanya di form |
| Putaran retest: antre, berjalan, dijeda, selesai, dibatalkan | `scan.kind = retest`, `status` sesuai, `stage = retest` |

## 10. Kontrak API

### 10.1 Prinsip

- **Satu set rute** melayani UI dan API. Format respons ditentukan dari permintaan:
  - Navigasi browser biasa → halaman HTML penuh.
  - Request HTMX (header `HX-Request`) → potongan HTML.
  - `Accept: application/json` → JSON sesuai skema di bawah.
- HTML wajib di v1. JSON berprioritas **Should**: dipakai untuk skrip dan mode agen di versi berikutnya, dan boleh ditambahkan bertahap per rute.
- Semua rute (kecuali setup awal dan login) butuh cookie sesi. Rute yang mengubah data butuh header `X-CSRF-Token`.
- Galat JSON: `{"error": {"code": "scope_violation", "message": "…", "details": {…}}}` dengan kode HTTP yang sesuai (400, 401, 403, 404, 409, 422).
- Daftar memakai paginasi `?limit=50&cursor=<id>`; respons berisi `{"items": [...], "next_cursor": …}`.

### 10.2 Autentikasi dan pengaturan

| Metode | Path | Keterangan |
|---|---|---|
| `GET`/`POST` | `/setup` | Buat password. Hanya tersedia jika `app_user` kosong. |
| `GET`/`POST` | `/login` | Body: `password`. Mengatur cookie sesi. |
| `POST` | `/logout` | |
| `POST` | `/settings/password` | Body: `current_password`, `new_password`. |
| `GET`/`PATCH` | `/settings` | Membaca dan mengubah `app_setting`. |
| `POST` | `/settings/llm/test` | Uji koneksi LLM; balikan: `{"ok", "model", "latency_ms", "error"}`. Memakai nilai di form (`llm_base_url`/`base_url`, `llm_model`/`model`, `llm_api_key`/`api_key`) atau yang tersimpan, tanpa menyimpan. |

### 10.3 Penugasan, scope, akun

| Metode | Path | Keterangan |
|---|---|---|
| `GET` | `/engagements` | Daftar penugasan beserta ringkasan angka temuan. |
| `POST` | `/engagements` | Body: `name`, `organization`, `target_url`, `notes`, `start_date`, `end_date`. Scope awal dibuat dari host `target_url`. |
| `GET`/`PATCH` | `/engagements/{id}` | |
| `DELETE` | `/engagements/{id}` | Body: `confirm_name`. Ditolak `409` jika ada scan berjalan. |
| `GET`/`POST` | `/engagements/{id}/scope` | Body `POST`: `pattern`. |
| `DELETE` | `/engagements/{id}/scope/{rule_id}` | Ditolak jika aturan terakhir atau `target_url` jadi di luar scope. |
| `GET`/`POST` | `/engagements/{id}/accounts` | Body `POST`: `label`, `auth_method`, `session` (`cookies` dan/atau `headers`, atau teks mentah), `credentials` (untuk auto-login). |
| `PATCH`/`DELETE` | `/engagements/{id}/accounts/{account_id}` | |
| `POST` | `/engagements/{id}/accounts/{account_id}/check` | Uji sesi lewat egress proxy; balikan: `{"status", "checked_at", "checked", "message", "http_status"}`. `checked = false` berarti pemeriksaan tidak bisa dijalankan (proxy atau target tidak terjangkau) dan status akun tidak diubah. |
| `PUT` | `/engagements/{id}/session-check` | Body: `url`, `marker`. |
| `GET` | `/engagements/{id}/endpoints` | Filter: `tag`, `excluded`, `source`. |

Catatan:
- `/` menampilkan daftar penugasan yang sama dengan `GET /engagements`.
- Halaman yang hanya untuk UI: `GET /engagements/new` (form penugasan baru) dan `GET /engagements/{id}/settings` (tab Pengaturan; versi JSON-nya berisi `settings` dan `effective_settings`). Tab Scope & Akun disajikan oleh `GET /engagements/{id}/scope`.
- `PATCH /engagements/{id}` mengubah satu bagian per permintaan, dipilih lewat field `section`: `details` (nama, instansi, URL target, catatan, tanggal), `overrides` (pengaturan scan, untuk JSON di dalam `settings`), atau `status` (`done` untuk menandai selesai, `reopen` untuk membuka kembali). Klien JSON boleh tanpa `section`; bagiannya ditentukan dari field yang dikirim.
- `DELETE` membaca `confirm_name` dari query string, body JSON, atau form, karena htmx 2 mengirim parameter `DELETE` di URL.
- Status `draft`/`ready` dihitung ulang setiap kali scope atau URL target berubah; `active` dan `done` tidak disentuh.

Contoh `POST /engagements` (JSON):

```json
// request
{"name": "SIMPEG (clone)", "organization": "Instansi A",
 "target_url": "https://simpeg.instansi.test", "notes": "ST-123/2026",
 "start_date": "2026-11-10", "end_date": "2026-11-21"}

// response 201
{"id": 7, "status": "draft", "scope": ["simpeg.instansi.test"], "created_at": "2026-11-04T03:10:00Z"}
```

### 10.4 Scan dan checkpoint

| Metode | Path | Keterangan |
|---|---|---|
| `GET` | `/engagements/{id}/scans` | Riwayat scan (`kind = scan`). |
| `POST` | `/engagements/{id}/scans` | Body: `profile` (`full`/`custom`), `modules` (untuk `custom`). Balikan `202` berisi scan. |
| `GET` | `/scans/{scan_id}` | Status, tahap, statistik, `checkpoint_deadline`, `paused_reason`. |
| `POST` | `/scans/{scan_id}/pause` | |
| `POST` | `/scans/{scan_id}/resume` | Body opsional: `rate_limit_rps` (dipakai saat lanjut setelah blokir WAF). Ditolak `409` jika alasan jeda `session_expired` dan sesi belum valid. |
| `POST` | `/scans/{scan_id}/cancel` | |
| `POST` | `/scans/{scan_id}/skip-blocked-modules` | Menandai tugas modul yang terblokir sebagai `blocked`, lalu melanjutkan scan. |
| `GET` | `/scans/{scan_id}/tasks` | Filter: `status`, `module`. |
| `GET` | `/scans/{scan_id}/events` | Polling: `?after_id=`. |
| `GET` | `/scans/{scan_id}/events/stream` | SSE untuk UI. Nama event: `stage`, `task`, `stats`, `finding`, `notice`, `done`. Isi event berupa potongan HTML untuk ekstensi SSE HTMX. |
| `GET` | `/scans/{scan_id}/checkpoint` | Data checkpoint (lihat contoh). |
| `POST` | `/scans/{scan_id}/checkpoint/hold` | Menahan hitung mundur (`checkpoint_deadline = null`) saat mulai menyunting. |
| `PATCH` | `/scans/{scan_id}/checkpoint` | Body: `modules`, `endpoints` (`[{"id", "excluded", "tags"}]`), `add_endpoints` (`[{"method", "url"}]` atau `[{"raw_request"}]`), `add_scope` (`[pattern]`). Hanya saat `awaiting_checkpoint` (selain itu `409`); suntingan pertama menahan hitung mundur. Halaman checkpoint mengirim satu aksi per form (`action` = `exclude`, `include`, `tags`, `modules`, `add_endpoint`, `raw_request`, `add_scope`). |
| `POST` | `/scans/{scan_id}/checkpoint/continue` | Lanjut ke tahap pengujian. |

Catatan implementasi (F4b):
- Stream SSE memakai satu koneksi `LISTEN scan_events` per klien. Setiap ada notifikasi untuk scan itu (dan paling lambat setiap 15 detik), potongan `stage`, `task`, `stats`, dan `finding` dirender ulang dan hanya yang berubah dikirim. `notice` berisi baris log baru dengan `id` = ID event terakhir, sehingga browser yang tersambung ulang (header `Last-Event-ID`) tidak menerima baris lama. `done` dikirim setelah scan selesai, dibatalkan, atau gagal; halaman memakainya sebagai `sse-close` agar browser tidak menyambung ulang. Stream ditutup server setelah 10 menit dan browser menyambung ulang sendiri.
- `GET /scans/{scan_id}/events` mengembalikan event urut naik (untuk polling); versi HTML berisi 500 baris terbaru.
- Aksi jeda, lanjut, batal, dan checkpoint menjawab potongan status scan untuk htmx, JSON ringkasan scan untuk klien JSON, atau redirect ke monitor untuk form biasa.
- Sejak F5b, rencana dihitung dari inventaris setiap kali ditampilkan: setiap endpoint membawa `modules` (modul yang akan mengujinya menurut tanda, `rajdoll/services/planning.py`), `recon_summary.estimated_requests` berisi perkiraan request tahap pengujian, dan `modules` berisi ke-12 modul profil Lengkap dengan `enabled`, `skipped_reason` (`not_available`, `needs_two_accounts`, `disabled`), dan jumlah endpoint. `editable` bernilai `true` selama scan menunggu checkpoint. Request Burp yang ditempel disimpan terenkripsi di `endpoint.sample_request_enc`; endpoint tambahan manual tidak dikenai pola pengecualian.
- Sejak F5a, `GET /scans/{scan_id}/checkpoint` berisi tenggat, `recon_summary` (lihat `scan.recon_summary`), daftar modul, dan inventaris endpoint penugasan (kolom BSD 4.4 ditambah `url`). Host yang dihubungi tool sendiri (`burpsuite`, probe proxy milik ProjectDiscovery) tidak ditampilkan sebagai host di luar scope. `PATCH /scans/{scan_id}/checkpoint` hadir di F5 dan `POST /scans/{scan_id}/skip-blocked-modules` di F9.

Contoh `GET /scans/{scan_id}/checkpoint`:

```json
{
  "scan_id": 12,
  "deadline": "2026-11-04T03:41:00Z",
  "recon_summary": {
    "technologies": [{"name": "nginx", "version": "1.24"}, {"name": "Laravel", "version": null}],
    "waf": {"detected": true, "name": "ModSecurity", "evidence": "header Server, halaman blokir 403"},
    "out_of_scope_hosts": [{"host": "cdn.instansi.test", "count": 41}],
    "estimated_requests": 21000
  },
  "modules": [{"name": "authorization", "enabled": true, "skipped_reason": null}],
  "endpoints": [
    {"id": 301, "method": "GET", "host": "simpeg.instansi.test", "path_template": "/api/users/{id}",
     "params": ["id"], "tags": ["idor_candidate"], "tag_source": "llm",
     "modules": ["authorization", "input_validation"], "excluded": false, "exclude_reason": null}
  ]
}
```

### 10.5 Temuan

| Metode | Path | Keterangan |
|---|---|---|
| `GET` | `/engagements/{id}/findings` | Filter: `validation`, `decision`, `severity`, `module`, `scan_id`. Urutan bawaan sesuai AFD A8. |
| `POST` | `/engagements/{id}/findings` | Temuan manual. Body: `template_id`, `title`, `method`, `url`, `parameter`, `description`, `impact`, `recommendation`, `cvss31_vector`, `cvss40_vector`, `severity` (jika tanpa CVSS), `evidence` (`request`, `response`). |
| `GET` | `/findings/{finding_id}` | Detail tanpa evidence. |
| `PATCH` | `/findings/{finding_id}` | Ubah teks dan vektor CVSS; skor dan severity dihitung ulang. |
| `POST` | `/findings/{finding_id}/decision` | Body: `decision` (`accepted`/`rejected`/`pending`), `reason`. |
| `POST` | `/findings/{finding_id}/merge` | Body: `into_finding_id`. Evidence dipindahkan ke temuan tujuan. |
| `GET` | `/findings/{finding_id}/evidence` | Daftar evidence (didekripsi). |
| `GET` | `/findings/{finding_id}/poc` | `?format=curl` atau `?format=raw`; balikan `text/plain`. |
| `POST` | `/findings/{finding_id}/resend` | Body: `raw_request`, `account`. Dikirim lewat egress proxy; hasil disimpan sebagai evidence `resend`. Ditolak `403` jika di luar scope. |

Catatan implementasi (F6c): `GET`, `/decision`, `/evidence`, dan `/poc` tersedia; `POST /engagements/{id}/findings`, `PATCH`, `/merge`, dan `/resend` datang di F9. `GET /findings/{id}` dari navigasi browser biasa dialihkan ke tab Temuan dengan temuan itu terpilih; dengan HTMX membalas panel detail. Daftar belum dipaginasi (`next_cursor` selalu `null`). PoC `raw` dan `curl` tidak memuat sesi akun.

Contoh `GET /findings/{finding_id}`:

```json
{
  "id": 88, "title": "IDOR pada /api/users/{id}", "vuln_type": "idor",
  "module": "authorization", "wstg_id": "WSTG-ATHZ-04", "cwe_id": "CWE-639",
  "endpoint": {"id": 301, "method": "GET", "path_template": "/api/users/{id}"},
  "parameter": "id", "severity": "high",
  "cvss31": {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "score": 6.5},
  "cvss40": {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "score": 7.1},
  "validation": "confirmed", "decision": "pending", "retest_result": "not_tested",
  "description": "…", "impact": "…", "recommendation": "…",
  "llm_notes": {"explanation": "…", "manual_test_suggestions": ["…"]},
  "evidence_count": 2, "first_scan_id": 12, "last_scan_id": 12
}
```

Pada contoh ini severity `high` mengikuti skor CVSS 4.0 (7.1) karena `cvss_primary` diatur ke `"4.0"`; dengan bawaan `"3.1"` severity menjadi `medium` (6.5). Angka contoh hanya ilustrasi.

### 10.6 Retest

| Metode | Path | Keterangan |
|---|---|---|
| `GET` | `/engagements/{id}/retests` | Daftar putaran. |
| `POST` | `/engagements/{id}/retests` | Body: `base_url` (opsional), `finding_ids` (bawaan: semua yang diterima). Balikan `202` berisi scan `kind = retest`. Jeda, lanjut, dan batal memakai rute `/scans/{scan_id}/…`. |
| `GET` | `/retests/{scan_id}/results` | Hasil per temuan, termasuk perbandingan dengan putaran sebelumnya. |
| `PATCH` | `/retests/{scan_id}/results/{finding_id}` | Body: `result`, `note`. Menandai `corrected = true`. |

### 10.7 Laporan dan template

| Metode | Path | Keterangan |
|---|---|---|
| `GET` | `/engagements/{id}/reports` | Riwayat ekspor. |
| `POST` | `/engagements/{id}/reports` | Body: `kind` (`va`/`retest`), `retest_scan_id`. Balikan `201` berisi `id` dan `warnings`. |
| `GET` | `/reports/{report_id}` | Pratinjau (HTML hasil render Markdown). |
| `GET` | `/reports/{report_id}/download` | `text/markdown`, nama berkas `<aplikasi>-<jenis>-<tanggal>.md`. |

Catatan implementasi (F6c): hanya `kind = va`; `retest` dibalas 422 sampai F10. `warnings` disimpan sebagai `{"pending_findings": n, "blocked_tasks": n}`; balikan `POST` berisi pesannya. Pratinjau dirender dari Markdown dengan HTML mentah dimatikan, dan evidence target ditaruh dalam blok kode yang pagarnya lebih panjang dari deretan backtick di dalamnya. Nama berkas memakai slug ASCII dari nama penugasan dan tanggal WIB. Rute template temuan datang di F9.
| `GET`/`POST` | `/finding-templates` | |
| `GET`/`PATCH`/`DELETE` | `/finding-templates/{id}` | Template bawaan tidak bisa dihapus, hanya disunting atau dikembalikan ke isi awal (`POST /finding-templates/{id}/reset`). |

## 11. API internal (`worker` → `tools`)

Hanya di jaringan internal Docker, dengan token bersama `TOOLS_TOKEN` (`.env`) di header `Authorization: Bearer <token>`. Token yang sama dipakai sebagai password kredensial egress proxy (TRD 4.2).

| Metode | Path | Keterangan |
|---|---|---|
| `GET` | `/health` | Status dan versi setiap tool serta template nuclei. |
| `POST` | `/run` | Menjalankan satu tool. |
| `POST` | `/run/{run_id}/cancel` | Menghentikan tool yang sedang berjalan (untuk jeda dan batal). |
| — | `/mcp` | Server MCP; tidak dipakai di v1. |

Contoh `POST /run`:

```json
// request
{
  "task_id": 4521, "scan_id": 12, "tool": "sqlmap", "timeout_s": 900,
  "scope": ["simpeg.instansi.test"],
  "params": {
    "url": "https://simpeg.instansi.test/api/search?q=test",
    "method": "GET", "parameter": "q",
    "headers": {"Cookie": "session=…"},
    "level": 2, "risk": 2
  }
}

// response 200
{
  "run_id": "b3f1…", "status": "completed", "exit_code": 0, "duration_ms": 182340,
  "normalized": {
    "candidates": [{"vuln_type": "sqli", "parameter": "q", "technique": "boolean-based blind",
                    "request": "GET /api/search?q=… HTTP/1.1\r\n…", "detail": "…"}],
    "endpoints": []
  },
  "raw_output": "…", "raw_truncated": true
}
```

Nilai `status`: `completed`, `failed`, `timeout`, `cancelled`, `scope_rejected`. Sesi akun dikirim oleh worker setiap pemanggilan dan tidak disimpan oleh `tools`.

Catatan implementasi (F3b):
- `run_id` dikirim oleh pemanggil (8–64 karakter `[A-Za-z0-9_-]`) supaya `POST /run/{run_id}/cancel` bisa dipanggil saat `/run` masih berjalan.
- `scope_rejected` dibalas tanpa menjalankan tool, dengan daftar host di luar scope di `out_of_scope`.
- Respons juga memuat `parse_error` (galat pengurai, keluaran mentah tetap dikembalikan) dan `stderr_tail`.
- Parameter tool yang tidak valid dibalas 422 tanpa memantulkan nilai yang ditolak, karena nilai header bisa berisi sesi.
- Tool yang tersedia: `httpx` (`urls`, `follow_redirects`, `threads`, `timeout_s`, `headers`) dan `nuclei` (`targets`, `templates`, `tags`, `severities`, `rate_limit`, `concurrency`, `timeout_s`, `follow_redirects`, `dast`, `oob`, `headers`). Model parameternya ada di `tools/runner/adapters/`.
- F5 menambah `katana`, `ffuf`, `nmap`, `browser`, dan `xss_check` (F6a). F6b menambah `sqlmap`, `commix`, dan `dalfox`. Ketiganya menerima request terstruktur, bukan baris perintah: `request` (`method`, `url` tanpa query string, `query`, `body`, `body_encoding` `form`/`json`) ditambah `parameter` dan `location` (`query`/`body`); dalfox menerima `parameters` (daftar). `nuclei` bisa menerima `requests` (daftar request dengan bentuk yang sama) sebagai ganti `targets`, untuk mode DAST. Contoh `params` sqlmap di atas ditulis dalam bentuk ini: `{"request": {"url": "https://simpeg.instansi.test/api/search", "query": {"q": "test"}}, "parameter": "q", "level": 2, "risk": 2, "headers": {...}}`.
- Hasil `normalized.candidates` sqlmap, commix, dan dalfox memuat `value`: nilai parameter berisi payload, yang dikirim ulang oleh worker sebagai evidence.

## 12. Perubahan terhadap dokumen lain

- **TRD 8.2 dan 12** diperbarui: kunci data penugasan disimpan sebagai berkas di volume `secrets`, bukan di database (bagian 7 dokumen ini).
- **AFD 3.4** merujuk ke bagian 9 dokumen ini untuk nama kolom dan nilai di database.
