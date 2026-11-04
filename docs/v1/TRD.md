# TRD — RAJDOLL v1: Asisten Asesor VA Web

| | |
|---|---|
| Dokumen | Technical Requirement Document (TRD) |
| Acuan | PRD v1.1 (`docs/v1/PRD.md`) |
| Status | Draf untuk ditinjau |
| Dokumen terkait | AFD (alur dan layar), BSD (skema data dan API), IPD (tahapan) |

Dokumen ini menjelaskan **bagaimana** kebutuhan di PRD dipenuhi secara teknis. Skema tabel dan kontrak API dirinci di BSD; di sini hanya disebut sejauh perlu untuk menjelaskan desain.

---

## 1. Prinsip desain

| No | Prinsip | Akibatnya |
|---|---|---|
| P1 | **Deterministik dulu.** Alur, pengujian, dan keputusan valid atau tidaknya temuan ditentukan kode dan aturan. | LLM tidak pernah mengendalikan urutan pipeline. |
| P2 | **LLM opsional dan terbatas.** Setiap tugas LLM kecil, berformat terstruktur, punya batas token, dan punya jalan cadangan tanpa LLM. | Pipeline tetap selesai walaupun LLM mati (PRD F-22). |
| P3 | **LLM tidak pernah sendirian menetapkan "terkonfirmasi".** Status itu hanya diberikan jika ada bukti deterministik. | Penilaian LLM hanya bisa menaikkan prioritas atau menambah catatan, bukan memvalidasi. |
| P4 | **Semua status di database.** Setiap tahap dan tugas pipeline tercatat dan bisa diulang dengan aman. | Pause, crash, atau restart laptop tidak membuat scan mulai dari awal (F-13). |
| P5 | **Satu pintu keluar.** Semua trafik HTTP ke target melewati satu egress proxy milik RAJDOLL. | Scope, audit log, rate limit, dan deteksi WAF ditegakkan di satu tempat. |
| P6 | **Evidence dulu.** Request dan response yang menjadi dasar temuan disimpan saat itu juga. | Laporan dan retest tidak bergantung pada tool atau Burp. |
| P7 | **Versi dikunci.** Semua tool, template, dan library memakai versi pasti. | Hasil bisa diulang dan tidak rusak karena pembaruan diam-diam. |

## 2. Arsitektur

### 2.1 Gambaran

```
 Windows (host)                                   Docker Desktop (WSL2)
 ───────────────                                  ────────────────────────────────────────────
 Browser ──── http://127.0.0.1:8000 ────────────▶ [api]  FastAPI + HTMX (UI dan REST)
                                                     │  ▲
                                                     │  │ SSE (LISTEN/NOTIFY)
                                                     ▼  │
                                                   [db]  PostgreSQL 16
                                                     ▲  │ antrean tugas, status, temuan, evidence
                                                     │  ▼
 LM Studio ◀── host.docker.internal:1234 ──────── [worker]  workflow engine, validator, lapisan LLM
 (LLM lokal, GPU)                                    │
                                                     ▼ HTTP internal
                                                  [tools]  runner tool + egress proxy + MCP
                                                     │      nuclei, katana, ffuf, httpx, sqlmap,
                                                     │      dalfox, nmap, testssl.sh, retire.js, ...
                                                     ▼
                                                  Target (clone aplikasi instansi)

 Burp Suite Community: dipakai manual oleh asesor, tidak terhubung ke RAJDOLL.
```

### 2.2 Layanan

| Layanan | Isi | Port | Catatan |
|---|---|---|---|
| `api` | FastAPI, template Jinja2, HTMX, endpoint SSE | `127.0.0.1:8000` | Satu-satunya port yang dibuka ke host, dan hanya di localhost. |
| `worker` | Workflow engine, modul uji, validator, lapisan LLM, pembuat laporan | — | Tidak membuka port. |
| `tools` | Runner tool (API internal), egress proxy, server MCP | internal saja | Satu image berisi semua tool. |
| `db` | PostgreSQL 16 | internal saja | Tidak dibuka ke host (sistem lama membuka 5432 ke semua antarmuka). |

Dibanding sistem lama (api, nginx, worker, db, redis, dan 13 container MCP), jumlah layanan turun dari sekitar 18 menjadi 4. Nginx tidak diperlukan karena UI disajikan langsung oleh `api`. Redis dan Celery diganti antrean di Postgres (bagian 3).

### 2.3 Stack teknologi

| Lapisan | Pilihan |
|---|---|
| Bahasa | Python 3.12 |
| Web | FastAPI, Uvicorn, Jinja2 |
| UI | HTMX 2 (dengan ekstensi SSE), Pico.css. Semua file disimpan lokal di repo, tanpa CDN dan tanpa proses build. |
| Database | PostgreSQL 16, SQLAlchemy 2, Alembic (satu-satunya sistem migrasi), psycopg 3 |
| Kriptografi | `cryptography` (AES-256-GCM), `argon2-cffi` untuk hash password |
| LLM | SDK `openai` ke endpoint yang kompatibel dengan OpenAI; Pydantic v2 untuk skema keluaran |
| CVSS | Library `cvss` (RedHat, versi 3.x ke atas) untuk menghitung skor 3.1 dan 4.0 dari vektor |
| Egress proxy | mitmproxy (sebagai library, dengan addon RAJDOLL) |
| MCP | SDK `mcp` resmi untuk Python |

## 3. Workflow engine (`worker`)

### 3.1 Struktur pipeline

Satu **scan** terdiri dari **tahap** (stage), dan setiap tahap terdiri dari **tugas** (task). Tugas adalah unit terkecil yang dijadwalkan, misalnya "modul Input Validation, mesin sqlmap, endpoint `/api/search`, parameter `q`".

```
scan
 ├─ 1 recon          tugas: crawl, fuzz direktori, fingerprint, port scan, deteksi WAF
 ├─ 2 perencanaan    tugas: klasifikasi endpoint (LLM), pemilihan modul (aturan)
 ├─ ◆ checkpoint     menunggu asesor, atau lanjut otomatis
 ├─ 3 pengujian      tugas: satu per (modul, mesin, endpoint/kelompok endpoint)
 ├─ 4 validasi       tugas: validator per kandidat temuan, mini-loop verifikasi
 ├─ 5 triase AI      tugas: deduplikasi, penjelasan, saran
 └─ selesai          menunggu triase asesor
```

Profil scan (Lengkap dan Kustom) didefinisikan dalam berkas YAML di repo: daftar tahap, modul yang aktif, dan parameter bawaan. Profil Kustom adalah salinan profil Lengkap yang modulnya bisa dipilih di UI.

### 3.2 Antrean tugas di Postgres

- Tugas disimpan di tabel dengan status `pending`, `running`, `done`, `failed`, `skipped`, atau `blocked` (terblokir WAF).
- Worker mengambil tugas dengan `SELECT … FOR UPDATE SKIP LOCKED`, sehingga aman walaupun nanti worker dijalankan lebih dari satu.
- Worker tidur sampai ada `NOTIFY` dari Postgres atau sampai batas polling 5 detik.
- Jumlah tugas paralel diatur per penugasan (bawaan: 2). Tugas LLM dijalankan satu per satu karena GPU hanya satu (bagian 5.4).
- Tahap berikutnya baru dimulai setelah semua tugas di tahap sebelumnya selesai, gagal, atau dilewati.

### 3.3 Pause, resume, crash, dan restart

| Kejadian | Perilaku |
|---|---|
| Pause oleh asesor | Worker berhenti mengambil tugas baru. Tugas yang sedang berjalan dihentikan dan dikembalikan ke `pending`. |
| Resume | Worker melanjutkan dari tugas `pending` berikutnya. |
| Worker crash atau laptop restart | Saat worker hidup kembali, tugas berstatus `running` milik worker lama dikembalikan ke `pending`. |
| Cancel | Semua tugas yang belum selesai menjadi `skipped`. Temuan yang sudah ada tetap disimpan. |

Agar tugas aman diulang, setiap temuan punya **sidik jari** (gabungan modul, jenis kerentanan, endpoint yang dinormalisasi, dan parameter). Temuan dengan sidik jari sama tidak dibuat dua kali; evidence barunya ditambahkan ke temuan yang sudah ada.

### 3.4 Checkpoint setelah perencanaan (PRD F-14, F-46)

- Setelah tahap perencanaan selesai, scan masuk status `menunggu_checkpoint` dengan waktu `lanjut_otomatis_pada` = sekarang + 15 menit (bisa diatur per penugasan, atau checkpoint dimatikan).
- Worker memeriksa status ini setiap kali polling. Jika waktunya lewat dan asesor tidak merespons, scan lanjut ke tahap pengujian dengan rencana apa adanya.
- Sunting rencana di checkpoint (tambah atau kecualikan endpoint, ubah tanda, aktif/nonaktifkan modul) langsung mengubah tugas tahap pengujian sebelum dibuat.
- Aturan bawaan menandai endpoint berisiko sebagai "dikecualikan" berdasarkan pola path dan nama parameter: `logout`, `signout`, `delete`, `remove`, `destroy`, `reset`, `change-password`, `deactivate`, dan sejenisnya. Daftar pola disimpan di berkas konfigurasi.

### 3.5 Sesi login ke target (PRD F-04 sampai F-07)

- Sesi disimpan per **akun** (minimal dua: A dan B) dalam bentuk cookie dan/atau header, terenkripsi.
- Adaptor tool menyisipkan sesi lewat opsi tool masing-masing (misalnya `-H` di nuclei, ffuf, dan katana; `--cookie` dan `--headers` di sqlmap).
- **Deteksi sesi kedaluwarsa:** asesor mengisi satu **URL cek sesi** dan **penanda login** (teks yang hanya muncul saat login, misalnya nama pengguna). Worker memeriksanya setiap 5 menit dan setiap kali proxy melihat lonjakan 401 atau redirect ke halaman login. Jika gagal, scan di-pause dengan alasan "sesi kedaluwarsa" dan UI meminta sesi baru.
- **Auto-login (Should):** skrip Playwright mengisi form login berdasarkan selector yang diberikan asesor, lalu mengambil cookie hasilnya. Ditunda ke akhir v1 jika waktu tidak cukup.

## 4. Runner tool dan egress proxy (`tools`)

### 4.1 Runner

- API HTTP internal: `POST /run` menerima nama tool, parameter bertipe, batas waktu, dan ID tugas; mengembalikan keluaran mentah dan hasil yang sudah dinormalisasi.
- Setiap tool punya **adaptor** yang:
  1. menyusun argumen dari parameter bertipe (tanpa shell, tanpa `shell=True`, tanpa merangkai string perintah dari keluaran LLM),
  2. memeriksa target terhadap scope sebelum menjalankan,
  3. mengarahkan tool ke egress proxy,
  4. mengurai keluaran tool menjadi struktur standar (kandidat temuan, endpoint, teknologi).
- Server MCP di container yang sama membungkus adaptor yang sama. Di v1 tidak dipakai oleh worker; disiapkan untuk mode agen di versi berikutnya (PRD NF-10).

### 4.2 Egress proxy

Semua tool HTTP dan validator diarahkan ke proxy internal berbasis mitmproxy. Proxy ini menjalankan empat fungsi sekaligus:

| Fungsi | Cara kerja | Kebutuhan PRD |
|---|---|---|
| **Penegakan scope** | Host tujuan dicocokkan dengan scope penugasan. Di luar scope: ditolak dengan respons 403 dan dicatat sebagai "host diblokir" (muncul di checkpoint). | F-02, NF-05 |
| **Audit log** | Setiap request dicatat: waktu, tugas, modul, metode, URL, kode status, ukuran. | F-36 |
| **Rate limit** | Token bucket per penugasan, berlaku untuk semua tool sekaligus. | F-15 |
| **Deteksi blokir dan WAF** | Lihat bagian 7. | F-48, F-49 |

Detail teknis:
- Adaptor menambahkan header internal `X-Rajdoll-Task: <id>` agar proxy tahu tugas mana yang mengirim request. Proxy menghapus header ini sebelum meneruskan ke target.
- Proxy mendekripsi HTTPS dengan CA milik RAJDOLL yang dibuat saat instalasi. Tool pengujian umumnya sudah mengabaikan verifikasi sertifikat; untuk tool yang tidak, CA ini dipasang di image `tools`.
- Tool non-HTTP (nmap, testssl.sh) tidak lewat proxy. Targetnya dicek oleh adaptor sebelum dijalankan dan eksekusinya dicatat di audit log sebagai satu entri per pemanggilan.
- Header identitas (PRD F-50) disisipkan oleh proxy jika diaktifkan di pengaturan penugasan.

### 4.3 Daftar tool

| Tool | Fungsi | Status dibanding sistem lama |
|---|---|---|
| nuclei (≥ 3.10) | Mesin utama: template dan mode DAST | Baru |
| katana | Crawling, termasuk mode headless untuk SPA | Dipertahankan, dipindah ke image `tools` |
| ffuf | Fuzzing direktori dan parameter | Dipertahankan |
| httpx (ProjectDiscovery) | Probe HTTP dan deteksi teknologi | Dipertahankan, menggantikan whatweb |
| nmap | Port scan dan deteksi layanan | Dipertahankan |
| sqlmap | SQL injection | Dipertahankan |
| dalfox | XSS | Dipertahankan |
| commix | Command injection | Dipertahankan |
| testssl.sh | Konfigurasi TLS (modul Weak Cryptography) | Dipertahankan |
| retire.js | Library JavaScript yang rentan | Dipertahankan |
| smuggler | HTTP request smuggling | Dipertahankan, opsional |
| Playwright + Chromium | Verifikasi XSS di browser, auto-login, render SPA | Dipertahankan |
| feroxbuster, dirsearch | Fuzzing direktori | **Dihapus**, digantikan ffuf |
| whatweb | Fingerprint teknologi | **Dihapus**, digantikan httpx (sekaligus menghapus Ruby dari image) |
| subfinder, subjack | Subdomain dan subdomain takeover | **Dihapus**, tidak relevan untuk clone satu host |
| tplmap | SSTI | **Dihapus** (tidak lagi dirawat), digantikan template nuclei dan verifikasi SSTI yang sudah ada |
| ssrfmap, kxss | SSRF dan refleksi XSS | **Dihapus**, digantikan template nuclei dan dalfox |

Semua tool dipasang dengan versi pasti di `Dockerfile` (sistem lama memakai `@latest` untuk beberapa tool). Template nuclei resmi dikunci pada satu rilis; template kustom RAJDOLL disimpan di repo (`templates/nuclei/`).

**Out-of-band (interactsh) dimatikan secara bawaan.** Server interactsh publik berada di internet, sehingga data pengujian keluar dari laptop (melanggar NF-06), dan clone target belum tentu bisa menjangkau internet. Bisa diaktifkan per penugasan dengan peringatan, atau memakai server interactsh lokal di versi berikutnya.

## 5. Lapisan LLM

### 5.1 Penyedia

- Satu klien untuk semua endpoint yang kompatibel dengan OpenAI. Konfigurasi: `base_url`, `model`, `api_key` (opsional).
- Bawaan: LM Studio di Windows, diakses dari container lewat `http://host.docker.internal:1234/v1` (sama seperti setup sekarang).
- Jika `base_url` bukan alamat lokal, UI menampilkan peringatan permanen bahwa data dikirim ke luar laptop (NF-06).

### 5.2 Katalog tugas LLM

| Tugas | Kebutuhan PRD | Masukan (dipangkas) | Keluaran terstruktur |
|---|---|---|---|
| `klasifikasi_endpoint` | F-17 | Metode, path, nama parameter, contoh body, potongan respons | Daftar tanda (misalnya `idor_kandidat`, `upload`, `harga`) dan alasan singkat |
| `susun_input` | F-18 | Contoh request yang valid, tipe parameter, tujuan uji | Body atau nilai parameter yang siap dipakai |
| `nilai_respons` | F-19 | Request, potongan respons akun A dan B, pertanyaan spesifik | Jawaban ya/tidak/ragu, alasan, bagian respons yang relevan |
| `langkah_verifikasi` | F-20 | Kandidat temuan, evidence, hasil putaran sebelumnya | 1–3 request lanjutan (metode, path, header, body) dan apa yang diharapkan |
| `triase_temuan` | F-21 | Temuan dan evidence ringkas | Kelompok duplikat, penjelasan dampak, saran perbaikan, saran uji manual (Bahasa Indonesia) |

Setiap tugas punya: templat prompt (Jinja2), model Pydantic yang diubah menjadi JSON schema untuk `response_format`, batas token masukan dan keluaran, batas waktu, dan **jalan cadangan** tanpa LLM (misalnya klasifikasi endpoint dengan aturan pola nama).

### 5.3 Batas konteks

- Target anggaran per panggilan: masukan ≤ 3.000 token, keluaran ≤ 800 token, agar muat di konteks 4–8 ribu token model kelas 4B.
- Body respons tidak pernah dikirim utuh. Pemangkas mengambil header penting, awal body, dan potongan di sekitar payload atau kata kunci yang relevan.
- Mode berpikir (thinking) model dimatikan secara bawaan untuk kecepatan; bisa diaktifkan per tugas lewat konfigurasi.

### 5.4 Eksekusi

- Panggilan LLM diantrikan dan dijalankan satu per satu, karena satu GPU 4 GB tidak efektif melayani panggilan paralel.
- Keluaran yang tidak lolos validasi skema diulang sekali dengan prompt perbaikan. Jika gagal lagi, dipakai jalan cadangan.
- Ada anggaran jumlah panggilan LLM per scan (bisa diatur). Jika habis, sisa tugas memakai jalan cadangan.
- Setiap panggilan disimpan: tugas, prompt, keluaran, durasi, dan status (PRD F-37).

### 5.5 Prompt injection dari target

Konten dari target (HTML, JSON, pesan error) bisa berisi teks yang menyerupai instruksi. Mitigasinya:
- Keluaran LLM selalu dibatasi skema; LLM tidak bisa memicu tindakan di luar yang didefinisikan.
- Request usulan mini-loop tetap melewati egress proxy (scope dan rate limit) dan dibatasi jumlahnya.
- Konten target dibungkus dalam blok data yang ditandai jelas di prompt.

## 6. Modul uji dan validasi

### 6.1 Antarmuka modul

Setiap modul uji mengimplementasikan:

| Metode | Fungsi |
|---|---|
| `berlaku_untuk(endpoint)` | Menentukan apakah modul relevan untuk endpoint, berdasarkan tanda dan aturan |
| `rencanakan(endpoints)` | Menghasilkan daftar tugas untuk tahap pengujian |
| `jalankan(tugas)` | Memanggil runner tool atau menjalankan cek kustom |
| `kandidat(hasil)` | Mengubah hasil mentah menjadi kandidat temuan beserta evidence |

Modul baru cukup ditambahkan ke registri (PRD NF-08). Cek yang cukup ditulis sebagai template nuclei disimpan di `templates/nuclei/` tanpa kode Python.

### 6.2 Pemetaan modul ke mesin

| Modul | Mesin utama | Cek kustom (Python) |
|---|---|---|
| Information Gathering | katana, ffuf, httpx, nmap, nuclei (exposure) | Analisis bundle JavaScript |
| Configuration & Deployment | nuclei (misconfig, header), httpx | Metode HTTP, file cadangan |
| Identity Management | nuclei | Enumerasi akun, kebijakan pendaftaran |
| Authentication | nuclei | JWT, lockout, alur reset password |
| Authorization | — | IDOR dan eskalasi hak dengan akun A dan B |
| Session Management | nuclei | Atribut cookie, fiksasi sesi, logout |
| Input Validation | nuclei DAST, sqlmap, dalfox, commix | SSTI, SSRF, injeksi berbasis konteks |
| Error Handling | nuclei | Pemicu dan analisis pesan error |
| Weak Cryptography | testssl.sh, nuclei | Algoritma token dan hash |
| Business Logic | — | Manipulasi harga dan jumlah, kupon, alur langkah |
| File Upload | nuclei | Bypass ekstensi dan tipe, eksekusi file |
| Client-Side | retire.js, dalfox, Playwright | DOM XSS, CORS, clickjacking, postMessage |

Cek kustom diambil dari modul sistem lama jika logikanya sudah teruji, lalu ditulis ulang mengikuti antarmuka di 6.1. Rinciannya di IPD.

### 6.3 Validator

- Satu validator per **jenis kerentanan** (bukan per modul). Validator mengirim ulang request lewat egress proxy dan memeriksa bukti secara deterministik.
- Contoh kriteria "terkonfirmasi":

| Jenis | Bukti deterministik |
|---|---|
| SQL injection | sqlmap mengonfirmasi, atau perbedaan respons boolean/waktu yang konsisten di beberapa ulangan |
| XSS | Payload tereksekusi di Playwright (hook `alert` atau penanda DOM) |
| IDOR | Akun B mendapat respons sukses untuk objek milik akun A, dan isinya sama dengan respons yang diterima akun A |
| Kebocoran informasi | Pola spesifik (stack trace, path internal, versi) muncul di respons |
| Template nuclei | Matcher template cocok, dan ulangan kedua memberi hasil yang sama |

- Kandidat yang tidak memenuhi kriteria menjadi "perlu cek manual" dan masuk mini-loop.

### 6.4 Mini-loop verifikasi (PRD F-20)

```
untuk setiap temuan "perlu cek manual" (sesuai anggaran):
  ulangi maksimal 3 putaran:
    LLM.langkah_verifikasi → 1–3 request usulan
    jalankan lewat egress proxy (scope dan rate limit tetap berlaku)
    validator dijalankan ulang dengan evidence baru
    jika kriteria deterministik terpenuhi → "terkonfirmasi", berhenti
  jika tidak → tetap "perlu cek manual", catatan LLM ditambahkan
```

Hanya metode yang diizinkan di konfigurasi yang boleh diusulkan (bawaan: GET, POST, PUT, PATCH). Request usulan dan hasilnya disimpan sebagai evidence.

### 6.5 Retest (PRD F-39 sampai F-44)

- Setiap temuan menyimpan **spesifikasi PoC** terstruktur: request (metode, path relatif, header, body), akun yang dipakai, dan validator yang berlaku.
- Retest adalah jenis scan tersendiri dengan satu tugas per temuan berstatus "diterima". Base URL dan sesi bisa diganti sebelum retest dimulai.
- Hasil: validator lolos → **masih rentan**; validator gagal dengan respons normal → **diperbaiki**; endpoint tidak ada atau error → **tidak bisa diuji ulang**. Temuan manual langsung ditandai "perlu retest manual".

### 6.6 CVSS (PRD F-28, F-38)

- Setiap temuan menyimpan dua vektor: CVSS 3.1 dan CVSS 4.0. Skor dihitung dari vektor oleh library `cvss`, tidak pernah diisi manual.
- Vektor awal berasal dari template temuan per jenis kerentanan. Asesor bisa menyunting keduanya.
- Pengaturan "versi utama" menentukan severity dan tampilan laporan (atau menampilkan keduanya). Bawaan: **CVSS 3.1**.

## 7. WAF dan pemblokiran (PRD F-47 sampai F-50)

| Bagian | Desain |
|---|---|
| Deteksi WAF di recon | Template nuclei untuk deteksi WAF dan sidik jari header/cookie/halaman blokir yang umum. Hasilnya ditampilkan di checkpoint. |
| Deteksi blokir saat scan | Egress proxy menghitung rasio respons 403/406/429/503, koneksi diputus, dan kecocokan dengan pola halaman blokir atau CAPTCHA dalam jendela waktu bergulir. |
| Reaksi bertahap | Rasio melewati ambang pertama → rate limit diturunkan setengah. Tetap tinggi setelah beberapa menit → scan di-pause dan asesor diberi tahu. |
| Penandaan | Tugas yang sebagian besar requestnya diblokir berstatus `blocked`. Laporan memuat daftar modul dan endpoint yang **tidak teruji (terblokir)**. |
| Respons 429 | `Retry-After` dihormati sebelum melanjutkan. |

Ambang dan durasi jendela disimpan di konfigurasi agar bisa disetel setelah dipakai di lapangan.

## 8. Penyimpanan dan enkripsi

### 8.1 Data yang dienkripsi

Dienkripsi di level aplikasi dengan AES-256-GCM sebelum disimpan ke Postgres:
- Body dan header request/response evidence.
- Sesi (cookie, header) dan kredensial akun target.
- Prompt dan keluaran LLM (karena berisi potongan respons target).

Tidak dienkripsi agar bisa dicari dan difilter: metadata temuan (judul, severity, status, endpoint), audit log, dan status pipeline.

### 8.2 Manajemen kunci

- **Kunci utama** (master key) disimpan sebagai berkas di volume Docker terpisah, dibuat saat instalasi pertama.
- **Setiap penugasan punya kunci data sendiri**, yang dienkripsi dengan kunci utama dan disimpan di database.
- **Menghapus penugasan (F-03)** menghapus baris datanya sekaligus kunci data penugasan itu. Sisa data di cadangan atau berkas log Postgres tidak bisa dibaca lagi tanpa kunci tersebut.
- Disarankan mengaktifkan BitLocker di laptop sebagai lapisan tambahan.

### 8.3 Batas ukuran

Body evidence dipotong pada ukuran maksimum (bawaan 1 MB per body, bisa diatur), dengan penanda bahwa body dipotong.

## 9. Keamanan aplikasi

| Aspek | Desain |
|---|---|
| Login | Satu akun pengguna. Password dibuat saat instalasi pertama, di-hash dengan Argon2id. |
| Sesi UI | Cookie `HttpOnly`, `SameSite=Strict`, berlaku 12 jam (bisa diatur). |
| CSRF | Token CSRF di setiap form dan request HTMX yang mengubah data. |
| Jaringan | Hanya `api` yang membuka port, dan hanya di `127.0.0.1`. `db` dan `tools` hanya di jaringan internal Docker. |
| Konten dari target | Semua konten target yang ditampilkan di UI di-escape. Pratinjau HTML respons hanya di `iframe` dengan `sandbox` tanpa izin script. Ini mencegah XSS dari target menyerang UI RAJDOLL. |
| Eksekusi perintah | Tidak ada `shell=True`. Argumen tool selalu disusun dari parameter bertipe. |
| Laporan | Konten dari target di-escape sebelum dimasukkan ke Markdown. |

## 10. Antarmuka web

- Halaman dirender server dengan Jinja2; HTMX dipakai untuk pembaruan sebagian halaman.
- Pembaruan realtime (progres, log, temuan baru) memakai **SSE**: worker menulis event ke tabel event dan mengirim `NOTIFY`; endpoint SSE di `api` mendengarkan `LISTEN` dan mengirim potongan HTML ke browser.
- Bahasa UI: Indonesia.
- Daftar layar: login, daftar penugasan, detail penugasan (scope, akun dan sesi, pengaturan), monitor scan, checkpoint, triase temuan (daftar, detail, penampil evidence, kirim ulang), retest, laporan, pengaturan aplikasi. Tata letak dan alur antarlayar dirinci di AFD.

## 11. Laporan

- Dihasilkan dari templat Jinja2 berformat Markdown, hanya dari temuan berstatus "diterima".
- Dua jenis: laporan VA dan laporan retest.
- Isi laporan VA: ringkasan, tabel temuan per severity, detail temuan (deskripsi, dampak, CVSS, evidence, langkah reproduksi dalam bentuk curl, rekomendasi), daftar pengujian yang terblokir, lampiran scope dan metodologi.
- Pustaka template temuan (PRD F-34) disimpan di database dan bisa disunting dari UI; isi awalnya dipindahkan dari basis pengetahuan enrichment sistem lama.

## 12. Deployment di Windows

| Aspek | Ketentuan |
|---|---|
| Prasyarat | Windows dengan Docker Desktop (backend WSL2), LM Studio dengan server lokal aktif di port 1234. |
| Lokasi repo | Di dalam filesystem WSL (misalnya `~/RAJDOLL`), bukan di `/mnt/c`, agar akses berkas dan build jauh lebih cepat. |
| Memori WSL2 | Bawaan WSL2 memakai maksimal 50% RAM (16 GB dari 32 GB). Ini cukup; bisa diatur lewat `%UserProfile%\.wslconfig` jika perlu. |
| Volume | `pgdata` (database), `secrets` (kunci utama dan CA proxy), `nuclei-templates`. |
| Instalasi pertama | `docker compose up -d`, lalu buka `http://127.0.0.1:8000` untuk membuat password dan memeriksa koneksi LLM. |
| Pembaruan template nuclei | Perintah manual yang butuh internet, dicatat versinya. Tidak otomatis. |

Perkiraan pemakaian memori saat scan: `api` dan `worker` masing-masing ratusan MB, `tools` 1–2 GB saat Chromium headless berjalan, `db` sekitar 200 MB. Angka pasti diukur saat implementasi.

## 13. Konfigurasi

Dua lapis:
- **Berkas `.env`** untuk hal yang jarang berubah: koneksi database, lokasi kunci, alamat LLM bawaan.
- **Pengaturan di database** yang bisa diubah dari UI: model LLM, anggaran panggilan LLM, versi CVSS utama, rate limit dan paralelisme bawaan, durasi checkpoint, header identitas, ambang deteksi blokir, out-of-band.

Pengaturan per penugasan menimpa pengaturan aplikasi.

## 14. Logging dan pengujian sistem

- Semua layanan menulis log terstruktur (JSON) ke stdout; log per scan juga disimpan di database dan bisa dilihat di UI.
- **Uji unit:** pengurai keluaran setiap adaptor (dengan berkas contoh keluaran), validator (dengan contoh request/response), tugas LLM (dengan penyedia palsu).
- **Uji integrasi:** aplikasi web rentan kecil buatan sendiri yang berjalan sebagai container uji, berisi satu contoh untuk setiap jenis kerentanan yang divalidasi. Dipakai untuk memastikan modul dan validator tetap bekerja setelah perubahan.

## 15. Keputusan teknis

| No | Keputusan | Alternatif yang ditolak | Alasan |
|---|---|---|---|
| D-01 | Antrean tugas di Postgres | Celery + Redis | Pause, checkpoint, dan resume setelah restart lebih sederhana; dua layanan berkurang. |
| D-02 | HTMX + Jinja2 | React/Vue, JavaScript biasa | Satu bahasa, tanpa proses build, cocok untuk aplikasi tabel dan form. |
| D-03 | Satu container `tools` dengan MCP | 13 container MCP | Lebih ringan; MCP tetap tersedia untuk mode agen nanti. |
| D-04 | Egress proxy internal | Pengecekan scope di setiap tool | Scope, audit, rate limit, dan deteksi blokir ditegakkan di satu tempat untuk semua tool. |
| D-05 | Nuclei sebagai mesin utama | Scanner kustom per kategori | Template matang dan mudah ditambah; kode kustom hanya untuk yang unik. |
| D-06 | LLM berformat terstruktur, dijalankan berurutan | LLM sebagai perencana | Sesuai kemampuan model kelas 4B dan satu GPU. |
| D-07 | Kunci data per penugasan | Satu kunci untuk semua data | Penghapusan penugasan benar-benar membuat datanya tidak terbaca. |
| D-08 | Out-of-band dimatikan secara bawaan | interactsh publik aktif | Data tidak keluar laptop; clone belum tentu terhubung internet. |
| D-09 | Burp tidak diintegrasikan | Burp sebagai upstream proxy | Evidence sudah disimpan sendiri; integrasi menambah masalah CA dan jaringan. |

## 16. Risiko

| Risiko | Mitigasi |
|---|---|
| Kualitas keluaran model 4B tidak konsisten | Skema ketat, ulangan sekali, jalan cadangan berbasis aturan, LLM tidak bisa menetapkan "terkonfirmasi". |
| Egress proxy jadi hambatan kecepatan | Rate limit memang membatasi trafik jauh di bawah kapasitas proxy; diukur saat implementasi. |
| Template nuclei menghasilkan false positive | Ulangan kedua di validator; temuan yang tidak stabil menjadi "perlu cek manual". |
| Target di belakang WAF memblokir pengujian | Whitelist IP oleh instansi; deteksi dan penandaan "terblokir". |
| Konten target berisi prompt injection | Keluaran dibatasi skema; request mini-loop tetap lewat proxy dan dibatasi. |
| Sumber daya laptop tidak cukup saat Chromium, LLM, dan Burp berjalan bersamaan | Paralelisme bawaan rendah (2), Chromium hanya untuk tugas yang membutuhkannya. |

## 17. Pertanyaan terbuka

| No | Pertanyaan | Usulan bawaan |
|---|---|---|
| T1 | Versi CVSS utama bawaan: 3.1 atau 4.0? | Selesai: 3.1, bisa diubah di pengaturan. |
| T2 | Kunci utama: berkas di volume Docker, atau diturunkan dari password login (data tidak bisa dibuka tanpa login)? | Berkas di volume untuk v1. Opsi password lebih aman tetapi membuat worker tidak bisa melanjutkan scan setelah restart sebelum Anda login. |
