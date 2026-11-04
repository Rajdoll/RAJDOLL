# AFD — RAJDOLL v1: Alur Aplikasi

| | |
|---|---|
| Dokumen | App Flow Document (AFD), termasuk wireframe layar (pengganti DBD) |
| Acuan | PRD v1.1, TRD v1.0 |
| Status | Disetujui (v1.0, 4 November 2026) |

Dokumen ini menjelaskan apa yang dilihat dan dilakukan pengguna di setiap langkah, bagaimana status penugasan, scan, tugas, dan temuan berubah, serta tata letak layar utama.

---

## 1. Peta layar

```
Login / Setup awal
└── Beranda: Daftar penugasan
    ├── Penugasan baru
    └── Penugasan  (satu halaman dengan tab)
        ├── Ringkasan        status, angka temuan, scan terakhir, peringatan
        ├── Scope & Akun     scope host, akun A/B dan sesinya, URL cek sesi
        ├── Scan             riwayat scan, mulai scan baru
        │   ├── Monitor scan
        │   └── Checkpoint
        ├── Temuan           triase: daftar + detail, tambah temuan manual
        ├── Retest           putaran retest dan hasilnya
        ├── Laporan          pratinjau dan unduh Markdown (VA dan retest)
        └── Pengaturan       rate limit, paralelisme, checkpoint, header identitas, hapus penugasan
Pengaturan aplikasi            LLM, CVSS utama, nilai bawaan, password
Pustaka template temuan        deskripsi, dampak, rekomendasi, vektor CVSS bawaan
```

Navigasi atas selalu berisi: **Penugasan**, **Template temuan**, **Pengaturan**, **Keluar**, dan indikator LLM (lokal/API/mati).

## 2. Alur utama

### A0. Setup awal (sekali)

1. Asesor menjalankan `docker compose up -d`, lalu membuka `http://127.0.0.1:8000`.
2. Belum ada password, jadi muncul halaman **Setup awal**: buat password (dua kali ketik).
3. Halaman cek koneksi LLM: alamat dan model terisi dari `.env`, tombol **Uji koneksi**. Bisa dilewati; RAJDOLL tetap jalan tanpa LLM.
4. Pengingat: aktifkan BitLocker jika belum (hanya teks, tidak bisa diperiksa otomatis dari dalam container).
5. Masuk ke Beranda.

### A1. Membuat penugasan

1. Beranda → **Penugasan baru**.
2. Isi form: nama aplikasi, instansi, URL target, catatan (misalnya nomor surat tugas), tanggal mulai dan selesai.
3. Saat disimpan, host dari URL target otomatis masuk ke scope, lalu pengguna diarahkan ke tab **Scope & Akun**. Karena scope langsung valid, penugasan baru biasanya langsung berstatus **siap**; status kembali ke **draf** bila URL target diubah ke host di luar scope (lihat A2.4).

### A2. Menyiapkan scope dan akun

1. **Scope:** daftar host atau pola (misalnya `app.instansi.test`, `*.instansi.test`). Bisa tambah dan hapus.
2. **Akun:** tambah akun dengan label (bawaan "Akun A" dan "Akun B"). Untuk tiap akun pilih cara:
   - **Tempel sesi:** tempel cookie dan/atau header dari Burp atau DevTools browser. Username akun boleh diisi (opsional) untuk uji enumerasi akun; disimpan terenkripsi.
   - **Auto-login** (Should): username, password, URL login, dan selector form.
3. **Cek sesi:** isi satu URL yang hanya bisa dibuka saat login dan teks penanda login (misalnya nama pengguna). Tombol **Uji sesi** memeriksa setiap akun dan menampilkan hasil valid atau tidak.
4. Penugasan menjadi **siap** jika scope tidak kosong dan URL target ada di dalam scope. Akun tidak wajib, tetapi:
   - Tanpa akun: modul yang butuh login hanya menguji bagian publik.
   - Kurang dari dua akun: modul Authorization dilewati, dengan alasan yang ditampilkan.

### A3. Memulai scan

1. Tab **Scan** → **Mulai scan**.
2. Pilih profil: **Lengkap** (bawaan) atau **Kustom** (centang modul).
3. Layar konfirmasi menampilkan ringkasan: target, scope, akun dan status sesinya, profil, rate limit, paralelisme, checkpoint (aktif, 15 menit), penyedia LLM (lokal atau API, dengan peringatan jika API).
4. Peringatan yang tidak menghalangi: sesi belum diuji, kurang dari dua akun, LLM tidak terhubung.
5. **Mulai** → scan masuk antrean, pengguna diarahkan ke **Monitor scan**.

Satu penugasan bisa punya beberapa scan (misalnya scan ulang setelah scope diubah). Temuan dari semua scan digabung di tingkat penugasan; temuan dengan sidik jari yang sama tidak diduplikasi.

### A4. Memantau scan

Monitor scan menampilkan secara realtime (SSE):
- Tahap aktif dan progresnya.
- Tugas per modul: menunggu, berjalan, selesai, gagal, terblokir.
- Jumlah request, laju request saat ini, jumlah request yang ditolak karena di luar scope.
- Temuan yang masuk (jumlah per severity dan status validasi), dengan tautan ke detail.
- Log ringkas yang bisa diperluas.

Tombol: **Jeda**, **Lanjutkan**, **Batalkan** (dengan konfirmasi).

Pengguna boleh menutup browser; scan tetap berjalan. Saat kembali, monitor menampilkan status terkini.

### A5. Checkpoint setelah perencanaan

Muncul otomatis setelah tahap perencanaan. Jika pengguna sedang di halaman lain milik RAJDOLL, muncul banner dengan tautan ke checkpoint.

Isi layar:
- Hitung mundur lanjut otomatis (bawaan 15 menit).
- WAF yang terdeteksi (jika ada) beserta saran: minta whitelist IP ke instansi.
- Daftar endpoint: metode, path, parameter, tanda dari LLM, modul yang akan menguji, status dikecualikan (dengan alasan, misalnya "pola logout").
- Teknologi yang terdeteksi.
- Host yang ditemukan tetapi diblokir karena di luar scope, masing-masing dengan tombol **Tambah ke scope**.
- Perkiraan jumlah request tahap pengujian.

Aksi:
- **Sunting:** tambah endpoint (manual, atau tempel request mentah dari Burp), kecualikan atau batalkan pengecualian endpoint, ubah tanda, aktif/nonaktifkan modul. Selama menyunting, hitung mundur berhenti.
- **Lanjutkan:** tahap pengujian dimulai dengan rencana terbaru.
- **Batalkan scan.**

Jika hitung mundur habis tanpa respons, scan lanjut dengan rencana apa adanya, dan riwayat scan mencatat "checkpoint dilewati otomatis".

### A6. Interupsi: sesi kedaluwarsa

1. Worker mendeteksi cek sesi gagal → scan **dijeda** dengan alasan "sesi kedaluwarsa (Akun A)".
2. Banner merah di semua halaman penugasan: "Scan dijeda: sesi Akun A kedaluwarsa".
3. Pengguna menempel sesi baru → **Uji sesi** → jika valid, tombol **Lanjutkan scan** aktif.
4. Tugas yang terdampak (yang berjalan dengan sesi lama setelah sesi terakhir valid) diulang otomatis.

### A7. Interupsi: pemblokiran WAF

1. Proxy mendeteksi rasio blokir tinggi → rate limit diturunkan otomatis, monitor menampilkan pemberitahuan kuning.
2. Jika berlanjut → scan **dijeda** dengan alasan "kemungkinan diblokir WAF", disertai statistik (rasio 403/429, contoh respons blokir).
3. Pilihan:
   - **Lanjutkan dengan rate lebih rendah** (isi rate baru).
   - **Lewati modul terdampak:** tugasnya ditandai terblokir dan masuk laporan sebagai "tidak teruji (terblokir)".
   - **Biarkan dijeda** (misalnya sambil menunggu instansi melakukan whitelist).

### A8. Triase temuan

Tab **Temuan** berbentuk dua panel: daftar di kiri, detail di kanan.

**Daftar:**
- Filter: status validasi, keputusan, severity, modul, scan.
- Urutan bawaan: belum diputuskan dulu, lalu terkonfirmasi sebelum perlu cek manual, lalu severity tertinggi.
- Penghitung di atas: "12 belum diputuskan · 20 diterima · 5 ditolak".

**Detail temuan:**
- Judul, severity, status validasi, modul, WSTG, CWE, endpoint dan parameter.
- Deskripsi, dampak, rekomendasi (dari template, bisa disunting).
- **Evidence:** tab Request dan Response mentah (teks di-escape); pratinjau HTML hanya di iframe sandbox tanpa script. Jika ada beberapa evidence (misalnya dari mini-loop), ditampilkan berurutan.
- **PoC:** tombol **Salin curl** dan **Salin request mentah** (untuk Burp Repeater).
- **Catatan LLM:** penjelasan, saran uji manual, dan riwayat mini-loop (request usulan dan hasilnya). Ditandai jelas sebagai keluaran AI.
- **CVSS:** vektor 3.1 dan 4.0 bisa disunting lewat pemilih metrik; skor dihitung ulang otomatis.

Aksi:
- **Terima** / **Tolak** (alasan wajib diisi saat menolak) / **Kembalikan ke belum diputuskan**.
- **Sunting** teks temuan.
- **Kirim ulang** (Should): sunting request, kirim lewat RAJDOLL; hasilnya ditambahkan sebagai evidence baru.
- **Gabungkan** dengan temuan lain jika duplikat.

**Tambah temuan manual:** tombol di atas daftar → pilih template (atau kosong) → isi endpoint, evidence (tempel request/response), CVSS → simpan. Temuan manual langsung berkeputusan **diterima**.

**Pintasan keyboard** (Could): `j`/`k` pindah temuan, `a` terima, `r` tolak.

### A9. Laporan

1. Tab **Laporan** → pilih **Laporan VA**.
2. Peringatan sebelum ekspor, tidak menghalangi:
   - Masih ada temuan yang belum diputuskan.
   - Ada pengujian yang terblokir (akan dicantumkan di laporan).
3. Pratinjau Markdown yang sudah dirender, plus tombol **Unduh .md**.
4. Setiap ekspor dicatat (waktu, jumlah temuan), sehingga versi laporan sebelumnya bisa diunduh lagi.

### A10. Retest

1. Tab **Retest** → **Mulai retest** (hanya aktif jika ada temuan diterima).
2. Langkah persiapan:
   - Ubah **base URL** jika clone versi perbaikan beralamat beda (scope ikut disesuaikan setelah dikonfirmasi).
   - Perbarui sesi akun dan uji sesi.
   - Pilih temuan yang diretest (bawaan: semua yang diterima).
3. **Mulai** → monitor sederhana: progres per temuan.
4. Hasil per temuan: **diperbaiki**, **masih rentan**, **tidak bisa diuji ulang**, atau **perlu retest manual** (untuk temuan manual dan yang tidak bisa diulang otomatis). Setiap hasil bisa dikoreksi pengguna, disertai catatan.
5. Tab **Laporan** → **Laporan retest** untuk putaran tersebut → unduh.
6. Retest bisa diulang (putaran ke-2, ke-3); setiap putaran tersimpan.

### A11. Menghapus penugasan

1. Tab **Pengaturan** penugasan → **Hapus penugasan**.
2. Dialog menjelaskan bahwa semua temuan, evidence, sesi, log, dan kunci data penugasan dihapus permanen.
3. Pengguna mengetik nama aplikasi untuk konfirmasi → hapus → kembali ke Beranda.
4. Tidak bisa dihapus saat scan atau retest sedang berjalan; harus dibatalkan dulu.

## 3. State machine

### 3.1 Penugasan

```
draf ──(scope valid)──▶ siap ──(scan/retest dimulai)──▶ aktif
                         ▲                               │
                         └──(scan/retest berhenti)───────┘
siap ──(tandai selesai)──▶ selesai ──(mulai retest)──▶ aktif
apa pun kecuali aktif ──(hapus)──▶ [data dan kunci dihapus]
```

"Selesai" hanya penanda bagi pengguna (misalnya laporan sudah dikirim); tidak mengunci data.

### 3.2 Scan

```
antre ─▶ recon ─▶ perencanaan ─▶ menunggu_checkpoint ─▶ pengujian ─▶ validasi ─▶ triase_ai ─▶ selesai
                                   │  (lanjutkan / 15 menit habis)
                                   └─ checkpoint dimatikan: langsung ke pengujian

dari tahap mana pun:
  ─(jeda manual | sesi kedaluwarsa | blokir WAF)─▶ dijeda ─(lanjutkan)─▶ tahap semula
  ─(batalkan)──────────────────────────────────▶ dibatalkan
  ─(galat yang tidak bisa dipulihkan)──────────▶ gagal
```

| Dari | Kejadian | Ke |
|---|---|---|
| antre | worker mengambil scan | recon |
| tahap N | semua tugas tahap N selesai/gagal/dilewati/terblokir | tahap N+1 |
| perencanaan | selesai, checkpoint aktif | menunggu_checkpoint |
| menunggu_checkpoint | pengguna menekan Lanjutkan, atau waktu habis | pengujian |
| tahap mana pun | pengguna menekan Jeda | dijeda (alasan: manual) |
| tahap mana pun | cek sesi gagal | dijeda (alasan: sesi kedaluwarsa) |
| tahap mana pun | blokir WAF berlanjut | dijeda (alasan: blokir WAF) |
| dijeda | pengguna menekan Lanjutkan (dan sesi valid, jika alasannya sesi) | tahap sebelum dijeda |
| tahap mana pun, dijeda | pengguna menekan Batalkan | dibatalkan |
| tahap mana pun | galat yang tidak bisa dipulihkan (misalnya database tidak bisa diakses lama) | gagal |

Scan yang gagal atau dibatalkan tetap menyimpan temuan yang sudah didapat. Scan berstatus gagal bisa **dilanjutkan** dari tugas terakhir yang belum selesai.

Kegagalan satu tugas **tidak** membuat scan gagal (PRD F-16).

### 3.3 Tugas

```
pending ─▶ running ─▶ done
                   ├─▶ failed     (setelah 1 kali ulang untuk galat sementara, misalnya timeout)
                   ├─▶ blocked    (sebagian besar request diblokir WAF)
                   └─▶ pending    (scan dijeda, atau worker mati lalu hidup lagi)
pending ─▶ skipped (scan dibatalkan, modul dinonaktifkan, atau prasyarat tidak terpenuhi)
```

### 3.4 Temuan

Status temuan disimpan dalam **tiga kolom terpisah**, karena ketiganya berubah oleh pihak dan waktu yang berbeda. Nama kolom dan nilai di database memakai bahasa Inggris; pemetaannya ada di BSD bagian 9.

| Kolom | Nilai | Diubah oleh |
|---|---|---|
| `validasi` | `terkonfirmasi`, `perlu_cek_manual`, `manual` | Validator dan mini-loop (otomatis); `manual` untuk temuan buatan asesor |
| `keputusan` | `belum`, `diterima`, `ditolak` | Asesor |
| `hasil_retest` | `belum`, `diperbaiki`, `masih_rentan`, `tidak_bisa_diuji`, `perlu_retest_manual` | Retest (otomatis), bisa dikoreksi asesor; menyimpan hasil putaran terakhir |

```
kandidat dari modul
   └─ validator ─▶ terkonfirmasi
               └─▶ perlu_cek_manual ─(mini-loop berhasil)─▶ terkonfirmasi

keputusan:     belum ─▶ diterima ⇄ ditolak   (bisa dikembalikan ke belum)
hasil_retest:  hanya untuk keputusan = diterima; diperbarui setiap putaran retest
```

Aturan:
- Hanya temuan dengan `keputusan = diterima` yang masuk laporan VA dan bisa diretest.
- Temuan manual: `validasi = manual`, `keputusan = diterima`, dan pada retest langsung `perlu_retest_manual`.
- Jika scan berikutnya menemukan sidik jari yang sama, evidence baru ditambahkan; `keputusan` yang sudah diambil asesor tidak berubah.

### 3.5 Putaran retest

```
persiapan ─▶ antre ─▶ berjalan ─▶ selesai
                         ├─(sesi kedaluwarsa | jeda)─▶ dijeda ─▶ berjalan
                         └─(batalkan)─▶ dibatalkan
```

## 4. Notifikasi dan interupsi

| Kejadian | Tampilan | Aksi yang tersedia |
|---|---|---|
| Checkpoint menunggu | Banner biru dengan hitung mundur di semua halaman penugasan | Buka checkpoint |
| Sesi kedaluwarsa | Banner merah, scan dijeda | Perbarui sesi |
| Rate diturunkan karena blokir | Pemberitahuan kuning di monitor | — |
| Scan dijeda karena WAF | Banner merah | Lanjutkan dengan rate lebih rendah, lewati modul, biarkan |
| Scan selesai | Banner hijau dan ringkasan jumlah temuan | Buka triase |
| Scan gagal | Banner merah dengan pesan galat | Lanjutkan, lihat log |
| LLM tidak terhubung | Indikator di navigasi berubah merah; pemberitahuan sekali per scan | Buka pengaturan |
| LLM memakai API (bukan lokal) | Label permanen "Data dikirim ke API" di navigasi | — |

**Notifikasi browser** (Could): saat tab RAJDOLL tidak aktif, notifikasi sistem Windows untuk checkpoint, sesi kedaluwarsa, dan scan selesai.

## 5. Wireframe

Wireframe ini menunjukkan isi dan susunan, bukan desain visual. Gaya mengikuti bawaan Pico.css.

### 5.1 Beranda: daftar penugasan

```
+--------------------------------------------------------------------------+
| RAJDOLL   Penugasan  Template temuan  Pengaturan     LLM: lokal ●  Keluar |
+--------------------------------------------------------------------------+
| Penugasan                                          [ + Penugasan baru ]   |
|                                                                          |
| Aplikasi          Instansi      Status   Temuan (diterima)   Diperbarui  |
| ---------------------------------------------------------------------- |
| SIMPEG (clone)    Instansi A    aktif    2K 4T 6S 3R          5 mnt lalu  |
|                                          ⏸ menunggu checkpoint (12:41)   |
| Portal Layanan    Instansi B    selesai  0K 1T 3S 2R          3 hari lalu |
| E-Arsip           Instansi C    draf     —                    1 mnt lalu  |
+--------------------------------------------------------------------------+
  K = kritis, T = tinggi, S = sedang, R = rendah
```

### 5.2 Penugasan: tab Ringkasan

```
+--------------------------------------------------------------------------+
| ← Penugasan  /  SIMPEG (clone) · Instansi A                     [aktif]   |
| [Ringkasan] Scope & Akun  Scan  Temuan  Retest  Laporan  Pengaturan       |
+--------------------------------------------------------------------------+
| ! Scan #2 menunggu checkpoint — lanjut otomatis dalam 12:41 [Buka]        |
|                                                                          |
| Target   https://simpeg.instansi.test        Scope  2 host               |
| Akun     Akun A ✓ valid   Akun B ✓ valid     Cek sesi tiap 5 mnt         |
|                                                                          |
| Temuan        Kritis  Tinggi  Sedang  Rendah  Info                       |
| Diterima        2       4       6       3      1                         |
| Belum diputus   0       1       5       4      2                         |
|                                                                          |
| Peringatan                                                               |
|  - WAF terdeteksi (ModSecurity). Pertimbangkan whitelist IP.              |
|  - 2 modul terblokir sebagian pada scan #1.                               |
+--------------------------------------------------------------------------+
```

### 5.3 Monitor scan

```
+--------------------------------------------------------------------------+
| Scan #2 · profil Lengkap · mulai 09:12 · 38 mnt          [Jeda] [Batalkan]|
+--------------------------------------------------------------------------+
| recon ✓ → perencanaan ✓ → checkpoint ✓ → [pengujian 54%] → validasi → AI |
|                                                                          |
| Modul                 Tugas   Selesai  Gagal  Terblokir                  |
| Input Validation        48      30       1       0     ███████░░░        |
| Authorization           12      12       0       0     ██████████        |
| Client-Side             20       6       0       0     ███░░░░░░░        |
| ...                                                                      |
|                                                                          |
| Request: 18.420 · 8,1 req/dtk · ditolak scope: 37                        |
| Temuan masuk: 3 terkonfirmasi · 7 perlu cek manual        [Buka temuan]  |
|                                                                          |
| Log ▸ 09:49:51 sqlmap /api/search?q= selesai, 1 kandidat                 |
|       09:49:40 nuclei DAST /api/users/{id} selesai                       |
+--------------------------------------------------------------------------+
```

### 5.4 Checkpoint

```
+--------------------------------------------------------------------------+
| Checkpoint scan #2          Lanjut otomatis dalam 12:41  [Lanjutkan]      |
|                                                 [Sunting] [Batalkan scan]|
+--------------------------------------------------------------------------+
| WAF: ModSecurity terdeteksi. Saran: minta whitelist IP ke instansi.       |
| Teknologi: nginx 1.24, PHP 8.1, Laravel, jQuery 3.4.1                    |
| Perkiraan request tahap pengujian: ±21.000                               |
|                                                                          |
| Endpoint (142)                   [filter: semua | ditandai | dikecualikan]|
| Metode Path                  Param       Tanda LLM      Modul    Status  |
| GET    /api/users/{id}       id          idor_kandidat  ATHZ,INPV  uji   |
| POST   /api/cart/checkout    qty,price   harga          BUSL,INPV  uji   |
| POST   /upload/avatar        file        upload         UPLD       uji   |
| GET    /logout               —           —              —      dikecuali-|
|                                                                kan (pola)|
| [+ Tambah endpoint] [Tempel request dari Burp]                           |
|                                                                          |
| Host di luar scope yang ditemukan (2)                                    |
|   cdn.instansi.test     [Tambah ke scope]                                |
|   sso.instansi.test     [Tambah ke scope]                                |
+--------------------------------------------------------------------------+
```

### 5.5 Triase temuan

```
+--------------------------------------------------------------------------+
| Temuan  12 belum diputuskan · 20 diterima · 5 ditolak  [+ Temuan manual]  |
| Filter: [validasi ▾] [keputusan ▾] [severity ▾] [modul ▾]                 |
+---------------------------------+----------------------------------------+
| ● T  IDOR /api/users/{id}       | IDOR pada /api/users/{id}               |
|      terkonfirmasi · belum      | Tinggi · CVSS 3.1: 7.1 · terkonfirmasi  |
| ● S  Reflected XSS /search      | WSTG-ATHZ-04 · CWE-639 · param: id      |
|      terkonfirmasi · belum      |-----------------------------------------|
| ○ S  Info leak /api/err         | Deskripsi  [sunting]                    |
|      perlu cek manual · belum   | Akun B dapat membaca data profil Akun A |
| ○ R  Cookie tanpa Secure        | ...                                     |
|      terkonfirmasi · belum      | Evidence  [Request] [Response] [Pratinj.]|
|  ...                            | GET /api/users/1001 HTTP/1.1            |
|                                 | Cookie: session=(Akun B)                |
|                                 | ...                                     |
|                                 | [Salin curl] [Salin request] [Kirim ulang]|
|                                 | Catatan AI ▸ penjelasan, saran uji manual|
|                                 | CVSS ▸ 3.1 AV:N/AC:L/PR:L/... 4.0 ...   |
|                                 |-----------------------------------------|
|                                 | [Terima] [Tolak…] [Gabungkan…]          |
+---------------------------------+----------------------------------------+
```

### 5.6 Retest

```
+--------------------------------------------------------------------------+
| Retest                                              [Mulai retest baru]   |
+--------------------------------------------------------------------------+
| Putaran 2 · 3 Des 2026 · base URL https://simpeg-v2.instansi.test  selesai|
|                                                                          |
| Temuan                          Putaran 1       Putaran 2     Catatan    |
| IDOR /api/users/{id}            masih rentan    diperbaiki               |
| Reflected XSS /search           diperbaiki      diperbaiki               |
| SQLi /api/search                masih rentan    masih rentan  [koreksi]  |
| Logika bisnis kupon (manual)    perlu manual    perlu manual  [koreksi]  |
|                                                                          |
| [Unduh laporan retest putaran 2]                                         |
+--------------------------------------------------------------------------+
```

## 6. Validasi form

| Form | Aturan |
|---|---|
| Penugasan baru | Nama aplikasi dan URL target wajib; URL harus `http` atau `https`. |
| Scope | Pola host saja (tanpa path); minimal satu; URL target harus cocok dengan salah satu pola. |
| Sesi akun | Minimal cookie atau header terisi. Tempel teks mentah diterima dalam format header `Nama: nilai` per baris atau string cookie `a=1; b=2`. |
| Cek sesi | URL harus di dalam scope; penanda login wajib jika URL diisi. |
| Tolak temuan | Alasan wajib diisi. |
| Hapus penugasan | Ketik nama aplikasi persis sama. |
| Base URL retest | Host baru harus dikonfirmasi untuk ditambahkan ke scope. |

## 7. Yang dihapus dibanding sistem lama

| Fitur lama | Penggantinya |
|---|---|
| Checkpoint di setiap pergantian agen (12 kali per scan) dengan pilihan Izinkan / Izinkan Semua / Beri Arahan Lain | Satu checkpoint setelah perencanaan (A5) |
| Chat dengan LLM di checkpoint (`hitl_chat`) | Sunting rencana langsung di checkpoint |
| Persetujuan per tool dan per risiko | Tidak diperlukan; target adalah clone, dan scope ditegakkan oleh egress proxy |
| Laporan PDF | Laporan Markdown |
