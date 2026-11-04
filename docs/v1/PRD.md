# PRD — RAJDOLL v1: Asisten Asesor VA Web

| | |
|---|---|
| Dokumen | Product Requirement Document (PRD) |
| Versi produk | v1 — Asisten Asesor |
| Status | Disetujui (v1.1, 4 November 2026) |
| Pengguna | Satu asesor VA (pemakaian pribadi) |
| Dokumen terkait | TRD, AFD, BSD, IPD (menyusul) |

---

## 1. Latar belakang

Vulnerability assessment (VA) aplikasi web menghabiskan banyak waktu di pekerjaan yang berulang: memetakan endpoint, menguji kategori kerentanan yang sama di setiap endpoint, memverifikasi hasil scanner, dan menulis laporan. Waktu asesor jadi tersita untuk pekerjaan mekanis, bukan untuk pengujian yang butuh penilaian manusia.

RAJDOLL v1 adalah **asisten pribadi asesor** yang menjalankan pipeline VA web lengkap di laptop, memvalidasi temuannya sendiri, lalu menyiapkan bahan triase dan draf laporan. Keputusan akhir tentang temuan mana yang dilaporkan tetap di tangan asesor.

## 2. Tujuan dan non-tujuan

### Tujuan v1

| ID | Tujuan |
|---|---|
| G1 | Mengotomatisasi bagian VA web yang berulang: recon, pengujian per kategori OWASP WSTG v4.2, dan pengumpulan evidence. |
| G2 | Setiap temuan yang disajikan sudah divalidasi, atau ditandai jelas "perlu cek manual", sehingga waktu verifikasi berkurang. |
| G3 | Setiap temuan bisa diverifikasi ulang dengan mudah: dikirim ulang langsung dari RAJDOLL, atau disalin sebagai curl / request mentah ke Burp. |
| G4 | Menghasilkan draf laporan Markdown yang siap disunting. |
| G5 | Berjalan penuh di satu laptop. Dengan LLM lokal, tidak ada data hasil VA yang keluar dari laptop. |
| G6 | Memverifikasi perbaikan (retest) secara terarah tanpa menjalankan ulang scan penuh. |

### Bukan tujuan v1

- Multi-user, role, dan persetujuan berjenjang.
- Laporan sesuai template kantor.
- Target selain aplikasi web (aplikasi mobile, infrastruktur jaringan).
- Mode agen otonom penuh yang dikendalikan LLM.
- Integrasi Burp Suite Professional (REST API, Burp Scanner).
- Profil pengujian aman untuk sistem production. Target v1 adalah clone aplikasi, jadi payload agresif diperbolehkan.

## 3. Pengguna dan konteks pemakaian

**Pengguna:** satu asesor VA yang menguji clone aplikasi web milik instansi.

**Lingkungan kerja:**

- Laptop Windows dengan Docker Desktop (backend WSL2), RAM 32 GB, dan GPU RTX 3050 (VRAM 4 GB).
- Burp Suite Community dipakai terpisah untuk pengujian manual. Tidak terhubung langsung ke RAJDOLL; pertukaran data cukup lewat salin-tempel atau berkas.
- Target diakses langsung dari laptop, tanpa VPN.
- LLM lokal kelas 4B (misalnya lewat LM Studio). Bisa diganti ke LLM API melalui konfigurasi.
- Target adalah clone aplikasi production, sehingga tidak ada larangan jenis payload.

## 4. Konsep produk

RAJDOLL v1 adalah **pipeline deterministik dengan LLM sebagai asisten**:

- **Urutan pengujian** ditentukan oleh workflow engine dan konfigurasi, bukan oleh LLM.
- **Pengujian** dijalankan oleh tool yang sudah matang (nuclei, sqlmap, dalfox, dan lainnya), ditambah cek kustom untuk kasus yang tidak dicakup tool tersebut.
- **Keputusan valid atau tidaknya temuan** diambil oleh validator deterministik per jenis kerentanan.
- **LLM** mengerjakan tugas kecil dengan keluaran terstruktur di empat titik yang tidak bisa diselesaikan aturan (lihat bagian 6.4).

Alasannya: model kelas 4B lemah dalam perencanaan jangka panjang dan rawan mengarang informasi, tetapi cukup andal untuk tugas sempit dengan format keluaran yang ketat.

### Alur pipeline

```
Input: target + scope + sesi login
 1. Recon         crawling, fuzzing direktori, fingerprint teknologi, port scan
                  → inventaris endpoint dan parameter
 2. Perencanaan   LLM menandai endpoint; aturan memilih modul uji per endpoint
 3. Pengujian     modul uji per kategori WSTG
 4. Validasi      validator per jenis kerentanan, plus mini-loop verifikasi LLM
                  → "terkonfirmasi" atau "perlu cek manual"
 5. Triase AI     gabung duplikat, jelaskan dampak, saran perbaikan, saran uji manual
 6. Triase asesor terima / tolak / sunting, tambah temuan manual, kirim ulang request
 7. Laporan       ekspor Markdown
```

### Modul uji

| Modul | Kategori WSTG v4.2 |
|---|---|
| Information Gathering | WSTG-INFO |
| Configuration & Deployment | WSTG-CONF |
| Identity Management | WSTG-IDNT |
| Authentication | WSTG-ATHN |
| Authorization | WSTG-ATHZ |
| Session Management | WSTG-SESS |
| Input Validation | WSTG-INPV |
| Error Handling | WSTG-ERRH |
| Weak Cryptography | WSTG-CRYP |
| Business Logic | WSTG-BUSL |
| File Upload | WSTG-BUSL (upload file) |
| Client-Side | WSTG-CLNT |

## 5. Alur kerja pengguna

Detail alur dan state machine ada di AFD. Ringkasannya:

1. Membuat penugasan: nama aplikasi, instansi, URL target, scope, dan catatan (misalnya nomor surat tugas).
2. Mengimpor sesi login dari Burp atau browser, atau mengisi kredensial untuk auto-login.
3. Memilih profil scan, lalu memulai.
4. Memantau progres. Scan bisa di-pause, dilanjutkan, atau dibatalkan.
5. Di checkpoint setelah recon, meninjau inventaris endpoint dan rencana uji sebelum pengujian aktif dimulai. Jika tidak direspons dalam 15 menit, scan lanjut otomatis.
6. Mentriase temuan: terima, tolak, sunting, tambah temuan manual, kirim ulang request dari RAJDOLL atau salin ke Burp.
7. Mengekspor laporan Markdown.
8. Setelah instansi memperbaiki, menjalankan retest atas temuan yang diterima. Bisa diulang beberapa putaran.
9. Menghapus seluruh data penugasan setelah pekerjaan selesai.

## 6. Kebutuhan fungsional

Prioritas: **Must** = wajib ada di v1, **Should** = sebaiknya ada di v1, **Could** = jika waktu memungkinkan.

### 6.1 Penugasan dan scope

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-01 | Membuat dan mengelola penugasan: nama aplikasi, instansi, URL target, catatan, periode pengujian. | Must |
| F-02 | Scope per penugasan berupa daftar host atau pola host. Semua request ke luar scope ditolak (default tolak). | Must |
| F-03 | Menghapus seluruh data satu penugasan: temuan, evidence, log, dan sesi. | Must |

### 6.2 Sesi login ke target

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-04 | Mengimpor sesi berupa cookie atau header (ditempel dari Burp atau browser). | Must |
| F-05 | Mendukung minimal dua akun per penugasan, untuk pengujian otorisasi dan IDOR. | Must |
| F-06 | Auto-login dengan form username dan password. | Should |
| F-07 | Mendeteksi sesi kedaluwarsa, lalu mem-pause scan dan meminta sesi baru. | Must |

### 6.3 Pipeline dan pengujian

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-08 | Menjalankan pipeline tujuh tahap seperti di bagian 4. | Must |
| F-09 | Recon menghasilkan inventaris endpoint dan parameter, termasuk dari aplikasi SPA (crawling headless dan analisis JavaScript). | Must |
| F-10 | Mengimpor request dari Burp sebagai tambahan inventaris endpoint. Format impor dari Burp Community perlu dicek. | Should |
| F-11 | Menjalankan modul uji per kategori WSTG (tabel bagian 4). Mesin utamanya nuclei (template dan mode DAST), ditambah sqlmap, dalfox, dan cek kustom. | Must |
| F-12 | Profil scan: **Lengkap** (semua modul, default) dan **Kustom** (pilih modul). | Must |
| F-13 | Pause, resume, dan cancel. Scan bisa dilanjutkan dari tahap terakhir setelah laptop restart atau proses crash. | Must |
| F-14 | **Checkpoint setelah recon dan perencanaan**, sebelum pengujian aktif. Menampilkan daftar endpoint dan parameter beserta tanda dari LLM, teknologi terdeteksi, rencana uji (modul per endpoint dan perkiraan jumlah request), serta host yang diblokir karena di luar scope. Aksi: lanjutkan, sunting (tambah atau kecualikan endpoint, ubah tanda, aktif/nonaktifkan modul), atau batalkan. Aktif secara default dan lanjut otomatis setelah 15 menit jika tidak direspons (durasi bisa diatur, checkpoint bisa dimatikan per penugasan). | Must |
| F-46 | Aturan bawaan mengecualikan endpoint yang bisa merusak jalannya scan (logout, ganti password, hapus akun, reset data). Pengecualian ini bisa dibatalkan di checkpoint. | Must |
| F-15 | Rate limit dan jumlah request paralel bisa diatur per penugasan. | Must |
| F-16 | Kegagalan satu tool atau modul tidak menghentikan pipeline. Kegagalannya dicatat dan ditampilkan. | Must |

### 6.4 Peran LLM

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-17 | **Memahami aplikasi:** menandai setiap endpoint dengan kandidat kerentanan (misalnya "objek milik user, kandidat IDOR" atau "parameter harga, kandidat logika bisnis"). Tanda ini ikut menentukan modul uji yang dijalankan. | Must |
| F-18 | **Menyusun input:** membuat body request yang valid sesuai API, variasi payload ketika diblokir filter, dan data uji logika bisnis. | Must |
| F-19 | **Menilai respons:** menilai hal yang butuh pemahaman makna, misalnya apakah respons untuk akun B berisi data akun A, atau apakah pesan error membocorkan informasi internal. | Must |
| F-20 | **Mini-loop verifikasi:** untuk temuan "perlu cek manual", LLM mengusulkan 1–3 request lanjutan, sistem menjalankannya, lalu LLM menilai hasilnya. Maksimal 3 putaran per temuan. | Must |
| F-21 | **Triase AI:** menggabungkan temuan duplikat, menjelaskan dampak dan saran perbaikan dalam Bahasa Indonesia, serta menyarankan uji manual lanjutan. | Must |
| F-22 | Semua keluaran LLM berformat terstruktur (JSON schema). Jika LLM gagal atau tidak tersedia, pipeline tetap jalan dengan aturan bawaan. | Must |
| F-23 | Penyedia LLM bisa diganti lewat konfigurasi: lokal (LM Studio, Ollama) atau API yang kompatibel dengan OpenAI. | Must |

### 6.5 Validasi dan temuan

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-24 | Validator deterministik per jenis kerentanan memberi status otomatis: **terkonfirmasi** atau **perlu cek manual**. | Must |
| F-25 | Setiap temuan menyimpan evidence lengkap: request dan response mentah, langkah reproduksi, dan PoC (perintah curl). | Must |
| F-26 | Status temuan: baru → terkonfirmasi / perlu cek manual → diterima / ditolak oleh asesor → (setelah retest) diperbaiki / masih rentan. | Must |
| F-27 | Asesor bisa menambah dan menyunting temuan secara manual. | Must |
| F-28 | Setiap temuan menyimpan vektor dan skor **CVSS 3.1 dan CVSS 4.0**, ID WSTG, dan CWE. Severity dan laporan mengikuti versi utama yang dipilih di pengaturan (bisa juga menampilkan keduanya). | Must |
| F-38 | Validator dan template temuan mengisi vektor awal untuk kedua versi CVSS. Asesor bisa menyunting masing-masing. Tidak ada konversi otomatis antarversi karena metrik keduanya berbeda. | Must |

### 6.6 Verifikasi manual

RAJDOLL tidak bergantung pada Burp. Burp tetap bisa dipakai untuk pengujian manual yang interaktif, cukup lewat salin-tempel.

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-30 | Menyalin request temuan dalam format HTTP mentah (siap ditempel ke Burp Repeater) dan sebagai perintah curl. | Must |
| F-45 | **Kirim ulang dari UI:** request temuan bisa disunting lalu dikirim ulang dari RAJDOLL. Hasilnya otomatis tersimpan sebagai evidence temuan, tercatat di audit log, dan tetap melewati pengecekan scope. | Should |

### 6.7 Laporan

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-32 | Ekspor laporan Markdown: ringkasan, daftar temuan per severity, detail temuan (deskripsi, dampak, evidence, langkah reproduksi, rekomendasi), serta lampiran scope dan metodologi. | Must |
| F-33 | Hanya temuan berstatus "diterima" yang masuk laporan. | Must |
| F-34 | Pustaka template temuan (deskripsi dan rekomendasi baku berbahasa Indonesia) yang bisa disunting dan dipakai ulang. | Should |

### 6.8 Pemantauan dan jejak audit

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-35 | Dashboard real-time: tahap aktif, modul berjalan, jumlah request, temuan yang masuk, dan log. | Must |
| F-36 | Audit log setiap request ke target: waktu, modul, metode, URL, dan kode status. | Must |
| F-37 | Setiap keputusan LLM (input dan output) disimpan dan bisa ditelusuri dari temuan terkait. | Should |

### 6.9 Retest

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-39 | Memulai retest untuk satu penugasan. Retest hanya menjalankan ulang PoC dan validator untuk temuan berstatus "diterima", bukan pipeline penuh. | Must |
| F-40 | URL target dan sesi login bisa diperbarui sebelum retest, karena clone versi perbaikan bisa berbeda alamat. | Must |
| F-41 | Hasil retest per temuan: **diperbaiki**, **masih rentan**, atau **tidak bisa diuji ulang** (misalnya endpoint sudah tidak ada). Evidence retest disimpan terpisah dari evidence awal. | Must |
| F-42 | Temuan manual ditandai "perlu retest manual". Asesor bisa mengubah hasil retest otomatis maupun manual. | Must |
| F-43 | Ekspor laporan retest Markdown: daftar temuan awal, status setelah retest, dan evidence retest. | Must |
| F-44 | Menyimpan riwayat beberapa putaran retest per penugasan (retest ke-1, ke-2, dan seterusnya). | Should |

### 6.10 WAF dan pemblokiran

| ID | Kebutuhan | Prioritas |
|---|---|---|
| F-47 | Mendeteksi keberadaan WAF di tahap recon dan menampilkannya di checkpoint. | Must |
| F-48 | Mendeteksi pemblokiran selama scan (lonjakan respons 403/406/429/503, halaman blokir, koneksi diputus, tantangan CAPTCHA). Kecepatan diturunkan otomatis; jika pemblokiran berlanjut, scan di-pause dan asesor diberi tahu. | Must |
| F-49 | Pengujian yang gagal karena diblokir ditandai **tidak teruji (terblokir)** per modul dan endpoint, lalu dicantumkan di laporan. Hasil kosong karena diblokir tidak boleh dianggap aman. | Must |
| F-50 | Header identitas yang bisa diatur (User-Agent atau header khusus) agar trafik VA mudah dikenali dan di-whitelist oleh instansi. | Should |

## 7. Kebutuhan non-fungsional

| ID | Kebutuhan |
|---|---|
| NF-01 | **Ringan:** seluruh sistem berjalan di satu laptop bersama Burp, browser, dan LLM lokal. Jumlah layanan dibuat seminimal mungkin. 13 container MCP dilebur menjadi satu runner tool. |
| NF-02 | **Batas LLM:** setiap tugas LLM dirancang muat dalam konteks model kelas 4B (sekitar 4–8 ribu token per panggilan). |
| NF-03 | **Keamanan akses:** UI dan API hanya bisa diakses setelah login, dan secara default hanya mendengarkan di localhost. |
| NF-04 | **Keamanan data:** evidence, sesi, dan kredensial target dienkripsi di database. |
| NF-05 | **Kepatuhan scope:** tidak ada request ke host di luar scope. Pengecualian hanya untuk LLM API (jika dipilih) dan pembaruan template nuclei. |
| NF-06 | **Privasi:** dengan LLM lokal, tidak ada data target yang keluar dari laptop. Jika LLM API dipakai, UI menampilkan peringatan jelas. |
| NF-07 | **Keandalan:** status pipeline disimpan per tahap sehingga bisa dilanjutkan setelah restart. |
| NF-08 | **Mudah dikembangkan:** menambah pengujian baru cukup dengan menambah template nuclei atau satu modul kustom, tanpa mengubah inti sistem. |
| NF-09 | **Bahasa:** UI dan laporan berbahasa Indonesia. |
| NF-10 | **Siap mode agen:** runner tool menyediakan satu antarmuka MCP agar mode agen bisa ditambahkan di versi berikutnya tanpa merombak runner. |

## 8. Asumsi dan batasan

- Target adalah clone aplikasi production, sehingga payload agresif dan pengujian yang mengubah data diperbolehkan.
- Laptop asesor punya akses jaringan langsung ke target, tanpa VPN.
- Jika clone berada di belakang WAF, IP laptop asesor di-whitelist oleh instansi agar yang diuji adalah aplikasinya, bukan WAF-nya. Menguji efektivitas WAF di luar scope v1.
- Sistem berjalan di Windows dengan Docker Desktop (WSL2). LLM lokal berjalan di sisi Windows, di luar container.
- RAJDOLL tidak bergantung pada Burp. Semua evidence disimpan di RAJDOLL sendiri; Burp hanya alat bantu manual di luar sistem.
- Model kelas 4B tidak dipakai untuk mengendalikan alur pipeline.
- Nuclei yang dipakai minimal versi 3.10 (perbaikan CVE-2026-76802 pada mode DAST).

## 9. Definisi selesai v1

v1 dianggap selesai jika:

1. Satu penugasan VA terhadap clone aplikasi web bisa dijalankan dari pembuatan penugasan sampai laporan Markdown, tanpa intervensi selain triase.
2. Setiap temuan di laporan punya evidence, langkah reproduksi, dan PoC yang bisa diulang (curl atau kirim ulang dari RAJDOLL).
3. Tidak ada satu pun request yang keluar dari scope selama scan.
4. Scan yang terhenti (pause, crash, restart laptop) bisa dilanjutkan tanpa mengulang dari awal.
5. Pipeline tetap selesai walaupun LLM dimatikan, hanya tanpa analisis tambahan dari LLM.
6. Retest atas temuan yang diterima bisa dijalankan dan menghasilkan laporan retest.

## 10. Rencana versi berikutnya

Kandidat untuk v2 dan seterusnya, belum dijadwalkan:

- Mode agen untuk menggali satu temuan lebih dalam, khusus saat memakai LLM API.
- Laporan sesuai template kantor.
- Target non-web.
- Ekstensi Burp untuk integrasi dua arah.

## 11. Pertanyaan terbuka

| No | Pertanyaan | Status |
|---|---|---|
| Q1 | Versi CVSS yang dipakai? | Selesai: keduanya (3.1 dan 4.0), lihat F-28 dan F-38 |
| Q2 | Apakah retest perlu masuk v1? | Selesai: ya, lihat bagian 6.9 |
| Q3 | Sistem operasi laptop? | Selesai: Windows dengan Docker Desktop (WSL2) |
| Q4 | Apakah target diakses lewat VPN? | Selesai: tidak |
| Q5 | Konsep dan default checkpoint setelah recon. | Selesai: aktif, lanjut otomatis setelah 15 menit (F-14, F-46) |
| Q6 | Apakah Burp diintegrasikan sebagai proxy? | Selesai: tidak, cukup salin-tempel (bagian 6.6) |
| Q7 | Bagaimana menangani WAF? | Selesai: whitelist IP oleh instansi, ditambah deteksi dan penandaan pemblokiran (bagian 6.10) |
