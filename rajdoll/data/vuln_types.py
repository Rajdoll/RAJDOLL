"""Built-in vulnerability types: title, WSTG/CWE, default CVSS 3.1 vector, and report text.

The texts are the starting point of each finding (BSD 6.1 `description`, `impact`,
`recommendation`); the assessor can edit them per finding. F9 seeds the `finding_template` table
from this catalog and adds CVSS 4.0 vectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class VulnType:
    key: str
    title: str
    wstg_id: str
    cwe_id: str
    cvss31: str
    description: str
    impact: str
    recommendation: str
    references: tuple[str, ...] = field(default_factory=tuple)


CATALOG: dict[str, VulnType] = {
    vt.key: vt
    for vt in [
        VulnType(
            key="sqli",
            title="SQL Injection",
            wstg_id="WSTG-INPV-05",
            cwe_id="CWE-89",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "Nilai parameter disisipkan langsung ke dalam kueri SQL tanpa parameterisasi, "
                "sehingga penyerang dapat mengubah struktur kueri yang dijalankan basis data."
            ),
            impact=(
                "Penyerang dapat membaca, mengubah, atau menghapus data di basis data, melewati "
                "autentikasi, dan pada konfigurasi tertentu menjalankan perintah di server basis "
                "data."
            ),
            recommendation=(
                "Gunakan prepared statement atau query parameterized untuk semua kueri, batasi "
                "hak akun basis data aplikasi, dan validasi input dengan daftar nilai yang "
                "diizinkan."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ),
        ),
        VulnType(
            key="xss_reflected",
            title="Reflected Cross-Site Scripting",
            wstg_id="WSTG-INPV-01",
            cwe_id="CWE-79",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            description=(
                "Nilai parameter dipantulkan ke halaman tanpa encoding sesuai konteks HTML, "
                "sehingga skrip yang disisipkan dijalankan oleh browser korban."
            ),
            impact=(
                "Penyerang dapat menjalankan skrip di sesi pengguna yang membuka tautan berbahaya: "
                "mencuri data sesi yang tidak dilindungi HttpOnly, melakukan aksi atas nama "
                "pengguna, atau menampilkan halaman palsu."
            ),
            recommendation=(
                "Lakukan output encoding sesuai konteks (HTML, atribut, JavaScript, URL) pada "
                "setiap data yang ditampilkan, gunakan template engine dengan auto-escaping, dan "
                "terapkan Content-Security-Policy yang ketat."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
                "https://cwe.mitre.org/data/definitions/79.html",
            ),
        ),
        VulnType(
            key="cmdi",
            title="OS Command Injection",
            wstg_id="WSTG-INPV-12",
            cwe_id="CWE-78",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "Nilai parameter diteruskan ke perintah sistem operasi melalui shell tanpa "
                "pembatasan, sehingga penyerang dapat menyisipkan perintah tambahan."
            ),
            impact=(
                "Penyerang dapat menjalankan perintah apa pun dengan hak akses proses aplikasi, "
                "membaca berkas konfigurasi dan kredensial, serta mengambil alih server."
            ),
            recommendation=(
                "Hindari memanggil shell dari aplikasi; gunakan API pustaka atau eksekusi proses "
                "dengan daftar argumen tanpa shell, dan validasi input dengan daftar nilai yang "
                "diizinkan."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ),
        ),
        VulnType(
            key="ssti",
            title="Server-Side Template Injection",
            wstg_id="WSTG-INPV-18",
            cwe_id="CWE-1336",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "Nilai parameter dimasukkan ke dalam template sisi server dan dievaluasi oleh "
                "template engine, sehingga ekspresi yang disisipkan dijalankan di server."
            ),
            impact=(
                "Penyerang dapat membaca data dan konfigurasi aplikasi, dan pada banyak template "
                "engine menjalankan kode atau perintah di server."
            ),
            recommendation=(
                "Jangan membangun template dari input pengguna; kirim data sebagai variabel ke "
                "template yang tetap, dan gunakan mode sandbox template engine bila tersedia."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                "https://cwe.mitre.org/data/definitions/1336.html",
            ),
        ),
        VulnType(
            key="ssrf",
            title="Server-Side Request Forgery",
            wstg_id="WSTG-INPV-19",
            cwe_id="CWE-918",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
            description=(
                "Aplikasi mengambil URL yang ditentukan pengguna dari sisi server tanpa membatasi "
                "tujuan, sehingga server dapat dipakai untuk mengakses alamat lain."
            ),
            impact=(
                "Penyerang dapat mengakses layanan internal yang tidak terbuka ke internet "
                "(panel admin, metadata cloud, basis data), memindai jaringan internal, dan "
                "membaca data dari layanan tersebut."
            ),
            recommendation=(
                "Batasi tujuan permintaan dengan daftar host dan skema yang diizinkan, tolak "
                "alamat internal dan loopback setelah resolusi DNS, dan nonaktifkan pengalihan "
                "otomatis."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html",
            ),
        ),
        VulnType(
            key="idor",
            title="Insecure Direct Object Reference (IDOR)",
            wstg_id="WSTG-ATHZ-04",
            cwe_id="CWE-639",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            description=(
                "Aplikasi menampilkan objek berdasarkan pengenal yang dikirim pengguna tanpa "
                "memeriksa apakah objek tersebut milik pengguna yang sedang login, sehingga akun "
                "lain dapat membuka objek milik akun ini hanya dengan mengganti pengenalnya."
            ),
            impact=(
                "Pengguna yang sudah login dapat membaca data milik pengguna lain (data pribadi, "
                "dokumen, transaksi) dengan menebak atau mengurutkan pengenal objek."
            ),
            recommendation=(
                "Periksa kepemilikan atau hak akses setiap objek di sisi server untuk setiap "
                "permintaan, berdasarkan identitas dari sesi, bukan dari parameter. Pertimbangkan "
                "pengenal acak yang tidak dapat ditebak sebagai lapisan tambahan."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                "https://cwe.mitre.org/data/definitions/639.html",
            ),
        ),
        VulnType(
            key="privilege_escalation",
            title="Eskalasi Hak Akses (fungsi admin tanpa pemeriksaan peran)",
            wstg_id="WSTG-ATHZ-03",
            cwe_id="CWE-269",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            description=(
                "Sebuah fungsi administratif hanya memeriksa bahwa pengguna sudah login, tanpa "
                "memeriksa perannya, sehingga akun berhak rendah yang ditolak di fungsi admin "
                "lain tetap dapat membuka fungsi ini."
            ),
            impact=(
                "Pengguna biasa dapat menjalankan atau melihat fungsi khusus admin, misalnya "
                "daftar seluruh pengguna, pengaturan, atau perubahan data milik orang lain."
            ),
            recommendation=(
                "Terapkan pemeriksaan peran di sisi server pada setiap fungsi administratif secara "
                "terpusat (deny by default), bukan hanya menyembunyikan menu di antarmuka."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation",
                "https://cwe.mitre.org/data/definitions/269.html",
            ),
        ),
        VulnType(
            key="jwt_signature_not_verified",
            title="Tanda Tangan JWT Tidak Diverifikasi",
            wstg_id="WSTG-SESS-10",
            cwe_id="CWE-347",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            description=(
                "Aplikasi menerima JSON Web Token yang tanda tangannya sudah diubah, sehingga "
                "isi token (identitas, peran, masa berlaku) tidak dilindungi sama sekali."
            ),
            impact=(
                "Penyerang dapat membuat token dengan klaim apa pun, misalnya menyamar sebagai "
                "pengguna lain atau admin, tanpa mengetahui kunci penandatangan."
            ),
            recommendation=(
                "Verifikasi tanda tangan setiap token di sisi server dengan library JWT yang "
                "terpercaya, tetapkan algoritma yang diizinkan secara eksplisit, dan tolak token "
                "yang gagal diverifikasi."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
                "https://cwe.mitre.org/data/definitions/347.html",
            ),
        ),
        VulnType(
            key="jwt_alg_none",
            title="JWT Tanpa Tanda Tangan (alg: none) Diterima",
            wstg_id="WSTG-SESS-10",
            cwe_id="CWE-347",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            description=(
                "Aplikasi menerima JSON Web Token dengan header `alg: none` dan tanpa tanda "
                "tangan, sehingga siapa pun dapat membuat token yang dianggap sah."
            ),
            impact=(
                "Penyerang dapat mengubah klaim token (identitas, peran) sesuka hati dan "
                "mengambil alih akun mana pun, termasuk akun admin."
            ),
            recommendation=(
                "Tolak token dengan algoritma `none` dan tetapkan daftar algoritma yang "
                "diizinkan di sisi server; jangan mengambil algoritma dari header token."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
                "https://cwe.mitre.org/data/definitions/347.html",
            ),
        ),
        VulnType(
            key="jwt_weak_secret",
            title="Secret Penandatangan JWT Lemah",
            wstg_id="WSTG-SESS-10",
            cwe_id="CWE-1391",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            description=(
                "JSON Web Token ditandatangani dengan HMAC memakai secret yang ada di daftar "
                "secret umum, sehingga secret dapat ditebak dari satu token secara offline."
            ),
            impact=(
                "Siapa pun yang memegang satu token (misalnya akun biasa) dapat menebak secret, "
                "lalu membuat token sah dengan klaim apa pun, termasuk menyamar sebagai admin."
            ),
            recommendation=(
                "Ganti secret dengan nilai acak minimal 256 bit dari pembangkit acak yang aman, "
                "simpan di luar kode sumber, dan cabut semua token lama. Pertimbangkan algoritma "
                "asimetris (RS256/ES256)."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
                "https://cwe.mitre.org/data/definitions/1391.html",
            ),
        ),
        VulnType(
            key="weak_lockout",
            title="Tidak Ada Pembatasan Percobaan Login",
            wstg_id="WSTG-ATHN-03",
            cwe_id="CWE-307",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                "Endpoint login menerima percobaan login gagal berturut-turut tanpa pembatasan: "
                "tidak ada penolakan, penundaan, CAPTCHA, maupun penguncian sementara."
            ),
            impact=(
                "Penyerang dapat menebak password secara otomatis (brute force atau credential "
                "stuffing) sampai menemukan password yang benar."
            ),
            recommendation=(
                "Batasi percobaan login per akun dan per alamat sumber (penundaan bertahap, "
                "penguncian sementara, atau CAPTCHA setelah beberapa kegagalan), catat dan pantau "
                "percobaan gagal, dan dorong autentikasi multifaktor."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
                "https://cwe.mitre.org/data/definitions/307.html",
            ),
        ),
        VulnType(
            key="cookie_flags",
            title="Cookie Sesi tanpa Atribut Keamanan",
            wstg_id="WSTG-SESS-02",
            cwe_id="CWE-1004",
            cvss31="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            description=(
                "Cookie sesi dibuat tanpa satu atau lebih atribut keamanan: `HttpOnly` (cookie "
                "dapat dibaca JavaScript), `Secure` (cookie dapat terkirim lewat HTTP biasa), "
                "atau `SameSite` (cookie ikut terkirim pada request lintas situs)."
            ),
            impact=(
                "Sesi lebih mudah dicuri melalui XSS atau penyadapan jaringan, dan request "
                "lintas situs (CSRF) lebih mudah membawa sesi pengguna."
            ),
            recommendation=(
                "Set cookie sesi dengan `HttpOnly`, `Secure`, dan `SameSite=Lax` atau `Strict` "
                "di konfigurasi framework atau server."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
                "https://cwe.mitre.org/data/definitions/1004.html",
            ),
        ),
        VulnType(
            key="sensitive_file",
            title="File Sensitif Dapat Diakses Publik",
            wstg_id="WSTG-CONF-04",
            cwe_id="CWE-538",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=(
                "Server web menyajikan file yang tidak seharusnya publik, misalnya konfigurasi "
                "(`.env`, `.git/config`, `docker-compose.yml`), file kata sandi, atau log "
                "aplikasi, tanpa perlu login."
            ),
            impact=(
                "Penyerang dapat membaca kredensial basis data, kunci API, alamat repositori "
                "beserta kredensialnya, atau isi log yang membuka jalan ke serangan lanjutan."
            ),
            recommendation=(
                "Hapus file tersebut dari direktori web atau blokir aksesnya di konfigurasi server "
                "(misalnya tolak semua dotfile dan direktori `.git`), lalu ganti semua kredensial "
                "yang sempat terbuka."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                "https://cwe.mitre.org/data/definitions/538.html",
            ),
        ),
        VulnType(
            key="backup_file",
            title="File Cadangan Dapat Diunduh",
            wstg_id="WSTG-CONF-04",
            cwe_id="CWE-530",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=(
                "Salinan cadangan file atau basis data (misalnya `index.php.bak`, `backup.sql`) "
                "tersimpan di direktori web dan dapat diunduh siapa pun."
            ),
            impact=(
                "Penyerang dapat membaca kode sumber, kredensial, atau isi basis data yang "
                "seharusnya tidak pernah keluar dari server."
            ),
            recommendation=(
                "Hapus file cadangan dari direktori web, simpan cadangan di luar web root, dan "
                "blokir ekstensi cadangan (`.bak`, `.old`, `.sql`, `~`) di konfigurasi server."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                "https://cwe.mitre.org/data/definitions/530.html",
            ),
        ),
        VulnType(
            key="debug_exposed",
            title="Halaman Debug atau Diagnostik Terbuka",
            wstg_id="WSTG-CONF-02",
            cwe_id="CWE-489",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                "Halaman debug atau diagnostik (misalnya `phpinfo()`, mode debug framework, "
                "`server-status`, endpoint actuator) dapat dibuka tanpa login."
            ),
            impact=(
                "Penyerang mendapat detail internal: versi komponen, path file, variabel "
                "lingkungan, dan konfigurasi yang memudahkan serangan lanjutan."
            ),
            recommendation=(
                "Matikan mode debug di produksi, hapus halaman diagnostik, dan batasi endpoint "
                "pemantauan hanya untuk jaringan internal atau pengguna yang berwenang."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
                "https://cwe.mitre.org/data/definitions/489.html",
            ),
        ),
        VulnType(
            key="missing_security_headers",
            title="Header Keamanan HTTP Tidak Lengkap",
            wstg_id="WSTG-CONF-12",
            cwe_id="CWE-693",
            cvss31="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            description=(
                "Respons aplikasi tidak menyertakan satu atau lebih header keamanan: "
                "`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, atau "
                "`Strict-Transport-Security` (HTTPS)."
            ),
            impact=(
                "Peramban tidak mendapat lapisan perlindungan tambahan terhadap XSS, clickjacking, "
                "MIME sniffing, dan downgrade ke HTTP."
            ),
            recommendation=(
                "Tambahkan header keamanan di server web atau aplikasi: CSP yang ketat, "
                "`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (atau CSP "
                "`frame-ancestors`), dan HSTS untuk situs HTTPS."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy",
                "https://owasp.org/www-project-secure-headers/",
                "https://cwe.mitre.org/data/definitions/693.html",
            ),
        ),
        VulnType(
            key="version_disclosure",
            title="Versi Perangkat Lunak Terlihat di Header",
            wstg_id="WSTG-INFO-02",
            cwe_id="CWE-200",
            cvss31="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                "Header respons (misalnya `Server` atau `X-Powered-By`) menyebut nama dan versi "
                "perangkat lunak server atau framework."
            ),
            impact=(
                "Penyerang dapat langsung mencari kerentanan yang diketahui untuk versi tersebut "
                "tanpa perlu menebak."
            ),
            recommendation=(
                "Hilangkan atau samarkan header versi di konfigurasi server dan framework "
                "(misalnya `expose_php = Off`, `server_tokens off`)."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                "https://cwe.mitre.org/data/definitions/200.html",
            ),
        ),
        VulnType(
            key="http_trace",
            title="Metode HTTP TRACE Aktif",
            wstg_id="WSTG-CONF-06",
            cwe_id="CWE-693",
            cvss31="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            description=(
                "Server menjawab request TRACE dengan memantulkan seluruh request, termasuk "
                "header-nya."
            ),
            impact=(
                "Dalam kombinasi dengan kelemahan lain, TRACE dapat dipakai untuk membaca header "
                "sensitif seperti cookie (Cross-Site Tracing)."
            ),
            recommendation=(
                "Nonaktifkan metode TRACE di server web (misalnya `TraceEnable off` di Apache) dan "
                "izinkan hanya metode yang dipakai aplikasi."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                "https://cwe.mitre.org/data/definitions/693.html",
            ),
        ),
        VulnType(
            key="error_disclosure",
            title="Pesan Error Membocorkan Detail Internal",
            wstg_id="WSTG-ERRH-01",
            cwe_id="CWE-209",
            cvss31="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                "Input yang tidak terduga membuat aplikasi menampilkan pesan error mentah: stack "
                "trace, halaman debug framework, atau path file di server."
            ),
            impact=(
                "Penyerang mengetahui teknologi, struktur kode, path instalasi, dan kadang "
                "potongan query atau konfigurasi, yang memudahkan serangan lanjutan."
            ),
            recommendation=(
                "Matikan mode debug di produksi, tangani error secara terpusat dengan pesan umum "
                "untuk pengguna, dan catat detail error hanya di log server."
            ),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling",
                "https://cwe.mitre.org/data/definitions/209.html",
            ),
        ),
    ]
}


def get(key: str) -> VulnType:
    try:
        return CATALOG[key]
    except KeyError:
        raise KeyError(f"unknown vulnerability type {key!r}") from None
