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
    ]
}


def get(key: str) -> VulnType:
    try:
        return CATALOG[key]
    except KeyError:
        raise KeyError(f"unknown vulnerability type {key!r}") from None
