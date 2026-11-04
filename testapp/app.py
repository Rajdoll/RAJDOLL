"""RAJDOLL testapp: a small, deliberately vulnerable web application for integration tests.

Never expose this app. It runs only under the compose `test` profile, on the internal Docker
network, so modules and validators can be proven against known weaknesses (IPD F3 onward).
Each deliberate weakness is listed in WEAKNESSES and gains a matching test as phases add
modules. RECON_ENDPOINTS lists every endpoint recon must find (IPD F5 exit criterion), with the
way it can be discovered.
"""

import base64
import binascii
import hashlib
import hmac
import http.client
import json
import secrets
import sqlite3
import subprocess
import threading
import traceback
import urllib.request
from html import escape

import jinja2
from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)

WEAKNESSES = {
    "exposed-env": "GET /.env serves configuration with credentials (WSTG-CONF-04, CWE-538)",
    "sqli": "GET /katalog?nama= builds an SQLite query by string concatenation (CWE-89)",
    "xss-reflected": "GET /sapa?nama= reflects the name without HTML encoding (CWE-79)",
    "cmdi": "POST /alat/ping passes `alamat` to a shell (CWE-78)",
    "ssti": "GET /pratinjau?templat= renders the value as a Jinja2 template (CWE-1336)",
    "ssrf": "GET /ambil?url= fetches any http URL from the server (CWE-918)",
    "idor": "GET /akun/{id} shows any user's private data to any logged-in user (CWE-639)",
    "privilege-escalation": (
        "GET /admin/pengguna checks only the login, not the admin role (CWE-269); /admin checks it"
    ),
    "jwt-alg-none": "GET /api/v1/saya accepts an unsigned JWT with alg none (CWE-347)",
    "jwt-weak-secret": "JWTs from POST /api/v1/token are signed with the HMAC secret 'rahasia'",
    "no-lockout": "POST /login and POST /api/v1/token never limit failed attempts (CWE-307)",
    "cookie-flags": "GET /login starts a session cookie `sid` without HttpOnly or SameSite",
    "git-config": "GET /.git/config serves the repository config with a deploy password",
    "phpinfo": "GET /info.php is a leftover phpinfo() page (CWE-489)",
    "backup-file": "GET /index.php.bak serves the old page's source with database credentials",
    "missing-headers": "no response sets CSP, X-Content-Type-Options, or X-Frame-Options",
    "version-header": "every response names its version: Server: rajdoll-testapp/1.0 (CWE-200)",
    "http-trace": "TRACE echoes the request back on any path (WSTG-CONF-06)",
    "debug-traceback": "GET /laporan?limit= shows a Python traceback for a non-number (CWE-209)",
}
# Findings the scan must confirm (IPD F6 and F8 exit criteria): (type, path, parameter).
# Authorization needs two accounts: Akun A = budi (admin), Akun B = sari (user). Each pasted
# session carries the `sid` cookie and a JWT from POST /api/v1/token (Authorization: Bearer).
EXPECTED_FINDINGS: list[tuple[str, str, str | None]] = [
    ("sqli", "/katalog", "nama"),
    ("xss_reflected", "/sapa", "nama"),
    ("cmdi", "/alat/ping", "alamat"),
    ("ssti", "/pratinjau", "templat"),
    ("ssrf", "/ambil", "url"),
    ("idor", "/akun/{id}", "id"),
    ("privilege_escalation", "/admin/pengguna", None),
    ("jwt_alg_none", "/api/v1/saya", "Authorization"),
    ("jwt_weak_secret", "/api/v1/saya", "Authorization"),
    ("weak_lockout", "/login", None),
    ("weak_lockout", "/api/v1/token", None),
    ("cookie_flags", "/login", "sid"),
    ("sensitive_file", "/.env", None),
    ("sensitive_file", "/.git/config", None),
    ("debug_exposed", "/info.php", None),
    ("backup_file", "/index.php.bak", None),
    ("missing_security_headers", "/", None),
    ("version_disclosure", "/", "Server"),
    ("http_trace", "/", None),
    ("error_disclosure", "/laporan", "limit"),
]

# (method, path template, how recon can find it). Paths use {id} for numeric segments.
RECON_ENDPOINTS: list[tuple[str, str, str]] = [
    ("GET", "/", "link"),
    ("GET", "/login", "link"),
    ("POST", "/login", "form"),
    ("GET", "/profil", "link"),
    ("GET", "/produk", "link"),
    ("GET", "/produk/{id}", "link"),
    ("GET", "/cari", "form"),
    ("POST", "/kontak", "form"),
    ("GET", "/logout", "link (logged in)"),
    ("GET", "/upload", "link (logged in)"),
    ("POST", "/upload", "form (logged in)"),
    ("GET", "/akun/{id}", "link (logged in)"),
    ("GET", "/static/app.js", "script"),
    ("GET", "/api/v1/ringkasan", "javascript (runtime fetch)"),
    ("GET", "/api/v1/pesanan", "javascript (source only)"),
    ("GET", "/api/v1/pesanan/{id}", "javascript (source only)"),
    ("POST", "/api/v1/keranjang", "javascript (source only)"),
    ("GET", "/api/v1/pengguna/{id}", "openapi"),
    ("POST", "/api/v1/transfer", "openapi"),
    ("GET", "/openapi.json", "openapi probe"),
    ("GET", "/admin", "directory fuzzing"),
    ("GET", "/robots.txt", "known file"),
    ("GET", "/internal/laporan", "robots.txt"),
    ("GET", "/.env", "directory fuzzing"),
    ("GET", "/katalog", "form"),
    ("GET", "/sapa", "link"),
    ("POST", "/alat/ping", "form"),
    ("GET", "/pratinjau", "link"),
    ("GET", "/ambil", "link"),
    ("GET", "/admin/pengguna", "link from /admin (admin account)"),
    ("POST", "/api/v1/token", "openapi"),
    ("GET", "/api/v1/saya", "openapi"),
    ("GET", "/index.php", "link"),
    ("GET", "/.git/config", "directory fuzzing"),
    ("GET", "/info.php", "directory fuzzing"),
    ("GET", "/laporan", "link"),
]
# Query parameter only found by parameter discovery: /cari?debug=1 adds diagnostics.
HIDDEN_PARAMS = {"/cari": ["debug"]}
OUT_OF_SCOPE_HOSTS = ["cdn.luar.test"]

USERS = {"budi": "budi123", "sari": "sari123"}
USER_IDS = {"budi": 1, "sari": 2}
ROLES = {"budi": "admin", "sari": "pengguna"}
PROFILES = {
    1: {"nama": "Budi Santoso", "email": "budi@instansi.test", "nip": "198801012010011001"},
    2: {"nama": "Sari Wulandari", "email": "sari@instansi.test", "nip": "199002022015022002"},
}
SESSIONS: dict[str, str] = {}
JWT_SECRET = "rahasia"  # noqa: S105 (weakness "jwt-weak-secret": a dictionary word)
PRODUCTS = {1: "Kopi Gayo", 2: "Teh Melati"}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def trace_echo(request: Request, call_next):  # type: ignore[no-untyped-def]
    if request.method != "TRACE":
        return await call_next(request)
    # Weakness "http-trace": the request is echoed back, headers included.
    lines = [f"TRACE {request.url.path} HTTP/1.1"]
    lines += [f"{name}: {value}" for name, value in request.headers.items()]
    return PlainTextResponse("\r\n".join(lines), media_type="message/http")


@app.middleware("http")
async def server_header(request: Request, call_next):  # type: ignore[no-untyped-def]
    response: Response = await call_next(request)
    # Weakness "version-header" (and "missing-headers": no security header is ever set).
    response.headers["Server"] = "rajdoll-testapp/1.0"
    return response


def _page(title: str, body: str, *, script: bool = False) -> HTMLResponse:
    scripts = (
        '<script src="/static/app.js"></script><script src="http://cdn.luar.test/lib.js"></script>'
        if script
        else ""
    )
    return HTMLResponse(
        f"<!doctype html><html><head><title>{title}</title>{scripts}</head>"
        f"<body>{body}</body></html>"
    )


def _user(request: Request) -> str | None:
    return SESSIONS.get(request.cookies.get("sid", ""))


@app.get("/")
def index() -> HTMLResponse:
    return _page(
        "RAJDOLL testapp",
        '<h1>RAJDOLL testapp</h1><nav><a href="/login">Masuk</a> <a href="/profil">Profil</a> '
        '<a href="/produk">Produk</a></nav>'
        '<form method="get" action="/cari"><input name="q"><button>Cari</button></form>'
        '<form method="post" action="/kontak"><input name="nama"><textarea name="pesan">'
        "</textarea><button>Kirim</button></form>"
        '<form method="get" action="/katalog"><input name="nama"><button>Cari produk</button>'
        "</form>"
        '<form method="post" action="/alat/ping"><input name="alamat" value="localhost">'
        "<button>Ping</button></form>"
        '<a href="/sapa?nama=Tamu">Sapa</a> <a href="/pratinjau?templat=Halo">Pratinjau</a> '
        '<a href="/ambil?url=/health">Status layanan</a> <a href="/index.php">Beranda lama</a> '
        '<a href="/laporan?limit=10">Laporan</a>'
        '<div id="ringkasan"></div>',
        script=True,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/robots.txt")
def robots() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nDisallow: /internal/laporan\n")


@app.get("/static/app.js")
def app_js() -> Response:
    # The /api/v1 endpoints below appear nowhere in HTML: only in this script. `ringkasan` is
    # requested when the page loads; the others only exist in the source.
    source = """
(function () {
  var api = "/api/v1";
  fetch(api + "/ringkasan").then(function (r) { return r.json(); }).then(function (data) {
    var el = document.getElementById("ringkasan");
    if (el) { el.textContent = data.pesan; }
  });
  window.muatPesanan = function () { return fetch("/api/v1/pesanan"); };
  window.detailPesanan = function (id) { return fetch("/api/v1/pesanan/" + id); };
  window.tambahKeKeranjang = function (produk, jumlah) {
    return fetch("/api/v1/keranjang", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({produk_id: produk, jumlah: jumlah})
    });
  };
})();
"""
    return Response(source, media_type="application/javascript")


@app.get("/api/v1/ringkasan")
def summary() -> dict[str, str]:
    return {"pesan": "Selamat datang di testapp"}


@app.get("/api/v1/pesanan")
def orders() -> list[dict[str, int]]:
    return [{"id": 10, "produk_id": 1}]


@app.get("/api/v1/pesanan/{order_id}")
def order(order_id: int) -> dict[str, int]:
    return {"id": order_id, "produk_id": 1}


@app.post("/api/v1/keranjang")
async def add_to_cart(request: Request) -> dict[str, object]:
    body = await request.json()
    return {"ok": True, "keranjang": [body]}


@app.get("/openapi.json")
def openapi_spec() -> dict[str, object]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "testapp API", "version": "1.0"},
        "paths": {
            "/api/v1/pengguna/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "responses": {"200": {"description": "Pengguna"}},
                }
            },
            "/api/v1/token": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Token JWT"}},
                }
            },
            "/api/v1/saya": {
                "get": {
                    "security": [{"bearer": []}],
                    "responses": {"200": {"description": "Pengguna yang login"}},
                }
            },
            "/api/v1/transfer": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "ke_rekening": {"type": "string"},
                                        "jumlah": {"type": "number"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Transfer"}},
                }
            },
        },
    }


@app.get("/api/v1/pengguna/{user_id}")
def api_user(user_id: int) -> dict[str, object]:
    name = next((n for n, i in USER_IDS.items() if i == user_id), None)
    return {"id": user_id, "nama": name}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_for(user: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _b64url(json.dumps({"sub": user, "uid": USER_IDS[user]}).encode())
    signature = hmac.new(JWT_SECRET.encode(), f"{header}.{claims}".encode(), hashlib.sha256)
    return f"{header}.{claims}.{_b64url(signature.digest())}"


def _jwt_user(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer":
        return None
    try:
        head, body, signature = token.strip().split(".")
        header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, binascii.Error):
        return None
    alg = str(header.get("alg", "")).lower()
    if alg == "hs256":
        expected = hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256)
        if not hmac.compare_digest(_b64url(expected.digest()), signature):
            return None
    elif alg != "none":  # weakness "jwt-alg-none": an unsigned token is accepted
        return None
    user = claims.get("sub") if isinstance(claims, dict) else None
    return user if user in USERS else None


@app.post("/api/v1/token")
async def api_token(request: Request) -> Response:
    try:
        body = await request.json()
    except ValueError:
        body = None
    # Weakness "no-lockout" here too: failed attempts are never limited.
    if not isinstance(body, dict) or USERS.get(str(body.get("username"))) != body.get("password"):
        return JSONResponse({"detail": "Username atau password salah"}, status_code=401)
    return JSONResponse({"token": _jwt_for(str(body["username"]))})


@app.get("/api/v1/saya")
def api_me(request: Request) -> Response:
    user = _jwt_user(request)
    if user is None:
        return JSONResponse({"detail": "Token tidak valid"}, status_code=401)
    data = PROFILES[USER_IDS[user]]
    return JSONResponse({"pengguna": user, "nama": data["nama"], "email": data["email"]})


@app.post("/api/v1/transfer")
async def transfer(request: Request) -> dict[str, object]:
    body = await request.json()
    return {"ok": True, "transfer": body}


@app.get("/login")
def login_form(request: Request) -> HTMLResponse:
    response = _page(
        "Masuk",
        '<form method="post" action="/login"><input name="username"><input name="password" '
        'type="password"><button>Masuk</button></form>',
    )
    if "sid" not in request.cookies:
        # Weakness "cookie-flags": like many PHP applications, the login page starts the session
        # cookie, here without HttpOnly or SameSite.
        response.set_cookie("sid", secrets.token_hex(16), samesite=None)
    return response


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)) -> Response:
    # Weakness "no-lockout": failed attempts are never counted or limited.
    if USERS.get(username) != password:
        return _page("Masuk", "<p>Login gagal</p>")
    token = secrets.token_hex(16)
    SESSIONS[token] = username
    response = RedirectResponse("/profil", status_code=303)
    response.set_cookie("sid", token)
    return response


@app.get("/logout")
def logout(request: Request) -> Response:
    SESSIONS.pop(request.cookies.get("sid", ""), None)
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("sid")
    return response


@app.get("/profil")
def profile(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login", status_code=302)
    admin = ' <a href="/admin">Panel admin</a>' if ROLES[user] == "admin" else ""
    return _page(
        "Profil",
        f"<p>Halo, {user.title()}</p>"
        f'<a href="/akun/{USER_IDS[user]}">Akun saya</a> <a href="/upload">Unggah berkas</a> '
        f'<a href="/logout">Keluar</a>{admin}',
    )


@app.get("/akun/{user_id}")
def account(user_id: int, request: Request) -> Response:
    if _user(request) is None:
        return RedirectResponse("/login", status_code=302)
    # Weakness "idor": the account is shown without checking that it is the caller's.
    data = PROFILES.get(user_id)
    if data is None:
        return _page("Akun", "<p>Akun tidak ditemukan</p>")
    return _page(
        "Akun",
        f"<h1>Akun #{user_id}</h1><p>{data['nama']}</p><p>Email: {data['email']}</p>"
        f"<p>NIP: {data['nip']}</p>",
    )


@app.get("/upload")
def upload_form(request: Request) -> Response:
    if _user(request) is None:
        return RedirectResponse("/login", status_code=302)
    return _page(
        "Unggah",
        '<form method="post" action="/upload" enctype="multipart/form-data">'
        '<input type="file" name="berkas"><button>Unggah</button></form>',
    )


@app.post("/upload")
async def upload(request: Request, berkas: UploadFile) -> Response:
    if _user(request) is None:
        return RedirectResponse("/login", status_code=302)
    return _page("Unggah", f"<p>Diterima: {berkas.filename}</p>")


@app.get("/produk")
def products() -> HTMLResponse:
    links = " ".join(f'<a href="/produk/{pid}">{name}</a>' for pid, name in PRODUCTS.items())
    return _page("Produk", f"<h1>Produk</h1>{links}")


@app.get("/produk/{product_id}")
def product(product_id: int) -> Response:
    name = PRODUCTS.get(product_id)
    if name is None:
        return _page("Produk", "<p>Tidak ditemukan</p>")
    return _page(name, f"<h1>{name}</h1>")


@app.get("/laporan")
def report(limit: str = "10") -> Response:
    try:
        rows = int(limit)
    except ValueError:
        # Weakness "debug-traceback": a debug error handler left on. The message is escaped and
        # plain text, so the value is not an XSS or template-injection weakness as well.
        return PlainTextResponse(escape(traceback.format_exc()), status_code=500)
    items = "".join(f"<li>Transaksi {n}</li>" for n in range(1, min(rows, 20) + 1))
    return _page("Laporan", f"<h1>Laporan</h1><ul>{items}</ul>")


@app.get("/cari")
def search(q: str = "", debug: str | None = None) -> HTMLResponse:
    extra = "<pre>mode diagnosa: query diproses oleh mesin pencari v2</pre>" if debug else ""
    return _page("Cari", f"<p>Hasil untuk: {len(q)} karakter</p>{extra}")


@app.post("/kontak")
def contact(nama: str = Form(""), pesan: str = Form("")) -> HTMLResponse:
    return _page("Kontak", "<p>Terima kasih</p>")


@app.get("/admin")
def admin(request: Request) -> Response:
    user = _user(request)
    if user is None or ROLES[user] != "admin":
        return JSONResponse({"detail": "Butuh hak admin"}, status_code=403)
    return _page("Panel admin", '<h1>Panel admin</h1><a href="/admin/pengguna">Daftar pengguna</a>')


@app.get("/admin/pengguna")
def admin_users(request: Request) -> Response:
    # Weakness "privilege-escalation": only the login is checked, not the admin role.
    if _user(request) is None:
        return RedirectResponse("/login", status_code=302)
    rows = "".join(
        f"<li>{p['nama']} ({p['email']}, NIP {p['nip']})</li>" for p in PROFILES.values()
    )
    return _page("Daftar pengguna", f"<h1>Daftar pengguna</h1><ul>{rows}</ul>")


@app.get("/internal/laporan")
def internal_report() -> HTMLResponse:
    return _page("Laporan internal", "<p>Laporan bulanan</p>")


# --- Deliberate Input Validation weaknesses (WEAKNESSES) ---------------------------------------

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB_LOCK = threading.Lock()  # one connection shared by the worker threads
_DB.executescript(
    "CREATE TABLE produk (id INTEGER PRIMARY KEY, nama TEXT, harga INTEGER);"
    "INSERT INTO produk (nama, harga) VALUES ('Kopi Gayo', 85000), ('Teh Melati', 40000);"
    "CREATE TABLE rahasia (kunci TEXT); INSERT INTO rahasia VALUES ('token-admin-123');"
)


@app.get("/katalog")
def product_search(nama: str = "") -> Response:
    # Weakness "sqli": the value is concatenated into the query.
    query = "SELECT nama, harga FROM produk WHERE nama LIKE '%" + nama + "%'"  # noqa: S608
    try:
        with _DB_LOCK:
            rows = _DB.execute(query).fetchall()
    except sqlite3.Error as exc:
        # The message is escaped: the planted weakness here is SQL injection, not XSS.
        message = escape(f"sqlite3.OperationalError: {exc}")
        return HTMLResponse(f"<p>Kesalahan basis data: {message}</p>", 500)
    items = "".join(f"<li>{escape(str(n))} — Rp{h}</li>" for n, h in rows)
    return _page("Cari produk", f"<ul>{items}</ul><p>{len(rows)} produk</p>")


@app.get("/sapa")
def greet(nama: str = "") -> HTMLResponse:
    # Weakness "xss-reflected": no HTML encoding.
    return _page("Sapa", f"<h1>Halo, {nama}!</h1>")


@app.post("/alat/ping")
def ping(alamat: str = Form("")) -> PlainTextResponse:
    # Weakness "cmdi": the value reaches a shell. Testapp only, never in RAJDOLL code.
    # (Not named `host`: sqlmap and commix read such a parameter as the Host header.)
    result = subprocess.run(  # noqa: S602
        "echo PING " + alamat, shell=True, capture_output=True, text=True, timeout=10
    )
    return PlainTextResponse(result.stdout + result.stderr)


@app.get("/pratinjau")
def preview(templat: str = "") -> HTMLResponse:
    # Weakness "ssti": user input becomes the template itself.
    rendered = jinja2.Environment().from_string(templat).render()  # noqa: S701
    return _page("Pratinjau", f"<div>{escape(rendered)}</div>")


@app.get("/ambil")
def fetch(url: str, request: Request) -> Response:
    # Weakness "ssrf": any http(s) URL is fetched from the server.
    if url.startswith("/"):
        url = str(request.base_url).rstrip("/") + url
    if not url.startswith(("http://", "https://")):
        return PlainTextResponse("URL tidak didukung", 400)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=5) as remote:  # noqa: S310
            body = remote.read(65536).decode("utf-8", errors="replace")
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return PlainTextResponse(f"Gagal mengambil: {exc}", 502)
    return PlainTextResponse(body)


@app.get("/.git/config")
def git_config() -> PlainTextResponse:
    # Weakness "git-config": the repository was deployed with its .git directory.
    return PlainTextResponse(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        '[remote "origin"]\n\turl = https://deploy:testapp-not-a-real-secret@git.instansi.test/'
        "aplikasi/testapp.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    )


@app.get("/info.php")
def phpinfo() -> HTMLResponse:
    # Weakness "phpinfo": a diagnostic page left on the server.
    return HTMLResponse(
        "<html><head><title>phpinfo()</title></head><body><table>"
        '<tr><td class="e">PHP Version </td><td class="v">7.4.3</td></tr>'
        '<tr><td class="e">System </td><td class="v">Linux testapp 5.15</td></tr>'
        "</table><h2>PHP Extension</h2><p>Core, mysqli, session</p></body></html>"
    )


@app.get("/index.php")
def old_index() -> HTMLResponse:
    return _page("Beranda lama", "<h1>Beranda lama</h1><p>Halaman ini sudah tidak dipakai.</p>")


@app.get("/index.php.bak")
def old_index_backup() -> PlainTextResponse:
    # Weakness "backup-file": an editor backup of the old page, with its source code.
    return PlainTextResponse(
        '<?php\n$db_host = "localhost";\n$db_user = "testapp";\n'
        '$db_pass = "testapp-not-a-real-secret";\n$conn = mysqli_connect($db_host, $db_user, '
        "$db_pass);\n?>\n<h1>Beranda lama</h1>\n",
        media_type="application/octet-stream",
    )


@app.get("/.env")
def exposed_env() -> PlainTextResponse:
    # Weakness "exposed-env": configuration file served to anyone.
    return PlainTextResponse(
        "APP_ENV=production\nDB_HOST=db\nDB_PASSWORD=testapp-not-a-real-secret\n"
    )
