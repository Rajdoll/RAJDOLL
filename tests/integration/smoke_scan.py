"""CI smoke test of the workflow engine and recon inside the running stack (piped into the api
container):

    docker compose exec -T api python - < tests/integration/smoke_scan.py

Starts a real scan of testapp with two logged-in accounts (Akun A = budi, admin; Akun B =
sari). The worker runs recon (httpx, katana, the Playwright browser, ffuf, nmap, and the custom
checks through the runner and the egress proxy), then the planning wave (JavaScript analysis,
parameter discovery), and stops at the checkpoint.
IPD F5 exit criteria: every endpoint testapp registers is in the inventory, including those only
in JavaScript, and logout is excluded and never requested. After the checkpoint, Input Validation
and Authorization and the validators run; IPD F6 and F8: every weakness of testapp becomes a
`confirmed` finding. Not collected by pytest.
"""

import re
import sys
import time
import uuid
from collections.abc import Callable

import httpx
from sqlalchemy import select

from rajdoll.core.config import get_settings
from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import get_sessionmaker
from rajdoll.core.models import Endpoint, Finding, RequestLog, Scan, ScanEvent, Task
from rajdoll.services import engagements, findings, inventory, scans

# Copy of testapp.RECON_ENDPOINTS (the api image does not contain testapp); kept equal by
# tests/test_testapp.py.
EXPECTED = [
    ("GET", "/"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/profil"),
    ("GET", "/produk"),
    ("GET", "/produk/{id}"),
    ("GET", "/cari"),
    ("POST", "/kontak"),
    ("GET", "/logout"),
    ("GET", "/upload"),
    ("POST", "/upload"),
    ("GET", "/akun/{id}"),
    ("GET", "/static/app.js"),
    ("GET", "/api/v1/ringkasan"),
    ("GET", "/api/v1/pesanan"),
    ("GET", "/api/v1/pesanan/{id}"),
    ("POST", "/api/v1/keranjang"),
    ("GET", "/api/v1/pengguna/{id}"),
    ("POST", "/api/v1/transfer"),
    ("GET", "/openapi.json"),
    ("GET", "/admin"),
    ("GET", "/robots.txt"),
    ("GET", "/internal/laporan"),
    ("GET", "/.env"),
    ("GET", "/katalog"),
    ("GET", "/sapa"),
    ("POST", "/alat/ping"),
    ("GET", "/pratinjau"),
    ("GET", "/ambil"),
    ("GET", "/admin/pengguna"),
    ("POST", "/api/v1/token"),
    ("GET", "/api/v1/saya"),
    ("GET", "/index.php"),
    ("GET", "/.git/config"),
    ("GET", "/info.php"),
    ("GET", "/laporan"),
]
# Copy of testapp.EXPECTED_FINDINGS, kept equal by tests/test_testapp.py.
EXPECTED_FINDINGS = [
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
    ("weak_tls_protocol", "/", None),  # the HTTPS site of serve.py
    ("certificate_problem", "/", None),
    ("cleartext_credentials", "/login", None),
    ("cleartext_credentials", "/api/v1/token", None),
    ("account_enumeration", "/api/v1/token", "username"),
]
TARGET = "http://testapp:8080"

settings = get_settings()
Session = get_sessionmaker()
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("ok   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def scan_state(scan_id: int) -> Scan:
    with Session() as db:
        return db.get(Scan, scan_id)


def wait_for(condition: Callable[[Scan], bool], scan_id: int, timeout: float) -> Scan:
    deadline = time.monotonic() + timeout
    scan = scan_state(scan_id)
    while time.monotonic() < deadline and not condition(scan):
        time.sleep(2)
        scan = scan_state(scan_id)
    return scan


# Test setup only: log in to testapp directly to get each account's session: the `sid` cookie
# and a JWT for the API, pasted together as from Burp.
def login(user: str, password: str) -> str:
    form = {"username": user, "password": password}
    sid = httpx.post(TARGET + "/login", data=form, trust_env=False).cookies["sid"]
    token = httpx.post(TARGET + "/api/v1/token", json=form, trust_env=False).json()["token"]
    return f"Cookie: sid={sid}\nAuthorization: Bearer {token}"


with Session() as db:
    keystore = KeyStore(settings.secrets_dir)
    engagement = engagements.create(
        db, keystore, {"name": f"smoke-scan-{uuid.uuid4().hex[:6]}", "target_url": TARGET + "/"}
    )
    engagements.update_overrides(db, engagement, {"rate_limit_rps": 100})
    for label, user, password in [("Akun A", "budi", "budi123"), ("Akun B", "sari", "sari123")]:
        account = {"label": label, "session_text": login(user, password), "username": user}
        engagements.add_account(db, keystore, engagement, account)
    modules = ["information_gathering", "configuration", "authentication", "authorization",
               "session", "input_validation", "error_handling", "cryptography",
               "identity"]  # fmt: skip
    scan = scans.start(db, engagement, "custom", modules)
    db.commit()
    scan_id, engagement_id = scan.id, engagement.id

scan = wait_for(lambda s: s.status not in ("queued", "running"), scan_id, timeout=900)
check(scan.status == "awaiting_checkpoint", f"scan stops at the checkpoint (status={scan.status})")
check(scan.checkpoint_deadline is not None, "checkpoint countdown is set")

with Session() as db:
    tasks = list(db.scalars(select(Task).where(Task.scan_id == scan_id).order_by(Task.id)))
    not_done = [(t.engine, t.status, t.error) for t in tasks if t.status != "done"]
    check(not not_done, f"all recon and planning tasks done ({not_done})")
    rows = {(e.method, e.path_template): e for e in inventory.list_for(db, engagement_id)}
    missing = [key for key in EXPECTED if key not in rows]
    check(
        not missing, f"inventory has every testapp endpoint ({len(rows)} rows, missing {missing})"
    )
    cari = rows.get(("GET", "/cari"))
    check(cari is not None and "debug" in cari.query_params, "hidden parameter found")
    logout = rows.get(("GET", "/logout"))
    check(
        logout is not None and logout.excluded and logout.exclude_reason == "pattern:logout",
        "logout excluded automatically",
    )
    logout_hits = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.url.like("%/logout%")
        )
    )
    check(logout_hits is None, "logout never requested")
    summary = scan_state(scan_id).recon_summary or {}
    check("cdn.luar.test" in (summary.get("out_of_scope_hosts") or {}), "out-of-scope host noted")
    check(8080 in {p["port"] for p in summary.get("open_ports", [])}, "nmap found port 8080")
    tool_exec = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.kind == "tool_exec"
        )
    )
    check(tool_exec is not None, "nmap run audited as tool_exec")
    audited = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.tool == "browser"
        )
    )
    check(audited is not None, "browser traffic went through the proxy")

    scans.checkpoint_continue(db, db.get(Scan, scan_id))
    db.commit()

scan = wait_for(lambda s: s.status not in ("running", "queued"), scan_id, timeout=1800)
check(scan.status == "completed", f"scan completes after the checkpoint (status={scan.status})")
check(scan.checkpoint_resolution == "user_continued", "checkpoint resolution recorded")

with Session() as db:
    not_done = [
        (t.engine, t.status, t.error)
        for t in db.scalars(select(Task).where(Task.scan_id == scan_id))
        if t.status != "done"
    ]
    check(not not_done, f"all testing and validation tasks done ({not_done})")
    found = {
        (f.vuln_type, path, f.parameter): f.validation
        for f, path in db.execute(
            select(Finding, Endpoint.path_template)
            .join(Endpoint, Finding.endpoint_id == Endpoint.id)
            .where(Finding.engagement_id == engagement_id)
        )
    }
    for key in EXPECTED_FINDINGS:
        check(found.get(key) == "confirmed", f"finding {key} confirmed ({found.get(key)})")
    extra = sorted(set(found) - set(EXPECTED_FINDINGS))
    check(not extra, f"no findings beyond testapp's weaknesses ({extra})")
    # Each tool's evidence lands on the same finding as the probes' (one per fingerprint).
    notes = {
        (f.vuln_type, f.parameter): " | ".join(
            row["note"] or "" for row in findings.evidence_rows(db, keystore, f)
        )
        for f in db.scalars(select(Finding).where(Finding.engagement_id == engagement_id))
    }
    for key, tool_note in [
        (("sqli", "nama"), "payload sqlmap"),
        (("sqli", "nama"), "nuclei sqli-error-based"),
        (("cmdi", "alamat"), "payload commix"),
        (("xss_reflected", "nama"), "payload dalfox"),
        (("ssti", "templat"), "nuclei reflection-ssti"),
    ]:
        check(tool_note in notes.get(key, ""), f"{tool_note} evidence on {key}")
    # Authorization evidence shows which account sent each request, never its cookie.
    idor = db.scalar(select(Finding).where(Finding.engagement_id == engagement_id,
                                           Finding.vuln_type == "idor"))  # fmt: skip
    idor_requests = " ".join(r["request"] for r in findings.evidence_rows(db, keystore, idor))
    check("[sesi Akun B]" in idor_requests and "sid=" not in idor_requests,
          "IDOR evidence names Akun B and masks its session")  # fmt: skip
    check(findings.poc(db, keystore, idor)["account"] == "Akun B", "IDOR PoC uses Akun B")
    commix_rows = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.tool == "commix"
        )
    )
    check(commix_rows is not None, "commix traffic went through the proxy")

# IPD F6 (M1): triage and the VA report through the real api, as the assessor would.
API = "http://127.0.0.1:8000"
PASSWORD = "smoke-scan-password-" + uuid.uuid4().hex[:8]
api = httpx.Client(base_url=API, trust_env=False, follow_redirects=False, timeout=60)
setup = api.post(
    "/setup",
    json={"password": PASSWORD, "password_confirm": PASSWORD},
    headers={"Accept": "application/json"},
)
if setup.status_code == 409:
    print("skip api triage checks: the api already has a password (not a fresh stack)")
else:
    check(setup.status_code == 201, f"first-run setup through the api ({setup.status_code})")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', api.get("/settings").text)
    headers = {"Accept": "application/json", "X-CSRF-Token": csrf.group(1) if csrf else ""}
    listed = api.get(f"/engagements/{engagement_id}/findings", headers=headers).json()["items"]
    check(len(listed) == len(EXPECTED_FINDINGS), f"findings tab lists {len(listed)} findings")
    rejected_id = None
    for item in listed:
        if item["vuln_type"] == "ssrf":
            rejected_id = item["id"]
            body = {"decision": "rejected", "reason": "Uji smoke: ditolak"}
        else:
            body = {"decision": "accepted"}
        decided = api.post(f"/findings/{item['id']}/decision", json=body, headers=headers)
        check(decided.status_code == 200, f"decision on #{item['id']} ({decided.status_code})")
    curl = api.get(f"/findings/{listed[0]['id']}/poc?format=curl").text
    check(curl.startswith("curl -i -X "), "PoC as curl")
    created = api.post(f"/engagements/{engagement_id}/reports", json={"kind": "va"},
                       headers=headers)  # fmt: skip
    check(created.status_code == 201, f"VA report created ({created.status_code})")
    report_id = created.json().get("id")
    download = api.get(f"/reports/{report_id}/download")
    markdown = download.text
    check(download.headers.get("content-type", "").startswith("text/markdown"), "report is .md")
    check("attachment; filename=" in download.headers.get("content-disposition", ""),
          "report downloads as a file")  # fmt: skip
    check(markdown.count("\n### 3.") == len(EXPECTED_FINDINGS) - 1,
          "report details every accepted finding")  # fmt: skip
    check("SSRF" not in markdown and "Server-Side Request Forgery" not in markdown,
          "rejected finding left out of the report")  # fmt: skip
    check("curl -i -X GET" in markdown, "report has reproduction steps")
    check("Kirim dengan sesi Akun B; objeknya milik Akun A." in markdown,
          "report says which account sends the IDOR PoC")  # fmt: skip
    preview = api.get(f"/reports/{report_id}")
    check(preview.status_code == 200 and "<h1>Laporan Vulnerability Assessment" in preview.text,
          "report preview renders")  # fmt: skip

with Session() as db:
    types = list(
        db.scalars(
            select(ScanEvent.type).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id)
        )
    )
    check(types.count("stage_changed") == 5, "every stage was entered")
    check(types[-1] == "completed", "completion event recorded")
    check(
        engagements.get(db, engagement_id).status == "ready", "engagement is ready again after scan"
    )

if failures:
    print(f"{len(failures)} check(s) failed", file=sys.stderr)
    sys.exit(1)
print("scan smoke test passed")
