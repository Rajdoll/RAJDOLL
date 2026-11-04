"""Findings tab and Reports tab (AFD A8, A9; BSD 10.5, 10.7; IPD F6c)."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.api.app import create_app
from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Engagement, ReportExport, Scan, Task
from rajdoll.modules.base import Candidate, EndpointSeen, Exchange, Verdict
from rajdoll.services import findings, inventory, reports

PASSWORD = "correct horse battery"
JSON = {"Accept": "application/json"}
TARGET = "https://simpeg.instansi.test/"
EVIL = "<script>alert('target')</script>\n```\n# bukan judul"


@dataclass
class Ui:
    client: TestClient
    csrf: str
    factory: sessionmaker[Session]
    keystore: KeyStore

    def htmx(self) -> dict[str, str]:
        return {"HX-Request": "true", "X-CSRF-Token": self.csrf}

    def api(self) -> dict[str, str]:
        return {**JSON, "X-CSRF-Token": self.csrf}


@pytest.fixture
def ui(db_engine: Engine, tmp_path: Path) -> Iterator[Ui]:
    with db_engine.begin() as conn:
        conn.execute(text("TRUNCATE app_user, ui_session, app_setting, engagement CASCADE"))
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    keystore = KeyStore(tmp_path)
    app = create_app(factory, keystore)
    with TestClient(app, follow_redirects=False) as client:
        client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
        match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/settings").text)
        assert match
        yield Ui(client, match.group(1), factory, keystore)


def _candidate(vuln_type: str, path: str, parameter: str, response: str) -> Candidate:
    url = TARGET.rstrip("/") + path
    return Candidate(
        vuln_type=vuln_type,
        method="GET",
        url=url,
        parameter=parameter,
        poc={"method": "GET", "path": path, "query": {parameter: "x'"}, "headers": {},
             "body": None, "body_encoding": "none", "account": None, "validator": vuln_type},
        evidence=(
            Exchange(f"GET {path}?{parameter}=x' HTTP/1.1\r\nHost: simpeg.instansi.test\r\n"
                     "Cookie: [sesi akun]\r\n\r\n", response, 200, "deteksi"),
        ),
    )  # fmt: skip


@pytest.fixture
def seeded(ui: Ui) -> dict[str, int]:
    """An engagement with a finished scan and three findings (confirmed sqli, xss, cmdi)."""
    created = ui.client.post(
        "/engagements", json={"name": "SIMPEG (clone)", "target_url": TARGET}, headers=ui.api()
    )
    engagement_id = int(created.json()["id"])
    html = "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n<h1>Halo</h1>" + EVIL
    with ui.factory() as session, session.begin():
        scan = Scan(engagement_id=engagement_id, kind="scan", number=1, profile="full",
                    status="completed", modules=["input_validation"])  # fmt: skip
        session.add(scan)
        session.flush()
        session.add(Task(scan_id=scan.id, stage="testing", module="input_validation",
                         engine="sqlmap", status="blocked", error="WAF memblokir",
                         target={"url": TARGET + "cari"}))  # fmt: skip
        inventory.record(
            session,
            engagement_id,
            scan.id,
            [EndpointSeen("GET", TARGET + path, "crawl", query_params=(param,))
             for path, param in (("katalog", "nama"), ("sapa", "nama"), ("ping", "alamat"))],
            ["simpeg.instansi.test"],
        )  # fmt: skip
        ids = {}
        for key, path, param in (("sqli", "/katalog", "nama"), ("xss_reflected", "/sapa", "nama"),
                                 ("cmdi", "/ping", "alamat")):  # fmt: skip
            finding, _ = findings.record_candidate(
                session, ui.keystore, engagement_id, scan.id, "input_validation",
                _candidate(key, path, param, html),
            )  # fmt: skip
            if key != "cmdi":
                findings.record_verdict(
                    session, ui.keystore, finding, scan.id,
                    Verdict(True, (Exchange("GET /ulang HTTP/1.1", "ok", 200, "ulang"),)),
                )  # fmt: skip
            ids[key] = finding.id
    return {"engagement": engagement_id, **ids}


def test_findings_page_lists_in_triage_order_with_detail(ui: Ui, seeded: dict) -> None:
    page = ui.client.get(f"/engagements/{seeded['engagement']}/findings")
    assert page.status_code == 200
    body = page.text
    assert "3</strong> belum diputuskan" in body
    # Undecided first, confirmed before needs-manual-check, then severity.
    titles = re.findall(r'class="sev sev-\w+" title="[^"]+">\w</span>([^<]+)', body)
    assert titles[0].startswith("SQL Injection") and titles[-1].startswith("OS Command")
    assert "Reflected Cross-Site Scripting" in titles[1]
    # The first finding's detail is shown, evidence escaped, HTML preview sandboxed.
    assert "&lt;script&gt;alert(&#39;target&#39;)" in body
    assert "<script>alert('target')" not in body
    assert 'sandbox="" referrerpolicy="no-referrer"' in body
    assert 'srcdoc="&lt;h1&gt;Halo&lt;/h1&gt;' in body
    assert "Cookie: [sesi akun]" in body
    assert 'data-copy="#poc-curl-' in body and "/static/app.js" in body
    assert "curl -i -X GET &#39;https://simpeg.instansi.test/katalog?nama=x%27&#39;" in body


def test_filters_htmx_and_json(ui: Ui, seeded: dict) -> None:
    base = f"/engagements/{seeded['engagement']}/findings"
    listing = ui.client.get(base + "?validation=needs_manual_check", headers=ui.htmx())
    assert listing.status_code == 200 and "<html" not in listing.text
    assert "OS Command" in listing.text and "SQL Injection" not in listing.text
    data = ui.client.get(base + "?severity=critical", headers=JSON).json()
    assert {i["vuln_type"] for i in data["items"]} == {"sqli", "cmdi"}
    assert data["counts"] == {"pending": 3, "accepted": 0, "rejected": 0}
    assert ui.client.get(base + "?severity=parah", headers=JSON).status_code == 422
    assert ui.client.get(base + "?scan_id=x", headers=JSON).status_code == 422

    detail = ui.client.get(f"/findings/{seeded['xss_reflected']}", headers=ui.htmx())
    assert detail.status_code == 200 and "Reflected Cross-Site Scripting" in detail.text
    full = ui.client.get(f"/findings/{seeded['sqli']}")
    assert full.status_code == 303 and full.headers["location"].endswith(
        f"?finding={seeded['sqli']}"
    )
    as_json = ui.client.get(f"/findings/{seeded['sqli']}", headers=JSON).json()
    assert as_json["cvss31"] == {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                 "score": 9.8}  # fmt: skip
    assert as_json["endpoint"]["path_template"] == "/katalog" and as_json["evidence_count"] == 2
    evidence = ui.client.get(f"/findings/{seeded['sqli']}/evidence", headers=JSON).json()
    assert [e["kind"] for e in evidence["items"]] == ["detection", "validation"]
    assert ui.client.get("/findings/999999", headers=JSON).status_code == 404


def test_poc_as_curl_and_raw(ui: Ui, seeded: dict) -> None:
    curl = ui.client.get(f"/findings/{seeded['sqli']}/poc?format=curl")
    assert curl.headers["content-type"].startswith("text/plain")
    assert curl.text == "curl -i -X GET 'https://simpeg.instansi.test/katalog?nama=x%27'"
    raw = ui.client.get(f"/findings/{seeded['sqli']}/poc?format=raw").text
    assert raw == "GET /katalog?nama=x%27 HTTP/1.1\r\nHost: simpeg.instansi.test\r\n\r\n"
    assert ui.client.get(f"/findings/{seeded['sqli']}/poc?format=pdf").status_code == 422


def test_decisions(ui: Ui, seeded: dict) -> None:
    url = f"/findings/{seeded['cmdi']}/decision"
    missing = ui.client.post(url, data={"decision": "rejected", "reason": " "}, headers=ui.htmx())
    assert missing.status_code == 422 and "Alasan wajib diisi" in missing.text
    assert ui.client.post(url, json={"decision": "nanti"}, headers=ui.api()).status_code == 422

    rejected = ui.client.post(
        url, data={"decision": "rejected", "reason": "Butuh akses admin"}, headers=ui.htmx()
    )
    assert rejected.status_code == 200
    assert 'id="finding-counts" hx-swap-oob="true"' in rejected.text
    assert f'id="finding-item-{seeded["cmdi"]}"' in rejected.text
    assert "Ditolak: Butuh akses admin" in rejected.text

    accepted = ui.client.post(
        f"/findings/{seeded['sqli']}/decision", json={"decision": "accepted"}, headers=ui.api()
    ).json()
    assert accepted["decision"] == "accepted" and accepted["decided_at"]
    form = ui.client.post(
        f"/findings/{seeded['xss_reflected']}/decision",
        data={"decision": "accepted", "csrf_token": ui.csrf},
    )
    assert form.status_code == 303
    # No CSRF token, no change.
    assert ui.client.post(url, data={"decision": "pending"}).status_code == 403

    with ui.factory() as session:
        cmdi = findings.get(session, seeded["cmdi"])
        assert (cmdi.decision, cmdi.decision_reason) == ("rejected", "Butuh akses admin")
        cmdi.retest_result = "not_tested"
    back = ui.client.post(url, json={"decision": "pending"}, headers=ui.api()).json()
    assert back["decision"] == "pending" and back["decision_reason"] is None
    counts = ui.client.get(f"/engagements/{seeded['engagement']}/findings", headers=JSON).json()
    assert counts["counts"] == {"pending": 1, "accepted": 2, "rejected": 0}


def test_leaving_accepted_resets_the_retest_result(ui: Ui, seeded: dict) -> None:
    with ui.factory() as session, session.begin():
        finding = findings.get(session, seeded["sqli"])
        findings.decide(session, finding, "accepted")
        finding.retest_result = "still_vulnerable"
        session.flush()
        findings.decide(session, finding, "rejected", "duplikat")
        assert finding.retest_result == "not_tested"


def test_report_contains_only_accepted_findings(ui: Ui, seeded: dict) -> None:
    engagement_id = seeded["engagement"]
    for key, decision in (("sqli", "accepted"), ("xss_reflected", "rejected")):
        ui.client.post(
            f"/findings/{seeded[key]}/decision",
            json={"decision": decision, "reason": "bukan celah"},
            headers=ui.api(),
        )
    tab = ui.client.get(f"/engagements/{engagement_id}/reports")
    assert "1 temuan yang belum diputuskan" in tab.text and "1 pengujian terblokir" in tab.text
    assert "Belum ada laporan" in tab.text

    created = ui.client.post(f"/engagements/{engagement_id}/reports", json={"kind": "va"},
                             headers=ui.api())  # fmt: skip
    assert created.status_code == 201
    report_id = created.json()["id"]
    assert len(created.json()["warnings"]) == 2
    retest = ui.client.post(f"/engagements/{engagement_id}/reports", json={"kind": "retest"},
                            headers=ui.api())  # fmt: skip
    assert retest.status_code == 422

    download = ui.client.get(f"/reports/{report_id}/download")
    assert download.headers["content-type"].startswith("text/markdown")
    assert re.fullmatch(
        r'attachment; filename="simpeg-clone-va-\d{4}-\d{2}-\d{2}\.md"',
        download.headers["content-disposition"],
    )
    markdown = download.text
    assert markdown.startswith("# Laporan Vulnerability Assessment: SIMPEG (clone)")
    assert "SQL Injection di /katalog pada parameter nama" in markdown
    assert "Reflected Cross-Site Scripting" not in markdown  # rejected
    assert "OS Command" not in markdown  # still pending
    assert "| Kritis | 1 |" in markdown
    assert "curl -i -X GET 'https://simpeg.instansi.test/katalog?nama=x%27'" in markdown
    assert "WAF memblokir" in markdown and "`simpeg.instansi.test`" in markdown
    # Target content cannot close its code block: the fence is longer than its backticks.
    assert "````http\nHTTP/1.1 200 OK" in markdown

    preview = ui.client.get(f"/reports/{report_id}")
    assert preview.status_code == 200
    assert "<h1>Laporan Vulnerability Assessment: SIMPEG (clone)</h1>" in preview.text
    assert "<script>alert('target')" not in preview.text
    assert "&lt;script&gt;alert(" in preview.text
    assert "<h1>bukan judul" not in preview.text and "# bukan judul" in preview.text

    history = ui.client.get(f"/engagements/{engagement_id}/reports", headers=JSON).json()
    assert [(i["id"], i["finding_count"]) for i in history["items"]] == [(report_id, 1)]
    page = ui.client.get(f"/engagements/{engagement_id}/reports").text
    assert f"/reports/{report_id}/download" in page

    form = ui.client.post(f"/engagements/{engagement_id}/reports",
                          data={"kind": "va", "csrf_token": ui.csrf})  # fmt: skip
    assert form.status_code == 303 and form.headers["location"].startswith("/reports/")
    with ui.factory() as session:
        rows = list(session.scalars(select(ReportExport).order_by(ReportExport.id)))
        assert len(rows) == 2 and b"SQL Injection" not in rows[0].content_enc  # encrypted
        engagement = session.get(Engagement, engagement_id)
        assert reports.content(session, ui.keystore, rows[0]) == markdown
        assert reports.filename(engagement, rows[0]).startswith("simpeg-clone-va-")


def test_tabs_link_to_findings_and_reports(ui: Ui, seeded: dict) -> None:
    page = ui.client.get(f"/engagements/{seeded['engagement']}").text
    assert f'href="/engagements/{seeded["engagement"]}/findings"' in page
    assert f'href="/engagements/{seeded["engagement"]}/reports"' in page
    empty = ui.client.post(
        "/engagements", json={"name": "Kosong", "target_url": "https://kosong.test/"},
        headers=ui.api(),
    )  # fmt: skip
    listing = ui.client.get(f"/engagements/{empty.json()['id']}/findings")
    assert "Belum ada temuan" in listing.text


def test_markdown_helpers() -> None:
    from rajdoll.reporting import va

    assert va.cell("a|b\nc") == "a\\|b c"
    assert va.fenced("x ```` y", "http") == "`````http\nx ```` y\n`````"
    assert va.fenced("plain") == "```\nplain\n```"
    assert "<script>" not in va.to_html("<script>x</script>")
    assert va.clip("abcdef", 3) == ("abc", True) and va.clip(None) == (None, False)


def test_ai_notes_and_mini_loop_rounds_are_shown_as_ai_output(ui: Ui, seeded: dict) -> None:
    with ui.factory() as session, session.begin():
        finding = findings.get(session, seeded["cmdi"])
        findings.save_llm_notes(session, ui.keystore, finding, {
            "explanation": "Input <b>masuk</b> ke shell.",
            "manual_test_suggestions": ["Coba `id` dengan pemisah |"],
            "possible_duplicates": [seeded["sqli"]],
            "verification_rounds": [{"round": 1, "requests": [
                {"method": "GET", "path": "/ping", "status": 200},
                {"method": "GET", "path": "/logout",
                 "skipped": "cocok dengan pola endpoint berisiko"},
            ], "base_value": "127.0.0.1", "reasoning": "nilai host valid",
                "validator_note": "belum", "confirmed": False}],
        })  # fmt: skip
        findings.save_llm_notes(session, ui.keystore, finding, {"verification_rounds": [
            {"round": 2, "requests": [], "confirmed": False}]})  # fmt: skip
        assert len(findings.llm_notes(session, ui.keystore, finding)["verification_rounds"]) == 2
        assert b"shell" not in finding.llm_notes_enc  # encrypted at rest
    detail = ui.client.get(f"/findings/{seeded['cmdi']}", headers=ui.htmx()).text
    assert "Catatan AI" in detail and "keluaran AI, periksa sebelum dipakai" in detail
    assert "Input &lt;b&gt;masuk&lt;/b&gt; ke shell." in detail  # escaped
    assert f'hx-get="/findings/{seeded["sqli"]}"' in detail
    assert "Riwayat mini-loop verifikasi (2 putaran)" in detail
    assert "dilewati: cocok dengan pola endpoint berisiko" in detail
    plain = ui.client.get(f"/findings/{seeded['sqli']}", headers=ui.htmx()).text
    assert "Catatan AI" not in plain
