"""Scan tab, monitor, controls, events, SSE stream, and checkpoint over HTTP (BSD 10.4)."""

import re
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text, update
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.api.app import create_app
from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import EventLevel, EventType
from rajdoll.core.models import RequestLog, Scan, Task
from rajdoll.modules.base import EndpointSeen
from rajdoll.services import inventory, scans
from rajdoll.services.events import emit

PASSWORD = "correct horse battery"
JSON = {"Accept": "application/json"}


@dataclass
class Ui:
    client: TestClient
    csrf: str
    factory: sessionmaker[Session]

    def htmx(self) -> dict[str, str]:
        return {"HX-Request": "true", "X-CSRF-Token": self.csrf}

    def api(self) -> dict[str, str]:
        return {**JSON, "X-CSRF-Token": self.csrf}


@pytest.fixture
def ui(db_engine: Engine, tmp_path: Path) -> Iterator[Ui]:
    with db_engine.begin() as conn:
        conn.execute(text("TRUNCATE app_user, ui_session, app_setting, engagement CASCADE"))
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    app = create_app(factory, KeyStore(tmp_path))
    app.state.sse_heartbeat_seconds = 0.2
    app.state.sse_max_seconds = 5.0
    with TestClient(app, follow_redirects=False) as client:
        client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
        match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/settings").text)
        assert match
        yield Ui(client, match.group(1), factory)


def _engagement(ui: Ui, name: str = "SIMPEG (clone)") -> int:
    response = ui.client.post(
        "/engagements",
        json={"name": name, "target_url": "https://simpeg.instansi.test/"},
        headers=ui.api(),
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _start(ui: Ui, engagement_id: int, **body: object) -> dict:
    response = ui.client.post(
        f"/engagements/{engagement_id}/scans",
        json={"profile": "full", **body},
        headers=ui.api(),
    )
    assert response.status_code == 202, response.text
    return response.json()


def _set(ui: Ui, scan_id: int, **values: object) -> None:
    with ui.factory() as session, session.begin():
        session.execute(update(Scan).where(Scan.id == scan_id).values(**values))


def test_scan_tab_shows_the_start_form_with_a_summary(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    page = ui.client.get(f"/engagements/{engagement_id}/scans")
    assert page.status_code == 200
    assert f'href="/engagements/{engagement_id}/scans" aria-current="page"' in page.text
    assert "Mulai scan" in page.text
    assert "Lengkap" in page.text and "Kustom" in page.text
    assert "Input Validation" in page.text
    assert "(belum tersedia)" in page.text
    assert "10 request/detik" in page.text
    assert "lanjut otomatis setelah 15 menit" in page.text
    assert "Kurang dari dua akun" in page.text
    assert "Belum ada scan." in page.text
    assert ui.client.get(f"/engagements/{engagement_id}/scans", headers=JSON).json() == {
        "items": []
    }


def test_start_via_form_redirects_to_the_monitor(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    response = ui.client.post(
        f"/engagements/{engagement_id}/scans", data={"csrf_token": ui.csrf, "profile": "full"}
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert re.fullmatch(r"/scans/\d+", location)

    page = ui.client.get(location)
    assert page.status_code == 200
    assert "Scan #1" in page.text
    assert "antre" in page.text
    assert f'sse-connect="{location}/events/stream?after_id=' in page.text
    assert 'sse-close="done"' in page.text
    assert "Jeda" in page.text and "Batalkan" in page.text
    assert "Scan masuk antrean." in page.text
    assert "banner" not in page.text.split("<section")[0]  # no banner about itself

    tab = ui.client.get(f"/engagements/{engagement_id}/scans")
    assert "masih antre" in tab.text
    assert "Mulai scan</button>" not in tab.text


def test_start_custom_with_checkboxes(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    response = ui.client.post(
        f"/engagements/{engagement_id}/scans",
        content=f"csrf_token={ui.csrf}&profile=custom&modules=session&modules=authentication",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 303
    scan = ui.client.get(response.headers["location"], headers=JSON).json()
    assert scan["modules"] == ["authentication", "session"]
    assert scan["profile"] == "custom"


def test_start_errors(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    page = ui.client.post(
        f"/engagements/{engagement_id}/scans", data={"csrf_token": ui.csrf, "profile": "custom"}
    )
    assert page.status_code == 422
    assert "Pilih minimal satu modul" in page.text
    assert 'value="custom" checked' in page.text

    _start(ui, engagement_id)
    again = ui.client.post(
        f"/engagements/{engagement_id}/scans", json={"profile": "full"}, headers=ui.api()
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "conflict"
    no_csrf = ui.client.post(f"/engagements/{engagement_id}/scans", json={}, headers=JSON)
    assert no_csrf.status_code == 403


def test_controls_answer_with_the_status_fragment(ui: Ui) -> None:
    scan_id = _start(ui, _engagement(ui))["id"]

    paused = ui.client.post(f"/scans/{scan_id}/pause", headers=ui.htmx())
    assert paused.status_code == 200
    assert "<html" not in paused.text
    assert "dijeda oleh asesor" in paused.text
    assert f'hx-post="/scans/{scan_id}/resume"' in paused.text

    again = ui.client.post(f"/scans/{scan_id}/pause", headers=ui.htmx())
    assert again.status_code == 409
    assert "tidak bisa dijeda" in again.text

    resumed = ui.client.post(f"/scans/{scan_id}/resume", headers=ui.api())
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "queued"
    assert "requests" in resumed.json()

    cancelled = ui.client.post(f"/scans/{scan_id}/cancel", data={"csrf_token": ui.csrf})
    assert cancelled.status_code == 303
    assert cancelled.headers["location"] == f"/scans/{scan_id}"
    page = ui.client.get(f"/scans/{scan_id}")
    assert "Scan dibatalkan" in page.text
    assert "sse-connect" not in page.text  # finished: no stream

    assert ui.client.post(f"/scans/{scan_id}/cancel", headers=ui.api()).status_code == 409
    assert ui.client.post(f"/scans/{scan_id}/pause").status_code == 403
    assert ui.client.post("/scans/999999/pause", headers=ui.api()).status_code == 404


def test_resume_with_a_lower_rate_after_waf_pause(ui: Ui) -> None:
    scan_id = _start(ui, _engagement(ui))["id"]
    _set(ui, scan_id, status="paused", paused_reason="waf_blocked", stage="testing")
    page = ui.client.get(f"/scans/{scan_id}")
    assert 'name="rate_limit_rps"' in page.text
    bad = ui.client.post(
        f"/scans/{scan_id}/resume", json={"rate_limit_rps": "cepat"}, headers=ui.api()
    )
    assert bad.status_code == 422
    ok = ui.client.post(
        f"/scans/{scan_id}/resume", data={"csrf_token": ui.csrf, "rate_limit_rps": "2.5"}
    )
    assert ok.status_code == 303
    with ui.factory() as session:
        scan = session.get(Scan, scan_id)
        assert (scan.status, scan.settings_snapshot["rate_limit_rps"]) == ("running", 2.5)


def test_banners_on_engagement_pages_and_list(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    scan_id = _start(ui, engagement_id)["id"]
    _set(
        ui,
        scan_id,
        status="awaiting_checkpoint",
        stage="planning",
        checkpoint_deadline=scans.utcnow() + timedelta(minutes=12, seconds=30),
    )
    summary = ui.client.get(f"/engagements/{engagement_id}")
    assert "Scan #1 menunggu checkpoint" in summary.text
    assert "(13 menit lagi)" in summary.text
    assert f'href="/scans/{scan_id}/checkpoint"' in summary.text
    assert "Scan terakhir:" in summary.text
    listing = ui.client.get("/")
    assert f'<a href="/scans/{scan_id}">scan #1 menunggu checkpoint (' in listing.text

    _set(ui, scan_id, status="paused", paused_reason="session_expired", checkpoint_deadline=None)
    scope = ui.client.get(f"/engagements/{engagement_id}/scope")
    assert "dijeda: sesi akun kedaluwarsa" in scope.text
    assert "Perbarui dan uji sesi" in scope.text

    _set(ui, scan_id, status="failed", paused_reason=None, error="ValueError: boom")
    settings = ui.client.get(f"/engagements/{engagement_id}/settings")
    assert "Scan #1 gagal: ValueError: boom" in settings.text

    _set(ui, scan_id, status="completed", error=None)
    assert "banner" not in ui.client.get(f"/engagements/{engagement_id}").text


def _seed_activity(ui: Ui, scan_id: int, engagement_id: int) -> list[int]:
    with ui.factory() as session, session.begin():
        scan = session.get(Scan, scan_id)
        scan.status, scan.stage, scan.started_at = "running", "recon", scans.utcnow()
        session.add_all(
            [
                Task(
                    scan_id=scan_id,
                    stage="recon",
                    module="information_gathering",
                    engine="httpx",
                    status="done",
                    attempt=1,
                    result_summary={
                        "endpoints": [
                            {
                                "url": "https://simpeg.instansi.test/",
                                "status": 200,
                                "title": "SIMPEG",
                                "server": "nginx",
                            }
                        ],
                        "technologies": [{"name": "nginx", "version": "1.24", "urls": []}],
                    },
                ),
                Task(
                    scan_id=scan_id,
                    stage="recon",
                    module="information_gathering",
                    engine="httpx",
                    status="failed",
                    attempt=2,
                    error="httpx timed out",
                ),
                Task(scan_id=scan_id, stage="recon", module="configuration", engine="nuclei"),
            ]
        )
        for outcome in ("forwarded", "forwarded", "blocked_scope"):
            session.add(
                RequestLog(
                    engagement_id=engagement_id,
                    scan_id=scan_id,
                    kind="http",
                    tool="httpx",
                    url="https://simpeg.instansi.test/",
                    host="simpeg.instansi.test",
                    outcome=outcome,
                )
            )
        ids = [
            emit(session, scan_id, EventType.STAGE_CHANGED, "Tahap Recon dimulai.").id,
            emit(
                session,
                scan_id,
                EventType.TASK_FINISHED,
                "Information Gathering · httpx: gagal.",
                level=EventLevel.WARNING,
            ).id,
        ]
        session.flush()
        return [e for e in ids]


def test_monitor_tasks_and_events(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    scan_id = _start(ui, engagement_id)["id"]
    _seed_activity(ui, scan_id, engagement_id)

    page = ui.client.get(f"/scans/{scan_id}")
    assert "Information Gathering" in page.text
    assert '<progress value="2" max="2"' in page.text
    assert "3 request" in page.text and "ditolak scope: 1" in page.text
    assert 'class="step-current" aria-current="step">Recon' in page.text
    assert "log-warning" in page.text

    data = ui.client.get(f"/scans/{scan_id}", headers=JSON).json()
    assert data["tasks"]["information_gathering"] == {"done": 1, "failed": 1}
    assert data["requests"]["total"] == 3 and data["requests"]["blocked_scope"] == 1
    assert data["findings"] == {"confirmed": 0, "needs_manual_check": 0, "total": 0}

    failed = ui.client.get(f"/scans/{scan_id}/tasks?status=failed", headers=JSON).json()
    assert [t["error"] for t in failed["items"]] == ["httpx timed out"]
    by_module = ui.client.get(f"/scans/{scan_id}/tasks?module=configuration", headers=JSON)
    assert [t["status"] for t in by_module.json()["items"]] == ["pending"]
    tasks_page = ui.client.get(f"/scans/{scan_id}/tasks")
    assert "httpx timed out" in tasks_page.text and "menunggu" in tasks_page.text

    events = ui.client.get(f"/scans/{scan_id}/events", headers=JSON).json()["items"]
    assert [e["type"] for e in events] == ["notice", "stage_changed", "task_finished"]
    later = ui.client.get(
        f"/scans/{scan_id}/events?after_id={events[1]['id']}", headers=JSON
    ).json()["items"]
    assert [e["type"] for e in later] == ["task_finished"]
    fragment = ui.client.get(f"/scans/{scan_id}/events", headers={"HX-Request": "true"})
    assert fragment.text.lstrip().startswith("<li")
    assert "Log scan #1" in ui.client.get(f"/scans/{scan_id}/events").text


def test_checkpoint_page_and_actions(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    scan_id = _start(ui, engagement_id)["id"]
    _seed_activity(ui, scan_id, engagement_id)
    _set(
        ui,
        scan_id,
        status="awaiting_checkpoint",
        stage="planning",
        checkpoint_deadline=scans.utcnow() + timedelta(minutes=15),
        recon_summary={
            "technologies": [{"name": "nginx", "version": "1.24"}],
            "waf": {"detected": True, "name": "ModSecurity", "evidence": "header server"},
            "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
            "out_of_scope_hosts": {"cdn.luar.test": 2, "burpsuite": 1},
        },
    )
    with ui.factory() as session, session.begin():
        inventory.record(
            session,
            engagement_id,
            scan_id,
            [
                EndpointSeen("GET", "https://simpeg.instansi.test/cari?q=1", "crawl"),
                EndpointSeen("GET", "https://simpeg.instansi.test/logout", "crawl"),
            ],
            ["simpeg.instansi.test"],
            exclude_patterns=["logout"],
        )

    page = ui.client.get(f"/scans/{scan_id}/checkpoint")
    assert page.status_code == 200
    assert "nginx 1.24" in page.text
    assert "WAF terdeteksi: <strong>ModSecurity</strong>" in page.text
    assert "443/tcp · https" in page.text
    assert "<code>cdn.luar.test</code>" in page.text
    assert "Endpoint (2)" in page.text
    assert 'class="excluded"' in page.text and "dikecualikan (pola)" in page.text
    assert "(belum tersedia di versi ini)" in page.text
    assert "Perkiraan request tahap pengujian" in page.text
    assert "Tahan hitung mundur" in page.text
    data = ui.client.get(f"/scans/{scan_id}/checkpoint", headers=JSON).json()
    summary = data["recon_summary"]
    assert summary["technologies"] == [{"name": "nginx", "version": "1.24"}]
    # Counted by recon, and by the proxy's refusals in request_log.
    assert summary["out_of_scope_hosts"][0] == {"host": "cdn.luar.test", "count": 2}
    assert "burpsuite" not in {h["host"] for h in summary["out_of_scope_hosts"]}
    first = data["modules"][0]
    assert (first["name"], first["enabled"], first["skipped_reason"]) == (
        "information_gathering",
        True,
        None,
    )
    endpoints = {e["path_template"]: e for e in data["endpoints"]}
    assert endpoints["/cari"]["query_params"] == ["q"]
    assert endpoints["/cari"]["tags"] == ["has_params"]
    assert endpoints["/logout"]["exclude_reason"] == "pattern:logout"
    assert endpoints["/logout"]["modules"] == []
    assert data["editable"] is True
    assert (
        ui.client.get(f"/scans/{scan_id}/checkpoint?filter=dikecualikan").text.count(
            'class="excluded"'
        )
        == 1
    )

    # htmx edits answer with the plan fragment and stop the countdown.
    logout_id = endpoints["/logout"]["id"]
    included = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        data={"action": "include", "endpoint_id": logout_id, "filter": "semua"},
        headers=ui.htmx(),
    )
    assert included.status_code == 200
    assert "<html" not in included.text
    assert "Disimpan: 1 endpoint diubah" in included.text
    tagged = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        data={
            "action": "tags",
            "endpoint_id": endpoints["/cari"]["id"],
            "tags": "has_params, upload",
        },
        headers=ui.htmx(),
    )
    assert "(asesor)" in tagged.text
    bad = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        data={"action": "add_endpoint", "method": "GET", "url": "https://other.test/x"},
        headers=ui.htmx(),
    )
    assert bad.status_code == 422
    assert "di luar scope" in bad.text
    scoped = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        data={"action": "add_scope", "pattern": "cdn.luar.test"},
        headers=ui.htmx(),
    )
    assert "sudah di scope" in scoped.text
    pasted = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        data={
            "action": "raw_request",
            "raw_request": "POST /api/beli HTTP/1.1\nHost: simpeg.instansi.test\n"
            'Content-Type: application/json\n\n{"harga": 1}',
        },
        headers=ui.htmx(),
    )
    assert "simpeg.instansi.test/api/beli" in pasted.text
    modules = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        content="action=modules&modules=authorization&modules=business_logic",
        headers={**ui.htmx(), "content-type": "application/x-www-form-urlencoded"},
    )
    assert modules.status_code == 200
    data = ui.client.get(f"/scans/{scan_id}/checkpoint", headers=JSON).json()
    assert data["deadline"] is None
    enabled = [m["name"] for m in data["modules"] if m["enabled"]]
    assert enabled == ["authorization", "business_logic"]
    beli = next(e for e in data["endpoints"] if e["path_template"] == "/api/beli")
    assert beli["source"] == "burp_paste" and beli["modules"] == ["business_logic"]

    # The BSD 10.4 JSON body works the same way.
    edited = ui.client.patch(
        f"/scans/{scan_id}/checkpoint",
        json={"endpoints": [{"id": logout_id, "excluded": True}], "modules": ["session"]},
        headers=ui.api(),
    )
    assert edited.status_code == 200
    assert next(e for e in edited.json()["endpoints"] if e["id"] == logout_id)["excluded"]
    unknown = ui.client.patch(
        f"/scans/{scan_id}/checkpoint", json={"modules": ["sqlmap"]}, headers=ui.api()
    )
    assert unknown.status_code == 422
    assert ui.client.patch(f"/scans/{scan_id}/checkpoint", json={}).status_code == 403

    held = ui.client.post(f"/scans/{scan_id}/checkpoint/hold", headers=ui.htmx())
    assert held.status_code == 200
    assert "Hitung mundur ditahan." in held.text
    assert "Tahan hitung mundur" not in held.text

    continued = ui.client.post(f"/scans/{scan_id}/checkpoint/continue", headers=ui.api())
    assert continued.json()["status"] == "running"
    assert continued.json()["checkpoint_resolution"] == "user_continued"
    assert ui.client.post(f"/scans/{scan_id}/checkpoint/hold", headers=ui.api()).status_code == 409
    late = ui.client.patch(
        f"/scans/{scan_id}/checkpoint", json={"modules": ["session"]}, headers=ui.api()
    )
    assert late.status_code == 409
    assert "Disimpan" not in ui.client.get(f"/scans/{scan_id}/checkpoint").text
    assert "Simpan modul" not in ui.client.get(f"/scans/{scan_id}/checkpoint").text


def _sse_events(body: str) -> list[dict[str, str]]:
    events = []
    for block in body.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line.startswith(":"):
                continue
            name, _, value = line.partition(": ")
            fields[name] = fields[name] + "\n" + value if name in fields else value
        if "event" in fields:
            events.append(fields)
    return events


def test_stream_of_a_finished_scan_sends_a_snapshot_and_done(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    scan_id = _start(ui, engagement_id)["id"]
    _seed_activity(ui, scan_id, engagement_id)
    _set(ui, scan_id, status="completed", finished_at=scans.utcnow())

    response = ui.client.get(f"/scans/{scan_id}/events/stream")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text.startswith("retry: 3000")
    events = _sse_events(response.text)
    names = [e["event"] for e in events]
    assert names == ["stage", "task", "stats", "finding", "notice", "done"]
    assert "Scan selesai" in events[0]["data"]
    assert "Information Gathering" in events[1]["data"]
    notice = events[4]
    assert "Tahap Recon dimulai." in notice["data"]
    assert notice["id"] == str(
        ui.client.get(f"/scans/{scan_id}/events", headers=JSON).json()["items"][-1]["id"]
    )

    # Reconnecting with Last-Event-ID sends no old log lines.
    again = ui.client.get(
        f"/scans/{scan_id}/events/stream", headers={"Last-Event-ID": notice["id"]}
    )
    assert "notice" not in [e["event"] for e in _sse_events(again.text)]


def test_stream_follows_a_running_scan_until_it_finishes(ui: Ui) -> None:
    engagement_id = _engagement(ui)
    scan_id = _start(ui, engagement_id)["id"]
    _set(ui, scan_id, status="running", stage="recon", started_at=scans.utcnow())
    last_id = ui.client.get(f"/scans/{scan_id}/events", headers=JSON).json()["items"][-1]["id"]

    def worker() -> None:
        time.sleep(0.6)
        with ui.factory() as session, session.begin():
            emit(session, scan_id, EventType.NOTICE, "Information Gathering: 1 endpoint menjawab")
        time.sleep(0.6)
        with ui.factory() as session, session.begin():
            scan = session.get(Scan, scan_id)
            scan.status, scan.finished_at = "completed", scans.utcnow()
            emit(session, scan_id, EventType.COMPLETED, "Scan selesai.")

    thread = threading.Thread(target=worker)
    started = time.monotonic()
    thread.start()
    response = ui.client.get(f"/scans/{scan_id}/events/stream?after_id={last_id}")
    thread.join()
    assert time.monotonic() - started < 4.5  # ended by `done`, not by sse_max_seconds

    events = _sse_events(response.text)
    names = [e["event"] for e in events]
    assert names[:4] == ["stage", "task", "stats", "finding"]
    assert names[-1] == "done"
    notices = [e["data"] for e in events if e["event"] == "notice"]
    assert any("1 endpoint menjawab" in n for n in notices)
    assert any("Scan selesai." in n for n in notices)
    stages = [e["data"] for e in events if e["event"] == "stage"]
    assert "berjalan" in stages[0] and "selesai" in stages[-1]
    assert ": ping" in response.text  # heartbeats while nothing changed
    assert len(stages) == 2  # the status fragment is only resent when it changes


def test_stream_of_an_idle_scan_ends_after_the_maximum_duration(ui: Ui) -> None:
    scan_id = _start(ui, _engagement(ui))["id"]
    ui.client.app.state.sse_max_seconds = 0.5
    started = time.monotonic()
    response = ui.client.get(f"/scans/{scan_id}/events/stream")
    assert time.monotonic() - started < 3
    names = [e["event"] for e in _sse_events(response.text)]
    assert "done" not in names  # the browser reconnects
    assert ui.client.get("/scans/999999/events/stream").status_code == 404
