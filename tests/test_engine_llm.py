"""The engine with the real AI module and gateway against a fake LLM server (IPD F7b):
LLM tags in planning, triage notes in AI_TRIAGE, and nothing at all when the LLM is off."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine as SqlEngine
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import ScanStage, ScanStatus
from rajdoll.core.models import Endpoint, Engagement, Finding, LlmCall, Scan
from rajdoll.llm import client as llm_client
from rajdoll.llm.gateway import LlmGateway
from rajdoll.modules.base import (
    Candidate,
    EndpointSeen,
    Exchange,
    PlanContext,
    TaskContext,
    TaskSpec,
    Verdict,
)
from rajdoll.services import engagements
from rajdoll.services import findings as findings_service
from rajdoll.validators import base as validator_base
from tests.test_engine import drive, make_engine, start_scan, tasks_of

ANSWERS = {
    "classify_endpoint": {
        "endpoints": [{"index": 0, "tags": ["profile"], "reason": "data pegawai"}]
    },
    "triage_finding": {
        "explanation": "Parameter masuk ke kueri SQL.",
        "impact": "Data pegawai bisa dibaca.",
        "fix": "Gunakan prepared statement.",
        "manual_test_suggestions": ["Coba UNION SELECT"],
        "possible_duplicates": [],
    },
}


class FakeLlmServer:
    def __init__(self) -> None:
        self.kinds: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        kind = body["response_format"]["json_schema"]["name"]
        self.kinds.append(kind)
        content = json.dumps(ANSWERS[kind])
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    def gateway(self, factory: sessionmaker[Session], keystore: KeyStore) -> LlmGateway:
        transport = httpx.MockTransport(self.handler)
        return LlmGateway(
            factory,
            keystore,
            client_factory=lambda config: llm_client.LlmClient(config, transport=transport),
        )


class SqliModule:
    """Adds one endpoint in recon and reports one SQLi candidate on it in testing."""

    name = "input_validation"
    label = "Input Validation"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage in (ScanStage.RECON, ScanStage.TESTING):
            return [TaskSpec("custom:x", {"stage": str(ctx.stage)})]
        return []

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        url = "https://app.test/api/pegawai/7?nip=1"
        if ctx.target["stage"] == ScanStage.RECON:
            ctx.add_endpoints([EndpointSeen("GET", url, "crawl", query_params=("nip",))])
            return {}
        ctx.report_candidate(
            Candidate("sqli", "GET", url, "nip", {"method": "GET", "path": "/api/pegawai/1"},
                      (Exchange("GET /api/pegawai/1?nip=1' HTTP/1.1", "SQL syntax", 500),))
        )  # fmt: skip
        return {}


@pytest.fixture(scope="module")
def factory(db_engine: SqlEngine) -> sessionmaker[Session]:
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    return KeyStore(tmp_path)


@pytest.fixture
def engagement_id(factory: sessionmaker[Session], keystore: KeyStore) -> Iterator[int]:
    with factory() as session, session.begin():
        engagement = engagements.create(
            session, keystore, {"name": "Uji LLM engine", "target_url": "https://app.test/"}
        )
        created = engagement.id
    yield created
    with factory() as session, session.begin():
        session.execute(delete(Engagement).where(Engagement.id == created))


@pytest.fixture
def engines() -> Iterator[list]:
    created: list = []
    yield created
    for engine in created:
        engine.shutdown(grace_seconds=5)


@pytest.fixture
def confirm_sqli(monkeypatch: pytest.MonkeyPatch) -> None:
    validator_base._load()
    monkeypatch.setitem(
        validator_base.VALIDATORS, "sqli", lambda _c, _f: Verdict(True, (), "dikonfirmasi")
    )


def test_llm_tags_endpoints_and_writes_triage_notes(
    factory: sessionmaker[Session],
    keystore: KeyStore,
    engagement_id: int,
    engines: list,
    confirm_sqli: None,
) -> None:
    server = FakeLlmServer()
    engine = make_engine(
        engines, factory, SqliModule(), keystore=keystore, llm=server.gateway(factory, keystore)
    )
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    scan = drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert scan.status == "completed"

    assert server.kinds == ["classify_endpoint", "triage_finding"]
    (classify,) = tasks_of(factory, scan_id, ScanStage.PLANNING)
    assert (classify.module, classify.engine, classify.status) == (
        "ai", "llm:classify_endpoint", "done",
    )  # fmt: skip
    with factory() as session:
        endpoint = session.scalars(
            select(Endpoint).where(Endpoint.engagement_id == engagement_id)
        ).one()
        assert endpoint.tag_source == "llm" and "profile" in endpoint.tags
        assert "has_params" in endpoint.tags  # rule tags stay
        finding = session.scalars(
            select(Finding).where(Finding.engagement_id == engagement_id)
        ).one()
        notes = findings_service.llm_notes(session, keystore, finding)
        assert notes["explanation"] == "Parameter masuk ke kueri SQL."
        assert finding.validation == "confirmed"  # by the validator, not the LLM
        calls = session.scalars(select(LlmCall).where(LlmCall.scan_id == scan_id)).all()
        assert sorted(c.task_kind for c in calls) == ["classify_endpoint", "triage_finding"]
        assert {c.status for c in calls} == {"ok"}
        assert next(c for c in calls if c.task_kind == "triage_finding").finding_id == finding.id


def test_no_llm_steps_when_the_llm_is_off(
    factory: sessionmaker[Session],
    keystore: KeyStore,
    engagement_id: int,
    engines: list,
    confirm_sqli: None,
) -> None:
    server = FakeLlmServer()
    engine = make_engine(
        engines, factory, SqliModule(), keystore=keystore, llm=server.gateway(factory, keystore)
    )
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    with factory() as session, session.begin():
        scan = session.get(Scan, scan_id)
        scan.llm_snapshot = {**scan.llm_snapshot, "enabled": False}
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert server.kinds == []
    assert [t.module for t in tasks_of(factory, scan_id)] == ["input_validation"] * 2 + [
        "validation"
    ]
    with factory() as session:
        endpoint = session.scalars(
            select(Endpoint).where(Endpoint.engagement_id == engagement_id)
        ).one()
        assert endpoint.tag_source == "rule"
        assert session.scalars(select(LlmCall).where(LlmCall.scan_id == scan_id)).all() == []
