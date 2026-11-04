"""The five LLM tasks and their fallbacks, with a stand-in `ctx.llm` (IPD F7b; TRD 5.2, 6.4)."""

import threading
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from rajdoll.core.enums import ScanStage
from rajdoll.llm import tasks
from rajdoll.llm.context import DATA_RULE
from rajdoll.llm.gateway import LlmOutcome
from rajdoll.modules.ai import AiModule
from rajdoll.modules.base import Exchange, PlanContext, TaskContext, Verdict
from rajdoll.modules.httpkit import Injection
from rajdoll.modules.input_validation import InputValidation
from rajdoll.validators import miniloop
from tests.test_injection_checks import _testapp

APP = _testapp().app


class FakeLlm:
    """Records calls; answers each task kind from a dict of values (None = no LLM)."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, list[dict[str, str]], dict]] = []

    def __call__(self, task: Any, messages: list[dict[str, str]], **ids: Any) -> Any:
        self.calls.append((task.kind, messages, ids))
        answer = self.answers.get(task.kind)
        if isinstance(answer, list):
            answer = answer.pop(0) if answer else None
        if answer is None:
            return LlmOutcome(None, "error")
        return LlmOutcome(task.output.model_validate(answer), "ok")


def _ctx(target: dict, engine: str, llm: Any, **hooks: Any) -> TaskContext:
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url="http://testserver/",
        scope=["testserver"],
        settings=hooks.pop("settings", {}),
        engine=engine,
        target=target,
        params={},
        cancel_event=threading.Event(),
        run_tool=lambda *_a, **_k: {"status": "completed", "normalized": {"candidates": []}},
        log=hooks.pop("log", lambda _m: None),
        llm=llm,
        http=hooks.pop("http", lambda _p: TestClient(APP, raise_server_exceptions=False)),
        **hooks,
    )


# -- schemas -------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["http://evil.test/x", "//evil.test/x", "x/y", "/a b", "/a\nb"])
def test_proposed_requests_stay_on_the_target_host(path: str) -> None:
    with pytest.raises(ValidationError):
        tasks.ProposedRequest(method="GET", path=path)
    with pytest.raises(ValidationError):
        tasks.ProposedRequest(method="DELETE", path="/x")
    assert tasks.ProposedRequest(method="POST", path="/api/x?y=1").path == "/api/x?y=1"


def test_outputs_are_bounded() -> None:
    with pytest.raises(ValidationError):
        tasks.Classification(endpoints=[{"index": 0, "tags": ["bukan_tanda"]}])
    with pytest.raises(ValidationError):
        tasks.InputValues(values=[{"name": "q", "value": "a\x00b"}])
    with pytest.raises(ValidationError):
        tasks.VerificationStep(requests=[])
    with pytest.raises(ValidationError):
        tasks.Judgement(answer="mungkin", reason="")
    with pytest.raises(ValidationError):
        tasks.Triage(explanation="x", extra="y")


def test_every_prompt_carries_the_data_rule() -> None:
    contexts = {
        "classify_endpoint": {"endpoints": []},
        "build_input": {"method": "GET", "path": "/", "parameters": ["q"], "sample": None},
        "judge_response": {"question": "?", "request": "r", "response_a": "a", "response_b": None},
        "verification_step": {
            "title": "t",
            "vuln_type": "sqli",
            "parameter": "q",
            "round": 1,
            "max_rounds": 3,
            "validator_note": None,
            "evidence": "-",
            "previous": [],
        },
        "triage_finding": {
            "finding": {
                "id": 1,
                "title": "t",
                "vuln_type": "sqli",
                "severity": "high",
                "validation": "confirmed",
                "parameter": "q",
            },
            "endpoint": "GET /",
            "evidence": "-",
            "others": [],
        },
    }
    for name, context in contexts.items():
        system, user = tasks.messages(name, **context)
        assert (system["role"], user["role"]) == ("system", "user")
        assert DATA_RULE in system["content"] and "JSON" in system["content"], name


# -- classify_endpoint ---------------------------------------------------------------------


def _endpoint(i: int, **extra: Any) -> dict:
    return {
        "id": i,
        "method": "GET",
        "url": f"http://app.test/api/{i}",
        "query_params": ["id"],
        "body_params": [],
        "tags": ["api"],
        "tag_source": "rule",
        **extra,
    }


def test_ai_module_plans_only_with_an_llm() -> None:
    endpoints = [_endpoint(i) for i in range(10)] + [
        _endpoint(10, excluded=True),
        _endpoint(11, tag_source="user"),
    ]
    module = AiModule()
    off = PlanContext(1, 1, "", [], {}, ScanStage.PLANNING, endpoints, llm_enabled=False)
    assert module.plan(off) == []
    on = PlanContext(1, 1, "", [], {}, ScanStage.PLANNING, endpoints, llm_enabled=True)
    batches = module.plan(on)
    assert [len(b.target["endpoints"]) for b in batches] == [8, 2]
    assert {e["id"] for b in batches for e in b.target["endpoints"]} == set(range(10))
    findings = [
        {"id": 1, "vuln_type": "sqli", "title": "A"},
        {"id": 2, "vuln_type": "x", "title": "B"},
    ]
    triage = module.plan(
        PlanContext(1, 1, "", [], {}, ScanStage.AI_TRIAGE, findings=findings, llm_enabled=True)
    )
    assert [(t.engine, t.target) for t in triage] == [
        ("llm:triage_finding", {"finding_id": 1, "others": [{"id": 2, "title": "B"}]}),
        ("llm:triage_finding", {"finding_id": 2, "others": [{"id": 1, "title": "A"}]}),
    ]


def test_classify_adds_llm_tags_and_falls_back_to_rules() -> None:
    tagged: list[tuple[int, list[str]]] = []
    llm = FakeLlm(
        {
            "classify_endpoint": {
                "endpoints": [
                    {"index": 0, "tags": ["idor_candidate"], "reason": "id di path"},
                    {"index": 7, "tags": ["admin"]},  # out of range: ignored
                ]
            }
        }
    )
    target = {
        "endpoints": [
            {
                "id": 5,
                "method": "GET",
                "path": "/api/5",
                "query_params": [],
                "body_params": [],
                "tags": [],
            }
        ]
    }
    ctx = _ctx(
        target,
        "llm:classify_endpoint",
        llm,
        tag_endpoint=lambda i, t: tagged.append((i, t)) or True,
    )
    assert AiModule().run(ctx)["tagged"] == [5]
    assert tagged == [(5, ["idor_candidate"])]
    fallback = AiModule().run(_ctx(target, "llm:classify_endpoint", FakeLlm({})))
    assert fallback["fallback"] == "rule_tags"
    assert (
        AiModule().run(_ctx(target, "llm:classify_endpoint", lambda *a, **k: None))["fallback"]
        == "rule_tags"
    )


# -- triage_finding ------------------------------------------------------------------------


def test_triage_saves_notes_and_keeps_known_duplicates_only() -> None:
    saved: list[tuple[int, dict]] = []
    finding = {
        "id": 3,
        "title": "SQL Injection di /katalog",
        "vuln_type": "sqli",
        "severity": "critical",
        "validation": "confirmed",
        "parameter": "nama",
        "endpoint_label": "GET /katalog",
        "evidence": [
            {
                "kind": "detection",
                "note": "x",
                "request": "GET /katalog?nama='",
                "response": "HTTP/1.1 500 x\r\n\r\nsqlite3.OperationalError",
            }
        ],
    }
    llm = FakeLlm(
        {
            "triage_finding": {
                "explanation": "Input masuk ke kueri.",
                "impact": "Data bocor.",
                "fix": "Pakai parameter.",
                "manual_test_suggestions": ["Coba UNION"],
                "possible_duplicates": [4, 99],
            }
        }
    )
    ctx = _ctx(
        {"finding_id": 3, "others": [{"id": 4, "title": "Lain"}]},
        "llm:triage_finding",
        llm,
        finding=lambda _i: finding,
        save_llm_notes=lambda i, n: saved.append((i, n)),
    )
    assert AiModule().run(ctx)["status"] == "ok"
    assert saved == [
        (
            3,
            {
                "explanation": "Input masuk ke kueri.",
                "impact": "Data bocor.",
                "fix": "Pakai parameter.",
                "manual_test_suggestions": ["Coba UNION"],
                "possible_duplicates": [4],
            },
        )
    ]
    prompt = llm.calls[0][1][1]["content"]
    assert "<<<DATA evidence detection" in prompt and "#4 Lain" in prompt
    assert llm.calls[0][2] == {"finding_id": 3}
    none = _ctx(
        {"finding_id": 3, "others": []},
        "llm:triage_finding",
        FakeLlm({}),
        finding=lambda _i: finding,
        save_llm_notes=lambda i, n: saved.append((i, n)),
    )
    assert AiModule().run(none)["fallback"] == "no_notes" and len(saved) == 1


# -- build_input ---------------------------------------------------------------------------


def test_build_input_values_become_the_probes_normal_values() -> None:
    endpoint = {
        "endpoint_id": 9,
        "method": "GET",
        "url": "http://testserver/katalog",
        "query_params": ["nama"],
        "body_params": [],
        "content_type": None,
    }
    llm = FakeLlm(
        {
            "build_input": {
                "values": [{"name": "nama", "value": "Kopi"}, {"name": "lain", "value": "x"}]
            }
        }
    )
    reported: list[Any] = []
    ctx = _ctx(endpoint, "custom:inpv", llm, report_candidate=lambda c: reported.append(c) or 1)
    InputValidation().run(ctx)
    assert llm.calls[0][0] == "build_input" and llm.calls[0][2] == {"endpoint_id": 9}
    (sqli,) = [c for c in reported if c.vuln_type == "sqli"]
    assert sqli.poc["validator_params"]["base"] == "Kopi"
    assert sqli.poc["query"]["nama"].startswith("Kopi")
    # Without an LLM the built-in normal value is used.
    reported.clear()
    InputValidation().run(
        _ctx(
            endpoint,
            "custom:inpv",
            lambda *a, **k: None,
            report_candidate=lambda c: reported.append(c) or 1,
        )
    )
    assert [c.poc["validator_params"]["base"] for c in reported] == ["rajdoll"]


# -- verification_step (mini-loop) ---------------------------------------------------------


def _finding() -> dict:
    point = Injection("GET", "http://testserver/katalog", "nama", "query", {"nama": "x"})
    return {
        "id": 7,
        "title": "SQLi",
        "vuln_type": "sqli",
        "parameter": "nama",
        "poc": point.poc("x'", "sqli", base="x"),
        "base_url": "http://testserver",
        "evidence": [
            {
                "note": "deteksi",
                "request": "GET /katalog?nama=x'",
                "response": "HTTP/1.1 200 OK\r\n\r\n0 produk",
            }
        ],
    }


def test_mini_loop_sends_proposals_and_only_the_validator_confirms() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, text="ok")

    evidence: list[tuple[int, list[Exchange], str]] = []
    notes: list[dict] = []
    llm = FakeLlm(
        {
            "verification_step": [
                {
                    "requests": [
                        {
                            "method": "GET",
                            "path": "/katalog",
                            "query": {"nama": "Kopi'"},
                            "expect": "error SQL",
                        },
                        {"method": "GET", "path": "/logout"},
                    ],
                    "base_value": None,
                    "reasoning": "coba nilai lain",
                },
                {
                    "requests": [{"method": "POST", "path": "/katalog", "body": {"nama": "Teh"}}],
                    "base_value": "Kopi",
                    "reasoning": "nilai normal yang ada di katalog",
                },
            ]
        }
    )
    bases: list[str] = []

    def validator(_ctx: Any, finding: dict) -> Verdict:
        base = finding["poc"]["validator_params"]["base"]
        bases.append(base)
        return Verdict(base == "Kopi", (), f"base {base}")

    ctx = _ctx(
        {},
        "validator:sqli",
        llm,
        settings={"excluded_patterns": ["logout"]},
        http=lambda _p: httpx.Client(transport=httpx.MockTransport(handler)),
        add_evidence=lambda i, ex, k: evidence.append((i, ex, k)),
        save_llm_notes=lambda i, n: notes.append(n),
    )
    first = Verdict(False, (Exchange("GET /x", "y", 200, "awal"),), "Bukti tidak berulang.")
    final = miniloop.run(ctx, _finding(), first, validator)

    assert final.confirmed and "putaran verifikasi 2" in final.note
    assert bases == ["x", "Kopi"]  # round 2 re-ran the validator with the proposed value
    assert [str(r.url) for r in sent] == [
        "http://testserver/katalog?nama=Kopi%27",
        "http://testserver/katalog",
    ]  # the logout proposal was never sent
    assert [k for _i, _e, k in evidence] == ["verification_round", "verification_round"]
    rounds = notes[0]["verification_rounds"]
    assert [r["confirmed"] for r in rounds] == [False, True]
    assert rounds[0]["requests"][1] == {
        "method": "GET",
        "path": "/logout",
        "skipped": "cocok dengan pola endpoint berisiko",
    }
    assert len(llm.calls) == 2 and llm.calls[0][2] == {"finding_id": 7}


def test_mini_loop_stops_after_three_rounds_or_without_an_llm() -> None:
    step = {"requests": [{"method": "GET", "path": "/katalog"}]}
    llm = FakeLlm({"verification_step": [dict(step) for _ in range(5)]})
    notes: list[dict] = []
    ctx = _ctx(
        {}, "v", llm, save_llm_notes=lambda i, n: notes.append(n), add_evidence=lambda *a: None
    )
    first = Verdict(False, (), "awal")
    final = miniloop.run(ctx, _finding(), first, lambda c, f: Verdict(False, (), "tidak"))
    assert not final.confirmed and "Mini-loop 3 putaran" in final.note
    assert len(llm.calls) == 3 and len(notes[0]["verification_rounds"]) == 3

    untouched = miniloop.run(
        _ctx({}, "v", lambda *a, **k: None), _finding(), first, lambda c, f: Verdict(True, (), "x")
    )
    assert untouched is first


# -- judge_response ------------------------------------------------------------------------


def test_judge_response_and_its_fallback() -> None:
    llm = FakeLlm(
        {
            "judge_response": {
                "answer": "ya",
                "reason": "data akun A terlihat",
                "relevant_part": "nip",
            }
        }
    )
    judgement = tasks.judge_response(
        llm,
        "Apakah akun B melihat data akun A?",
        "GET /akun/1",
        'HTTP/1.1 200 OK\r\n\r\n{"nip": 1}',
        "HTTP/1.1 200 OK",
    )
    assert judgement.answer == "ya"
    prompt = llm.calls[0][1][1]["content"]
    assert "<<<DATA respons akun A" in prompt and "<<<DATA respons akun B" in prompt
    assert tasks.judge_response(FakeLlm({}), "?", "r", "a").answer == "ragu"
