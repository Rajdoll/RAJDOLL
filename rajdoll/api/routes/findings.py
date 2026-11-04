"""Findings tab (triage) and Reports tab (AFD A8, A9; BSD 10.5, 10.7)."""

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from rajdoll.api import pages
from rajdoll.api.deps import current_session, get_db, get_keystore, require_csrf
from rajdoll.api.forms import read_fields
from rajdoll.api.render import is_htmx, respond, service_error_response, wants_json
from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Engagement, Finding
from rajdoll.modules.registry import label as module_label
from rajdoll.reporting import va
from rajdoll.services import engagements, findings, reports
from rajdoll.services.auth import ActiveSession
from rajdoll.services.errors import ServiceError, ValidationFailed

router = APIRouter()

PREVIEW_TYPES = ("text/html", "application/xhtml")


def _errors(exc: ServiceError) -> list[str]:
    return exc.errors if isinstance(exc, ValidationFailed) else [exc.message]


# --------------------------------------------------------------------------------------
# Contexts
# --------------------------------------------------------------------------------------


def _preview(response: str | None) -> str | None:
    """The HTML body of a raw response, for the sandboxed preview (None when not HTML)."""
    if not response or "\r\n\r\n" not in response and "\n\n" not in response:
        return None
    head, _, body = response.replace("\r\n", "\n").partition("\n\n")
    content_type = next(
        (line.split(":", 1)[1].lower() for line in head.split("\n")
         if line.lower().startswith("content-type:")),
        "",
    )  # fmt: skip
    return body if any(kind in content_type for kind in PREVIEW_TYPES) else None


def detail_context(db: Session, keystore: KeyStore, finding: Finding) -> dict[str, Any]:
    detail = findings.detail(db, keystore, finding)
    evidence = findings.evidence_rows(db, keystore, finding)
    for row in evidence:
        row["preview"] = _preview(row["response"])
    poc = {}
    if detail["has_poc"]:
        poc = {fmt: findings.poc_text(db, keystore, finding, fmt) for fmt in ("curl", "raw")}
    return {
        "finding": detail,
        "evidence": evidence,
        "poc": poc,
        "ai_notes": findings.llm_notes(db, keystore, finding),
        "decision_errors": [],
    }


def _list_context(db: Session, engagement: Engagement, filters: dict[str, Any]) -> dict[str, Any]:
    items = findings.list_for(db, engagement.id, filters)
    modules = sorted({f.module for f in findings.list_for(db, engagement.id)})
    return {
        "items": items,
        "counts": findings.decision_counts(db, engagement.id),
        "filters": {name: str(filters.get(name) or "") for name in findings.FILTERS},
        "filter_query": "&".join(
            f"{name}={value}" for name in findings.FILTERS if (value := filters.get(name))
        ),
        "module_options": [(m, module_label(m)) for m in modules],
        "validation_labels": findings.VALIDATION_LABELS,
        "decision_labels": findings.DECISION_LABELS,
        "evidence_kind_labels": findings.EVIDENCE_KIND_LABELS,
    }


def _filters(request: Request) -> dict[str, Any]:
    return {name: request.query_params.get(name, "") for name in findings.FILTERS}


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------


@router.get("/engagements/{engagement_id}/findings")
def findings_page(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = engagements.get(db, engagement_id)
    filters = _filters(request)
    try:
        listing = _list_context(db, engagement, filters)
    except ServiceError as exc:
        return service_error_response(request, exc)
    if wants_json(request):
        return respond(
            request,
            "engagement_findings.html",
            {},
            data={
                "items": [findings.as_dict(f) for f in listing["items"]],
                "counts": listing["counts"],
                "next_cursor": None,
            },
        )
    selected_id = request.query_params.get("finding")
    selected = None
    if selected_id and selected_id.isdigit():
        selected = next((f for f in listing["items"] if f.id == int(selected_id)), None)
    if selected is None and listing["items"]:
        selected = listing["items"][0]
    context = {
        **pages.engagement_context(db, engagement, "findings"),
        **listing,
        "selected_id": selected.id if selected else None,
        **(detail_context(db, keystore, selected) if selected else {"finding": None}),
    }
    template = "_findings_list.html" if is_htmx(request) else "engagement_findings.html"
    return respond(request, template, context)


def _finding_and_engagement(db: Session, finding_id: int) -> tuple[Finding, Engagement]:
    finding = findings.get(db, finding_id)
    return finding, engagements.get(db, finding.engagement_id)


@router.get("/findings/{finding_id}")
def finding_detail(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    try:
        finding, engagement = _finding_and_engagement(db, finding_id)
    except ServiceError as exc:
        return service_error_response(request, exc)
    if wants_json(request):
        data = findings.detail(db, keystore, finding)
        return respond(request, "_finding_detail.html", {}, data=data)
    if not is_htmx(request):
        return RedirectResponse(
            f"/engagements/{engagement.id}/findings?finding={finding.id}", status_code=303
        )
    context = {
        **detail_context(db, keystore, finding),
        **_labels(),
        "engagement": engagement,
    }
    return respond(request, "_finding_detail.html", context)


def _labels() -> dict[str, Any]:
    return {
        "validation_labels": findings.VALIDATION_LABELS,
        "decision_labels": findings.DECISION_LABELS,
        "evidence_kind_labels": findings.EVIDENCE_KIND_LABELS,
    }


@router.get("/findings/{finding_id}/evidence")
def finding_evidence(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    try:
        finding, engagement = _finding_and_engagement(db, finding_id)
    except ServiceError as exc:
        return service_error_response(request, exc)
    rows = findings.evidence_rows(db, keystore, finding)
    if not wants_json(request) and not is_htmx(request):
        return RedirectResponse(
            f"/engagements/{engagement.id}/findings?finding={finding.id}", status_code=303
        )
    context = {**detail_context(db, keystore, finding), **_labels(), "engagement": engagement}
    return respond(request, "_finding_evidence.html", context, data={"items": rows})


@router.get("/findings/{finding_id}/poc")
def finding_poc(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    try:
        finding = findings.get(db, finding_id)
        text = findings.poc_text(db, keystore, finding, request.query_params.get("format", "curl"))
    except ServiceError as exc:
        return service_error_response(request, exc)
    return PlainTextResponse(text)


@router.post("/findings/{finding_id}/decision")
async def finding_decision(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    fields = await read_fields(request)
    try:
        finding, engagement = _finding_and_engagement(db, finding_id)
    except ServiceError as exc:
        return service_error_response(request, exc)
    try:
        findings.decide(db, finding, str(fields.get("decision", "")), fields.get("reason"))
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        finding, engagement = _finding_and_engagement(db, finding_id)
        context = {
            **detail_context(db, keystore, finding),
            **_labels(),
            "engagement": engagement,
            "decision_errors": _errors(exc),
            "reason_value": str(fields.get("reason") or ""),
        }
        if is_htmx(request):
            return respond(request, "_finding_detail.html", context, status_code=422)
        return service_error_response(request, exc)
    db.commit()
    if wants_json(request):
        data = findings.detail(db, keystore, finding)
        return respond(request, "_finding_detail.html", {}, data=data)
    back = f"/engagements/{engagement.id}/findings?finding={finding.id}"
    if not is_htmx(request):
        return RedirectResponse(back, status_code=303)
    # The detail panel is swapped; the list item and the counters update out of band.
    listing = _list_context(db, engagement, {})
    context = {
        **detail_context(db, keystore, finding),
        **listing,
        "engagement": engagement,
        "oob_item": finding,
        "selected_id": finding.id,
    }
    return respond(request, "_finding_detail.html", context)


# --------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------


def _reports_context(db: Session, engagement: Engagement) -> dict[str, Any]:
    current = reports.warnings(db, engagement.id)
    return {
        **pages.engagement_context(db, engagement, "report"),
        "history": reports.list_for(db, engagement.id),
        "warnings": reports.warning_messages(current),
        "accepted": findings.decision_counts(db, engagement.id).get("accepted", 0),
        "kind_labels": reports.KIND_LABELS,
        "report_errors": [],
    }


@router.get("/engagements/{engagement_id}/reports")
def reports_page(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = engagements.get(db, engagement_id)
    context = _reports_context(db, engagement)
    data = {"items": [reports.as_dict(r) for r in context["history"]], "next_cursor": None}
    return respond(request, "engagement_reports.html", context, data=data)


@router.post("/engagements/{engagement_id}/reports")
async def create_report(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    fields = await read_fields(request)
    engagement = engagements.get(db, engagement_id)
    try:
        report = reports.create(db, keystore, engagement, str(fields.get("kind") or "va"))
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        context = {**_reports_context(db, engagement), "report_errors": _errors(exc)}
        return respond(request, "engagement_reports.html", context, status_code=422)
    db.commit()
    if wants_json(request):
        body = {"id": report.id, "warnings": reports.warning_messages(report.warnings)}
        return respond(request, "engagement_reports.html", {}, data=body, status_code=201)
    url = f"/reports/{report.id}"
    if is_htmx(request):
        return Response(status_code=204, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)


@router.get("/reports/{report_id}")
def report_preview(
    report_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    try:
        report = reports.get(db, report_id)
    except ServiceError as exc:
        return service_error_response(request, exc)
    engagement = engagements.get(db, report.engagement_id)
    markdown = reports.content(db, keystore, report)
    context = {
        **pages.engagement_context(db, engagement, "report"),
        "report": report,
        "kind_labels": reports.KIND_LABELS,
        "warnings": reports.warning_messages(report.warnings),
        "preview_html": va.to_html(markdown),
        "filename": reports.filename(engagement, report),
    }
    data = {**reports.as_dict(report), "content": markdown}
    return respond(request, "report_preview.html", context, data=data)


@router.get("/reports/{report_id}/download")
def report_download(
    report_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    try:
        report = reports.get(db, report_id)
    except ServiceError as exc:
        return service_error_response(request, exc)
    engagement = engagements.get(db, report.engagement_id)
    name = reports.filename(engagement, report)
    return Response(
        reports.content(db, keystore, report),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
