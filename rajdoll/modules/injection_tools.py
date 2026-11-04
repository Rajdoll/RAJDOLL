"""Input Validation with sqlmap, commix, dalfox, and nuclei DAST (IPD F6b; TRD 6.2).

Each function runs one tool through the runner for an endpoint (nuclei: a batch of endpoints) and
turns its findings into candidates. The payload a tool reports is sent again through the egress
proxy so the finding has a raw request and response as evidence even when the tool's output does
not include one; tool output that does carry requests is stored with session headers masked.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from rajdoll.modules import httpkit
from rajdoll.modules.base import Candidate, Exchange, TaskContext

SQLMAP_TIMEOUT_S = 900
COMMIX_TIMEOUT_S = 600
DALFOX_TIMEOUT_S = 600
NUCLEI_TIMEOUT_S = 1800
NUCLEI_TEMPLATES = ["dast"]  # templates/nuclei/dast/<vuln_type>/ (pinned official subset)
# commix bypasses every proxy for these hosts, so it is never run against them.
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
# sqlmap technique names (log "Type:") to its --technique letters, for the validator's re-run.
SQLMAP_TECHNIQUES = {
    "boolean-based blind": "B",
    "error-based": "E",
    "UNION query": "U",
    "stacked queries": "S",
    "time-based blind": "T",
    "inline query": "Q",
}


@dataclass
class Found:
    point: httpkit.Injection
    candidate: Candidate


def _base(point: httpkit.Injection) -> str:
    defaults = point.query if point.location == "query" else point.body
    return defaults.get(point.parameter) or httpkit.default_value(point.parameter)


def _resend(ctx: TaskContext, point: httpkit.Injection, value: str, note: str) -> Exchange | None:
    """Send the tool's payload once more ourselves, to keep a raw request/response pair."""
    try:
        with ctx.http("evidence") as client:
            _, exchange = point.send(client, value, ctx.session_headers(None), note)
            return exchange
    except Exception as exc:  # noqa: BLE001 (evidence is best effort; the tool's finding stands)
        ctx.log(f"Gagal mengirim ulang payload {point.parameter}: {type(exc).__name__}")
        return None


def _run(ctx: TaskContext, tool: str, params: dict[str, Any], timeout_s: int) -> list[dict]:
    result = ctx.run_tool(tool, params, timeout_s=timeout_s)
    if result.get("status") != "completed":
        ctx.log(f"{tool} {params.get('parameter', '')}: {result.get('status')}".strip())
    return list((result.get("normalized") or {}).get("candidates") or [])


def tool_points(endpoint: dict[str, Any]) -> list[httpkit.Injection]:
    """Injection points the tools can address (query, form, and JSON parameters)."""
    return [p for p in httpkit.injections(endpoint) if p.tool_location]


def sqlmap(ctx: TaskContext, endpoint: dict[str, Any]) -> Iterator[Found]:
    headers = ctx.session_headers(None)
    for point in tool_points(endpoint):
        ctx.check_cancelled()
        params = {
            "request": point.request_spec(),
            "parameter": point.parameter,
            "location": point.tool_location,
            "headers": headers,
        }
        points = _run(ctx, "sqlmap", params, SQLMAP_TIMEOUT_S)
        usable = [p for p in points if p.get("value")]
        if not usable:
            continue
        techniques = [p["technique"] for p in points]
        first = usable[0]
        evidence = [
            e
            for p in usable[:3]
            if (e := _resend(ctx, point, p["value"], f"payload sqlmap ({p['technique']})"))
        ]
        dbms = first.get("dbms") or "tidak diketahui"
        yield Found(
            point,
            Candidate(
                vuln_type="sqli",
                method=point.method,
                url=point.url,
                parameter=point.parameter,
                poc=point.poc(
                    first["value"],
                    "sqli",
                    base=_base(point),
                    source="sqlmap",
                    techniques="".join(SQLMAP_TECHNIQUES.get(t, "") for t in techniques),
                ),
                evidence=tuple(evidence),
                note=f"sqlmap: {', '.join(techniques)}; DBMS {dbms}.",
            ),
        )


def commix(ctx: TaskContext, endpoint: dict[str, Any]) -> Iterator[Found]:
    if (urlsplit(endpoint["url"]).hostname or "").lower() in LOOPBACK:
        ctx.log("commix dilewati: target loopback tidak bisa dipaksa lewat egress proxy.")
        return
    headers = ctx.session_headers(None)
    for point in tool_points(endpoint):
        ctx.check_cancelled()
        params = {
            "request": point.request_spec(),
            "parameter": point.parameter,
            "location": point.tool_location,
            "headers": headers,
        }
        points = [p for p in _run(ctx, "commix", params, COMMIX_TIMEOUT_S) if p.get("value")]
        if not points:
            continue
        hit = points[0]
        exchange = _resend(ctx, point, hit["value"], f"payload commix ({hit.get('technique')})")
        yield Found(
            point,
            Candidate(
                vuln_type="cmdi",
                method=point.method,
                url=point.url,
                parameter=point.parameter,
                poc=point.poc(hit["value"], "cmdi", base=_base(point), source="commix"),
                evidence=(exchange,) if exchange else (),
                note=f"commix: {hit.get('technique')} ({hit.get('type')}).",
            ),
        )


def dalfox(ctx: TaskContext, endpoint: dict[str, Any]) -> Iterator[Found]:
    headers = ctx.session_headers(None)
    groups: dict[str, list[httpkit.Injection]] = {}
    for point in tool_points(endpoint):
        if point.tool_location == "body" and point.body_location == "json":
            continue  # dalfox tests query and form parameters
        groups.setdefault(point.tool_location or "", []).append(point)
    for location, points in groups.items():
        ctx.check_cancelled()
        by_name = {p.parameter: p for p in points}
        params = {
            "request": points[0].request_spec(),
            "parameters": list(by_name)[:20],
            "location": location,
            "headers": headers,
        }
        seen: set[str] = set()
        for hit in _run(ctx, "dalfox", params, DALFOX_TIMEOUT_S):
            point = by_name.get(hit.get("parameter") or "")
            if point is None or point.parameter in seen:
                continue
            seen.add(point.parameter)
            value = hit.get("value") or _base(point) + (hit.get("payload") or "")
            exchange = _resend(ctx, point, value, f"payload dalfox ({hit.get('inject_type')})")
            yield Found(
                point,
                Candidate(
                    vuln_type="xss_reflected",
                    method=point.method,
                    url=point.url,
                    parameter=point.parameter,
                    poc=point.poc(value, "xss_reflected", base=_base(point), source="dalfox"),
                    evidence=(exchange,) if exchange else (),
                    note=f"dalfox: {hit.get('message') or hit.get('type')}",
                ),
            )


def _changed(original: str, matched: str) -> dict[str, str]:
    """Query parameters whose value differs between two URLs (nuclei omits some names)."""
    before = dict(parse_qsl(urlsplit(original).query, keep_blank_values=True))
    after = dict(parse_qsl(urlsplit(matched).query, keep_blank_values=True))
    return {k: v for k, v in after.items() if before.get(k) != v}


def _body_value(raw_request: str, parameter: str) -> str | None:
    body = raw_request.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_request else ""
    for name, value in parse_qsl(body, keep_blank_values=True):
        if name == parameter:
            return value
    return None


def _status(raw_response: str | None) -> int | None:
    try:
        return int((raw_response or "").split(" ", 2)[1])
    except (IndexError, ValueError):
        return None


def nuclei_dast(ctx: TaskContext, endpoints: list[dict[str, Any]]) -> Iterator[Found]:
    """One nuclei DAST run over the endpoints' requests; matches map back to injection points."""
    requests, points_by_url = [], {}
    for endpoint in endpoints:
        points = tool_points(endpoint)
        if not points:
            continue
        spec = points[0].request_spec()
        requests.append(spec)
        points_by_url[request_key(spec["url"], spec["query"])] = points
    if not requests:
        return
    params = {
        "requests": requests,
        "templates": NUCLEI_TEMPLATES,
        "dast": True,
        "headers": ctx.session_headers(None),
    }
    seen: set[tuple[str, str, str]] = set()
    for hit in _run(ctx, "nuclei", params, NUCLEI_TIMEOUT_S):
        found = nuclei_hit(hit, points_by_url)
        if found is None:
            continue
        key = (found.candidate.vuln_type, found.point.url, found.point.parameter)
        if key not in seen:
            seen.add(key)
            yield found


def request_key(url: str, query: dict[str, str]) -> tuple[str, frozenset[str]]:
    return url, frozenset(query)


def nuclei_hit(
    hit: dict[str, Any], points_by_url: dict[tuple[str, frozenset[str]], list[httpkit.Injection]]
) -> Found | None:
    path = (hit.get("template_path") or "").split("/")
    if len(path) < 3 or path[0] != "dast":
        return None
    vuln_type = path[1]
    original = hit.get("url") or ""
    parts = urlsplit(original)
    base_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    points = points_by_url.get(request_key(base_url, query)) or []
    position = hit.get("fuzzing_position") or "query"
    parameter = hit.get("fuzzing_parameter")
    value = None
    if position == "query":
        changed = _changed(original, hit.get("matched_at") or "")
        if parameter is None and len(changed) == 1:
            parameter = next(iter(changed))
        value = changed.get(parameter or "")
    elif position == "body" and parameter:
        value = _body_value(hit.get("request") or "", parameter)
    location = "query" if position == "query" else "body"
    point = next(
        (p for p in points if p.parameter == parameter and p.tool_location == location), None
    )
    if point is None or value is None:
        return None
    exchange = Exchange(
        httpkit.mask_raw(hit.get("request") or ""),
        httpkit.mask_raw(hit.get("response") or "") or None,
        _status(hit.get("response")),
        f"nuclei {hit.get('template_id')}",
    )
    return Found(
        point,
        Candidate(
            vuln_type=vuln_type,
            method=point.method,
            url=point.url,
            parameter=point.parameter,
            poc=point.poc(
                value,
                vuln_type,
                base=_base(point),
                source="nuclei",
                template="/".join(path),
                template_id=hit.get("template_id"),
            ),
            evidence=(exchange,),
            note=f"nuclei: {hit.get('name') or hit.get('template_id')}",
        ),
    )
