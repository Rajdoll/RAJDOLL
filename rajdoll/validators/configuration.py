"""Validators for Configuration & Deployment findings (TRD 6.3).

- `sensitive_file`, `backup_file`, `debug_exposed` from a nuclei template: the same template must
  match the same path again ("ulangan kedua"); from RAJDOLL's backup check: the copy is still
  served, twice, and is still neither the soft-404 page nor the original page.
- `missing_security_headers`, `version_disclosure`: the root page, fetched twice, still lacks
  the headers or still names the version.
- `http_trace`: TRACE with a new random header value is echoed twice.
"""

from __future__ import annotations

from typing import Any

from rajdoll.modules import config_checks
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.validators.base import base_url, validator

ROUNDS = 2


def _url(ctx: TaskContext, finding: dict[str, Any]) -> str:
    return base_url(ctx, finding).rstrip("/") + str(finding["poc"].get("path", "/"))


def _template(ctx: TaskContext, finding: dict[str, Any], params: dict[str, Any]) -> Verdict:
    template = params.get("template")
    if not template:
        return Verdict(False, (), "PoC tidak menyebut template nuclei; perlu cek manual.")
    url = _url(ctx, finding)
    origin = config_checks.origin_of(url)
    run = {"targets": [origin + "/"], "templates": [template]}
    result = ctx.run_tool("nuclei", run, timeout_s=config_checks.NUCLEI_TIMEOUT_S)
    for hit in (result.get("normalized") or {}).get("candidates") or []:
        matched = (hit.get("matched_at") or "").split("?", 1)[0]
        if hit.get("template_id") == params.get("template_id") and matched == url:
            note = f"Template {hit.get('template_id')} cocok lagi pada ulangan kedua."
            return Verdict(True, (config_checks.nuclei_exchange(hit),), note)
    return Verdict(False, (), f"Template {template} tidak cocok lagi; perlu cek manual.")


def _backup(ctx: TaskContext, finding: dict[str, Any], params: dict[str, Any]) -> Verdict:
    url = _url(ctx, finding)
    original = config_checks.origin_of(url) + str(params.get("original_path") or "/")
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            ctx.check_cancelled()
            not_found = config_checks.soft_404(client, url)
            page = config_checks.fetch(client, original, "halaman asli")
            seen = config_checks.fetch(client, url, "salinan cadangan")
            evidence.append(seen.exchange)
            if not config_checks.is_backup(seen, page.text if page.ok else "", not_found):
                return Verdict(False, tuple(evidence), "Salinan tidak lagi tersedia; cek manual.")
    return Verdict(True, tuple(evidence), f"Salinan cadangan masih dapat diunduh ({ROUNDS} kali).")


def _exposure(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    params = finding["poc"].get("validator_params") or {}
    if params.get("source") == "backup":
        return _backup(ctx, finding, params)
    return _template(ctx, finding, params)


for _kind in ("sensitive_file", "backup_file", "debug_exposed"):
    validator(_kind)(_exposure)


def _root_twice(ctx: TaskContext, finding: dict[str, Any]) -> list[config_checks.Seen]:
    url = _url(ctx, finding)
    seen = []
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            ctx.check_cancelled()
            seen.append(config_checks.fetch(client, url, "ulang validasi"))
    return seen


@validator("missing_security_headers")
def missing_security_headers(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    url = _url(ctx, finding)
    rounds = _root_twice(ctx, finding)
    missing = [
        config_checks.missing_headers(s.response.headers, url.startswith("https")) for s in rounds
    ]
    evidence = tuple(s.exchange for s in rounds)
    if all(missing) and all(s.response.status_code < 500 for s in rounds):
        note = f"Header tidak ada: {', '.join(missing[-1])} (terulang {ROUNDS} kali)."
        return Verdict(True, evidence, note)
    return Verdict(False, evidence, "Header keamanan sudah lengkap; perlu cek manual.")


@validator("version_disclosure")
def version_disclosure(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    header = str((finding["poc"].get("validator_params") or {}).get("header") or "")
    rounds = _root_twice(ctx, finding)
    evidence = tuple(s.exchange for s in rounds)
    if header and all(header in config_checks.version_headers(s.response.headers) for s in rounds):
        return Verdict(True, evidence, f"Header {header} masih menyebut versi ({ROUNDS} kali).")
    return Verdict(False, evidence, f"Header {header} tidak lagi menyebut versi; cek manual.")


@validator("http_trace")
def http_trace(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    url = _url(ctx, finding)
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            ctx.check_cancelled()
            echoed, seen = config_checks.trace(client, url)
            evidence.append(seen.exchange)
            if not echoed:
                return Verdict(False, tuple(evidence), "TRACE tidak lagi memantulkan request.")
    return Verdict(True, tuple(evidence), f"TRACE memantulkan header acak ({ROUNDS} kali).")
