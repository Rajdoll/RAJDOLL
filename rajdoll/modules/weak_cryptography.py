"""Weak Cryptography (WSTG-CRYP-01, -03) (IPD F8b).

Testing stage:
- `sslyze`, once per HTTPS origin of the target and the inventory: protocols, cipher suites,
  the certificate, and known TLS flaws, through a CONNECT tunnel that the egress proxy relays
  without intercepting TLS (TRD decision F8b-3);
- `custom:cleartext`: login endpoints served over plain HTTP get one failed login with a random
  username; a server that answers it instead of redirecting to HTTPS takes credentials in
  cleartext.
"""

from __future__ import annotations

import json
import secrets
from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.modules import auth_checks, httpkit
from rajdoll.modules.base import (
    Candidate,
    Exchange,
    PlanContext,
    TaskContext,
    TaskSpec,
    TransientTaskError,
)

MAX_HOSTS = 5
MAX_LOGINS = 5
SSLYZE_TIMEOUT_S = 900
_REDIRECTS = {301, 302, 303, 307, 308}


def tls_issues(result: dict[str, Any]) -> dict[str, list[str]]:
    """Findings in a normalized sslyze result: {vuln_type: [details]}."""
    issues: dict[str, list[str]] = {}
    if result.get("legacy_protocols"):
        issues["weak_tls_protocol"] = list(result["legacy_protocols"])
    if result.get("weak_ciphers"):
        issues["weak_cipher"] = list(result["weak_ciphers"])
    certificate = result.get("certificate") or {}
    problems = []
    if certificate and not certificate.get("trusted"):
        problems.append("self-signed" if certificate.get("self_signed") else "tidak tepercaya")
    if certificate.get("expired"):
        problems.append("kedaluwarsa")
    if certificate and not certificate.get("hostname_matches", True):
        problems.append("nama host tidak cocok")
    if certificate.get("sha1_signature"):
        problems.append("tanda tangan SHA-1")
    if (
        certificate.get("key_algorithm") == "RSAPublicKey"
        and (certificate.get("key_size") or 0) < 2048
    ):
        problems.append(f"kunci RSA {certificate.get('key_size')} bit")
    if problems:
        issues["certificate_problem"] = problems
    flaws = [name for name, present in (result.get("vulnerabilities") or {}).items() if present]
    if flaws:
        issues["tls_vulnerability"] = flaws
    return issues


DETAIL_LABELS = {
    "weak_tls_protocol": "Protokol usang diterima",
    "weak_cipher": "Cipher suite lemah diterima",
    "certificate_problem": "Masalah sertifikat",
    "tls_vulnerability": "Kerentanan TLS",
}


def tls_exchange(host: str, port: int, result: dict[str, Any], note: str) -> Exchange:
    """The scan as evidence: what was run, and the part of the result that matters."""
    summary = {
        "protocols": sorted(result.get("protocols") or {}),
        "legacy_protocols": result.get("legacy_protocols"),
        "weak_ciphers": result.get("weak_ciphers"),
        "certificate": result.get("certificate"),
        "vulnerabilities": result.get("vulnerabilities"),
    }
    request = (
        f"sslyze {result.get('sslyze_version') or ''} {host}:{port}\n"
        "(CONNECT lewat egress proxy; TLS diteruskan tanpa didekripsi)"
    )
    return Exchange(request, json.dumps(summary, indent=1, ensure_ascii=False), None, note)


def login_over_http(client: Any, endpoint: dict[str, Any]) -> tuple[bool, Exchange] | None:
    """One failed login over HTTP: (answered without a redirect to HTTPS, evidence)."""
    form = auth_checks.login_form(endpoint)
    if form is None or urlsplit(form.url).scheme != "http":
        return None
    body = {form.user_field: auth_checks.random_username(form.user_field), form.password_field: ""}
    body.update({name: httpkit.default_value(name) for name in form.other_fields})
    point = httpkit.Injection(
        form.method, form.url, form.password_field, form.location, {}, body, form.location
    )
    client.cookies.clear()
    client.follow_redirects = False  # the redirect (or its absence) is the answer
    response, exchange = point.send(
        client, f"Salah-{secrets.token_hex(4)}", None, "login (password salah) lewat HTTP"
    )
    location = response.headers.get("location", "")
    upgraded = response.status_code in _REDIRECTS and location.lower().startswith("https://")
    return not upgraded and response.status_code < 500, exchange


class WeakCryptography:
    name: ClassVar[str] = "cryptography"
    label: ClassVar[str] = "Weak Cryptography"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        origins = [ctx.target_url] + [e["url"] for e in ctx.endpoints if not e.get("excluded")]
        hosts: dict[tuple[str, int], str] = {}
        for url in origins:
            parts = urlsplit(url)
            if parts.scheme == "https" and parts.hostname:
                key = (parts.hostname, parts.port or 443)
                hosts.setdefault(key, f"https://{parts.netloc}")
        specs = [
            TaskSpec("sslyze", {"host": host, "port": port, "origin": origin})
            for (host, port), origin in list(hosts.items())[:MAX_HOSTS]
        ]
        logins = [
            {"endpoint_id": e["id"], "method": e["method"], "url": e["url"],
             "body_params": e.get("body_params", [])}
            for e in ctx.endpoints
            if not e.get("excluded")
            and urlsplit(e["url"]).scheme == "http"
            and auth_checks.login_form(e) is not None
        ][:MAX_LOGINS]  # fmt: skip
        if logins:
            specs.append(TaskSpec("custom:cleartext", {"endpoints": logins}))
        return specs

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine == "sslyze":
            return self._tls(ctx)
        if ctx.engine == "custom:cleartext":
            return self._cleartext(ctx)
        raise ValueError(f"unknown engine {ctx.engine}")

    def _tls(self, ctx: TaskContext) -> dict[str, Any]:
        host, port = ctx.target["host"], int(ctx.target["port"])
        result = ctx.run_tool("sslyze", {"host": host, "port": port}, timeout_s=SSLYZE_TIMEOUT_S)
        if result.get("status") == "timeout":
            raise TransientTaskError("sslyze timed out")
        normalized = result.get("normalized") or {}
        if result.get("status") != "completed" or not normalized.get("connected"):
            reason = normalized.get("error") or result.get("status")
            ctx.log(f"sslyze {host}:{port}: tidak bisa memindai TLS ({reason}).")
            return {"connected": False}
        reported = []
        for vuln_type, details in tls_issues(normalized).items():
            note = f"{DETAIL_LABELS[vuln_type]}: {', '.join(details)}."
            origin = ctx.target["origin"]
            ctx.report_candidate(
                Candidate(
                    vuln_type=vuln_type,
                    method="GET",
                    url=origin + "/",
                    parameter=None,
                    poc={
                        "method": "GET",
                        "path": "/",
                        "query": {},
                        "headers": {},
                        "body": None,
                        "body_encoding": "none",
                        "account": None,
                        "validator": vuln_type,
                        "validator_params": {
                            "source": "sslyze",
                            "host": host,
                            "port": port,
                            "details": details,
                        },
                    },
                    evidence=(tls_exchange(host, port, normalized, note),),
                    note=note,
                )
            )
            reported.append(vuln_type)
        if reported:
            ctx.log(f"sslyze {host}:{port}: kandidat {', '.join(reported)}")
        return {"connected": True, "candidates": reported}

    def _cleartext(self, ctx: TaskContext) -> dict[str, Any]:
        reported = []
        with ctx.http("cleartext") as client:
            for endpoint in ctx.target["endpoints"]:
                ctx.check_cancelled()
                outcome = login_over_http(client, endpoint)
                if outcome is None or not outcome[0]:
                    continue
                url = httpkit.concrete_url(endpoint["url"])
                ctx.report_candidate(
                    Candidate(
                        vuln_type="cleartext_credentials",
                        method=endpoint["method"],
                        url=url,
                        parameter=None,
                        poc={
                            "method": endpoint["method"],
                            "path": urlsplit(url).path or "/",
                            "query": {},
                            "headers": {},
                            "body": None,
                            "body_encoding": "none",
                            "account": None,
                            "validator": "cleartext_credentials",
                            "validator_params": {"body_params": endpoint.get("body_params", [])},
                        },
                        evidence=(outcome[1],),
                        note="Login dijawab lewat HTTP tanpa dialihkan ke HTTPS.",
                    )
                )
                reported.append(urlsplit(url).path)
        if reported:
            ctx.log(f"Login lewat HTTP: {', '.join(reported)}")
        return {"candidates": reported}
