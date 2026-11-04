"""Configuration & Deployment (WSTG-CONF, WSTG-INFO-02) (IPD F8b).

Testing stage, once per host of the target and the inventory (TRD 6.2):
- `nuclei:config`: the pinned templates for exposed files, backups, and debug pages
  (`templates/nuclei/config/`, plus `rajdoll/exposure/`), without a session;
- `custom:headers`: security headers and software versions in the root page's headers;
- `custom:trace`: whether TRACE echoes requests;
and `custom:backups` over the inventory's server-side files (`index.php` -> `index.php.bak`).

Exposed files become inventory endpoints (source `fuzz`) before they are reported, so a finding
always has its endpoint. Notes never carry values taken from the target: those stay in the
encrypted evidence.
"""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import EndpointSource, ScanStage
from rajdoll.modules import config_checks
from rajdoll.modules.base import Candidate, EndpointSeen, PlanContext, TaskContext, TaskSpec
from rajdoll.modules.config_checks import origin_of

MAX_HOSTS = 5


def _poc(url: str, validator: str, params: dict[str, Any], method: str = "GET") -> dict:
    parts = urlsplit(url)
    return {
        "method": method,
        "path": parts.path or "/",
        "query": {},
        "headers": {},
        "body": None,
        "body_encoding": "none",
        "account": None,
        "validator": validator,
        "validator_params": params,
    }


class Configuration:
    name: ClassVar[str] = "configuration"
    label: ClassVar[str] = "Configuration & Deployment"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        origins = [origin_of(ctx.target_url)] + [
            f"{e['scheme']}://{e['host']}" for e in ctx.endpoints if not e.get("excluded")
        ]
        specs: list[TaskSpec] = []
        for origin in list(dict.fromkeys(origins))[:MAX_HOSTS]:
            target = {"origin": origin}
            specs += [
                TaskSpec("nuclei:config", target),
                TaskSpec("custom:headers", target),
                TaskSpec("custom:trace", target),
            ]
        backups = config_checks.backup_targets(ctx.endpoints)
        if backups:
            specs.append(TaskSpec("custom:backups", {"urls": backups}))
        return specs

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        handlers = {
            "nuclei:config": self._nuclei,
            "custom:headers": self._headers,
            "custom:trace": self._trace,
            "custom:backups": self._backups,
        }
        if ctx.engine not in handlers:
            raise ValueError(f"unknown engine {ctx.engine}")
        reported = handlers[ctx.engine](ctx)
        if reported:
            ctx.log(f"{ctx.engine}: kandidat {', '.join(reported)}")
        return {"candidates": reported}

    def _report(self, ctx: TaskContext, candidate: Candidate, new_endpoint: bool = False) -> str:
        if new_endpoint:
            ctx.add_endpoints([EndpointSeen("GET", candidate.url, EndpointSource.FUZZ)])
        ctx.report_candidate(candidate)
        path = urlsplit(candidate.url).path or "/"
        return f"{candidate.vuln_type}:{path}"

    # -- nuclei ------------------------------------------------------------------------------------

    def _nuclei(self, ctx: TaskContext) -> list[str]:
        origin = ctx.target["origin"]
        # The origin without a trailing slash: templates that build `{{BaseURL}}{{paths}}` from
        # paths starting with "/" would otherwise request `//info.php`.
        params = {"targets": [origin], "templates": config_checks.NUCLEI_TEMPLATES}
        result = ctx.run_tool("nuclei", params, timeout_s=config_checks.NUCLEI_TIMEOUT_S)
        if result.get("status") != "completed":
            ctx.log(f"nuclei config {origin}: {result.get('status')}")
        reported: list[str] = []
        for hit in (result.get("normalized") or {}).get("candidates") or []:
            vuln_type = config_checks.nuclei_vuln_type(hit.get("template_path"))
            url = hit.get("matched_at") or hit.get("url") or ""
            if vuln_type is None or origin_of(url) != origin:
                continue
            candidate = Candidate(
                vuln_type=vuln_type,
                method="GET",
                url=url.split("?", 1)[0],
                parameter=None,
                poc=_poc(
                    url,
                    vuln_type,
                    {
                        "source": "nuclei_template",
                        "template": hit.get("template_path"),
                        "template_id": hit.get("template_id"),
                    },
                ),
                evidence=(config_checks.nuclei_exchange(hit),),
                note=f"Template {hit.get('template_id')} cocok.",
            )
            reported.append(self._report(ctx, candidate, new_endpoint=True))
        return reported

    # -- headers -----------------------------------------------------------------------------------

    def _headers(self, ctx: TaskContext) -> list[str]:
        root = ctx.target["origin"] + "/"
        with ctx.http("headers") as client:
            seen = config_checks.fetch(client, root, "halaman root tanpa sesi")
        reported: list[str] = []
        if seen.response.status_code >= 500:
            ctx.log(f"{root}: HTTP {seen.response.status_code}; header tidak diperiksa.")
            return reported
        missing = config_checks.missing_headers(seen.response.headers, root.startswith("https"))
        if missing:
            candidate = Candidate(
                vuln_type="missing_security_headers",
                method="GET",
                url=root,
                parameter=None,
                poc=_poc(root, "missing_security_headers", {"missing": missing}),
                evidence=(seen.exchange,),
                note="Header tidak ada: " + ", ".join(missing) + ".",
            )
            reported.append(self._report(ctx, candidate))
        for header, value in config_checks.version_headers(seen.response.headers).items():
            candidate = Candidate(
                vuln_type="version_disclosure",
                method="GET",
                url=root,
                parameter=header,
                poc=_poc(root, "version_disclosure", {"header": header}),
                evidence=(seen.exchange,),
                note=f"Header {header} menyebut versi perangkat lunak: {value}.",
            )
            reported.append(self._report(ctx, candidate))
        return reported

    # -- TRACE -------------------------------------------------------------------------------------

    def _trace(self, ctx: TaskContext) -> list[str]:
        root = ctx.target["origin"] + "/"
        with ctx.http("trace") as client:
            echoed, seen = config_checks.trace(client, root)
        if not echoed:
            return []
        candidate = Candidate(
            vuln_type="http_trace",
            method="GET",  # the finding is about the host; the PoC itself is a TRACE
            url=root,
            parameter=None,
            poc=_poc(root, "http_trace", {}, method="TRACE"),
            evidence=(seen.exchange,),
            note="TRACE dijawab 200 dan memantulkan header request.",
        )
        return [self._report(ctx, candidate)]

    # -- backup files ------------------------------------------------------------------------------

    def _backups(self, ctx: TaskContext) -> list[str]:
        reported: list[str] = []
        with ctx.http("backups") as client:
            not_found: dict[str, str] = {}
            for url in ctx.target["urls"]:
                ctx.check_cancelled()
                origin = origin_of(url)
                if origin not in not_found:
                    not_found[origin] = config_checks.soft_404(client, url)
                hit = config_checks.find_backups(client, url, not_found[origin])
                if hit is None:
                    continue
                original_path = urlsplit(url).path
                candidate = Candidate(
                    vuln_type="backup_file",
                    method="GET",
                    url=hit.url,
                    parameter=None,
                    poc=_poc(
                        hit.url,
                        "backup_file",
                        {"source": "backup", "original_path": original_path, "suffix": hit.suffix},
                    ),
                    evidence=(hit.original_seen.exchange, hit.seen.exchange),
                    note=f"Salinan cadangan {original_path}{hit.suffix} dapat diunduh.",
                )
                reported.append(self._report(ctx, candidate, new_endpoint=True))
        return reported
