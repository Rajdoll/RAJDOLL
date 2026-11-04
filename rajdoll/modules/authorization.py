"""Authorization (WSTG-ATHZ): IDOR and privilege escalation with two accounts (IPD F8a).

Testing stage: one `custom:authz` task over the GET endpoints the plan assigns to Authorization
(tags `idor_candidate`, `admin`, `profile`), with the accounts of the engagement. Without two
accounts the module plans nothing; the checkpoint and the scan say why (PRD F-05).

The checks are in rajdoll/modules/authz_checks.py and send GET requests only. A candidate
records which account sent the request (`poc.account`) and which account owns the object or is
privileged (`validator_params`); the validators repeat the same rounds. The LLM is asked only
when a comparison is ambiguous, and its answer only decides whether a candidate is reported
(TRD P3): the validators confirm.
"""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.llm import tasks
from rajdoll.modules import authz_checks
from rajdoll.modules.authz_checks import AdminView, Fetch, Owned, Reference, Target
from rajdoll.modules.base import Candidate, Exchange, PlanContext, TaskContext, TaskSpec

MAX_ENDPOINTS = 200
MAX_PAGES = 10  # own pages per account where object references are looked up
MAX_ADMIN = 30
MAX_ACCOUNTS = 3
OBJECTS_PER_OWNER = 2


def _has_placeholder(endpoint: dict[str, Any]) -> bool:
    return "{" in str(endpoint.get("path_template", ""))


class Authorization:
    name: ClassVar[str] = "authorization"
    label: ClassVar[str] = "Authorization"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING or len(ctx.accounts) < 2:
            return []
        chosen = [
            e for e in ctx.endpoints if self.name in e.get("modules", []) and e["method"] == "GET"
        ][:MAX_ENDPOINTS]
        if not chosen:
            return []
        pages = [
            e["url"]
            for e in ctx.endpoints
            if not e.get("excluded")
            and e["method"] == "GET"
            and "profile" in e.get("tags", [])
            and not _has_placeholder(e)
        ][:MAX_PAGES]
        endpoints = [
            {
                "endpoint_id": e["id"],
                "method": e["method"],
                "url": e["url"],
                "path_template": e["path_template"],
                "query_params": e.get("query_params", []),
                "tags": e.get("tags", []),
            }
            for e in chosen
        ]
        target = {"endpoints": endpoints, "pages": pages, "accounts": ctx.accounts[:MAX_ACCOUNTS]}
        return [TaskSpec("custom:authz", target)]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine != "custom:authz":
            raise ValueError(f"unknown engine {ctx.engine}")
        headers = {label: ctx.session_headers(label) for label in ctx.target["accounts"]}
        accounts = [label for label, sent in headers.items() if sent]
        if len(accounts) < 2:
            ctx.log("Authorization dilewati: butuh minimal dua akun dengan sesi.")
            return {"skipped": "needs_two_accounts"}
        with ctx.http("authz") as client:
            fetch = authz_checks.fetcher(client, headers, ctx.check_cancelled)
            idor = self._idor(ctx, fetch, accounts)
            escalation = self._escalation(ctx, fetch, accounts)
        reported = idor + escalation
        if reported:
            ctx.log(f"Authorization: kandidat {', '.join(reported)}")
        return {"candidates": reported, "accounts": accounts}

    # -- IDOR ------------------------------------------------------------------------------------

    def _own_pages(
        self, ctx: TaskContext, fetch: Fetch, accounts: list[str]
    ) -> dict[str, list[tuple[Target, authz_checks.Fetched]]]:
        urls = list(dict.fromkeys([ctx.target_url, *ctx.target["pages"]]))
        return {
            account: [
                (Target(url), fetch(Target(url), account, f"halaman {account} sendiri"))
                for url in urls
            ]
            for account in accounts
        }

    def _idor(self, ctx: TaskContext, fetch: Fetch, accounts: list[str]) -> list[str]:
        refs = [
            (endpoint, ref)
            for endpoint in ctx.target["endpoints"]
            for ref in authz_checks.references(endpoint)
        ]
        if not refs:
            return []
        pages = self._own_pages(ctx, fetch, accounts)
        reported: list[str] = []
        unknown: list[str] = []
        for endpoint, ref in refs:
            owned = authz_checks.owned_objects(ref, pages)
            if not any(owned.values()):
                unknown.append(endpoint["path_template"])
                continue
            if self._idor_endpoint(ctx, fetch, accounts, ref, owned):
                reported.append(f"idor:{endpoint['path_template']}")
        if unknown:
            ctx.log(
                "Kepemilikan objek tidak ditemukan di halaman akun (perlu cek manual): "
                + ", ".join(sorted(set(unknown))[:20])
            )
        return reported

    def _idor_endpoint(
        self,
        ctx: TaskContext,
        fetch: Fetch,
        accounts: list[str],
        ref: Reference,
        owned: dict[str, dict[str, Owned]],
    ) -> bool:
        for owner in accounts:
            for other in accounts:
                if other == owner:
                    continue
                # The other account's own object; else an object that does not exist.
                mine = next(iter(owned[other].values()), None)
                control = mine.target if mine else ref.target(authz_checks.NONEXISTENT)
                for obj in list(owned[owner].values())[:OBJECTS_PER_OWNER]:
                    result = authz_checks.idor_round(fetch, obj.target, control, owner, other)
                    note = self._idor_decision(ctx, result, obj.target, owner, other)
                    if note is None:
                        continue
                    evidence = (
                        Exchange(
                            obj.page.exchange.request,
                            obj.page.exchange.response,
                            obj.page.status,
                            f"halaman {owner} merujuk objek {obj.target.label}",
                        ),
                        *result.evidence,
                    )
                    ctx.report_candidate(
                        Candidate(
                            vuln_type="idor",
                            method="GET",
                            url=obj.target.url,
                            parameter=ref.parameter,
                            poc=_poc(
                                obj.target,
                                other,
                                "idor",
                                {
                                    "parameter": ref.parameter,
                                    "location": ref.location,
                                    "owner_account": owner,
                                    "control_path": control.path,
                                    "control_query": control.query,
                                },
                            ),
                            evidence=evidence,
                            note=note,
                        )
                    )
                    return True
        return False

    def _idor_decision(
        self,
        ctx: TaskContext,
        result: authz_checks.IdorRound,
        obj: Target,
        owner: str,
        other: str,
    ) -> str | None:
        """The candidate's note, or None when this round is not a candidate."""
        if result.share >= authz_checks.SHARE_CONFIRM:
            return result.note + "."
        if result.share < authz_checks.SHARE_ASK:
            return None
        # Ambiguous: the LLM may say whether the other account sees the owner's data. Its
        # answer only decides whether to report; the validator still decides (TRD P3).
        judgement = tasks.judge_response(
            ctx.llm,
            f"Respons A adalah objek {obj.label} yang dibuka pemiliknya ({owner}). Respons B "
            f"adalah objek yang sama yang dibuka {other}. Apakah respons B berisi data milik "
            f"{owner}, bukan data {other} atau pesan penolakan?",
            result.evidence[2].request if len(result.evidence) > 2 else f"GET {obj.label}",
            result.owner_text,
            result.other_text,
            keywords=tuple(result.values[:10]),
        )
        if judgement.answer != "ya":
            return None
        return f"{result.note}. Penilaian LLM: {judgement.reason} (validator yang memutuskan)."

    # -- privilege escalation --------------------------------------------------------------------

    def _escalation(self, ctx: TaskContext, fetch: Fetch, accounts: list[str]) -> list[str]:
        admin = [
            e
            for e in ctx.target["endpoints"]
            if "admin" in e.get("tags", []) and not _has_placeholder(e)
        ][:MAX_ADMIN]
        if not admin:
            return []
        views = [_admin_view(fetch, Target(e["url"]), accounts) for e in admin]
        refs = authz_checks.denials(views, accounts)
        if not refs:
            ctx.log(
                "Tidak ada fungsi admin yang menolak salah satu akun, jadi peran akun tidak bisa "
                "dibedakan; eskalasi hak perlu cek manual."
            )
            return []
        denying = {id(view) for view, _high, _low in refs}
        reported: list[str] = []
        for view in views:
            if id(view) in denying:
                continue
            area = authz_checks.admin_area(view.target.path)
            same_area = next(
                (r for r in refs if authz_checks.admin_area(r[0].target.path) == area), None
            )
            reference, high, low = same_area or refs[0]
            ok, note = authz_checks.escalation(
                view.responses[high], view.responses[low], view.responses[None], high, low
            )
            if not ok:
                continue
            if same_area is None:
                # Outside the area of every refusing function: only the LLM can say whether
                # this is an admin function at all; the validator cannot confirm it.
                judgement = tasks.judge_response(
                    ctx.llm,
                    "Apakah respons A halaman fungsi administratif (misalnya mengelola pengguna, "
                    "pengaturan sistem, atau data seluruh pengguna) yang seharusnya hanya untuk "
                    "admin?",
                    view.responses[low].exchange.request,
                    view.responses[high].text,
                )
                if judgement.answer != "ya":
                    continue
                note += f". Penilaian LLM: {judgement.reason} (perlu cek manual)"
            evidence = (
                reference.responses[high].exchange,
                reference.responses[low].exchange,
                view.responses[high].exchange,
                view.responses[low].exchange,
                view.responses[None].exchange,
            )
            params = {
                "privileged_account": high,
                "reference_path": reference.target.path if same_area else None,
            }
            ctx.report_candidate(
                Candidate(
                    vuln_type="privilege_escalation",
                    method="GET",
                    url=view.target.url,
                    parameter=None,
                    poc=_poc(view.target, low, "privilege_escalation", params),
                    evidence=evidence,
                    note=f"{note}; {reference.target.label} menolak {low}.",
                )
            )
            reported.append(f"privilege_escalation:{view.target.path}")
        return reported


def _admin_view(fetch: Fetch, target: Target, accounts: list[str]) -> AdminView:
    seen: dict[str | None, authz_checks.Fetched] = {
        account: fetch(target, account, f"{account} membuka fungsi admin") for account in accounts
    }
    seen[None] = fetch(target, None, "tanpa sesi")
    return AdminView(target, seen)


def _poc(target: Target, account: str, validator: str, params: dict[str, Any]) -> dict[str, Any]:
    """BSD 6.2 PoC spec: a GET sent with `account`'s session (taken at run time)."""
    return {
        "method": "GET",
        "path": urlsplit(target.url).path or "/",
        "query": dict(target.query),
        "headers": {},
        "body": None,
        "body_encoding": "none",
        "account": account,
        "validator": validator,
        "validator_params": params,
    }
