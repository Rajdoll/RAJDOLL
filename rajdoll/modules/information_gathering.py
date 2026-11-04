"""Information Gathering (WSTG-INFO): build the endpoint inventory (IPD F5).

Recon stage, in parallel:
  httpx (probe, technologies), katana (crawl: links, forms, JavaScript), browser (rendered pages,
  fetch/XHR calls), ffuf (hidden paths), nmap (ports), and custom checks through the egress proxy:
  OpenAPI/GraphQL, robots.txt/sitemap, WAF fingerprint.
Planning stage, using what recon stored:
  JavaScript analysis of every script in the inventory, and parameter discovery (ffuf) on GET
  endpoints.
Every result goes into the inventory through `ctx.add_endpoints`; facts for the checkpoint go into
`scan.recon_summary` through `ctx.add_recon`. Links matching the exclusion patterns (logout and
other state-destroying actions) are recorded but never requested.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar
from urllib.parse import urljoin, urlsplit

from rajdoll.core.enums import EndpointSource, ScanStage
from rajdoll.modules.base import (
    EndpointSeen,
    PlanContext,
    TaskContext,
    TaskSpec,
    TransientTaskError,
)
from rajdoll.modules.recon import js_analysis, known_files, openapi, waf

_SAFE_PATTERN = re.compile(r"^[A-Za-z0-9_./-]{1,64}$")
MAX_SCRIPTS = 50
MAX_PARAM_ENDPOINTS = 15
MAX_SCRIPT_BYTES = 5_000_000
_SKIP_PARAMS = re.compile(r"\.(js|json|xml|txt|map)$", re.I)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _exclusions(settings: dict[str, Any]) -> list[str]:
    return [p for p in settings.get("excluded_patterns", []) if _SAFE_PATTERN.match(str(p))]


def _rate(settings: dict[str, Any]) -> int:
    return max(1, int(float(settings.get("rate_limit_rps", 10))))


def _completed(result: dict[str, Any], tool: str) -> dict[str, Any]:
    if result["status"] == "timeout":
        raise TransientTaskError(f"{tool} timed out")
    if result["status"] != "completed":
        raise RuntimeError(f"{tool} {result['status']}: {result.get('stderr_tail', '')[-300:]}")
    return result["normalized"]


def _form_seen(form: dict[str, Any], source: str) -> EndpointSeen:
    method = (form.get("method") or "GET").upper()
    enctype = form.get("enctype") or ""
    names = tuple(p for p in form.get("params") or [] if p)
    if method == "GET":
        return EndpointSeen(method, form["url"], source, query_params=names)
    location = "multipart" if "multipart" in enctype else "form"
    return EndpointSeen(
        method,
        form["url"],
        source,
        body_params=tuple({"name": n, "location": location} for n in names),
        content_type=enctype or None,
    )


def _json_keys(post_data: str | None) -> tuple[dict[str, str], ...]:
    if not post_data:
        return ()
    try:
        data = json.loads(post_data)
    except (json.JSONDecodeError, TypeError):
        return ()
    if isinstance(data, dict):
        return tuple({"name": str(k), "location": "json"} for k in data)
    return ()


class InformationGathering:
    name: ClassVar[str] = "information_gathering"
    label: ClassVar[str] = "Information Gathering"

    # ------------------------------------------------------------------ plan

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage == ScanStage.RECON:
            return self._plan_recon(ctx)
        if ctx.stage == ScanStage.PLANNING:
            return self._plan_second_wave(ctx)
        return []

    def _plan_recon(self, ctx: PlanContext) -> list[TaskSpec]:
        target = ctx.target_url
        host = urlsplit(target).hostname or ""
        return [
            TaskSpec("httpx", {"urls": [target]}),
            TaskSpec("katana", {"urls": [target]}),
            TaskSpec("browser", {"urls": [target]}),
            TaskSpec("ffuf", {"url": _origin(target) + "/"}, {"mode": "directory"}),
            TaskSpec("nmap", {"host": host}),
            TaskSpec("custom:openapi", {"base": _origin(target)}),
            TaskSpec("custom:known_files", {"base": _origin(target)}),
            TaskSpec("custom:waf", {"url": target}),
        ]

    def _plan_second_wave(self, ctx: PlanContext) -> list[TaskSpec]:
        live = [e for e in ctx.endpoints if not e.get("excluded")]
        scripts = [e["url"] for e in live if e["path_template"].lower().endswith(".js")]
        specs = [
            TaskSpec("custom:js", {"pages": [ctx.target_url], "scripts": scripts[:MAX_SCRIPTS]})
        ]
        candidates = [
            e
            for e in live
            if e["method"] == "GET"
            and "{" not in e["path_template"]
            and not _SKIP_PARAMS.search(e["path_template"])
        ]
        # Pages that already take parameters first: hidden ones tend to sit next to them.
        candidates.sort(key=lambda e: (not e["query_params"], e["path_template"]))
        for endpoint in candidates[:MAX_PARAM_ENDPOINTS]:
            specs.append(TaskSpec("ffuf", {"url": endpoint["url"]}, {"mode": "parameter"}))
        return specs

    # ------------------------------------------------------------------- run

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        handler = {
            "httpx": self._httpx,
            "katana": self._katana,
            "browser": self._browser,
            "ffuf": self._ffuf,
            "nmap": self._nmap,
            "custom:openapi": self._openapi,
            "custom:known_files": self._known_files,
            "custom:waf": self._waf,
            "custom:js": self._javascript,
        }.get(ctx.engine)
        if handler is None:
            raise RuntimeError(f"unknown engine {ctx.engine}")
        return handler(ctx)

    def _httpx(self, ctx: TaskContext) -> dict[str, Any]:
        normalized = _completed(
            ctx.run_tool("httpx", {"urls": ctx.target["urls"]}, timeout_s=300), "httpx"
        )
        endpoints = normalized.get("endpoints", [])
        technologies = normalized.get("technologies", [])
        ctx.add_endpoints(
            [EndpointSeen("GET", e["url"], EndpointSource.CRAWL) for e in endpoints if e.get("url")]
        )
        ctx.add_recon(
            {
                "technologies": [
                    {"name": t["name"], "version": t.get("version")} for t in technologies
                ],
                "servers": sorted({e["server"] for e in endpoints if e.get("server")}),
            }
        )
        ctx.log(f"httpx: {len(endpoints)} endpoint menjawab, {len(technologies)} teknologi")
        return {"endpoints": len(endpoints), "technologies": technologies}

    def _katana(self, ctx: TaskContext) -> dict[str, Any]:
        params = {
            "urls": ctx.target["urls"],
            "exclude": _exclusions(ctx.settings),
            "rate_limit": _rate(ctx.settings),
            "headers": ctx.session_headers(None),
        }
        normalized = _completed(ctx.run_tool("katana", params, timeout_s=700), "katana")
        seen = [
            EndpointSeen(e["method"], e["url"], EndpointSource.CRAWL, content_type=None)
            for e in normalized.get("endpoints", [])
        ]
        seen += [_form_seen(f, EndpointSource.CRAWL) for f in normalized.get("forms", [])]
        added = ctx.add_endpoints(seen)
        ctx.log(f"katana: {len(seen)} URL dan form, {added} endpoint baru")
        return {"seen": len(seen), "added": added}

    def _browser(self, ctx: TaskContext) -> dict[str, Any]:
        params = {
            "urls": ctx.target["urls"],
            "exclude": _exclusions(ctx.settings),
            "headers": ctx.session_headers(None),
        }
        normalized = _completed(ctx.run_tool("browser", params, timeout_s=900), "browser")
        seen = []
        for request in normalized.get("requests", []):
            kind = request.get("resource_type")
            if kind not in ("document", "xhr", "fetch", "script", "other"):
                continue
            source = EndpointSource.JS if kind in ("xhr", "fetch") else EndpointSource.CRAWL
            seen.append(
                EndpointSeen(
                    request["method"],
                    request["url"],
                    source,
                    body_params=_json_keys(request.get("post_data")),
                    content_type=request.get("content_type"),
                )
            )
        # Links are stored even when not followed (logout): the checkpoint shows them excluded.
        seen += [
            EndpointSeen("GET", link["url"], EndpointSource.CRAWL)
            for link in normalized.get("links", [])
        ]
        seen += [
            _form_seen({**form, "url": form.get("action")}, EndpointSource.CRAWL)
            for form in normalized.get("forms", [])
            if form.get("action")
        ]
        added = ctx.add_endpoints(seen)
        pages = normalized.get("pages", [])
        ctx.log(f"browser: {len(pages)} halaman dirender, {added} endpoint baru")
        return {"pages": len(pages), "seen": len(seen), "added": added}

    def _ffuf(self, ctx: TaskContext) -> dict[str, Any]:
        mode = ctx.params.get("mode", "directory")
        params = {
            "url": ctx.target["url"],
            "mode": mode,
            "wordlist": "directories" if mode == "directory" else "parameters",
            "exclude": _exclusions(ctx.settings),
            "rate_limit": _rate(ctx.settings),
            "headers": ctx.session_headers(None),
        }
        normalized = _completed(ctx.run_tool("ffuf", params, timeout_s=700), "ffuf")
        results = normalized.get("results", [])
        if mode == "parameter":
            names = tuple(sorted({r["param"] for r in results if r.get("param")}))
            if names:
                ctx.add_endpoints(
                    [
                        EndpointSeen(
                            "GET", ctx.target["url"], EndpointSource.FUZZ, query_params=names
                        )
                    ]
                )
                ctx.log(f"ffuf: parameter {', '.join(names)} pada {ctx.target['url']}")
            return {"params": list(names)}
        added = ctx.add_endpoints(
            [EndpointSeen("GET", r["url"], EndpointSource.FUZZ) for r in results]
        )
        ctx.log(f"ffuf: {len(results)} path ditemukan, {added} endpoint baru")
        return {"found": [{"url": r["url"], "status": r["status"]} for r in results]}

    def _nmap(self, ctx: TaskContext) -> dict[str, Any]:
        params = {"host": ctx.target["host"], "max_rate": _rate(ctx.settings) * 5}
        normalized = _completed(ctx.run_tool("nmap", params, timeout_s=1000), "nmap")
        ports = normalized.get("ports", [])
        ctx.add_recon({"open_ports": ports})
        ctx.log(f"nmap: {len(ports)} port terbuka")
        return {"ports": ports}

    # ------------------------------------------------------------ custom checks

    def _openapi(self, ctx: TaskContext) -> dict[str, Any]:
        base = ctx.target["base"]
        headers = ctx.session_headers(None)
        seen: list[EndpointSeen] = []
        spec_found = None
        with ctx.http("openapi") as client:
            for path in openapi.SPEC_PATHS:
                ctx.check_cancelled()
                url = base + path
                response = client.get(url, headers=headers)
                if response.status_code != 200:
                    continue
                spec = openapi.load_spec(response.text)
                if spec is None and "html" in response.headers.get("content-type", ""):
                    embedded = openapi.spec_url_in_html(response.text)
                    if embedded:
                        url = urljoin(url, embedded)
                        inner = client.get(url, headers=headers)
                        spec = openapi.load_spec(inner.text) if inner.status_code == 200 else None
                if spec is not None:
                    spec_found = url
                    seen.append(EndpointSeen("GET", url, EndpointSource.OPENAPI))
                    for op in openapi.endpoints_from_spec(spec):
                        seen.append(
                            EndpointSeen(
                                op["method"],
                                urljoin(base + "/", op["path"].lstrip("/")),
                                EndpointSource.OPENAPI,
                                query_params=tuple(op["query_params"]),
                                body_params=tuple(op["body_params"]),
                                content_type=op["content_type"],
                            )
                        )
                    break
            for path in openapi.GRAPHQL_PATHS:
                ctx.check_cancelled()
                response = client.post(base + path, json=openapi.INTROSPECTION, headers=headers)
                try:
                    answered = response.status_code == 200 and openapi.graphql_answered(
                        response.json()
                    )
                except ValueError:
                    answered = False
                if answered:
                    seen.append(
                        EndpointSeen(
                            "POST",
                            base + path,
                            EndpointSource.OPENAPI,
                            body_params=({"name": "query", "location": "json"},),
                            content_type="application/json",
                        )
                    )
        added = ctx.add_endpoints(seen)
        if spec_found:
            ctx.add_recon({"api_specs": [spec_found]})
            ctx.log(f"OpenAPI: spesifikasi di {spec_found}, {added} endpoint baru")
        return {"spec": spec_found, "endpoints": len(seen)}

    def _known_files(self, ctx: TaskContext) -> dict[str, Any]:
        base = ctx.target["base"]
        seen: list[EndpointSeen] = []
        with ctx.http("known_files") as client:
            response = client.get(base + "/robots.txt")
            sitemaps = [base + "/sitemap.xml"]
            if response.status_code == 200 and "html" not in response.headers.get(
                "content-type", ""
            ):
                paths, listed = known_files.robots_paths(response.text)
                seen.append(EndpointSeen("GET", base + "/robots.txt", EndpointSource.CRAWL))
                seen += [EndpointSeen("GET", base + p, EndpointSource.CRAWL) for p in paths]
                sitemaps = listed or sitemaps
            for sitemap in sitemaps[:5]:
                ctx.check_cancelled()
                response = client.get(sitemap)
                if response.status_code == 200 and "<loc>" in response.text[:100_000]:
                    urls = known_files.sitemap_urls(response.text, sitemap)
                    seen += [EndpointSeen("GET", u, EndpointSource.CRAWL) for u in urls]
        added = ctx.add_endpoints(seen)
        ctx.log(f"robots.txt/sitemap: {len(seen)} URL, {added} endpoint baru")
        return {"seen": len(seen), "added": added}

    def _waf(self, ctx: TaskContext) -> dict[str, Any]:
        url = ctx.target["url"]

        def sample(response: Any) -> waf.Sample:
            return waf.Sample(
                status=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                cookies=list(response.cookies.keys()),
                body=response.text[:200_000],
            )

        with ctx.http("waf") as client:
            baseline = sample(client.get(url))
            attack = sample(client.get(url, params=waf.ATTACK_QUERY))
        result = waf.detect(baseline, attack)
        ctx.add_recon({"waf": result})
        if result["detected"]:
            ctx.log(f"WAF terdeteksi: {result['name'] or 'tidak dikenal'} ({result['evidence']})")
        return result

    def _javascript(self, ctx: TaskContext) -> dict[str, Any]:
        headers = ctx.session_headers(None)
        scripts = list(ctx.target.get("scripts", []))
        sources: list[tuple[str, str]] = []
        with ctx.http("js") as client:
            for page in ctx.target.get("pages", []):
                response = client.get(page, headers=headers)
                if response.status_code == 200 and "html" in response.headers.get(
                    "content-type", ""
                ):
                    external, inline = js_analysis.scripts_in_html(response.text, page)
                    scripts += [s for s in external if s not in scripts]
                    sources += [(page, body) for body in inline]
            for script in scripts[:MAX_SCRIPTS]:
                ctx.check_cancelled()
                response = client.get(script, headers=headers)
                if response.status_code != 200:
                    continue
                text = response.text[:MAX_SCRIPT_BYTES]
                sources.append((script, text))
                map_url = js_analysis.source_map_url(text, script)
                if map_url:
                    mapped = client.get(map_url, headers=headers)
                    if mapped.status_code == 200:
                        try:
                            data = mapped.json()
                        except ValueError:
                            data = None
                        if isinstance(data, dict):
                            sources += [
                                (script, content)
                                for content in data.get("sourcesContent") or []
                                if isinstance(content, str)
                            ]
        seen: list[EndpointSeen] = []
        for origin_url, text in sources:
            for found in js_analysis.extract(text):
                seen.append(
                    EndpointSeen(
                        found.method,
                        urljoin(origin_url, found.path),
                        EndpointSource.JS,
                        body_params=tuple(
                            {"name": n, "location": "json"} for n in found.body_params
                        ),
                        content_type="application/json" if found.body_params else None,
                    )
                )
        added = ctx.add_endpoints(seen)
        ctx.log(f"analisis JavaScript: {len(sources)} sumber, {added} endpoint baru")
        return {"sources": len(sources), "seen": len(seen), "added": added}
