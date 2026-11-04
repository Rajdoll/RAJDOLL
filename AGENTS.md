# Agent Guide

RAJDOLL v1 is a personal web vulnerability-assessment assistant: a **deterministic pipeline** (recon → planning → checkpoint → testing → validation → AI triage) with a **bounded local LLM** helping at four decision points. It is being rebuilt from scratch.

## Source of truth

The approved documents in `docs/v1/` define what to build. Read the relevant one before changing code, and update it in the same PR if the implementation must deviate.

| Doc | Use it for |
|---|---|
| `docs/v1/PRD.md` | Requirements (F-xx functional, NF-xx non-functional) |
| `docs/v1/TRD.md` | Architecture, principles P1–P7, technical decisions D-01–D-09 |
| `docs/v1/AFD.md` | User flows (A0–A11), state machines, wireframes |
| `docs/v1/BSD.md` | Database schema and route contract |
| `docs/v1/IPD.md` | Phases F0–F11, exit criteria, legacy-code mapping, development rules |

## Current phase

**F1 — foundation (done).** F1a: the 17-table schema (`rajdoll/core/models/`, `migrations/`), the `rajdoll_tools` role, the scan-event NOTIFY trigger, encryption (`rajdoll/core/crypto.py`), and the startup bootstrap (`rajdoll/core/bootstrap.py`). F1b: single-user login and UI sessions (`rajdoll/services/auth.py`), CSRF, settings (`rajdoll/services/settings.py`), HTML/HTMX/JSON rendering (`rajdoll/api/render.py`), and the base UI. **F2 — engagements.** Engagement CRUD, scope rules (`rajdoll/core/scope.py`, deny by default, reused by the egress proxy in F3), target accounts with pasted sessions parsed by `rajdoll/services/target_sessions.py` and encrypted per engagement, session-check configuration, per-engagement scan settings, and deletion that removes the key file first (`rajdoll/services/engagements.py`). **F3 — tools container.** F3a: the egress proxy (`tools/proxy/`, a mitmproxy addon: proxy-credential context, scope before connect, audit rows, per-engagement rate limit, identity header), the tools entrypoint running proxy and runner together, `rajdoll_tools` login at bootstrap, and the account session check through the proxy (`rajdoll/services/session_check.py`). F3b: the runner (`tools/runner/`: `/run` with scope pre-check and cancel, executor with minimal environment and process groups), the httpx and nuclei adapters, nuclei 3.11.1 and httpx 1.12.0 built from Go modules in `tools/Dockerfile`, the first custom nuclei template, and `testapp/`. **F4 — workflow engine.** F4a: the engine (`rajdoll/worker/engine.py`: Postgres queue with `FOR UPDATE SKIP LOCKED`, fixed stage order, checkpoint with auto-continue and hold, pause/resume/cancel with runner cancel, lease-based recovery of a dead worker's tasks, one retry for transient errors, session-expiry pause), the runner client (`rajdoll/worker/tools_client.py`), the scan service (`rajdoll/services/scans.py`), profiles (`profiles/full.yaml`), the module contract and registry (`rajdoll/modules/`), and the first Information Gathering step (httpx probe in recon). F4b: the Scan tab (start form with profile, summary and warnings; history), the scan monitor with live updates over SSE (`rajdoll/api/sse.py`, `rajdoll/services/monitor.py`), pause/resume/cancel and checkpoint controls, the task and log pages, a first checkpoint page (recon summary, hold, continue), and scan banners on every engagement page. **F5 — recon and planning.** F5a: katana, ffuf, nmap, and `browser` (Playwright) adapters (`tools/runner/adapters/`, `tools/runner/browser_crawl.py`, bundled wordlists in `tools/wordlists/`), the Information Gathering module (`rajdoll/modules/information_gathering.py` with helpers in `rajdoll/modules/recon/`), the endpoint inventory (`rajdoll/services/inventory.py`), and recon results on the checkpoint page. F5b: rule-based endpoint tags (`rajdoll/services/tagging.py`), module selection per endpoint and the request estimate (`rajdoll/services/planning.py`), and the editable checkpoint (`PATCH /scans/{id}/checkpoint`: exclude/include, tags, modules, manual endpoints, pasted Burp requests via `rajdoll/services/raw_request.py`, add to scope). **F6 — first end-to-end slice (M1).** F6a: the vulnerability catalog and CVSS 3.1 scoring (`rajdoll/data/vuln_types.py`, `rajdoll/core/cvss.py`), findings with fingerprints and encrypted evidence and PoC (`rajdoll/services/findings.py`), the validation stage, the Input Validation module with RAJDOLL's own probes (`rajdoll/modules/input_validation.py`, `injection_checks.py`, request toolkit `httpkit.py`), validators (`rajdoll/validators/`), the `xss_check` browser adapter, and testapp's Input Validation weaknesses (`testapp.EXPECTED_FINDINGS`). F6b: sqlmap, commix, and dalfox adapters (structured requests, `tools/runner/adapters/request.py`), nuclei DAST over whole requests with the pinned official DAST templates in `templates/nuclei/dast/`, the tools' tasks in Input Validation (`rajdoll/modules/injection_tools.py`), and second runs of the finding's tool in validation (`rajdoll/validators/tools.py`). F6c: the Findings tab (`rajdoll/api/routes/findings.py`: list, filters, detail, escaped evidence with a sandboxed HTML preview, copy curl/raw, accept/reject) and the VA report in Markdown from accepted findings (`rajdoll/reporting/`, `rajdoll/services/reports.py`) with preview, download, and export history. **F7 — LLM layer.** F7a: the OpenAI-compatible client and the gateway every call goes through (`rajdoll/llm/`: one call at a time, per-scan budget, one repair retry, encrypted `llm_call` rows, unreachable server skipped), context trimming and target-data blocks, `ctx.llm` in the engine, and the LLM settings with connection test and the navigation indicator. F7b: the five LLM tasks (`rajdoll/llm/tasks.py`, prompts in `rajdoll/llm/prompts/`) with fallbacks: the built-in `ai` module (endpoint tags in planning, triage notes in AI triage), `build_input` in the Input Validation probes, the verification mini-loop after the validators (`rajdoll/validators/miniloop.py`), `judge_response` for F8, and AI notes with the mini-loop history in the finding detail. **F8 — the other test modules (M2), in progress.** F8a-1: the Authorization module with two accounts (`rajdoll/modules/authorization.py`, checks in `authz_checks.py`: IDOR from object references on each account's own pages, privilege escalation against an admin function that refuses one account, GET only), its validators (`rajdoll/validators/authorization.py`), `PlanContext.accounts`, the skip notice without two accounts, the account in PoC and evidence (`[sesi Akun B]`), and testapp's `idor` and `privilege-escalation` weaknesses. F8a-2: the Authentication module (`rajdoll/modules/authentication.py`, checks in `auth_checks.py`: JWT from the pasted sessions — signature not verified, `alg: none`, weak HMAC secret from `rajdoll/data/payloads/jwt_secrets.txt` — and login attempt limits with a random username), the Session Management module (`rajdoll/modules/session_management.py`: session-cookie attributes), their validators (`rajdoll/validators/authentication.py`, `session.py`), `PlanContext.session_check_url`, and testapp's JWT, no-lockout, and cookie-flags weaknesses. F8b-1: the Configuration & Deployment module (`rajdoll/modules/configuration.py`, checks in `config_checks.py`: pinned official nuclei exposure and debug templates in `templates/nuclei/config/<type>/`, security headers, versions in headers, TRACE, backup copies of server-side files), its validators (`rajdoll/validators/configuration.py`), and testapp's configuration weaknesses. F8b-2: the Error Handling module (`rajdoll/modules/error_handling.py`, runtime-specific patterns in `error_checks.py`: error-inducing values per parameter compared with the normal value, the not-found page per host, the LLM only for unmatched 5xx), its validator (`rajdoll/validators/errors.py`), and testapp's traceback weakness. Next is F8b-3 (Weak Cryptography with testssl.sh, and Identity Management). See `docs/v1/IPD.md` section 4.

## Layout

```
rajdoll/      main package (api + worker image): api, core, services, worker, modules,
              validators, llm, reporting, data
tools/        tools container: runner (/run, adapters), proxy (egress), mcp
templates/nuclei/  custom nuclei templates
profiles/     scan profiles (YAML)
migrations/   Alembic migrations (the only migration system)
testapp/      small intentionally-vulnerable app for integration tests
tests/        unit and integration tests
legacy/       previous multi-agent system, reference only (removed in F11)
```

## Legacy code

`legacy/` holds the old 13-agent system. **Do not import from it or extend it.** Use it only as reference when porting logic, following the keep/reference/drop map in `docs/v1/IPD.md` section 3. Ported logic must pass against `testapp/`, not just be copied. The last runnable legacy state is tag `v0-legacy` (commit `3307255`).

## Non-negotiable rules

- The LLM never controls pipeline order and never marks a finding `confirmed` on its own (TRD P1, P3).
- Every LLM task has a schema-constrained output and a non-LLM fallback (TRD P2).
- All target HTTP traffic goes through the egress proxy; scope is deny-by-default (TRD P5, D-04).
- No `shell=True`; tool arguments are built from typed parameters, never from LLM text.
- Only `api` publishes a port, and only on `127.0.0.1`.
- Evidence, target sessions, credentials, and LLM prompts/outputs are encrypted at rest (BSD section 1, 7).
- Pin every dependency and tool version.

## Commands

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
docker compose up -d --build        # needs .env with POSTGRES_PASSWORD
```

Database tests need PostgreSQL 16 (UTF-8) and a user that can create databases and roles:

```bash
export RAJDOLL_TEST_DATABASE_URL=postgresql+psycopg://rajdoll_app:secret@127.0.0.1:5432/postgres
pytest                              # each test module gets a fresh migrated database
```

Without that variable the database tests are skipped; CI sets `RAJDOLL_REQUIRE_DB_TESTS=1` so they can never be skipped there.

Proxy tests need mitmproxy, which belongs to the tools image, not the main package: `pip install -e ".[dev]" -r tools/requirements.txt`. They are skipped without it; CI sets `RAJDOLL_REQUIRE_PROXY_TESTS=1`. `tests/test_proxy_integration.py` starts a real `mitmdump` against PostgreSQL and local HTTP/HTTPS servers.

Tool tests need the real binaries. Build them with Go (the module proxy resolves the Go 1.26 toolchain automatically) and point `RAJDOLL_TOOL_BIN_DIR` at them:

```bash
GOBIN=$PWD/.tools go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
GOBIN=$PWD/.tools go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
GOBIN=$PWD/.tools go install github.com/projectdiscovery/katana/cmd/katana@v1.8.0
GOBIN=$PWD/.tools go install github.com/ffuf/ffuf/v2@v2.2.1
GOBIN=$PWD/.tools go install github.com/hahwul/dalfox/v2@v2.13.0
ln -s "$(command -v nmap)" .tools/nmap
ln -s "$(command -v sqlmap)" .tools/sqlmap          # sqlmap comes from tools/requirements.txt
git clone --depth 1 --branch v4.1 https://github.com/commixproject/commix.git .commix
printf '#!/bin/sh\nexec python %s/.commix/commix.py "$@"\n' "$PWD" > .tools/commix && chmod +x .tools/commix
python -m playwright install chromium   # the browser adapter (tools requirements)
RAJDOLL_TOOL_BIN_DIR=$PWD/.tools pytest tests/test_runner_integration.py tests/test_recon_e2e.py   # recon → findings
```

CI runs the same flow inside the real containers: `docker compose --profile test up`, then `tests/integration/smoke_tools.py` (runner and proxy) and `tests/integration/smoke_scan.py` (a real scan through the worker) are piped into the api container.

New migration: change the models, then `alembic revision --autogenerate -m "<what>"`, review the file, and keep `tests/test_migrations.py::test_models_match_migration` green.

## Web layer conventions

- Every route returns through `respond()` (or `error_response()`), so one route serves a full page, an HTMX fragment (`HX-Request`), or JSON (`Accept: application/json`). Templates extend `{% extends layout %}`.
- Routes commit explicitly with `db.commit()`; the `get_db` dependency rolls back anything left uncommitted.
- State-changing authenticated routes depend on `require_csrf` (header `X-CSRF-Token`, set on `<body hx-headers>`, or form field `csrf_token`).
- No inline `<script>`, `style=` or `<style>`: the CSP is `script-src 'self'; style-src 'self'`. Add CSS to `rajdoll/api/static/app.css` and behaviour to `rajdoll/api/static/app.js` (for example `data-copy="<selector>"` copy buttons).
- Target content (evidence) is always shown escaped; an HTML preview goes only into `<iframe sandbox="" srcdoc=...>`. In Markdown reports, put it through the `fenced` filter (`rajdoll/reporting/va.py`) and table text through `cell`. Front-end libraries are vendored with pinned versions in `rajdoll/api/static/vendor/` (see `LICENSES.txt` there).
- htmx swaps 2xx and 422 responses; return 422 with the re-rendered fragment for validation errors.
- UI text is Indonesian; validation messages go through the label maps in the services.
- Services raise `ServiceError` subclasses (`ValidationFailed`, `NotFound`, `Conflict`) from `rajdoll/services/errors.py`; the app maps them to the BSD 10.1 error format. Section fragments catch them and re-render with the message (htmx swaps 409 as well as 422).
- A section that can change the engagement status includes `_engagement_status.html` when `htmx` is true, so the header badge updates out of band.
- Read input with `read_fields()` (`rajdoll/api/forms.py`): it merges query, JSON, and form fields the same way for every client. A repeated form key (checkboxes) becomes a list; read it with `as_list()`.
- Engagement pages build their header context with `pages.engagement_context()` (tabs plus the active-scan banner).
- Live pages use the vendored htmx SSE extension: an element with `hx-ext="sse" sse-connect=... sse-close="done"` and children with `sse-swap="<event>"`. The stream renders fragments with `render_fragment()`, so fragment templates must not depend on `request`.
- Show times with `wib()` and numbers with `num()` (Indonesian separators).

## Workflow engine conventions

- Only the engine changes `scan.stage`; the scan service (`rajdoll/services/scans.py`) handles the assessor's actions (start, pause, resume, cancel, checkpoint) and sends `NOTIFY rajdoll_worker` so the worker reacts at once.
- A module implements `plan(ctx) -> list[TaskSpec]` per stage and `run(ctx) -> dict` per task (`rajdoll/modules/base.py`). It never chooses the stage order. Register it in `rajdoll/modules/registry.py`; `MODULE_LABELS` lists all twelve, and profiles may name modules that do not exist yet (the scan reports them as unavailable).
- In `run`, call tools only through `ctx.run_tool(tool, params, timeout_s=...)` (the runner, with scope and cancel), check `ctx.check_cancelled()` between long steps, and signal outcomes with `TransientTaskError` (one retry), `TaskBlocked`, or `TaskCancelled`. Any other exception fails only that task (PRD F-16). The returned summary must be JSON.
- Modules report results through the task context, never the database: `ctx.add_endpoints([EndpointSeen(...)])` (normalized and de-duplicated by `rajdoll/services/inventory.py`), `ctx.add_recon({...})` (merged into `scan.recon_summary`), `ctx.http(purpose)` (an httpx client through the egress proxy as `task.<id>.<purpose>`, for custom checks), and `ctx.session_headers(label)` (a target account's session). Pass the settings' exclusion patterns to crawlers and fuzzers so logout-like URLs are never requested.
- Authorization-style checks that compare accounts: get each account's headers with `ctx.session_headers(label)` (labels in `PlanContext.accounts`), send through `authz_checks.fetcher` (one session per request, cookies cleared, redirects never followed, evidence masked as `[sesi <label>]`), and put the sending account in `poc["account"]` and the other account in `validator_params`.
- Notes (`Exchange.note`, `Verdict.note`, task logs) are stored in plaintext: never put values taken from the target (credentials a template extracted, a cracked secret) in them; they belong in the encrypted request/response or PoC.
- Findings: a module calls `ctx.report_candidate(Candidate(...))` with the PoC spec (BSD 6.2; build it with `httpkit.Injection.poc()`) and `Exchange` evidence (`Injection.send()` records the raw request and response with session headers masked as `[sesi akun]`). The engine stores it through `rajdoll/services/findings.py` (fingerprint dedup, encryption, CVSS from the catalog vector). A new vulnerability type needs a `VulnType` entry in `rajdoll/data/vuln_types.py`.
- LLM: define a task in `rajdoll/llm/tasks.py` (a bounded pydantic output model, prompts in `rajdoll/llm/prompts/<kind>.system.j2` / `.user.j2`) and call it only through `ctx.llm(task, tasks.messages(...), ...)`, which returns an `LlmOutcome` (or None). Always handle a result that is not `ok` with a rule-based fallback; never let LLM output start a tool, choose the stage order, or confirm a finding. Put target content in prompts only through `rajdoll/llm/context.py` (`trim_response`, `data_block`) and add its `DATA_RULE` to the system prompt.
- Validators: one per vulnerability type, registered with `@validator("<type>")` in `rajdoll/validators/` (import the module in `_load()`). They re-send requests through `ctx.http("validator")` or a runner tool and return a `Verdict`; only deterministic evidence that repeats may confirm. Never confirm on reflection alone, and never from LLM output.
- Tests drive the engine with `tests/dummy_module.py` (`RAJDOLL_EXTRA_MODULES=tests.dummy_module` loads it into a real worker process); `tests/test_worker_restart.py` kills a real worker with SIGKILL and checks recovery.

## Tools container conventions

- Every request to a target goes through the egress proxy with credentials `task.<task_id>.<tool>` or `eng.<engagement_id>.<purpose>` and the `TOOLS_TOKEN` password; build proxy URLs with `rajdoll.services.session_check.proxy_url()`.
- The proxy runs as the `rajdoll_tools` database role: it may read `task`, `scan`, `scope_rule`, and `engagement(id, settings)`, and insert into `request_log` and `scan_event`. Never widen that.
- The tools image copies only `rajdoll/core/scope.py` from the main package; keep that module standard-library only.
- The tools container must never mount the `secrets` volume.
- Non-HTTP tools (nmap) set `audit_exec = True`: the runner writes one `tool_exec` row in `request_log` before running them and refuses to run if it cannot.
- Adding a tool: an `Adapter` subclass in `tools/runner/adapters/` with a strict pydantic `Params` model (`extra="forbid"`), `targets()` for the runner's scope pre-check, `command()` returning argv that passes `ctx.proxy_url` to the tool (or `environment()` when the tool only honours proxy variables, as commix does), and `parse()` covered by a fixture from a real run through the egress proxy in `tests/fixtures/`. Check that the tool really sends every request through the proxy (its `request_log` rows), including its first one. Pin the binary in `tools/Dockerfile`. Tools that test one parameter take a structured `RequestSpec` (`tools/runner/adapters/request.py`), never a command line.
- Official nuclei templates are vendored, unchanged, from one pinned release (`templates/nuclei/dast/README.md`); the directory under `dast/` names the RAJDOLL vulnerability type a match becomes.
- `testapp/` is deliberately vulnerable. List each weakness in `WEAKNESSES`, keep it under the compose `test` profile, and never publish its port.

## Conventions

- Python 3.12, type hints on public functions, `ruff` for lint and format, `pytest` for tests.
- Code, comments, and identifiers in English; UI text and reports in Indonesian.
- Every schema change goes through Alembic and updates `docs/v1/BSD.md` in the same PR.
- One branch and PR per phase (or several small PRs for large phases), targeting `main`.
