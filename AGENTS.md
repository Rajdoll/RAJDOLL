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

**F0 — preparation.** Skeleton only: `/health` on `api` and `tools`, a heartbeat-only `worker`, and `db`. See `docs/v1/IPD.md` section 4 for what each later phase adds.

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

## Conventions

- Python 3.12, type hints on public functions, `ruff` for lint and format, `pytest` for tests.
- Code, comments, and identifiers in English; UI text and reports in Indonesian.
- Every schema change goes through Alembic and updates `docs/v1/BSD.md` in the same PR.
- One branch and PR per phase (or several small PRs for large phases), targeting `main`.
