# External Target Readiness — Pre-Queue HITL & Safe Mode Design

**Date:** 2026-04-14
**Author:** Martua Raja Doli Pangaribuan
**Status:** Draft — pending implementation plan

---

## 1. Problem Statement

RAJDOLL saat ini berhasil divalidasi di OWASP Juice Shop (Job #2 & #8) dengan Precision 100% / Recall 98.2% / F1 99.1%. Namun sistem belum siap dibawa ke dua arah berikut tanpa intervensi manual:

1. **VDP (Vulnerability Disclosure Program) / Bug Bounty** — target web publik dengan scope & authorization eksplisit.
2. **CTF / Capture the Flag** — target lab publik (mis. HackTheBox, TryHackMe, CTF challenge) dengan izin implicit.

Dua arah itu sama-sama merupakan **external target**, berbeda dengan lab internal (Juice Shop, DVWA, localhost). Perbedaan threat model:

| Aspek | Internal lab | External (VDP/CTF) |
|---|---|---|
| Izin | Implicit (local) | Wajib tertulis / program rules |
| Rate limit | Tidak perlu | Wajib (produksi) |
| Brute-force tools | OK | Harus di-disable (scope violation risk) |
| Audit trail | Opsional | Wajib (contact, reference, timestamps) |
| User-Agent | Default | Branded + contact info |

Existing `SCAN_PROFILE_DEFAULTS` (`lab`/`vdp`) sudah generic (bukan hardcoding) tetapi:
- Tidak ada **target auto-classification** — user harus pilih profile manual.
- Tidak ada **pre-queue HITL gate** — scan langsung di-enqueue meski target external.
- Profile `vdp` belum punya **hardening fields** (rate limit, user-agent, disable brute-force, dll).
- Tidak ada **audit field** (authorization reference, contact email) yang tersimpan per-job.

---

## 2. Goal & Non-Goals

**Goals:**
- Sistem dapat diterapkan ke target external (VDP / CTF) tanpa perubahan kode per-target.
- User diminta konfirmasi eksplisit sebelum scan external di-enqueue (HITL di target-input time).
- Profile `vdp` menerapkan hardening otomatis: rate limit global, disable brute-force, branded user-agent, audit trail.
- Flow existing untuk internal lab (Juice Shop, localhost) tidak berubah — zero regression.

**Non-Goals:**
- Tidak menambah tool baru (recall coverage existing dipertahankan).
- Tidak mengganti Director Mode existing (mid-scan HITL tetap jalan sejajar).
- Tidak membuat profile ketiga — cukup extend `vdp` dengan hardening fields.
- Tidak integrasi dengan VDP/bounty platform API (manual authorization reference untuk v1).

---

## 3. High-Level Flow

```
User input target
     │
     ▼
[Target Classifier] (hostname pattern only, no network probe)
     │
     ├── internal  → auto profile=lab → Job created → Celery enqueue (existing flow)
     │
     └── external  → respond 202 + pending_confirmation_id
                     │
                     ▼
              [Frontend modal]
                 - Checkbox: authorization tertulis
                 - Contact email, auth reference, scope domains
                     │
                     ▼
              POST /api/hitl/pre-queue/{id}/confirm
                     │
                     ├── valid   → Job created with profile=vdp + audit fields → enqueue
                     └── timeout → Job cancelled
```

Setelah enqueue, orchestrator existing jalan seperti biasa. Perbedaan cuma di **middleware** `ExternalSafeMode` yang aktif saat `job.profile == "vdp"`:
- `base_agent._before_tool_execution()` memanggil middleware
- Middleware enforce 4 guardrails: rate limit, disable brute-force, branded UA, scope check
- Jika internal (`lab`), middleware no-op → tidak ada overhead.

---

## 4. Components

### 4.1 Target Classifier — `multi_agent_system/core/security_guards.py`

Fungsi baru `classify_target(url: str) -> dict`:

```python
def classify_target(url: str) -> dict:
    """
    Classify target as internal or external based on hostname pattern.
    No network probe — static analysis only.
    Returns: {"classification": "internal"|"external", "reason": str, "suggested_profile": str}
    """
```

Auto-detection rules (prioritas top-down):

| Pattern | Classification | Suggested profile |
|---|---|---|
| `localhost`, `127.0.0.1`, `::1` | internal | lab |
| RFC1918 IP (10/8, 172.16/12, 192.168/16) | internal | lab |
| Docker service name (hostname tanpa dot) | internal | lab |
| Hostname in `auto_approve_domains` | internal | lab |
| Everything else | external | vdp |

### 4.2 Pre-Queue HITL Endpoints — `api/routes/scans.py` + `api/routes/hitl.py`

Modifikasi `POST /api/scans`:
1. Panggil `classify_target()` sebelum enqueue.
2. Jika `internal` → flow existing.
3. Jika `external` dan body belum punya `confirmation_token` → buat `PreQueueConfirmation` record dengan `expires_at = now + 10min`, return 202 dengan `pending_confirmation_id`.
4. Jika `external` dan body punya `confirmation_token` valid → ambil audit fields dari record, enqueue job dengan `profile=vdp`.

Endpoint baru `POST /api/hitl/pre-queue/{id}/confirm` — menerima form:
```json
{
  "authorization_checkbox": true,
  "contact_email": "pentest@example.com",
  "authorization_reference": "VDP-BSSN-2026-042",
  "scope_domains": ["target.bssn.go.id"]
}
```
Validasi: checkbox harus `true`, email format valid, reference non-empty. Return `confirmation_token` (reuse ID) untuk dipakai di POST `/api/scans` berikutnya.

Endpoint lightweight `POST /api/targets/classify` — untuk frontend real-time badge. Return hasil `classify_target()` tanpa side effect.

### 4.3 Profile Hardening Fields — `multi_agent_system/core/config.py`

Extend `SCAN_PROFILE_DEFAULTS["vdp"]` dengan fields:
```python
SCAN_PROFILE_DEFAULTS: dict[str, dict] = {
    "lab": {
        "hitl_mode": "off",
        "adaptive_mode": "aggressive",
        # hardening fields absent → middleware no-op
    },
    "vdp": {
        "hitl_mode": "agent",
        "adaptive_mode": "balanced",
        "user_agent_branded": True,
        "global_rps_limit": 2,
        "disable_brute_force": True,
        "enforce_robots_txt": True,
        "max_scan_duration_seconds": 14400,
        "max_concurrent_scans": 1,
        "disclosure_report_block": True,
    },
}
```

### 4.4 ExternalSafeMode Middleware — `multi_agent_system/utils/external_safe_mode.py`

Class baru:
```python
class ExternalSafeMode:
    def __init__(self, job: Job):
        self.profile_config = SCAN_PROFILE_DEFAULTS.get(job.profile, {})
        self.semaphore = asyncio.Semaphore(
            self.profile_config.get("global_rps_limit", 1000)
        )
        self.brute_force_tools = frozenset({
            "run_sqlmap_full",
            "run_nikto_tuning_all",
            "test_user_enumeration_brute",
            "test_password_brute",
            "enumerate_directories_brute",
            "test_jwt_brute",
        })

    async def before_tool(self, tool_name: str, args: dict) -> dict | None:
        """
        Returns None to allow, or {"status": "skipped", "reason": ...} to block.
        Called from base_agent._before_tool_execution().
        """
```

Perilaku:
- Profile `lab` → no-op (return None selalu).
- Profile `vdp`:
  - Brute-force tool → return skipped + log info finding
  - Branded UA → inject `User-Agent: RAJDOLL-Scanner/1.0 (+contact@...)` di args
  - Rate limiter via `async with self.semaphore:` sekitar call (di base_agent)
  - Scope check → tool args `url` harus punya hostname match dengan `job.scope_domains`

### 4.5 Audit Fields — `multi_agent_system/models/models.py`

Tambah ke `Job` model:
- `profile: str` (existing, mungkin perlu verify)
- `authorization_reference: str | None`
- `contact_email: str | None`
- `scope_domains: list[str]` (JSON column)
- `classification: str` ("internal"|"external")
- `confirmation_id: int | None` (FK ke PreQueueConfirmation)

Model baru `PreQueueConfirmation`:
- id, target_url, created_at, expires_at, status (pending/confirmed/timeout/cancelled)
- audit fields (email, reference, scope, checkbox_accepted)

### 4.6 Frontend Components — `frontend/`

- `index.html` — tambah `<span id="target-badge">` di samping target input, debounced classify call.
- `components/external_confirm_modal.js` — modal dengan form audit (checkbox, email, reference, scope).
- `components/scan_detail.js` — panel "Safe Mode Active" saat `job.profile == "vdp"`, tab "Policy Skipped" untuk info-level skip findings.

---

## 5. Data Flow Detail

```
┌─────────────┐   POST /api/targets/classify      ┌──────────────────┐
│  Frontend   │─────────────────────────────────▶│  classify_target │
│             │◀──────────────── {internal|ext}  └──────────────────┘
└─────────────┘
       │
       │  user clicks "Start Scan"
       ▼
┌─────────────┐   POST /api/scans {target}
│  Frontend   │───────────────────────────────▶┌──────────────────┐
└─────────────┘                                 │  scans.py        │
       ▲                                        │  classify+branch │
       │ 202 + pending_confirmation_id          └──────────────────┘
       │         (external)                              │
       │                                                 │ internal
       ▼                                                 ▼
┌─────────────┐                                 ┌──────────────────┐
│  Modal UI   │                                 │  Job(profile=lab)│
│  form       │                                 │  → Celery enqueue│
└─────────────┘                                 └──────────────────┘
       │
       │ POST /api/hitl/pre-queue/{id}/confirm
       ▼
┌─────────────────────────────────┐
│  hitl.py pre_queue confirm      │
│  validate → Job(profile=vdp,    │
│  audit_fields) → Celery enqueue │
└─────────────────────────────────┘
                │
                ▼
       orchestrator.run() (existing, unchanged)
                │
                ▼
       agent.execute() → base_agent._before_tool_execution():
                │
                ├─ ExternalSafeMode.before_tool()
                │    ├─ profile=lab → no-op
                │    └─ profile=vdp → enforce 4 guardrails
                │
                └─ existing HITLManager.approve() (Director Mode)
```

**Key behaviors:**
- Internal target = middleware no-op = zero overhead.
- External target = 4 guardrails enforced at tool boundary.
- Global rate limiter per-job via `asyncio.Semaphore` (bukan per-agent).
- Brute-force skip logged as info-level finding untuk transparency (recall gap visible di report).
- Scope check via hostname match; tool args dengan hostname di luar `scope_domains` → skipped + logged.

---

## 6. Error Handling

**Rate limit trigger (hit `global_rps_limit`):**
- Semaphore blocks tool call → log info finding sekali per agent: "Rate limiter throttled X calls"
- No backoff retry di middleware level — per-tool timeout handle
- Tool timeout karena queued lama → agent continues, tercatat di JobAgent

**Brute-force tool blocked (`disable_brute_force=True`):**
- Middleware returns `{"status": "skipped", "reason": "brute_force_disabled_on_external"}` tanpa memanggil MCP
- Dicatat sebagai info-finding biar Director/user tahu recall gap

**HITL confirmation timeout (10 min no response):**
- PreQueueConfirmation status → `timeout`
- Tidak auto-proceed (safety default)
- Frontend show retry button → POST ulang ke `/api/scans`

**Target unreachable saat classification:**
- Classifier hostname-only → tidak ada network error di stage ini
- Unreachable muncul di ReconnaissanceAgent, handled existing

**Missing security.txt saat `disclosure_report_block=True`:**
- Reuse existing `security_txt_checker` di SecurityGuardRails
- Warning di pre-queue HITL modal, tidak hard-block (user dapat lanjut jika reference valid)

---

## 7. Testing Strategy

**Unit — `tests/test_target_classifier.py`** (no Docker):
- `localhost:3000` → internal; RFC1918 → internal; Docker name → internal
- `target.bssn.go.id` → external; public IPv6 → external
- Edge: `127.0.0.1.nip.io` → external (hostname ≠ 127.0.0.1)

**Unit — `tests/test_external_safe_mode.py`** (no Docker):
- profile=lab → no-op untuk semua tool
- profile=vdp + brute-force tool → `skipped`
- Semaphore: 10 concurrent calls dengan rps=2 → max 2 concurrent
- `user_agent_branded=True` → headers dimodifikasi

**Integration — `tests/test_prequeue_hitl.py`** (live DB):
- Internal target → langsung queued
- External target tanpa confirmation → 202 + pending_confirmation_id
- Confirm dengan checkbox=false → 400
- Confirm valid → job transitions to queued
- Simulate 10-min timeout → job cancelled

**E2E — `tests/test_external_scan_e2e.py`** (live Docker, marked slow):
- Dummy external target (non-Docker nginx) + scan dengan vdp profile
- Assert: brute-force logged skipped, report generated

**Regression:**
- Existing `test_vdp_generalization.py` tetap pass (classifier return internal untuk juice-shop:3000 → pre-HITL tidak kepicu).
- Juice Shop regression scan (Job baseline) harus hasilkan ≥98% recall.

---

## 8. Frontend UI Integration

**1. Target input form — `frontend/index.html` + `main.js`**
- Debounce 500ms → POST `/api/targets/classify`
- Badge hijau "Internal • lab" atau kuning "External • vdp • authorization required"

**2. Confirmation modal — `frontend/components/external_confirm_modal.js`**
- Checkbox mandatory: "Saya memiliki otorisasi tertulis..."
- Email, authorization reference, scope domains
- Submit → POST `/api/hitl/pre-queue/{id}/confirm`

**3. Scan detail — `frontend/components/scan_detail.js`**
- Badge classification di header
- Panel "Safe Mode Active" (rate limit, disabled tools, auth ref, contact)
- Tab "Policy Skipped" untuk info-level skip findings

No new WebSocket messages — existing channel cukup; pre-queue HITL pakai plain REST.

---

## 9. Migration & Rollout

**DB migration:**
- ALTER TABLE jobs: add `authorization_reference`, `contact_email`, `scope_domains` (JSONB), `classification`, `confirmation_id`
- CREATE TABLE prequeue_confirmations
- SQL di docstring `models.py` (ikuti pattern existing HITL migration)

**Backwards compatibility:**
- Existing Juice Shop scan flow (POST /api/scans dengan target=juice-shop:3000) → unchanged (classifier → internal → flow lama).
- Existing `hitl_mode` per-request override tetap jalan di atas classifier output.

**Rollout:**
1. Deploy DB migration
2. Deploy backend (classifier + endpoints + middleware)
3. Deploy frontend
4. Validasi: Juice Shop baseline scan (target internal) → lulus tanpa confirmation modal
5. Validasi: dummy external target → HITL modal muncul, confirm → scan jalan dengan rate limit

---

## 10. Out of Scope / Future Work

- Integrasi VDP platform API (HackerOne, Bugcrowd) untuk auto-validate authorization reference.
- Machine-learning target classifier (v1 cukup hostname pattern).
- Per-endpoint rate limiting (v1 global per-job).
- Scope enforcement berdasarkan robots.txt parse (v1 hanya hostname match).

---

## 11. Key Files Touched

| File | Change |
|---|---|
| `multi_agent_system/core/security_guards.py` | Add `classify_target()` |
| `multi_agent_system/core/config.py` | Extend `SCAN_PROFILE_DEFAULTS["vdp"]` with hardening fields |
| `multi_agent_system/utils/external_safe_mode.py` | NEW middleware class |
| `multi_agent_system/agents/base_agent.py` | Hook middleware in `_before_tool_execution()` |
| `multi_agent_system/models/models.py` | Add audit fields + `PreQueueConfirmation` model |
| `api/routes/scans.py` | Classify + branch; support `confirmation_token` |
| `api/routes/hitl.py` | `POST /api/hitl/pre-queue/{id}/confirm` |
| `api/routes/targets.py` | NEW `POST /api/targets/classify` |
| `frontend/index.html` | Target badge |
| `frontend/main.js` | Debounced classify call |
| `frontend/components/external_confirm_modal.js` | NEW |
| `frontend/components/scan_detail.js` | Safe Mode panel + Policy Skipped tab |
| `multi_agent_system/tests/test_target_classifier.py` | NEW |
| `multi_agent_system/tests/test_external_safe_mode.py` | NEW |
| `multi_agent_system/tests/test_prequeue_hitl.py` | NEW |
| `multi_agent_system/tests/test_external_scan_e2e.py` | NEW (slow-marked) |
