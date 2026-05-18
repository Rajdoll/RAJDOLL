#!/usr/bin/env bash
# run_benchmarks.sh — Run 3x Juice Shop + 3x WebGoat + 3x PyGoat benchmark scans
# Usage: ./multi_agent_system/evaluation/run_benchmarks.sh
# Each scan takes ~2-3h with Qwen 3-4B. Total ~18-27h. Run overnight.

set -euo pipefail

API="http://localhost:8000"
EVAL_DIR="multi_agent_system/evaluation"
DB_CONTAINER="rajdoll-db-1"
LOG_FILE="$EVAL_DIR/benchmark_run_$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

wait_for_job() {
    local job_id=$1
    local label=$2
    log "Waiting for job $job_id ($label)..."
    while true; do
        STATUS=$(curl -s "$API/api/scans/$job_id/status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
        log "  Job $job_id status: $STATUS"
        if [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]]; then
            break
        fi
        sleep 300
    done
    log "Job $job_id finished: $STATUS"
    echo "$STATUS"
}

export_and_compute() {
    local job_id=$1
    local label=$2
    local target=$3

    mkdir -p "$EVAL_DIR/runs/$label"

    docker exec "$DB_CONTAINER" psql -U rajdoll -d rajdoll -c \
        "COPY (SELECT wstg_id as category, title, severity::text, COALESCE(details,'') as description FROM findings WHERE job_id=${job_id}) TO STDOUT WITH CSV HEADER;" \
        | python3 -c "
import sys, csv, json
reader = csv.DictReader(sys.stdin)
data = [{'category': r['category'] or '', 'title': r['title'], 'severity': r['severity'], 'description': r['description']} for r in reader]
json.dump(data, open('${EVAL_DIR}/runs/${label}/findings.json','w'), indent=2)
print(f'Exported {len(data)} findings to ${label}')
"
    python3 "$EVAL_DIR/compute_metrics.py" --target "$target" --runs "$label"
}

trigger_scan() {
    local target_url=$1
    local email=$2
    local password=$3
    local label=$4

    log "Triggering scan: $label -> $target_url"

    PAYLOAD="{\"target\":\"$target_url\",\"scan_profile\":\"lab\",\"hitl_mode\":\"off\""
    if [[ -n "$email" ]]; then
        PAYLOAD="$PAYLOAD,\"email\":\"$email\",\"password\":\"$password\""
    fi
    PAYLOAD="$PAYLOAD}"

    JOB_ID=$(curl -s -X POST "$API/api/scans" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id','ERROR'))" 2>/dev/null)

    if [[ "$JOB_ID" == "ERROR" || -z "$JOB_ID" ]]; then
        log "ERROR: Failed to trigger scan for $label"
        return 1
    fi

    log "Scan triggered: job_id=$JOB_ID label=$label"
    echo "$JOB_ID"
}

# ── Prerequisites check ───────────────────────────────────────────────
log "=== RAJDOLL Benchmark Suite ==="
log "Checking services..."

curl -sf "$API/api/health" > /dev/null 2>&1 || { log "ERROR: API not reachable at $API"; exit 1; }
curl -sf "http://localhost:3000/" > /dev/null 2>&1 || { log "ERROR: Juice Shop not reachable at :3000"; exit 1; }
log "API and Juice Shop OK"

WEBGOAT_OK=false
curl -sf "http://localhost:8081/WebGoat/login" > /dev/null 2>&1 && WEBGOAT_OK=true
$WEBGOAT_OK && log "WebGoat OK" || log "WARNING: WebGoat not reachable — WebGoat runs will be skipped"

PYGOAT_OK=false
curl -sf "http://localhost:8090/" > /dev/null 2>&1 && PYGOAT_OK=true
$PYGOAT_OK && log "PyGoat OK" || log "WARNING: PyGoat not reachable — PyGoat runs will be skipped"

# ── Juice Shop — 3 runs ───────────────────────────────────────────────
log "=== Juice Shop Benchmarks (3 runs) ==="
JS_RUNS=()

for i in 1 2 3; do
    JOB=$(trigger_scan "http://juice-shop:3000" "admin@juice-sh.op" "admin123" "juiceshop_bench_run$i")
    STATUS=$(wait_for_job "$JOB" "juiceshop_bench_run$i")
    if [[ "$STATUS" == "completed" ]]; then
        export_and_compute "$JOB" "juiceshop_bench_run$i" "juiceshop"
        JS_RUNS+=("juiceshop_bench_run$i")
    else
        log "WARNING: juiceshop_bench_run$i failed (job $JOB)"
    fi
done

if [[ ${#JS_RUNS[@]} -gt 0 ]]; then
    log "Computing Juice Shop aggregate (${#JS_RUNS[@]} runs)..."
    python3 "$EVAL_DIR/compute_metrics.py" --target juiceshop --runs "${JS_RUNS[@]}"
fi

# ── WebGoat — 3 runs ──────────────────────────────────────────────────
if $WEBGOAT_OK; then
    log "=== WebGoat Benchmarks (3 runs) ==="
    # Register account (idempotent — ok if already exists)
    curl -s -X POST "http://localhost:8081/WebGoat/register.mvc" \
        -d "username=rajdoll&password=Test1234!&matchingPassword=Test1234!&agree=agree" \
        -c /tmp/wg_cookies.txt > /dev/null 2>&1 || true

    WG_RUNS=()
    for i in 1 2 3; do
        JOB=$(trigger_scan "http://webgoat:8080/WebGoat" "rajdoll" "Test1234!" "webgoat_bench_run$i")
        STATUS=$(wait_for_job "$JOB" "webgoat_bench_run$i")
        if [[ "$STATUS" == "completed" ]]; then
            export_and_compute "$JOB" "webgoat_bench_run$i" "webgoat"
            WG_RUNS+=("webgoat_bench_run$i")
        else
            log "WARNING: webgoat_bench_run$i failed (job $JOB)"
        fi
    done

    if [[ ${#WG_RUNS[@]} -gt 0 ]]; then
        log "Computing WebGoat aggregate (${#WG_RUNS[@]} runs)..."
        python3 "$EVAL_DIR/compute_metrics.py" --target webgoat --runs "${WG_RUNS[@]}"
    fi
else
    log "Skipping WebGoat — not reachable"
fi

# ── PyGoat — 3 runs ───────────────────────────────────────────────────
if $PYGOAT_OK; then
    log "=== PyGoat Benchmarks (3 runs) ==="
    PG_RUNS=()
    for i in 1 2 3; do
        JOB=$(trigger_scan "http://pygoat:8000" "" "" "pygoat_bench_run$i")
        STATUS=$(wait_for_job "$JOB" "pygoat_bench_run$i")
        if [[ "$STATUS" == "completed" ]]; then
            export_and_compute "$JOB" "pygoat_bench_run$i" "pygoat"
            PG_RUNS+=("pygoat_bench_run$i")
        else
            log "WARNING: pygoat_bench_run$i failed (job $JOB)"
        fi
    done

    if [[ ${#PG_RUNS[@]} -gt 0 ]]; then
        log "Computing PyGoat aggregate (${#PG_RUNS[@]} runs)..."
        python3 "$EVAL_DIR/compute_metrics.py" --target pygoat --runs "${PG_RUNS[@]}"
    fi
else
    log "Skipping PyGoat — not reachable"
fi

# ── Final commit ──────────────────────────────────────────────────────
log "=== Committing results ==="
git add "$EVAL_DIR/runs/" \
        "$EVAL_DIR/evaluation_juiceshop_summary.json" \
        "$EVAL_DIR/evaluation_webgoat_summary.json" \
        "$EVAL_DIR/evaluation_pygoat_summary.json" 2>/dev/null || true

git diff --cached --quiet || git commit -m "eval: benchmark results — Juice Shop x3, WebGoat x3, PyGoat x3 (Qwen 3-4B)"

log "=== Done. Results in $EVAL_DIR/evaluation_*_summary.json ==="
