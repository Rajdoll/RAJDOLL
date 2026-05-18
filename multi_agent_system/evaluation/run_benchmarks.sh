#!/usr/bin/env bash
# run_benchmarks.sh — Run 7x Juice Shop benchmark scans (Qwen 3-4B)
# Usage: ./multi_agent_system/evaluation/run_benchmarks.sh
# Each scan ~2-3h. Total ~14-21h. Run overnight.

set -euo pipefail

API="http://localhost:8000"
EVAL_DIR="multi_agent_system/evaluation"
DB_CONTAINER="rajdoll-db-1"
LOG_FILE="$EVAL_DIR/benchmark_run_$(date +%Y%m%d_%H%M%S).log"
N_RUNS=${1:-1}  # default 1 run; override: ./run_benchmarks.sh 3

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

wait_for_job() {
    local job_id=$1
    local label=$2
    log "Waiting for job $job_id ($label)..."
    while true; do
        STATUS=$(curl -s "$API/api/scans/$job_id/status" \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
        log "  Job $job_id: $STATUS"
        [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
        sleep 300
    done
    log "Job $job_id finished: $STATUS"
    echo "$STATUS"
}

export_and_compute() {
    local job_id=$1
    local label=$2
    mkdir -p "$EVAL_DIR/runs/$label"
    docker exec "$DB_CONTAINER" psql -U rajdoll -d rajdoll -c \
        "COPY (SELECT wstg_id as category, title, severity::text, COALESCE(details,'') as description FROM findings WHERE job_id=${job_id}) TO STDOUT WITH CSV HEADER;" \
        | python3 -c "
import sys, csv, json
reader = csv.DictReader(sys.stdin)
data = [{'category': r['category'] or '', 'title': r['title'], 'severity': r['severity'], 'description': r['description']} for r in reader]
json.dump(data, open('${EVAL_DIR}/runs/${label}/findings.json','w'), indent=2)
print(f'Exported {len(data)} findings -> ${label}')
"
    python3 "$EVAL_DIR/compute_metrics.py" --target juiceshop --runs "$label"
}

# ── Prerequisites ─────────────────────────────────────────────────────
log "=== RAJDOLL Benchmark — Juice Shop x${N_RUNS} run(s) (Qwen 3-4B) ==="
curl -sf "$API/api/health" > /dev/null 2>&1 || { log "ERROR: API not reachable at $API"; exit 1; }
curl -sf "http://localhost:3000/" > /dev/null 2>&1 || { log "ERROR: Juice Shop not reachable"; exit 1; }
log "Prerequisites OK"

# ── 7 sequential runs ─────────────────────────────────────────────────
SUCCESSFUL_RUNS=()

for i in $(seq 1 $N_RUNS); do
    log "--- Run $i / $N_RUNS ---"

    JOB_ID=$(curl -s -X POST "$API/api/scans" \
        -H "Content-Type: application/json" \
        -d '{"target":"http://juice-shop:3000","scan_profile":"lab","hitl_mode":"off","email":"admin@juice-sh.op","password":"admin123"}' \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('job_id','ERROR'))" 2>/dev/null)

    if [[ "$JOB_ID" == "ERROR" || -z "$JOB_ID" ]]; then
        log "ERROR: Failed to trigger run $i — skipping"
        continue
    fi

    log "Job $JOB_ID started"
    STATUS=$(wait_for_job "$JOB_ID" "juiceshop_run${i}")

    if [[ "$STATUS" == "completed" ]]; then
        LABEL="juiceshop_bench_run${i}"
        export_and_compute "$JOB_ID" "$LABEL"
        SUCCESSFUL_RUNS+=("$LABEL")
        log "Run $i complete. Successful so far: ${#SUCCESSFUL_RUNS[@]}"
    else
        log "WARNING: Run $i failed (job $JOB_ID) — continuing to next run"
    fi
done

# ── Aggregate metrics ─────────────────────────────────────────────────
if [[ ${#SUCCESSFUL_RUNS[@]} -ge 3 ]]; then
    log "=== Aggregate metrics (${#SUCCESSFUL_RUNS[@]} runs) ==="
    python3 "$EVAL_DIR/compute_metrics.py" --target juiceshop --runs "${SUCCESSFUL_RUNS[@]}"
else
    log "WARNING: Only ${#SUCCESSFUL_RUNS[@]} successful runs — aggregate may not be meaningful"
fi

# ── Commit results ────────────────────────────────────────────────────
git add "$EVAL_DIR/runs/" "$EVAL_DIR/evaluation_juiceshop_summary.json" 2>/dev/null || true
git diff --cached --quiet || git commit -m "eval: Juice Shop benchmark x${#SUCCESSFUL_RUNS[@]} runs (Qwen 3-4B)"

log "=== Done. Results: $EVAL_DIR/evaluation_juiceshop_summary.json ==="
log "Log: $LOG_FILE"
