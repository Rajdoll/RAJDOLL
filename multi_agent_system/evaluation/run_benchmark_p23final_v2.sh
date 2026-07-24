#!/bin/bash
set -uo pipefail
API="http://localhost:8000"
EVAL_DIR="/mnt/d/MCP/RAJDOLL/multi_agent_system/evaluation"
LOG="$EVAL_DIR/benchmark_v15final_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$EVAL_DIR/runs"
log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }

run_scan() {
  local RUN_LABEL="$1"
  local OUT="$EVAL_DIR/runs/$RUN_LABEL"
  mkdir -p "$OUT"
  log "=== START: $RUN_LABEL ==="
  BODY='{"target":"http://juice-shop:3000","credentials":{"username":"admin@juice-sh.op","password":"admin123"}}'
  RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" -d "$BODY")
  JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id') or d.get('id',''))" 2>/dev/null)
  [ -z "$JOB_ID" ] && { log "ERROR: no job_id. Response: $RESP"; return 1; }
  log "$RUN_LABEL -> Job #$JOB_ID"
  echo "$JOB_ID" > "$OUT/job_id.txt"
  while true; do
    RAW=$(curl -s "$API/api/scans/$JOB_ID")
    STATUS=$(echo "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
    PROG=$(echo "$RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); a=d.get('agents',[]); print(sum(1 for x in a if x.get('status')=='completed'),'/',len(a))" 2>/dev/null || echo "?")
    log "$RUN_LABEL | status=$STATUS agents=$PROG"
    [[ "$STATUS" =~ ^(completed|failed|cancelled)$ ]] && break
    sleep 60
  done
  curl -s "$API/api/scans/$JOB_ID" > "$OUT/job_result.json"
  curl -s "$API/api/scans/$JOB_ID/findings?mode=raw" > "$OUT/findings.json"
  TOTAL=$(python3 -c "import json; print(len(json.load(open('$OUT/findings.json'))))" 2>/dev/null || echo "?")
  log "$RUN_LABEL done -- $TOTAL findings (Job #$JOB_ID)"
}

log "=== RAJDOLL Phase2/3 FINAL Re-scan -- 4 more runs (run1 already done as job 173), GT=80, post full evidence-quality Phase2/3 fix ==="
for i in $(seq 4 5); do
  run_scan "juiceshop_p23final_run${i}"
done
log "=== ALL 5 FINAL SCANS DONE ==="

cd /mnt/d/MCP/RAJDOLL
python3 "$EVAL_DIR/compute_metrics.py" --target juiceshop \
  --runs juiceshop_p23final_run1 juiceshop_p23final_run2 juiceshop_p23final_run3 \
         juiceshop_p23final_run4 juiceshop_p23final_run5 2>&1 | tee -a "$LOG"
log "Script done. Log: $LOG"
