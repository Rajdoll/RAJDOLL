#!/bin/bash
# continue_benchmarks.sh — Resume benchmark suite from current state.
# dvwa_run1: already done. dvwa_run2 (job 14): running — collect it, then run the rest.

API="http://localhost:8000"
RUNS_DIR="$(cd "$(dirname "$0")/runs" && pwd)"
LOG="$(dirname "$0")/benchmark_run.log"

collect_job() {
  local JOB_ID="$1"
  local LABEL="$2"
  local OUTPUT_DIR="$RUNS_DIR/$LABEL"
  mkdir -p "$OUTPUT_DIR"

  echo "[$(date '+%H:%M:%S')] Collecting job $JOB_ID → $LABEL" | tee -a "$LOG"

  # Poll to completion
  while true; do
    STATUS=$(curl -s "$API/api/scans/$JOB_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
    echo "  $(date '+%H:%M:%S') job=$JOB_ID status=$STATUS" | tee -a "$LOG"
    [[ "$STATUS" == "completed" || "$STATUS" == "failed" || "$STATUS" == "cancelled" ]] && break
    sleep 60
  done

  curl -s "$API/api/scans/$JOB_ID" | tee "$OUTPUT_DIR/job_result.json" > /dev/null
  curl -s "$API/api/scans/$JOB_ID/findings" | tee "$OUTPUT_DIR/findings.json" | python3 -c "
import sys,json; f=json.load(sys.stdin)
print(f'  findings={len(f)}')
" 2>/dev/null | tee -a "$LOG"
  echo "[$(date '+%H:%M:%S')] $LABEL done (status=$STATUS)" | tee -a "$LOG"
}

start_scan() {
  local TARGET="$1"
  local LABEL="$2"
  local WHITELIST="${3:-}"
  local CREDS="${4:-}"
  local OUTPUT_DIR="$RUNS_DIR/$LABEL"
  mkdir -p "$OUTPUT_DIR"

  if [ -n "$WHITELIST" ] && [ -n "$CREDS" ]; then
    BODY="{\"target\":\"$TARGET\",\"whitelist_domain\":\"$WHITELIST\",\"credentials\":$CREDS}"
  elif [ -n "$WHITELIST" ]; then
    BODY="{\"target\":\"$TARGET\",\"whitelist_domain\":\"$WHITELIST\"}"
  elif [ -n "$CREDS" ]; then
    BODY="{\"target\":\"$TARGET\",\"credentials\":$CREDS}"
  else
    BODY="{\"target\":\"$TARGET\"}"
  fi

  echo "[$(date '+%H:%M:%S')] Starting $LABEL: $TARGET" | tee -a "$LOG"
  RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" -d "$BODY")
  echo "$RESP" | tee "$OUTPUT_DIR/scan_start.json" > /dev/null
  JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('job_id',''))" 2>/dev/null)
  if [ -z "$JOB_ID" ]; then
    echo "ERROR: no job_id for $LABEL" | tee -a "$LOG"
    return 1
  fi
  echo "  job_id=$JOB_ID" | tee -a "$LOG"
  collect_job "$JOB_ID" "$LABEL"
}

echo "=== Benchmark continuation started: $(date) ===" | tee -a "$LOG"

# Step 1: collect running dvwa_run2 (job 14)
collect_job 14 "dvwa_run2"

# Step 2: dvwa_run3
start_scan "http://dvwa:80" "dvwa_run3" "dvwa"

# Step 3: bWAPP runs
start_scan "http://bwapp:80" "bwapp_run1" "bwapp"
start_scan "http://bwapp:80" "bwapp_run2" "bwapp"
start_scan "http://bwapp:80" "bwapp_run3" "bwapp"

# Step 4: Juice Shop runs 3/4/5
JS_CREDS='{"username":"admin@juice-sh.op","password":"admin123"}'
start_scan "http://juice-shop:3000" "juiceshop_run3" "" "$JS_CREDS"
start_scan "http://juice-shop:3000" "juiceshop_run4" "" "$JS_CREDS"
start_scan "http://juice-shop:3000" "juiceshop_run5" "" "$JS_CREDS"

echo "=== All benchmark scans complete: $(date) ===" | tee -a "$LOG"
echo "Next: python3 multi_agent_system/evaluation/compute_metrics.py --target dvwa --runs dvwa_run1 dvwa_run2 dvwa_run3" | tee -a "$LOG"
