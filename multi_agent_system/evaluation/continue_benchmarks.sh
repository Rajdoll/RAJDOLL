#!/bin/bash
# continue_benchmarks.sh — Run all 9 benchmark scans with credentials.
# DVWA×3 (admin/password), bWAPP×3 (bee/bug), Juice Shop×3 (admin@juice-sh.op/admin123)
# Supersedes previous run that lacked auth — all runs started fresh.

API="http://localhost:8000"
RUNS_DIR="$(cd "$(dirname "$0")/runs" && pwd)"
LOG="$(dirname "$0")/benchmark_run.log"

DVWA_CREDS='{"username":"admin","password":"password"}'
BWAPP_CREDS='{"username":"bee","password":"bug"}'
JS_CREDS='{"username":"admin@juice-sh.op","password":"admin123"}'

collect_job() {
  local JOB_ID="$1"
  local LABEL="$2"
  local OUTPUT_DIR="$RUNS_DIR/$LABEL"
  mkdir -p "$OUTPUT_DIR"

  echo "[$(date '+%H:%M:%S')] Polling job $JOB_ID ($LABEL)..." | tee -a "$LOG"
  while true; do
    STATUS=$(curl -s "$API/api/scans/$JOB_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
    echo "  $(date '+%H:%M:%S') job=$JOB_ID status=$STATUS" >> "$LOG"
    [[ "$STATUS" == "completed" || "$STATUS" == "failed" || "$STATUS" == "cancelled" ]] && break
    sleep 60
  done

  curl -s "$API/api/scans/$JOB_ID" > "$OUTPUT_DIR/job_result.json"
  FINDINGS=$(curl -s "$API/api/scans/$JOB_ID/findings")
  echo "$FINDINGS" > "$OUTPUT_DIR/findings.json"
  COUNT=$(echo "$FINDINGS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
  echo "[$(date '+%H:%M:%S')] $LABEL done: status=$STATUS findings=$COUNT" | tee -a "$LOG"
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

  echo "[$(date '+%H:%M:%S')] Starting $LABEL → $TARGET" | tee -a "$LOG"
  RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" -d "$BODY")
  echo "$RESP" > "$OUTPUT_DIR/scan_start.json"
  JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('job_id',''))" 2>/dev/null)
  if [ -z "$JOB_ID" ]; then
    echo "ERROR: no job_id for $LABEL — response: $RESP" | tee -a "$LOG"
    return 1
  fi
  echo "  job_id=$JOB_ID" | tee -a "$LOG"
  collect_job "$JOB_ID" "$LABEL"
}

echo "" >> "$LOG"
echo "=== Benchmark restart (with credentials): $(date) ===" | tee -a "$LOG"

# DVWA ×3
for N in 1 2 3; do
  start_scan "http://dvwa:80" "dvwa_run${N}" "dvwa" "$DVWA_CREDS"
done

# bWAPP ×3
for N in 1 2 3; do
  start_scan "http://bwapp:80" "bwapp_run${N}" "bwapp" "$BWAPP_CREDS"
done

# Juice Shop ×3 (runs 3/4/5)
for N in 3 4 5; do
  start_scan "http://juice-shop:3000" "juiceshop_run${N}" "" "$JS_CREDS"
done

echo "=== All benchmark scans complete: $(date) ===" | tee -a "$LOG"
echo "Run: python3 multi_agent_system/evaluation/compute_metrics.py --all" | tee -a "$LOG"
