#!/bin/bash
# continue_benchmarks.sh — Run all 9 benchmark scans with credentials.
# DVWA×3 (admin/password), bWAPP×3 (bee/bug), Juice Shop×3 (admin@juice-sh.op/admin123)
#
# Pause-aware: if the current scan gets paused via API, this script saves a
# checkpoint and exits cleanly. Resume with: bash resume_benchmarks.sh

API="http://localhost:8000"
EVAL_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNS_DIR="$EVAL_DIR/runs"
LOG="$EVAL_DIR/benchmark_run.log"
CHECKPOINT="$EVAL_DIR/benchmark_checkpoint.txt"

DVWA_CREDS='{"username":"admin","password":"password"}'
BWAPP_CREDS='{"username":"bee","password":"bug"}'
JS_CREDS='{"username":"admin@juice-sh.op","password":"admin123"}'

# Write current scan info so pause_benchmark.sh and resume_benchmarks.sh can find it
write_checkpoint() {
  local LABEL="$1"
  local JOB_ID="$2"
  local REMAINING="$3"   # space-separated remaining labels after this one
  echo "LABEL=$LABEL" > "$CHECKPOINT"
  echo "JOB_ID=$JOB_ID" >> "$CHECKPOINT"
  echo "REMAINING=$REMAINING" >> "$CHECKPOINT"
  echo "RUNNER_PID=$$" >> "$CHECKPOINT"
}

collect_job() {
  local JOB_ID="$1"
  local LABEL="$2"
  local OUTPUT_DIR="$RUNS_DIR/$LABEL"
  mkdir -p "$OUTPUT_DIR"

  echo "[$(date '+%H:%M:%S')] Polling job $JOB_ID ($LABEL)..." | tee -a "$LOG"
  local STATUS=""
  while true; do
    STATUS=$(curl -s "$API/api/scans/$JOB_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
    echo "  $(date '+%H:%M:%S') job=$JOB_ID status=$STATUS" >> "$LOG"
    [[ "$STATUS" == "completed" || "$STATUS" == "failed" || "$STATUS" == "cancelled" || "$STATUS" == "paused" ]] && break
    sleep 60
  done

  if [[ "$STATUS" == "paused" ]]; then
    echo "[$(date '+%H:%M:%S')] Scan PAUSED — checkpoint saved. Run resume_benchmarks.sh to continue." | tee -a "$LOG"
    # Save partial results so far
    curl -s "$API/api/scans/$JOB_ID" > "$OUTPUT_DIR/job_result_partial.json"
    # Signal to main loop to stop
    return 2
  fi

  curl -s "$API/api/scans/$JOB_ID" > "$OUTPUT_DIR/job_result.json"
  local FINDINGS
  FINDINGS=$(curl -s "$API/api/scans/$JOB_ID/findings")
  echo "$FINDINGS" > "$OUTPUT_DIR/findings.json"
  local COUNT
  COUNT=$(echo "$FINDINGS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
  echo "[$(date '+%H:%M:%S')] $LABEL done: status=$STATUS findings=$COUNT" | tee -a "$LOG"
  return 0
}

start_scan() {
  local TARGET="$1"
  local LABEL="$2"
  local WHITELIST="${3:-}"
  local CREDS="${4:-}"
  local REMAINING="${5:-}"
  local OUTPUT_DIR="$RUNS_DIR/$LABEL"
  mkdir -p "$OUTPUT_DIR"

  local BODY
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
  local RESP
  RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" -d "$BODY")
  echo "$RESP" > "$OUTPUT_DIR/scan_start.json"
  local JOB_ID
  JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('job_id',''))" 2>/dev/null)
  if [ -z "$JOB_ID" ]; then
    echo "ERROR: no job_id for $LABEL — response: $RESP" | tee -a "$LOG"
    return 1
  fi
  echo "  job_id=$JOB_ID" | tee -a "$LOG"
  write_checkpoint "$LABEL" "$JOB_ID" "$REMAINING"
  collect_job "$JOB_ID" "$LABEL"
}

run_sequence() {
  # Called with list of "label|target|whitelist|creds" entries
  local ENTRIES=("$@")
  local N=${#ENTRIES[@]}

  for (( i=0; i<N; i++ )); do
    IFS='|' read -r LABEL TARGET WHITELIST CREDS <<< "${ENTRIES[$i]}"
    # Build remaining labels for checkpoint
    local REMAINING=""
    for (( j=i+1; j<N; j++ )); do
      local RLABEL; IFS='|' read -r RLABEL _ _ _ <<< "${ENTRIES[$j]}"
      REMAINING="$REMAINING $RLABEL"
    done
    REMAINING="${REMAINING# }"

    # Skip if results already exist (resume support)
    if [ -f "$RUNS_DIR/$LABEL/findings.json" ]; then
      echo "[$(date '+%H:%M:%S')] Skipping $LABEL (findings.json already exists)" | tee -a "$LOG"
      continue
    fi

    start_scan "$TARGET" "$LABEL" "$WHITELIST" "$CREDS" "$REMAINING"
    local RC=$?
    if [[ $RC -eq 2 ]]; then
      echo "[$(date '+%H:%M:%S')] Exiting runner — resume later with: bash resume_benchmarks.sh" | tee -a "$LOG"
      exit 0
    fi
  done
}

echo "" >> "$LOG"
echo "=== Benchmark started: $(date) ===" | tee -a "$LOG"

run_sequence \
  "dvwa_run1|http://dvwa:80|dvwa|$DVWA_CREDS" \
  "dvwa_run2|http://dvwa:80|dvwa|$DVWA_CREDS" \
  "dvwa_run3|http://dvwa:80|dvwa|$DVWA_CREDS" \
  "bwapp_run1|http://bwapp:80|bwapp|$BWAPP_CREDS" \
  "bwapp_run2|http://bwapp:80|bwapp|$BWAPP_CREDS" \
  "bwapp_run3|http://bwapp:80|bwapp|$BWAPP_CREDS" \
  "juiceshop_run3|http://juice-shop:3000||$JS_CREDS" \
  "juiceshop_run4|http://juice-shop:3000||$JS_CREDS" \
  "juiceshop_run5|http://juice-shop:3000||$JS_CREDS"

echo "=== All benchmark scans complete: $(date) ===" | tee -a "$LOG"
rm -f "$EVAL_DIR/benchmark_checkpoint.txt"
echo "Run: python3 multi_agent_system/evaluation/compute_metrics.py --all" | tee -a "$LOG"
