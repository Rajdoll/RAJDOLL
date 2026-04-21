#!/bin/bash
# resume_benchmarks.sh — Resume benchmark after pause_benchmark.sh was used.
# Resumes the paused scan, waits for it to complete, then continues remaining scans.

API="http://localhost:8000"
EVAL_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKPOINT="$EVAL_DIR/benchmark_checkpoint.txt"
LOG="$EVAL_DIR/benchmark_run.log"

if [ ! -f "$CHECKPOINT" ]; then
  echo "No checkpoint found — nothing to resume."
  echo "If all scans already completed, run:"
  echo "  python3 $EVAL_DIR/compute_metrics.py --all"
  exit 0
fi

source "$CHECKPOINT"
echo "=== Resuming benchmark from checkpoint ==="
echo "  Paused scan: $LABEL (job_id=$JOB_ID)"
echo "  Remaining after this: $REMAINING"
echo ""

# Resume the paused scan
STATUS=$(curl -s "$API/api/scans/$JOB_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
echo "Current status: $STATUS"

if [[ "$STATUS" == "paused" ]]; then
  echo "Sending resume..."
  curl -s -X POST "$API/api/scans/$JOB_ID/resume" | python3 -m json.tool 2>/dev/null
elif [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]]; then
  echo "Scan already finished ($STATUS) — saving results and skipping to next."
  mkdir -p "$EVAL_DIR/runs/$LABEL"
  curl -s "$API/api/scans/$JOB_ID" > "$EVAL_DIR/runs/$LABEL/job_result.json"
  curl -s "$API/api/scans/$JOB_ID/findings" > "$EVAL_DIR/runs/$LABEL/findings.json"
fi

echo "[$(date '+%H:%M:%S')] Benchmark resumed" >> "$LOG"

# Now hand off to continue_benchmarks.sh — it skips labels with existing findings.json
echo ""
echo "Handing off to continue_benchmarks.sh (skips completed runs automatically)..."
exec bash "$EVAL_DIR/continue_benchmarks.sh"
