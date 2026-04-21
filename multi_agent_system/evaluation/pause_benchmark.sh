#!/bin/bash
# pause_benchmark.sh — Pause the currently running benchmark scan gracefully.
# Run this when you need to stop (e.g., before closing laptop).
# Resume later with: bash resume_benchmarks.sh

API="http://localhost:8000"
EVAL_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKPOINT="$EVAL_DIR/benchmark_checkpoint.txt"
LOG="$EVAL_DIR/benchmark_run.log"

if [ ! -f "$CHECKPOINT" ]; then
  echo "No active benchmark checkpoint found."
  echo "Is continue_benchmarks.sh running? Check: pgrep -fa continue_benchmark"
  exit 1
fi

source "$CHECKPOINT"
echo "Active scan: $LABEL (job_id=$JOB_ID)"

# Request pause via API
RESP=$(curl -s -X POST "$API/api/scans/$JOB_ID/pause")
STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
echo "Pause requested → current status: $STATUS"
echo "$RESP" | python3 -m json.tool 2>/dev/null

echo ""
echo "The current agent will finish (up to 45 min), then the scan pauses."
echo "The benchmark runner will exit automatically when paused."
echo ""
echo "To check: curl -s $API/api/scans/$JOB_ID | python3 -c \"import sys,json; print(json.load(sys.stdin)['status'])\""
echo "To resume tonight: bash $EVAL_DIR/resume_benchmarks.sh"
echo "[$(date '+%H:%M:%S')] Pause requested for job $JOB_ID ($LABEL)" >> "$LOG"
