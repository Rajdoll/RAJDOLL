#!/usr/bin/env bash
# scripts/run_benchmark.sh
# Multi-target baseline vs framework benchmark.
#
# Usage: ./scripts/run_benchmark.sh [output_dir]
set -euo pipefail

API="${API_BASE:-http://localhost:8000}"
OUTDIR="${1:-multi_agent_system/evaluation/runs/benchmark_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

TARGETS=(
  "juiceshop|http://juice-shop:3000/"
  "dvwa|http://dvwa/login.php"
  "bwapp|http://bwapp/login.php"
  "webgoat|http://webgoat:8080/WebGoat/"
)
MODES=("baseline" "framework")
RUNS=3

set_env_flag() {
  local value="$1"
  sed -i "s/^USE_FRAMEWORK=.*/USE_FRAMEWORK=$value/" .env || echo "USE_FRAMEWORK=$value" >> .env
  docker compose up -d worker api > /dev/null
  # wait for ready
  for _ in $(seq 1 30); do
    if curl -fsS "$API/openapi.json" > /dev/null 2>&1; then
      sleep 5
      return 0
    fi
    sleep 2
  done
  echo "API not ready" >&2
  return 1
}

run_scan() {
  local target_name="$1"
  local target_url="$2"
  local mode="$3"
  local run_idx="$4"

  echo "[$target_name|$mode|run$run_idx] starting scan against $target_url"
  local resp
  resp=$(curl -fsS -X POST "$API/api/scans" \
    -H "Content-Type: application/json" \
    -d "{\"target\":\"$target_url\",\"profile\":\"lab\"}")
  local job_id
  job_id=$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  echo "[$target_name|$mode|run$run_idx] job_id=$job_id"

  # Poll for completion (cap at 90 min)
  for _ in $(seq 1 540); do
    local status
    status=$(curl -fsS "$API/api/scans/$job_id" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' \
      || echo "error")
    if [[ "$status" == "completed" || "$status" == "failed" || "$status" == "cancelled" ]]; then
      break
    fi
    sleep 10
  done

  # Save artefacts
  local outfile="$OUTDIR/${target_name}_${mode}_run${run_idx}.json"
  python3 -m multi_agent_system.evaluation.coverage_matrix "$job_id" \
    --target "$target_name" --mode reportable --output "$outfile" \
    2>&1 | tail -5
  echo "[$target_name|$mode|run$run_idx] saved $outfile"
}

main() {
  for mode in "${MODES[@]}"; do
    if [[ "$mode" == "baseline" ]]; then
      set_env_flag false
    else
      set_env_flag true
    fi
    for entry in "${TARGETS[@]}"; do
      IFS='|' read -r tname turl <<< "$entry"
      for i in $(seq 1 "$RUNS"); do
        run_scan "$tname" "$turl" "$mode" "$i"
      done
    done
  done
  echo "All scans complete. Artefacts in $OUTDIR"
}

main "$@"
