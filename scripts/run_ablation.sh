#!/usr/bin/env bash
# scripts/run_ablation.sh -- Juice Shop only, ablate framework components individually.
#
# Component flags expected in .env:
#   USE_PAYLOAD_SYNTH=true|false
#   USE_JS_ANALYZER=true|false
#   USE_ACTIVE_FLOW=true|false
#   USE_SEMANTIC_CLASSIFIER=true|false
# (USE_FRAMEWORK acts as global gate; per-component flags refine.)
set -euo pipefail

API="${API_BASE:-http://localhost:8000}"
OUTDIR="${1:-multi_agent_system/evaluation/runs/ablation_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

TARGET_URL="${TARGET_URL:-http://juice-shop:3000/}"
TARGET_NAME=juiceshop

# Configurations to ablate (1 = component on)
declare -A CONFIGS=(
  ["A_only"]="1 0 0 0"
  ["B_only"]="0 1 0 0"
  ["C_only"]="0 0 1 0"
  ["D_only"]="0 0 0 1"
  ["A_B"]="1 1 0 0"
  ["A_B_C"]="1 1 1 0"
  ["A_B_C_D"]="1 1 1 1"
)
RUNS=2

apply_config() {
  local cfg_str="$1"
  read -r a b c d <<< "$cfg_str"
  local val_a=$([ "$a" = "1" ] && echo true || echo false)
  local val_b=$([ "$b" = "1" ] && echo true || echo false)
  local val_c=$([ "$c" = "1" ] && echo true || echo false)
  local val_d=$([ "$d" = "1" ] && echo true || echo false)
  for k in USE_PAYLOAD_SYNTH:$val_a USE_JS_ANALYZER:$val_b \
           USE_ACTIVE_FLOW:$val_c USE_SEMANTIC_CLASSIFIER:$val_d \
           USE_FRAMEWORK:true; do
    key="${k%%:*}"; value="${k#*:}"
    sed -i "s/^$key=.*/$key=$value/" .env || echo "$key=$value" >> .env
  done
  docker compose up -d worker api > /dev/null
  sleep 8
}

run_scan() {
  local cfg="$1"
  local run_idx="$2"
  local resp job_id outfile
  resp=$(curl -fsS -X POST "$API/api/scans" \
    -H "Content-Type: application/json" \
    -d "{\"target\":\"$TARGET_URL\",\"profile\":\"lab\"}")
  job_id=$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  echo "[$cfg|run$run_idx] job_id=$job_id"

  for _ in $(seq 1 540); do
    status=$(curl -fsS "$API/api/scans/$job_id" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' || echo "error")
    [[ "$status" == "completed" || "$status" == "failed" || "$status" == "cancelled" ]] && break
    sleep 10
  done

  outfile="$OUTDIR/ablation_${cfg}_run${run_idx}.json"
  python3 -m multi_agent_system.evaluation.coverage_matrix "$job_id" \
    --target "$TARGET_NAME" --mode reportable --output "$outfile"
}

main() {
  for cfg_name in "${!CONFIGS[@]}"; do
    apply_config "${CONFIGS[$cfg_name]}"
    for i in $(seq 1 "$RUNS"); do
      run_scan "$cfg_name" "$i"
    done
  done
  echo "Ablation complete. Artefacts in $OUTDIR"
}

main "$@"
