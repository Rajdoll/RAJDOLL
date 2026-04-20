#!/bin/bash
# ablation_runner.sh — Run 12 single-agent-skip scans on Juice Shop.
# Each run skips exactly one non-critical agent to measure its delta-Recall contribution.
#
# Usage: bash multi_agent_system/evaluation/ablation_runner.sh
# Prerequisites:
#   - RAJDOLL stack running (docker-compose up -d)
#   - LM Studio + Qwen 3-4B running on port 1234
#   - juiceshop_run3 must already exist (used as baseline by compute_ablation.py)

BASE_URL="http://localhost:8000"
CREDENTIALS='{"username":"admin@juice-sh.op","password":"admin123"}'
EVAL_DIR="$(cd "$(dirname "$0")" && pwd)"

# The 12 agents to ablate (Recon and Report excluded — both are required for scan integrity)
AGENTS=(
  "AuthenticationAgent"
  "SessionManagementAgent"
  "InputValidationAgent"
  "AuthorizationAgent"
  "ConfigDeploymentAgent"
  "ClientSideAgent"
  "FileUploadAgent"
  "APITestingAgent"
  "ErrorHandlingAgent"
  "WeakCryptographyAgent"
  "BusinessLogicAgent"
  "IdentityManagementAgent"
)

for AGENT in "${AGENTS[@]}"; do
  LABEL="ablation_skip_${AGENT}"
  OUTPUT_DIR="$EVAL_DIR/runs/$LABEL"
  mkdir -p "$OUTPUT_DIR"

  echo ""
  echo "=== Ablation: skipping $AGENT ==="

  BODY="{\"target\": \"http://juice-shop:3000\", \"credentials\": $CREDENTIALS, \"skip_agents\": [\"$AGENT\"]}"
  RESPONSE=$(curl -s -X POST "$BASE_URL/api/scans" \
    -H "Content-Type: application/json" \
    -d "$BODY")
  echo "$RESPONSE" > "$OUTPUT_DIR/scan_start.json"

  JOB_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
  if [ -z "$JOB_ID" ]; then
    echo "ERROR: Could not start scan for $AGENT — skipping"
    echo "{\"skipped_agent\": \"$AGENT\", \"error\": \"failed to start\"}" > "$OUTPUT_DIR/ablation_config.json"
    continue
  fi
  echo "{\"skipped_agent\": \"$AGENT\", \"job_id\": $JOB_ID}" > "$OUTPUT_DIR/ablation_config.json"
  echo "Job ID: $JOB_ID — polling every 60s"

  while true; do
    STATUS=$(curl -s "$BASE_URL/api/scans/$JOB_ID" | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
    echo "  $(date '+%H:%M:%S') [$AGENT] $STATUS"
    if [[ "$STATUS" == "completed" || "$STATUS" == "failed" || "$STATUS" == "cancelled" ]]; then
      break
    fi
    sleep 60
  done

  curl -s "$BASE_URL/api/scans/$JOB_ID/findings" > "$OUTPUT_DIR/findings.json"
  COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT_DIR/findings.json'))))" 2>/dev/null || echo "?")
  echo "  Done: $COUNT findings -> $OUTPUT_DIR/"
done

echo ""
echo "=== All ablation runs complete ==="
echo "Next: python3 multi_agent_system/evaluation/compute_ablation.py \\"
echo "        --baseline juiceshop_run3 \\"
echo "        --agents ${AGENTS[*]}"
