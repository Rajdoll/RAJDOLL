#!/bin/bash
# Usage: ./scan_runner.sh <target_url> <run_label> [whitelist_domain] [credentials_json]
# Example: ./scan_runner.sh "http://dvwa:80" "dvwa_run1" "dvwa"
# Example: ./scan_runner.sh "http://juice-shop:3000" "juiceshop_run3" "" '{"username":"admin@juice-sh.op","password":"admin123"}'

TARGET_URL="$1"
RUN_LABEL="$2"
WHITELIST="${3:-}"
CREDENTIALS="${4:-}"
OUTPUT_DIR="/mnt/d/MCP/RAJDOLL/multi_agent_system/evaluation/runs/${RUN_LABEL}"
API_BASE="http://localhost:8000"

mkdir -p "$OUTPUT_DIR"

# Build request body
if [ -n "$WHITELIST" ] && [ -n "$CREDENTIALS" ]; then
  BODY="{\"target\": \"$TARGET_URL\", \"whitelist_domain\": \"$WHITELIST\", \"credentials\": $CREDENTIALS}"
elif [ -n "$WHITELIST" ]; then
  BODY="{\"target\": \"$TARGET_URL\", \"whitelist_domain\": \"$WHITELIST\"}"
elif [ -n "$CREDENTIALS" ]; then
  BODY="{\"target\": \"$TARGET_URL\", \"credentials\": $CREDENTIALS}"
else
  BODY="{\"target\": \"$TARGET_URL\"}"
fi

echo "Starting scan: $TARGET_URL (label: $RUN_LABEL)"
echo "Request body: $BODY"

# Start scan
RESPONSE=$(curl -s -X POST "$API_BASE/api/scans" \
  -H "Content-Type: application/json" \
  -d "$BODY")
echo "$RESPONSE" | tee "$OUTPUT_DIR/scan_start.json"

JOB_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
if [ -z "$JOB_ID" ]; then
  echo "ERROR: Could not extract job ID from response"
  exit 1
fi
echo "Job ID: $JOB_ID"

# Poll until complete (check every 60s)
echo "Polling job $JOB_ID..."
while true; do
  STATUS=$(curl -s "$API_BASE/api/scans/$JOB_ID" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null)
  echo "$(date '+%H:%M:%S') Status: $STATUS"
  if [[ "$STATUS" == "completed" || "$STATUS" == "failed" || "$STATUS" == "cancelled" ]]; then
    break
  fi
  sleep 60
done

# Save results
curl -s "$API_BASE/api/scans/$JOB_ID" | tee "$OUTPUT_DIR/job_result.json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"Status: {d.get('status')}\")
print(f\"Findings: {len(d.get('findings', []))}\")
"

curl -s "$API_BASE/api/scans/$JOB_ID/findings" | tee "$OUTPUT_DIR/findings.json" | python3 -c "
import sys, json
findings = json.load(sys.stdin)
print(f'Total findings saved: {len(findings)}')
by_severity = {}
for f in findings:
    sev = f.get('severity', 'unknown')
    by_severity[sev] = by_severity.get(sev, 0) + 1
for sev, count in sorted(by_severity.items()):
    print(f'  {sev}: {count}')
" 2>/dev/null

echo "Results saved to $OUTPUT_DIR/"
