#!/bin/bash
# End-to-end pause/resume test against DVWA.
# Expects RAJDOLL stack running (docker-compose up -d) + LM Studio on :1234.
#
# What it does:
#   1. Start a DVWA scan
#   2. Wait 5 min (Recon + Phase 2 + first 1-2 agents)
#   3. POST /pause → verify status eventually becomes "paused"
#   4. Restart docker-compose worker (simulates real restart)
#   5. Verify status is still "paused" (durability check)
#   6. POST /resume → verify status = running
#   7. Poll to completion → verify agent count grew post-resume

set -e
API="http://localhost:8000"

echo "=== Starting DVWA scan ==="
RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" \
  -d '{"target":"http://dvwa:80","whitelist_domain":"dvwa"}')
JOB=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")
echo "Job $JOB started"

echo "=== Waiting 5 min for scan to reach Phase 3 ==="
sleep 300

echo "=== Requesting pause ==="
curl -s -X POST "$API/api/scans/$JOB/pause" | python3 -m json.tool

echo "=== Polling until status=paused (up to 50 min for current agent to finish) ==="
STATUS=""
for i in $(seq 1 50); do
  STATUS=$(curl -s "$API/api/scans/$JOB" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "  $(date '+%H:%M:%S') status=$STATUS"
  [ "$STATUS" = "paused" ] && break
  sleep 60
done
[ "$STATUS" != "paused" ] && echo "FAIL: never reached paused" && exit 1

AGENTS_BEFORE=$(curl -s "$API/api/scans/$JOB" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for a in d.get('agents',[]) if a['status']=='completed'))
")
echo "Agents completed pre-restart: $AGENTS_BEFORE"

echo "=== Restarting worker to prove durability ==="
docker-compose restart worker
sleep 15

STATUS=$(curl -s "$API/api/scans/$JOB" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
echo "Status after restart: $STATUS (expect: paused)"
[ "$STATUS" != "paused" ] && echo "FAIL: status changed after restart" && exit 1

echo "=== Resuming ==="
curl -s -X POST "$API/api/scans/$JOB/resume" | python3 -m json.tool

echo "=== Polling to completion ==="
for i in $(seq 1 120); do
  STATUS=$(curl -s "$API/api/scans/$JOB" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "  $(date '+%H:%M:%S') status=$STATUS"
  [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
  sleep 60
done

AGENTS_AFTER=$(curl -s "$API/api/scans/$JOB" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for a in d.get('agents',[]) if a['status']=='completed'))
")
echo "Agents completed total: $AGENTS_AFTER (expect > $AGENTS_BEFORE)"
[ "$AGENTS_AFTER" -le "$AGENTS_BEFORE" ] && echo "FAIL: no agents ran post-resume" && exit 1

echo "=== E2E PASS: pause/resume durability confirmed ==="
