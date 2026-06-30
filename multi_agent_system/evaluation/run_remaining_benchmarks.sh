#!/bin/bash
# Jalankan 8 scan benchmark tersisa secara sequential
# Estimasi total: ~9 jam — bisa ditinggal semalam
# Usage: bash multi_agent_system/evaluation/run_remaining_benchmarks.sh

set -e
API="http://localhost:8000"
EVAL_DIR="multi_agent_system/evaluation"
LOG="$EVAL_DIR/benchmark_run_$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }

run_scan() {
  local LABEL="$1" URL="$2" WHITELIST="$3" CREDS="$4"
  local OUT="$EVAL_DIR/runs/$LABEL"
  mkdir -p "$OUT"

  log "=== START: $LABEL ==="
  BODY="{\"target\":\"$URL\",\"whitelist_domain\":\"$WHITELIST\",\"credentials\":$CREDS,\"scan_label\":\"$LABEL\"}"
  RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" -d "$BODY")
  JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id') or d.get('id'))" 2>/dev/null)
  log "$LABEL -> Job #$JOB_ID"

  # Poll hingga selesai
  while true; do
    STATUS=$(curl -s "$API/api/scans/$JOB_ID" | python3 -c "import sys,json; d=json.load(sys.stdin); agents=d.get('agents',[]); done=sum(1 for a in agents if a['status']=='completed'); running=[a['agent_name'] for a in agents if a['status']=='running']; print(d.get('status'), done, running[0] if running else '-')" 2>/dev/null)
    log "$LABEL | $STATUS"
    echo "$STATUS" | grep -qE "^completed|^failed|^cancelled" && break
    sleep 60
  done

  # Simpan hasil
  curl -s "$API/api/scans/$JOB_ID" > "$OUT/job_result.json"
  curl -s "$API/api/scans/$JOB_ID/findings?mode=raw" > "$OUT/findings.json"
  TOTAL=$(python3 -c "import json; d=json.load(open('$OUT/findings.json')); print(len(d))" 2>/dev/null)
  log "$LABEL selesai — $TOTAL findings disimpan ke $OUT"
}

# ── DVWA ──────────────────────────────────────────────────────────────────
# Run all 3 fresh — dvwa_run1 pre-fix results are stale (P=18.75%)
run_scan "dvwa_run1" "http://dvwa/" "dvwa" '{"username":"admin","password":"password"}'
run_scan "dvwa_run2" "http://dvwa/" "dvwa" '{"username":"admin","password":"password"}'
run_scan "dvwa_run3" "http://dvwa/" "dvwa" '{"username":"admin","password":"password"}'

# ── bWAPP ─────────────────────────────────────────────────────────────────
run_scan "bwapp_run1" "http://bwapp/" "bwapp" '{"username":"bee","password":"bug"}'
run_scan "bwapp_run2" "http://bwapp/" "bwapp" '{"username":"bee","password":"bug"}'
run_scan "bwapp_run3" "http://bwapp/" "bwapp" '{"username":"bee","password":"bug"}'

# ── Juice Shop ────────────────────────────────────────────────────────────
run_scan "juiceshop_run3" "http://juice-shop:3000" "" '{"username":"admin@juice-sh.op","password":"admin123"}'
run_scan "juiceshop_run4" "http://juice-shop:3000" "" '{"username":"admin@juice-sh.op","password":"admin123"}'
run_scan "juiceshop_run5" "http://juice-shop:3000" "" '{"username":"admin@juice-sh.op","password":"admin123"}'

# ── Hitung metrik semua target ─────────────────────────────────────────────
log "=== MENGHITUNG METRIK ==="
python3 "$EVAL_DIR/compute_metrics.py" --target dvwa    --runs dvwa_run1 dvwa_run2 dvwa_run3          | tee -a "$LOG"
python3 "$EVAL_DIR/compute_metrics.py" --target bwapp   --runs bwapp_run1 bwapp_run2 bwapp_run3       | tee -a "$LOG"
python3 "$EVAL_DIR/compute_metrics.py" --target juiceshop --runs juiceshop_run3 juiceshop_run4 juiceshop_run5 | tee -a "$LOG"

log "=== SEMUA SELESAI ==="
