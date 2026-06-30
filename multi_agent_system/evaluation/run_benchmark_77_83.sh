#!/bin/bash
# Jalankan 7 scan benchmark tersisa (jobs 77-83) + download semua laporan (74-83)
# Usage: bash multi_agent_system/evaluation/run_benchmark_77_83.sh
# Estimasi: ~8 jam total (7 x ~70 menit/scan)

set -euo pipefail
API="http://localhost:8000"
EVAL_DIR="/mnt/d/MCP/RAJDOLL/multi_agent_system/evaluation"
REPORT_DIR="$EVAL_DIR/reports"
LOG="$EVAL_DIR/benchmark_77_83_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$REPORT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }

# ── Simpan findings dari job yang sudah ada ke direktori run ──────────────
save_existing_job() {
  local JOB_ID="$1" RUN_LABEL="$2"
  local OUT="$EVAL_DIR/runs/$RUN_LABEL"
  mkdir -p "$OUT"
  log "Simpan job #$JOB_ID → $RUN_LABEL"
  curl -s "$API/api/scans/$JOB_ID" > "$OUT/job_result.json"
  curl -s "$API/api/scans/$JOB_ID/findings?mode=raw" > "$OUT/findings.json"
  TOTAL=$(python3 -c "import json; print(len(json.load(open('$OUT/findings.json'))))" 2>/dev/null || echo "?")
  log "  $RUN_LABEL: $TOTAL findings"
}

# ── Jalankan 1 scan dan tunggu selesai ───────────────────────────────────
run_scan() {
  local RUN_LABEL="$1"
  local OUT="$EVAL_DIR/runs/$RUN_LABEL"
  mkdir -p "$OUT"
  log "=== START: $RUN_LABEL ==="

  BODY='{"target":"http://juice-shop:3000","credentials":{"username":"admin@juice-sh.op","password":"admin123"}}'
  RESP=$(curl -s -X POST "$API/api/scans" -H "Content-Type: application/json" -d "$BODY")
  JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id') or d.get('id',''))" 2>/dev/null)

  if [ -z "$JOB_ID" ]; then
    log "ERROR: Gagal mendapat job_id. Response: $RESP"
    return 1
  fi
  log "$RUN_LABEL → Job #$JOB_ID"
  echo "$JOB_ID" > "$OUT/job_id.txt"

  # Simpan job_id ke file tracking global
  echo "$JOB_ID" >> "$EVAL_DIR/benchmark_job_ids.txt"

  # Poll hingga selesai (cek tiap 60 detik)
  while true; do
    RAW=$(curl -s "$API/api/scans/$JOB_ID")
    STATUS=$(echo "$RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")
    RUNNING=$(echo "$RAW" | python3 -c "
import sys,json; d=json.load(sys.stdin)
agents=d.get('agents',[])
running=[a['agent_name'] for a in agents if a.get('status')=='running']
done=sum(1 for a in agents if a.get('status')=='completed')
total=len(agents)
print(f'{done}/{total}', running[0] if running else '-')
" 2>/dev/null || echo "? -")
    log "$RUN_LABEL | status=$STATUS agents=$RUNNING"
    [[ "$STATUS" =~ ^(completed|failed|cancelled)$ ]] && break
    sleep 60
  done

  # Simpan hasil
  curl -s "$API/api/scans/$JOB_ID" > "$OUT/job_result.json"
  curl -s "$API/api/scans/$JOB_ID/findings?mode=raw" > "$OUT/findings.json"
  TOTAL=$(python3 -c "import json; print(len(json.load(open('$OUT/findings.json'))))" 2>/dev/null || echo "?")
  log "$RUN_LABEL selesai — $TOTAL findings (Job #$JOB_ID)"
}

# ── Download laporan untuk 1 job ─────────────────────────────────────────
download_report() {
  local JOB_ID="$1"
  local OUT_PREFIX="$REPORT_DIR/job_${JOB_ID}"

  log "Download laporan Job #$JOB_ID..."

  # PDF report
  HTTP=$(curl -s -w "%{http_code}" -o "${OUT_PREFIX}_report.pdf" \
    "$API/api/scans/$JOB_ID/report/pdf" 2>/dev/null)
  if [ "$HTTP" = "200" ]; then
    log "  PDF → ${OUT_PREFIX}_report.pdf ($(du -sh "${OUT_PREFIX}_report.pdf" | cut -f1))"
  else
    log "  PDF gagal (HTTP $HTTP), coba OWASP download..."
    HTTP2=$(curl -s -w "%{http_code}" -o "${OUT_PREFIX}_report_owasp.pdf" \
      "$API/api/reports/owasp/download/$JOB_ID/pdf" 2>/dev/null)
    if [ "$HTTP2" = "200" ]; then
      log "  OWASP PDF → ${OUT_PREFIX}_report_owasp.pdf"
    else
      log "  WARNING: PDF download gagal untuk Job #$JOB_ID (HTTP $HTTP / $HTTP2)"
    fi
  fi

  # JSON report (findings raw)
  curl -s "$API/api/scans/$JOB_ID/findings?mode=raw" > "${OUT_PREFIX}_findings.json"
  TOTAL=$(python3 -c "import json; print(len(json.load(open('${OUT_PREFIX}_findings.json'))))" 2>/dev/null || echo "?")

  # Metrics report
  curl -s "$API/api/jobs/$JOB_ID/metrics" > "${OUT_PREFIX}_metrics.json" 2>/dev/null

  log "  Findings: $TOTAL | Metrics saved"
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

log "=== RAJDOLL Benchmark Runner — 7 scan tersisa ==="
log "Target: http://juice-shop:3000"
log "Log: $LOG"

# Inisialisasi file tracking
echo "# Job IDs dari run yang sudah ada (74, 75, 76):" > "$EVAL_DIR/benchmark_job_ids.txt"
echo "74" >> "$EVAL_DIR/benchmark_job_ids.txt"
echo "75" >> "$EVAL_DIR/benchmark_job_ids.txt"
echo "76" >> "$EVAL_DIR/benchmark_job_ids.txt"
echo "# Job IDs baru (akan ditambahkan otomatis):" >> "$EVAL_DIR/benchmark_job_ids.txt"

# Simpan data dari 3 job yang sudah ada
log "--- Simpan data job 74, 75, 76 ---"
save_existing_job 74 "juiceshop_benchmark_run1"
save_existing_job 75 "juiceshop_benchmark_run2"
save_existing_job 76 "juiceshop_benchmark_run3"

# Jalankan 7 scan baru secara sequential
log "--- Mulai 7 scan baru ---"
run_scan "juiceshop_benchmark_run4"
run_scan "juiceshop_benchmark_run5"
run_scan "juiceshop_benchmark_run6"
run_scan "juiceshop_benchmark_run7"
run_scan "juiceshop_benchmark_run8"
run_scan "juiceshop_benchmark_run9"
run_scan "juiceshop_benchmark_run10"

log "=== SEMUA SCAN SELESAI ==="

# ── Hitung metrik semua benchmark run ────────────────────────────────────
log "--- Menghitung metrik ---"
cd /mnt/d/MCP/RAJDOLL
python3 "$EVAL_DIR/compute_metrics.py" \
  --target juiceshop \
  --runs juiceshop_benchmark_run1 juiceshop_benchmark_run2 juiceshop_benchmark_run3 \
         juiceshop_benchmark_run4 juiceshop_benchmark_run5 juiceshop_benchmark_run6 \
         juiceshop_benchmark_run7 juiceshop_benchmark_run8 juiceshop_benchmark_run9 \
         juiceshop_benchmark_run10 \
  2>&1 | tee -a "$LOG"

# ── Download laporan untuk semua 10 job ──────────────────────────────────
log "--- Download laporan semua job ---"

# Job 74, 75, 76 yang sudah ada
for JOB_ID in 74 75 76; do
  download_report "$JOB_ID"
done

# 7 job baru (baca dari file tracking)
NEW_JOBS=$(grep -v "#" "$EVAL_DIR/benchmark_job_ids.txt" | grep -v -E "^(74|75|76)$" | sort -n)
for JOB_ID in $NEW_JOBS; do
  [ -n "$JOB_ID" ] && download_report "$JOB_ID"
done

# ── Ringkasan akhir ───────────────────────────────────────────────────────
log "=== SELESAI SEMUA ==="
log "Laporan tersimpan di: $REPORT_DIR"
log "Job IDs: $(cat "$EVAL_DIR/benchmark_job_ids.txt" | grep -v "#" | tr '\n' ' ')"

# Print tabel metrik final
echo ""
echo "=== HASIL METRIK BENCHMARK ==="
python3 - <<'PYEOF'
import json, os, glob
from pathlib import Path

RUNS_DIR = Path("/mnt/d/MCP/RAJDOLL/multi_agent_system/evaluation/runs")
runs = sorted(RUNS_DIR.glob("juiceshop_benchmark_run*"))
if not runs:
    print("Tidak ada data run ditemukan.")
    exit()

print(f"{'Run':<30} {'Precision':>10} {'Recall':>8} {'F1':>8} {'TP':>5} {'FP':>5} {'FN':>5}")
print("-" * 75)
metrics_list = []
for run_dir in sorted(runs, key=lambda x: x.name):
    m_file = run_dir / "metrics.json"
    if not m_file.exists():
        continue
    m = json.loads(m_file.read_text())
    p, r, f1 = m.get('precision', 0), m.get('recall', 0), m.get('f1', 0)
    tp = m.get('tp_gt_entries', 0)
    fp = m.get('fp_findings', 0)
    fn = m.get('fn_gt_entries', 0)
    print(f"{run_dir.name:<30} {p:>9.2f}% {r:>7.2f}% {f1:>7.2f}% {tp:>5} {fp:>5} {fn:>5}")
    metrics_list.append((p, r, f1))

if metrics_list:
    print("-" * 75)
    import statistics
    ps = [x[0] for x in metrics_list]
    rs = [x[1] for x in metrics_list]
    f1s = [x[2] for x in metrics_list]
    n = len(metrics_list)
    print(f"{'RATA-RATA (n='+str(n)+')':<30} {statistics.mean(ps):>9.2f}% {statistics.mean(rs):>7.2f}% {statistics.mean(f1s):>7.2f}%")
    if n > 1:
        print(f"{'STD DEV':<30} {statistics.stdev(ps):>9.2f}% {statistics.stdev(rs):>7.2f}% {statistics.stdev(f1s):>7.2f}%")
PYEOF

log "Script selesai. Cek $LOG untuk detail lengkap."
