#!/bin/bash
# run_all_benchmark_scans.sh — Run all 9 OWASP benchmark scans sequentially.
# DVWA×3, bWAPP×3, Juice Shop×3
# Logs to: multi_agent_system/evaluation/benchmark_run.log
#
# Usage: bash multi_agent_system/evaluation/run_all_benchmark_scans.sh
# Or background: nohup bash multi_agent_system/evaluation/run_all_benchmark_scans.sh &

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$SCRIPT_DIR/scan_runner.sh"

echo "=== RAJDOLL Benchmark Scan Suite ==="
echo "Started: $(date)"
echo ""

# ── DVWA (3 runs) — credentials: admin/password ──────────────────
DVWA_CREDS='{"username":"admin","password":"password"}'
for N in 1 2 3; do
  echo ""
  echo ">>> DVWA run $N of 3 ($(date '+%H:%M'))"
  bash "$RUNNER" "http://dvwa:80" "dvwa_run${N}" "dvwa" "$DVWA_CREDS"
  echo "<<< DVWA run $N complete"
done

# ── bWAPP (3 runs) — credentials: bee/bug ────────────────────────
BWAPP_CREDS='{"username":"bee","password":"bug"}'
for N in 1 2 3; do
  echo ""
  echo ">>> bWAPP run $N of 3 ($(date '+%H:%M'))"
  bash "$RUNNER" "http://bwapp:80" "bwapp_run${N}" "bwapp" "$BWAPP_CREDS"
  echo "<<< bWAPP run $N complete"
done

# ── Juice Shop (runs 3, 4, 5) ─────────────────────────────────────
JS_CREDS='{"username":"admin@juice-sh.op","password":"admin123"}'
for N in 3 4 5; do
  echo ""
  echo ">>> Juice Shop run $N of 5 ($(date '+%H:%M'))"
  bash "$RUNNER" "http://juice-shop:3000" "juiceshop_run${N}" "" "$JS_CREDS"
  echo "<<< Juice Shop run $N complete"
done

echo ""
echo "=== All benchmark scans complete: $(date) ==="
echo "Next: python3 multi_agent_system/evaluation/compute_metrics.py --target dvwa --runs dvwa_run1 dvwa_run2 dvwa_run3"
