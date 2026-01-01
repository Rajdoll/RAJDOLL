#!/bin/bash
# Monitor Job ID 4 Progress with Auth Propagation Validation

echo "🔍 RAJDOLL Job ID 4 Monitor - Phase 3 Auth Propagation Test"
echo "============================================================"
echo ""

while true; do
    clear
    echo "🔍 RAJDOLL Job ID 4 Monitor - $(date '+%H:%M:%S')"
    echo "============================================================"
    echo ""
    
    # Job status
    STATUS=$(curl -s http://localhost:8000/api/scans/4 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null)
    echo "📊 Job Status: $STATUS"
    echo ""
    
    # Agent status
    echo "🤖 Agent Progress:"
    curl -s http://localhost:8000/api/scans/4 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for agent in data.get('agents', []):
    name = agent['agent_name']
    status = agent['status']
    emoji = '✅' if status == 'completed' else '🔄' if status == 'running' else '⏳'
    print(f'  {emoji} {name}: {status}')
" 2>/dev/null
    echo ""
    
    # Findings count
    echo "📈 Findings Breakdown:"
    curl -s http://localhost:8000/api/scans/4/findings 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
data = json.load(sys.stdin)
print(f'  Total: {len(data)} findings')
agents = Counter([f['agent_name'] for f in data])
for agent, count in agents.most_common():
    print(f'    {agent}: {count}')
" 2>/dev/null
    echo ""
    
    # Check for auth injection logs
    echo "🔑 Auth Injection Verification:"
    AUTH_COUNT=$(docker-compose logs worker 2>&1 | grep -c "🔑 Auto-injected" 2>/dev/null || echo "0")
    echo "  Auth injections detected: $AUTH_COUNT"
    
    if [ "$AUTH_COUNT" -gt 0 ]; then
        echo "  ✅ Authentication propagation WORKING!"
    else
        echo "  ⚠️  No auth injection yet (may appear after ReconAgent completes)"
    fi
    echo ""
    
    # Comparison with Job 3
    JOB3_COUNT=$(curl -s http://localhost:8000/api/scans/3/findings 2>/dev/null | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null)
    JOB4_COUNT=$(curl -s http://localhost:8000/api/scans/4/findings 2>/dev/null | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null)
    
    echo "📊 Comparison with Job 3 (Baseline):"
    echo "  Job 3 (No Auth): $JOB3_COUNT findings"
    echo "  Job 4 (Auth):    $JOB4_COUNT findings"
    
    if [ "$JOB4_COUNT" -gt "$JOB3_COUNT" ]; then
        IMPROVEMENT=$(( (JOB4_COUNT - JOB3_COUNT) * 100 / JOB3_COUNT ))
        echo "  ✅ Improvement: +${IMPROVEMENT}% (+$((JOB4_COUNT - JOB3_COUNT)) findings)"
    fi
    echo ""
    
    # Exit if completed
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        echo "✅ Scan $STATUS! Check full results above."
        break
    fi
    
    echo "Press Ctrl+C to stop monitoring..."
    sleep 10
done
