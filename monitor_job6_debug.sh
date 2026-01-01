#!/bin/bash
echo "🔍 Monitoring Job ID 6 Debug Logs - Real-Time"
echo "=============================================="
echo ""

LAST_LINE_COUNT=0

while true; do
    # Check job status
    STATUS=$(curl -s http://localhost:8000/api/scans/6 2>/dev/null | python3 -c "import sys, json; data = json.load(sys.stdin); agents = data.get('agents', []); recon = [a for a in agents if a['agent_name'] == 'ReconnaissanceAgent']; print(recon[0]['status'] if recon else 'unknown')" 2>/dev/null)
    
    # Get debug logs
    DEBUG_LOGS=$(docker-compose logs worker 2>&1 | grep "PHASE 4 DEBUG")
    CURRENT_LINE_COUNT=$(echo "$DEBUG_LOGS" | wc -l)
    
    # Show new logs only
    if [ "$CURRENT_LINE_COUNT" -gt "$LAST_LINE_COUNT" ]; then
        echo ""
        echo "$(date '+%H:%M:%S') - NEW DEBUG LOGS:"
        echo "$DEBUG_LOGS" | tail -n $((CURRENT_LINE_COUNT - LAST_LINE_COUNT))
        LAST_LINE_COUNT=$CURRENT_LINE_COUNT
    fi
    
    echo -ne "\r$(date '+%H:%M:%S') - ReconAgent: $STATUS | Debug logs: $CURRENT_LINE_COUNT lines"
    
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        echo ""
        echo ""
        echo "✅ ReconAgent $STATUS!"
        echo ""
        echo "📋 All Phase 4 Debug Logs:"
        docker-compose logs worker 2>&1 | grep "PHASE 4 DEBUG"
        break
    fi
    
    sleep 3
done
