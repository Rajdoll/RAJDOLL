#!/bin/bash
echo "🔍 Monitoring Auto-Login Debug Logs for Job ID 5"
echo "================================================"
echo ""

while true; do
    STATUS=$(curl -s http://localhost:8000/api/scans/5 2>/dev/null | python3 -c "import sys, json; data = json.load(sys.stdin); agents = data['agents']; recon = [a for a in agents if a['agent_name'] == 'ReconnaissanceAgent'][0]; print(recon['status'])" 2>/dev/null)
    
    echo "$(date '+%H:%M:%S') - ReconAgent Status: $STATUS"
    
    # Check for debug logs
    DEBUG_LOGS=$(docker-compose logs worker 2>&1 | grep "PHASE 4 DEBUG" | tail -20)
    
    if [ ! -z "$DEBUG_LOGS" ]; then
        echo ""
        echo "📝 DEBUG LOGS FOUND:"
        echo "$DEBUG_LOGS"
        echo ""
    fi
    
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        echo "✅ ReconAgent $STATUS!"
        
        # Show all Phase 4 debug logs
        echo ""
        echo "📋 Full Phase 4 Debug Logs:"
        docker-compose logs worker 2>&1 | grep "PHASE 4 DEBUG"
        break
    fi
    
    sleep 10
done
