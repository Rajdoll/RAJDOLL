#!/bin/bash
# Quick Start Script After LLM Planning Fix
# Automates validation and testing

set -e  # Exit on error

echo "======================================================================"
echo "🚀 RAJDOLL Quick Start - After LLM Planning Fix"
echo "======================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Validate fix
echo -e "${BLUE}Step 1: Validating LLM Planning Fix${NC}"
echo "----------------------------------------------------------------------"
python3 fix_validation.py
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Validation failed! Please check the fix.${NC}"
    exit 1
fi
echo ""

# Step 2: Check LM Studio
echo -e "${BLUE}Step 2: Checking LM Studio Server${NC}"
echo "----------------------------------------------------------------------"
echo "Testing connection to http://localhost:1234/v1/models"

if curl -s -f http://localhost:1234/v1/models > /dev/null 2>&1; then
    echo -e "${GREEN}✅ LM Studio server is running!${NC}"
    MODEL=$(curl -s http://localhost:1234/v1/models | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo "   Model loaded: $MODEL"
else
    echo -e "${YELLOW}⚠️  LM Studio server not responding${NC}"
    echo ""
    echo "Please start LM Studio server:"
    echo "  1. Open LM Studio"
    echo "  2. Go to 'Local Server' tab"
    echo "  3. Click 'Start Server'"
    echo "  4. Verify port is 1234"
    echo ""
    echo "Then run this script again."
    exit 1
fi
echo ""

# Step 3: Check .env configuration
echo -e "${BLUE}Step 3: Verifying .env Configuration${NC}"
echo "----------------------------------------------------------------------"

if [ ! -f .env ]; then
    echo -e "${RED}❌ .env file not found!${NC}"
    exit 1
fi

LLM_PROVIDER=$(grep "^LLM_PROVIDER=" .env | cut -d'=' -f2)
LLM_BASE_URL=$(grep "^LLM_BASE_URL=" .env | cut -d'=' -f2)
DISABLE_LLM=$(grep "^DISABLE_LLM_PLANNING=" .env | cut -d'=' -f2)

echo "   LLM_PROVIDER: $LLM_PROVIDER"
echo "   LLM_BASE_URL: $LLM_BASE_URL"
echo "   DISABLE_LLM_PLANNING: $DISABLE_LLM"

if [ "$LLM_BASE_URL" != "http://localhost:1234/v1" ]; then
    echo -e "${YELLOW}⚠️  Warning: LLM_BASE_URL is not set to LM Studio${NC}"
    echo "   Expected: http://localhost:1234/v1"
    echo "   Current: $LLM_BASE_URL"
fi

if [ "$DISABLE_LLM" = "true" ]; then
    echo -e "${YELLOW}⚠️  Warning: LLM planning is DISABLED${NC}"
    echo "   Set DISABLE_LLM_PLANNING=false to enable LLM planning"
fi
echo ""

# Step 4: Check Docker status
echo -e "${BLUE}Step 4: Checking Docker Services${NC}"
echo "----------------------------------------------------------------------"

if ! docker compose ps | grep -q "Up"; then
    echo -e "${YELLOW}⚠️  Docker services not running. Starting...${NC}"
    docker compose up -d
    echo "   Waiting 10s for services to initialize..."
    sleep 10
else
    echo -e "${GREEN}✅ Docker services are running${NC}"
fi

# Show service status
docker compose ps
echo ""

# Step 5: Run quick test
echo -e "${BLUE}Step 5: Running Quick System Test${NC}"
echo "----------------------------------------------------------------------"
echo "Testing API endpoint..."

API_TEST=$(curl -s -f http://localhost:8000/health 2>&1 || echo "failed")
if [[ "$API_TEST" == *"failed"* ]]; then
    echo -e "${RED}❌ API is not responding${NC}"
    echo "   Check logs: docker compose logs rajdoll-api"
else
    echo -e "${GREEN}✅ API is responding${NC}"
fi
echo ""

# Step 6: Instructions for next steps
echo "======================================================================"
echo -e "${GREEN}🎉 Setup Complete! Next Steps:${NC}"
echo "======================================================================"
echo ""
echo "1️⃣  Start a test scan:"
echo "   curl -X POST http://localhost:8000/api/scans \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"target\": \"http://juice-shop:3000\"}'"
echo ""
echo "2️⃣  Monitor WebSocket events:"
echo "   python3 test_websocket.py --job-id 1"
echo ""
echo "3️⃣  Watch logs for LLM planning:"
echo "   docker compose logs -f rajdoll-api | grep 'LLM'"
echo ""
echo "4️⃣  Check for merged arguments in logs:"
echo "   docker compose logs rajdoll-api | grep 'Using LLM arguments'"
echo "   docker compose logs rajdoll-api | grep 'final_args'"
echo ""
echo "5️⃣  After scan completes, check report:"
echo "   curl http://localhost:8000/api/scans/1/report?format=pdf -o report.pdf"
echo ""
echo "======================================================================"
echo -e "${BLUE}📚 Documentation:${NC}"
echo "   - LM Studio Setup: cat LM_STUDIO_SETUP_GUIDE.md"
echo "   - Fix Validation: python3 fix_validation.py --show-test"
echo "   - WebSocket Test: python3 test_websocket.py --help"
echo "======================================================================"
echo ""
echo -e "${GREEN}✅ All systems ready! Good luck with your research! 🚀${NC}"
echo ""
