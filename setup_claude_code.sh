#!/bin/bash
# Claude Code Setup Script
# Initializes Claude Code environment for research project

set -e

echo "======================================================================"
echo "🚀 Claude Code Setup for RAJDOLL Research Project"
echo "======================================================================"
echo ""

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .claude directory exists
if [ -d ".claude" ]; then
    echo -e "${GREEN}✅ .claude directory exists${NC}"
else
    echo -e "${YELLOW}Creating .claude directory structure...${NC}"
    mkdir -p .claude/commands .claude/skills
fi

# Check CLAUDE.md
if [ -f ".claude/CLAUDE.md" ]; then
    echo -e "${GREEN}✅ CLAUDE.md exists ($(wc -l < .claude/CLAUDE.md) lines)${NC}"
else
    echo -e "${YELLOW}⚠️  CLAUDE.md not found${NC}"
    echo "   Run: claude"
    echo "   Then: /init"
fi

# Count custom commands
CMD_COUNT=$(find .claude/commands -name "*.md" 2>/dev/null | wc -l)
echo -e "${GREEN}✅ Custom commands: ${CMD_COUNT}${NC}"
if [ $CMD_COUNT -gt 0 ]; then
    echo "   Available commands:"
    find .claude/commands -name "*.md" -exec basename {} .md \; | sed 's/^/   - \//'
fi

# Check skills
SKILL_COUNT=$(find .claude/skills -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
if [ $SKILL_COUNT -gt 0 ]; then
    echo -e "${GREEN}✅ Skills configured: ${SKILL_COUNT}${NC}"
else
    echo -e "${BLUE}ℹ️  No skills configured (optional)${NC}"
fi

echo ""
echo "======================================================================"
echo -e "${BLUE}📚 Quick Start Guide${NC}"
echo "======================================================================"
echo ""
echo "1️⃣  Start Claude Code:"
echo "   cd /mnt/d/MCP/RAJDOLL"
echo "   claude"
echo ""
echo "2️⃣  Initialize project (first time only):"
echo "   > /init"
echo ""
echo "3️⃣  See available commands:"
echo "   > /help"
echo ""
echo "4️⃣  Try custom commands:"
echo "   > /llm-status         # Check LLM integration"
echo "   > /test-agent <name>  # Test specific agent"
echo "   > /debug-logs         # Analyze errors"
echo ""
echo "======================================================================"
echo -e "${BLUE}⌨️  Essential Shortcuts${NC}"
echo "======================================================================"
echo ""
echo "Ctrl+O       - Verbose mode (see Claude's thinking)"
echo "Shift+Tab    - Cycle permission modes"
echo "Esc+Esc      - Undo changes"
echo "Ctrl+B       - Background command"
echo "!<cmd>       - Direct bash command"
echo "@<file>      - Reference file"
echo ""
echo "======================================================================"
echo -e "${BLUE}📋 Custom Commands Available${NC}"
echo "======================================================================"
echo ""
echo "/test-agent <module>    - Test agent with coverage"
echo "/debug-logs             - Analyze Docker logs"
echo "/security-audit         - Security scan"
echo "/run-scan <url>         - Start pentest scan"
echo "/eval-metrics <job_id>  - Calculate metrics"
echo "/llm-status             - Check LLM status"
echo ""
echo "======================================================================"
echo -e "${GREEN}✅ Setup Complete!${NC}"
echo "======================================================================"
echo ""
echo "Next step: Run 'claude' to start"
echo ""
echo "📖 Full reference: cat CLAUDE_CODE_CHEATSHEET.md"
echo ""
