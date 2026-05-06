#!/usr/bin/env bash
# V5 validation: ensure no Juice Shop-specific paths reintroduced in agents/MCP servers.
set -u
PATTERNS='juice-shop|juiceshop|/rest/basket|/api/Feedback|/api/Users/[0-9]|/rest/user/login'
TARGET_DIRS='multi_agent_system/agents multi_agent_system/mcp_servers mcp_adapter'

# Skip pycache and tests; tests may legitimately reference Juice Shop in fixtures.
HITS=$(grep -rEn "$PATTERNS" $TARGET_DIRS 2>/dev/null \
  | grep -v __pycache__ \
  | grep -v '/tests/' \
  | grep -v '\.pyc:' || true)

if [ -n "$HITS" ]; then
  echo "FAIL: hardcoded Juice Shop references found:"
  echo "$HITS"
  exit 1
fi
echo "PASS: no hardcoded Juice Shop references in agents/mcp_servers/mcp_adapter"
