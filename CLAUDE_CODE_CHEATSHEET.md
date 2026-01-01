# 🚀 Claude Code Quick Reference Cheatsheet

**For:** Multi-Agent Penetration Testing Research
**Project:** RAJDOLL (Agentic AI dengan MCP untuk OWASP WSTG 4.2)

---

## ⚡ Quick Start (First Time)

```bash
cd /mnt/d/MCP/RAJDOLL
claude

# In Claude Code session:
> /init            # Setup project memory (creates .claude/CLAUDE.md)
> /help            # See all available commands
> /llm-status      # Verify LLM integration
```

---

## 📋 Custom Slash Commands (Your Project)

| Command | Description | Example |
|---------|-------------|---------|
| `/test-agent <module>` | Test agent with coverage | `/test-agent input_validation_agent` |
| `/debug-logs` | Analyze Docker logs, find errors | `/debug-logs` |
| `/security-audit` | Security scan for credential leaks | `/security-audit` |
| `/run-scan <url>` | Start pentest scan & monitor | `/run-scan http://juice-shop:3000` |
| `/eval-metrics <job_id>` | Calculate Precision/Recall/F1 | `/eval-metrics 1` |
| `/llm-status` | Check LLM integration status | `/llm-status` |

---

## 🔧 Built-in Commands

### Essential Commands
```
/help              - Show all available commands
/init              - Initialize project memory (CLAUDE.md)
/context           - Show remaining context space
/cost              - Show token usage & cost
/review            - Code review before commit
/rewind            - Undo last changes (Esc+Esc also works)
/resume [name]     - Resume previous session
/rename <name>     - Rename current session
```

### Advanced Commands
```
/agents            - Manage specialized subagents
/hooks             - Setup automation hooks
/mcp               - MCP server management
/sandbox           - Enable sandboxed execution
/compact           - Compress conversation, keep insights
/stats             - View usage statistics
```

---

## ⌨️ Keyboard Shortcuts

### Must-Know Shortcuts
```
Ctrl+O             - Toggle verbose mode (see Claude's thinking process)
Shift+Tab          - Cycle permission modes (Normal → Auto → Plan)
Ctrl+R             - Reverse search command history
Ctrl+L             - Clear screen (keep history)
Ctrl+B             - Send command to background
Esc+Esc            - Rewind (undo changes)
```

### Quick Operations
```
!<command>         - Direct bash (no Claude approval)
                     Example: !git status, !docker ps

@<path>            - Reference file/directory in prompt
                     Example: @multi_agent_system/agents/base_agent.py

#<text>            - Quick add to CLAUDE.md memory
                     Example: #Remember: LLM args merged in execute_tool()
```

---

## 🔄 Permission Modes (Shift+Tab to cycle)

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Normal** | Claude asks permission for file edits | Default, safe mode |
| **Auto-Accept** | Auto-approve all operations | Quick iterations, trust mode |
| **Plan** | Read-only, no file modifications | Architecture design, reviews |

**Pro Tip:** Use Plan Mode when:
- Designing new features
- Reviewing large refactors
- Exploring codebase without accidents

---

## 📂 File & Directory Operations

### Reference Files
```
> @multi_agent_system/agents/base_agent.py
  Show me the execute_tool() method

> @.env
  What's the current LLM configuration?

> @api/routes/
  List all API endpoints
```

### Glob Patterns
```
> @**/*.py
  Find all Python files

> @multi_agent_system/agents/*_agent.py
  Show all agent implementations

> @tests/**/*test*.py
  Find all test files
```

---

## 🧪 Testing Workflow

### Quick Test Pattern
```
> /test-agent input_validation_agent
  # Runs tests, shows coverage, suggests improvements

> Run all tests with coverage
  # pytest tests/ --cov=multi_agent_system --cov-report=html

> Show me the uncovered lines in base_agent.py
```

### Docker Test Pattern
```
> Start Docker services and run integration tests
  # docker-compose up -d && pytest tests/integration/

> /debug-logs
  # Analyze errors if tests fail
```

---

## 🐛 Debugging Workflow

### Quick Debug Pattern
```
> /debug-logs
  # Analyzes logs, finds errors, suggests fixes

> Show me the stack trace for the latest error
> Fix the <specific error> in <file>
> Verify fix by running the test again
```

### LLM Planning Debug
```
> /llm-status
  # Check LLM integration

> Check if LLM arguments are being applied in latest scan
  # Grep logs for "Using LLM arguments"

> python fix_validation.py
  # Validate LLM planning fix
```

---

## 🔒 Security Workflow

### Pre-Commit Security Check
```
> /security-audit
  # Scan for credential leaks, vulnerabilities

> /review
  # Code review

> Check for any .env files staged for commit
```

### Before Pushing Code
```
> /security-audit
> Ensure no API keys in code
> Check .gitignore includes .env
> /review
```

---

## 📊 Research Workflow

### Daily Development Pattern
```bash
# Morning: Resume yesterday's work
claude --resume agent-optimization

# Development cycle
> /test-agent <module>              # Test current code
> Implement <feature>               # Make changes
> /test-agent <module>              # Verify tests pass
> /security-audit                   # Security check
> /review                           # Code review
> !git add . && git commit -m "..."  # Commit

# End of day
> /rename agent-optimization-day2   # Name session for tomorrow
```

### Evaluation Workflow
```bash
# Start scan
> /run-scan http://juice-shop:3000

# Monitor (in another terminal)
python test_websocket.py --job-id 1

# After scan completes
> /eval-metrics 1
  # Calculates Precision, Recall, F1-Score

> Generate comprehensive evaluation report
  # Analysis + recommendations
```

---

## 💡 Pro Tips & Tricks

### 1. Use Extended Thinking for Complex Problems
```
> ultrathink: Why does the inter-agent communication timeout under load?
  Analyze code flow, identify bottlenecks, suggest 3 solutions.
```
**Tip:** Toggle `Ctrl+O` to see Claude's reasoning process.

### 2. Background Long Commands
```
> Build Docker images and start all services
  # While building (takes 5 min), press Ctrl+B to background
  # Continue asking other questions

> /tasks  # Check background task status
```

### 3. Quick Context Management
```
> /context
  # If context getting full:

> /compact
  # Compress conversation, keep important insights
```

### 4. Session Organization
```bash
# Name sessions by feature/task
> /rename llm-planning-fix
> /rename websocket-debugging
> /rename evaluation-metrics

# Later, resume by name
claude --resume llm-planning-fix
```

### 5. Memory Management
```
# Quick add to memory
> #LLM arguments: execute_tool() calls _before_tool_execution() at line 473

# View memory
> @.claude/CLAUDE.md
```

---

## 🎯 Common Research Scenarios

### Scenario 1: Implementing New Agent
```
> /rename new-agent-<name>
> Design a new agent for <WSTG category>
  - Follow BaseAgent pattern
  - Implement run() method
  - Add MCP tool integration
  - Generate comprehensive tests
> /test-agent <name>_agent
> /security-audit
> /review
```

### Scenario 2: Debugging Failed Scan
```
> /debug-logs
> Show me the last 50 lines of rajdoll-worker logs
> Analyze the error: <paste error>
> Fix the issue in <file>
> Verify fix: !docker-compose restart rajdoll-worker
```

### Scenario 3: Performance Optimization
```
> Analyze performance bottlenecks in the orchestrator
> Profile the code execution
> Suggest 3 optimization strategies
> Implement the best approach
> Benchmark improvements
```

### Scenario 4: Preparing for Demo
```
> /llm-status
  # Verify LLM working

> /run-scan http://juice-shop:3000
  # Start test scan

> Monitor via WebSocket
  # In another terminal: python test_websocket.py

> Generate professional PDF report
  # curl .../report?format=pdf -o demo_report.pdf
```

---

## 📚 File Structure Reference

```
.claude/
├── CLAUDE.md              # Project memory (auto-loaded)
├── commands/              # Custom slash commands
│   ├── test-agent.md
│   ├── debug-logs.md
│   ├── security-audit.md
│   ├── run-scan.md
│   ├── eval-metrics.md
│   └── llm-status.md
├── skills/                # Auto-discovered capabilities (optional)
│   └── docker-testing/
└── hooks/                 # Automation triggers (optional)
    └── post-edit.sh
```

---

## 🚨 Emergency Commands

### System Not Responding
```
> /rewind            # Undo last operation
> Esc+Esc            # Also undo
> Ctrl+C             # Interrupt current command
```

### Context Overflow
```
> /context           # Check space remaining
> /compact           # Compress conversation
# Or start new session and /resume later
```

### Lost Session
```
> /stats             # View all sessions
> /resume [name]     # Resume by name
claude --resume [name]  # From terminal
```

---

## 📊 Cost Management

### Monitor Usage
```
> /cost              # Current session cost
> /stats             # All sessions usage
> /context           # Context space remaining
```

### Optimize Costs
- Use **Plan Mode** for read-only exploration (less tokens)
- Use **Claude Haiku** for simple tasks (`--model haiku`)
- Use `/compact` regularly to reduce context
- Name sessions well for easy resume (avoid re-explaining)

---

## 🔗 Integration with Other Tools

### Git Integration
```
> /review            # Before commit
> !git status --short
> Create comprehensive commit message with:
  - Summary of changes
  - OWASP WSTG categories affected
  - Security implications
```

### Docker Integration
```
> !docker-compose ps  # Check services
> !docker-compose logs -f rajdoll-api  # Follow logs
> /debug-logs        # Analyze errors
```

### Testing Integration
```
> !pytest tests/ -v
> /test-agent <module>
> Show coverage report as HTML table
```

---

## 💾 Backup & Restore

### Save Session for Later
```
> /rename thesis-chapter-4-implementation
> /compact
# Session auto-saved

# Next day
claude --resume thesis-chapter-4-implementation
```

### Export Important Insights
```
> Summarize all key architectural decisions from this session
> Save to ARCHITECTURE_DECISIONS.md

> @.claude/CLAUDE.md
> Append today's learnings to project memory
```

---

## 🎓 Learning Resources

### Built-in Help
```
> /help                    # All commands
> /help <command>          # Specific command help
```

### Documentation
```
> Show me Claude Code documentation
> How do I create a custom skill?
> What's the difference between commands and skills?
```

---

## ✅ Quick Checklist: Starting Your Day

```
[ ] cd /mnt/d/MCP/RAJDOLL && claude
[ ] /resume <yesterday-session> OR /rename <today-task>
[ ] /llm-status (verify LLM working)
[ ] /context (check space)
[ ] !docker-compose ps (verify services)
[ ] Review CLAUDE.md for yesterday's notes
[ ] Start coding! 🚀
```

---

## ✅ Quick Checklist: Before Commit

```
[ ] /test-agent <changed-module>  (tests pass?)
[ ] /security-audit               (no credential leaks?)
[ ] /review                       (code quality OK?)
[ ] !git status                   (staged correctly?)
[ ] Create commit message
[ ] !git commit && git push
```

---

## ⚠️ Common Mistakes to Avoid

1. ❌ **Don't paste credentials in prompts**
   - Use: `@.env` to reference, not paste content

2. ❌ **Don't let context overflow**
   - Use: `/compact` regularly

3. ❌ **Don't forget to name sessions**
   - Use: `/rename` for important work

4. ❌ **Don't skip security checks**
   - Use: `/security-audit` before commits

5. ❌ **Don't ignore cost monitoring**
   - Use: `/cost` and `/context` regularly

---

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| Command not found | Run `/help` to see available commands |
| Permission denied | Check if in Plan Mode (Shift+Tab to Normal) |
| Context full | Run `/compact` or start new session |
| LLM not responding | Check `/llm-status`, restart LM Studio |
| High costs | Use Plan Mode or Haiku for simple tasks |

---

**Quick Reference Card:**
```
┌──────────────────────────────────────────────────┐
│  ESSENTIAL SHORTCUTS                             │
├──────────────────────────────────────────────────┤
│  Ctrl+O        - Verbose mode (see thinking)     │
│  Shift+Tab     - Cycle permission modes          │
│  Esc+Esc       - Undo changes                    │
│  Ctrl+B        - Background command              │
│  !cmd          - Direct bash                     │
│  @file         - Reference file                  │
│  #text         - Add to memory                   │
├──────────────────────────────────────────────────┤
│  MUST-USE COMMANDS                               │
├──────────────────────────────────────────────────┤
│  /init         - Setup project                   │
│  /test-agent   - Test with coverage              │
│  /debug-logs   - Analyze errors                  │
│  /security-audit - Security check                │
│  /llm-status   - Verify LLM working              │
│  /review       - Code review                     │
│  /compact      - Compress conversation           │
└──────────────────────────────────────────────────┘
```

---

**Happy coding with Claude Code! 🚀**

*For research questions: See `.claude/CLAUDE.md`*
*For bug fixes: Run `/debug-logs`*
*For testing: Run `/test-agent <module>`*
*For evaluation: Run `/eval-metrics <job_id>`*
