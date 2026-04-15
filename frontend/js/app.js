// ========================================
// RAJDOLL Frontend Application
// Multi-Agent Vulnerability Scanner UI
// ========================================

const API_BASE = window.location.origin + '/api';
let currentJobId = null;
let statusPollInterval = null;
let websocket = null;
let wsReconnectAttempts = 0;
let wsReconnectTimer = null;
const WS_MAX_RECONNECT_ATTEMPTS = 5;
const WS_BASE_DELAY_MS = 1000;

// DOM Elements
const scanForm = document.getElementById('scanForm');
const startBtn = document.getElementById('startBtn');
const cancelBtn = document.getElementById('cancelBtn');
const downloadBtn = document.getElementById('downloadBtn');
const downloadPdfBtn = document.getElementById('downloadPdfBtn');
const clearLogsBtn = document.getElementById('clearLogsBtn');

const statusPanel = document.getElementById('statusPanel');
const agentsPanel = document.getElementById('agentsPanel');
const monitorPanel = document.getElementById('monitorPanel');
const logsPanel = document.getElementById('logsPanel');

const jobIdDisplay = document.getElementById('jobId');
const scanStatusDisplay = document.getElementById('scanStatus');
const targetDisplay = document.getElementById('targetDisplay');
const progressText = document.getElementById('progressText');
const progressBar = document.getElementById('progressBar');
const agentsList = document.getElementById('agentsList');
const logsContainer = document.getElementById('logsContainer');

// ========== INITIALIZATION ==========
document.addEventListener('DOMContentLoaded', () => {
    scanForm.addEventListener('submit', handleScanSubmit);
    cancelBtn.addEventListener('click', handleCancelScan);
    downloadBtn.addEventListener('click', handleDownloadReport);
    downloadPdfBtn.addEventListener('click', handleDownloadPdfReport);
    clearLogsBtn.addEventListener('click', clearLogs);

    // HITL Live Monitor buttons
    document.getElementById('hitlSkipUrl').addEventListener('click', () => sendIntervention('skip_url'));
    document.getElementById('hitlCancelTest').addEventListener('click', () => sendIntervention('cancel_test'));
    document.getElementById('hitlSkipAgent').addEventListener('click', () => sendIntervention('skip_agent'));
    document.getElementById('hitlTechniqueSelect').addEventListener('change', (e) => {
        if (e.target.value) {
            sendIntervention('change_technique', e.target.value);
            e.target.value = '';
        }
    });

    addLog('[SYSTEM] RAJDOLL initialized. Ready to scan.', 'success');

    // Auto-restore last scan state on page load
    restoreLastScan();
});

// ========== AUTO-RESTORE LAST SCAN ==========
async function restoreLastScan() {
    try {
        const response = await fetch(`${API_BASE}/scans`);
        if (!response.ok) return;
        const scans = await response.json();
        if (!scans || scans.length === 0) return;

        // Get the most recent scan (API returns newest first)
        const lastScan = scans[0];
        const jobId = lastScan.job_id || lastScan.id;
        if (!jobId) return;

        currentJobId = jobId;
        jobIdDisplay.textContent = jobId;
        targetDisplay.textContent = lastScan.target || '-';

        // Show panels before populating
        statusPanel.style.display = 'block';
        agentsPanel.style.display = 'block';
        monitorPanel.style.display = 'block';
        logsPanel.style.display = 'block';
        document.getElementById('btnValidateFindings').style.display = 'inline-block';
        _findingsLoaded = false;
        document.getElementById('findingsValidationPanel').style.display = 'none';

        const status = lastScan.status || 'unknown';
        if (['queued', 'running'].includes(status)) {
            addLog(`[SYSTEM] Resuming monitoring of scan #${jobId}...`, 'info');
            await loadHistoricalLogs(jobId);
            startStatusPolling();
        } else {
            // Fetch full status to show agents and buttons
            const detailResp = await fetch(`${API_BASE}/scans/${jobId}`);
            if (detailResp.ok) {
                const data = await detailResp.json();
                updateStatusDisplay(data);
                if (data.agents) updateAgentsDisplay(data.agents);
                await loadHistoricalLogs(jobId);
                addLog(`[SYSTEM] Restored scan #${jobId} (${status})`, 'info');
            }
        }
    } catch (e) {
        console.log('[restoreLastScan] No previous scan found:', e.message);
    }
}

async function loadHistoricalLogs(jobId) {
    try {
        const resp = await fetch(`${API_BASE}/scans/${jobId}/events?limit=500`);
        if (!resp.ok) return;
        const events = await resp.json();
        if (!events || events.length === 0) return;
        addLog(`[SYSTEM] --- Log history for scan #${jobId} (${events.length} events) ---`, 'info');
        for (const e of events) {
            const agent = e.agent_name || 'SYSTEM';
            const level = e.level || 'info';
            addLog(`[${agent}] ${e.message}`, level);
        }
        addLog(`[SYSTEM] --- End of history ---`, 'info');
    } catch (err) {
        console.log('[loadHistoricalLogs] Failed:', err.message);
    }
}

// ========== CREDENTIALS TOGGLE ==========
function toggleCredentials() {
    const section = document.getElementById('credentialsSection');
    const icon = document.getElementById('credToggleIcon');
    const isHidden = section.style.display === 'none';
    section.style.display = isHidden ? 'block' : 'none';
    icon.textContent = isHidden ? '▼' : '▶';
}

// ========== SCAN OPERATIONS ==========
async function handleScanSubmit(e) {
    e.preventDefault();

    const targetUrl = document.getElementById('targetUrl').value.trim();
    const scanName = document.getElementById('scanName').value.trim();
    const credUsername = document.getElementById('credUsername').value.trim();
    const credPassword = document.getElementById('credPassword').value;

    if (!targetUrl) {
        addLog('[ERROR] Target URL is required', 'error');
        return;
    }

    // Build credentials payload if provided
    const credentials = (credUsername && credPassword)
        ? { username: credUsername, password: credPassword }
        : null;

    if (credentials) {
        addLog(`[SYSTEM] Credentials provided for: ${credUsername}`, 'info');
    }

    try {
        startBtn.disabled = true;
        startBtn.innerHTML = '<span class="btn-icon">⏳</span> Initializing...';
        addLog(`[SYSTEM] Initiating scan for ${targetUrl}...`, 'info');

        const payload = {
            target: targetUrl,
            full_wstg_coverage: true,
            ...(credentials && { credentials }),
        };

        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        currentJobId = data.job_id;
        
        addLog(`[SUCCESS] Scan created! Job ID: ${currentJobId}`, 'success');
        addLog('[SYSTEM] Starting multi-agent vulnerability assessment...', 'info');
        
        // Show status panels
        statusPanel.style.display = 'block';
        agentsPanel.style.display = 'block';
        monitorPanel.style.display = 'block';
        logsPanel.style.display = 'block';
        document.getElementById('btnValidateFindings').style.display = 'inline-block';
        _findingsLoaded = false;
        document.getElementById('findingsValidationPanel').style.display = 'none';

        // Update displays
        jobIdDisplay.textContent = currentJobId;
        targetDisplay.textContent = targetUrl;

        // Start monitoring
        startStatusPolling();
        connectWebSocket();
        
    } catch (error) {
        addLog(`[ERROR] Failed to create scan: ${error.message}`, 'error');
        startBtn.disabled = false;
        startBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
    }
}

async function handleCancelScan() {
    if (!currentJobId) return;
    
    if (!confirm('Are you sure you want to cancel this scan?')) return;
    
    try {
        cancelBtn.disabled = true;
        addLog(`[SYSTEM] Cancelling scan ${currentJobId}...`, 'warning');
        
        const response = await fetch(`${API_BASE}/scans/${currentJobId}/cancel`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        addLog(`[SUCCESS] ${data.message}`, 'success');
        
    } catch (error) {
        addLog(`[ERROR] Failed to cancel scan: ${error.message}`, 'error');
        cancelBtn.disabled = false;
    }
}

async function handleDownloadReport() {
    if (!currentJobId) return;
    
    try {
        addLog('[SYSTEM] Generating report...', 'info');
        
        const response = await fetch(`${API_BASE}/scans/${currentJobId}/report`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `RAJDOLL_Report_${currentJobId}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        addLog('[SUCCESS] Markdown report downloaded', 'success');
        
    } catch (error) {
        addLog(`[ERROR] Failed to download report: ${error.message}`, 'error');
    }
}

async function handleDownloadPdfReport() {
    if (!currentJobId) return;
    
    try {
        addLog('[SYSTEM] Generating PDF report... This may take a few seconds.', 'info');
        
        const response = await fetch(`${API_BASE}/scans/${currentJobId}/report/pdf`);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `RAJDOLL_Security_Report_Job${currentJobId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        addLog('[SUCCESS] PDF report downloaded successfully', 'success');
    } catch (error) {
        addLog(`[ERROR] PDF download failed: ${error.message}`, 'error');
    }
}

// ========== STATUS POLLING ==========
function startStatusPolling() {
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
    }
    
    // Poll immediately, then every 2 seconds
    updateStatus();
    statusPollInterval = setInterval(updateStatus, 2000);
}

async function updateStatus() {
    if (!currentJobId) return;
    
    try {
        const response = await fetch(`${API_BASE}/scans/${currentJobId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('[DEBUG] Poll response:', { status: data.status, agents: data.agents?.length, job_id: data.job_id });
        
        // Update status display
        updateStatusDisplay(data);
        
        // Update agents
        if (data.agents && data.agents.length > 0) {
            updateAgentsDisplay(data.agents);
        }
        
        // Handle terminal states
        if (['completed', 'failed', 'cancelled'].includes(data.status)) {
            console.log('[DEBUG] Terminal state detected:', data.status);
            stopStatusPolling();
            handleScanComplete(data.status);
        }
        
    } catch (error) {
        console.error('Status poll error:', error);
    }
}

function updateStatusDisplay(data) {
    // Update status badge
    const displayStatus = data.status || 'initializing';
    scanStatusDisplay.textContent = displayStatus.toUpperCase();
    scanStatusDisplay.className = `status-value status-badge ${displayStatus}`;
    
    // Calculate progress
    const totalAgents = data.agents ? data.agents.length : 11;
    const completedAgents = data.agents 
        ? data.agents.filter(a => ['completed', 'failed', 'skipped'].includes(a.status)).length 
        : 0;
    const progressPercent = totalAgents > 0 ? (completedAgents / totalAgents) * 100 : 0;
    
    progressText.textContent = `${completedAgents} / ${totalAgents} agents`;
    progressBar.style.width = `${progressPercent}%`;
    
    // Show/hide buttons based on status
    const status = data.status || 'queued';
    console.log('[DEBUG] Button visibility logic - status:', status);
    
    if (['queued', 'running'].includes(status)) {
        cancelBtn.style.display = 'inline-flex';
        downloadBtn.style.display = 'none';
        downloadPdfBtn.style.display = 'none';
        startBtn.disabled = true;
    } else if (status === 'completed') {
        console.log('[DEBUG] Setting buttons visible for completed status');
        cancelBtn.style.display = 'none';
        downloadBtn.style.display = 'inline-flex';
        downloadPdfBtn.style.display = 'inline-flex';
        startBtn.disabled = false;
        startBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
    } else {
        cancelBtn.style.display = 'none';
        downloadBtn.style.display = 'none';
        downloadPdfBtn.style.display = 'none';
        startBtn.disabled = false;
        startBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
    }
}

function updateAgentsDisplay(agents) {
    agentsList.innerHTML = '';
    
    agents.forEach(agent => {
        const agentItem = document.createElement('div');
        agentItem.className = 'agent-item';
        
        const icon = getAgentIcon(agent.status);
        const agentName = agent.agent_name || agent.agent_type || 'Unknown Agent';
        
        agentItem.innerHTML = `
            <span class="agent-icon ${agent.status}">${icon}</span>
            <div class="agent-info">
                <div class="agent-name">${formatAgentName(agentName)}</div>
                <div class="agent-status">${agent.status.toUpperCase()}</div>
            </div>
        `;
        
        agentsList.appendChild(agentItem);
    });
}

function getAgentIcon(status) {
    const icons = {
        'pending': '◯',
        'queued': '◉',
        'running': '◉',
        'completed': '✓',
        'failed': '✗',
        'skipped': '⊘'
    };
    return icons[status] || '◯';
}

function formatAgentName(agentType) {
    if (!agentType || typeof agentType !== 'string') {
        return 'Unknown Agent';
    }
    
    // Handle both snake_case and CamelCase
    return agentType
        .replace(/([A-Z])/g, ' $1') // Add space before capitals
        .replace(/_/g, ' ')           // Replace underscores with spaces
        .trim()
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ');
}

function stopStatusPolling() {
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
        statusPollInterval = null;
    }
}

function handleScanComplete(status) {
    if (status === 'completed') {
        addLog('[SUCCESS] Scan completed successfully!', 'success');
        addLog('[SYSTEM] Report ready for download.', 'info');
    } else if (status === 'failed') {
        addLog('[ERROR] Scan failed. Check logs for details.', 'error');
    } else if (status === 'cancelled') {
        addLog('[SYSTEM] Scan cancelled by user.', 'warning');
    }
    
    // Re-enable start button
    startBtn.disabled = false;
    startBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
    
    // Disconnect WebSocket and cancel pending reconnects
    if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }
    wsReconnectAttempts = WS_MAX_RECONNECT_ATTEMPTS; // Prevent reconnect during close
    if (websocket) {
        websocket.close();
    }
}

// ========== WEBSOCKET LOGS ==========
function connectWebSocket() {
    if (!currentJobId) {
        console.warn('[WebSocket] No currentJobId, skipping connection');
        return;
    }

    // Reset reconnect state on fresh connection
    wsReconnectAttempts = 0;
    if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }

    _createWebSocket();
}

function _createWebSocket() {
    if (!currentJobId) return;

    // Close existing connection
    if (websocket && websocket.readyState !== WebSocket.CLOSED) {
        console.log('[WebSocket] Closing existing connection');
        websocket.close();
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/${currentJobId}`;

    const isReconnect = wsReconnectAttempts > 0;
    console.log(`[WebSocket] ${isReconnect ? 'Reconnecting' : 'Connecting'} to: ${wsUrl} (attempt ${wsReconnectAttempts + 1})`);
    if (!isReconnect) {
        addLog(`[SYSTEM] Connecting to real-time log stream (Job ${currentJobId})...`, 'info');
    }

    try {
        let suppressServerConnectedMessage = false;
        websocket = new WebSocket(wsUrl);

        websocket.onopen = () => {
            console.log('[WebSocket] Connection OPENED');
            if (isReconnect) {
                addLog('[SYSTEM] Reconnected to log stream', 'success');
            } else {
                addLog('[SYSTEM] Connected to log stream', 'success');
            }
            suppressServerConnectedMessage = true;
            wsReconnectAttempts = 0; // Reset on successful connection
        };

        websocket.onmessage = (event) => {
            console.log('[WebSocket] Message received:', event.data);
            try {
                const data = JSON.parse(event.data);

                // Avoid duplicate "Connected" lines: UI logs on open, server also sends a handshake log.
                if (
                    suppressServerConnectedMessage &&
                    data.type === 'log' &&
                    data.agent === 'SYSTEM' &&
                    data.message === 'Connected to log stream'
                ) {
                    return;
                }

                if (data.type === 'log') {
                    addLog(`[${data.agent || 'SYSTEM'}] ${data.message}`, data.level || 'info');
                } else if (data.type === 'agent_update') {
                    addLog(`[AGENT] ${data.agent}: ${data.status}`, 'info');
                } else if (data.type === 'execution_status') {
                    updateExecutionMonitor(data);
                } else if (data.type === 'agent_checkpoint') {
                    showAgentCheckpoint(data);
                } else if (data.type === 'pre_agent_checkpoint') {
                    showPreAgentCheckpoint(data.data);
                } else if (data.type === 'high_risk_tool_approval') {
                    showHighRiskReview(data.data);
                }
            } catch (error) {
                console.error('[WebSocket] Message parse error:', error);
                addLog(`[WebSocket] Raw message: ${event.data}`, 'info');
            }
        };

        websocket.onerror = (error) => {
            console.error('[WebSocket] ERROR:', error);
        };

        websocket.onclose = (event) => {
            console.log(`[WebSocket] Connection CLOSED - Code: ${event.code}, Reason: ${event.reason}`);

            // Don't reconnect if scan is in a terminal state or was intentionally closed (code 1000)
            const statusText = scanStatusDisplay ? scanStatusDisplay.textContent.toLowerCase() : '';
            const isTerminal = ['completed', 'failed', 'cancelled'].some(s => statusText.includes(s));

            if (event.code === 1000 || isTerminal) {
                addLog(`[SYSTEM] Log stream closed`, 'info');
                return;
            }

            // Attempt reconnect with exponential backoff
            if (wsReconnectAttempts < WS_MAX_RECONNECT_ATTEMPTS) {
                wsReconnectAttempts++;
                const delay = WS_BASE_DELAY_MS * Math.pow(2, wsReconnectAttempts - 1);
                addLog(`[SYSTEM] Log stream disconnected. Reconnecting in ${delay / 1000}s (attempt ${wsReconnectAttempts}/${WS_MAX_RECONNECT_ATTEMPTS})...`, 'warning');
                wsReconnectTimer = setTimeout(() => _createWebSocket(), delay);
            } else {
                addLog('[SYSTEM] Log stream disconnected. Max reconnect attempts reached — using status polling only.', 'warning');
            }
        };
    } catch (error) {
        console.error('[WebSocket] Failed to create WebSocket:', error);
        addLog(`[ERROR] Failed to create WebSocket: ${error.message}`, 'error');
    }
}

// ========== HITL LIVE EXECUTION MONITOR ==========
function updateExecutionMonitor(data) {
    const monAgent = document.getElementById('monAgent');
    const monUrl = document.getElementById('monUrl');
    const monTestType = document.getElementById('monTestType');
    const monProgress = document.getElementById('monProgress');
    const monTechniques = document.getElementById('monTechniques');
    const monFindings = document.getElementById('monFindings');
    const monProgressBar = document.getElementById('monProgressBar');
    const monitorBadge = document.getElementById('monitorBadge');

    if (data.agent) monAgent.textContent = formatAgentName(data.agent);

    if (data.phase === 'url_testing') {
        monUrl.textContent = data.current_url || '-';
        monTestType.textContent = (data.tests_for_url || []).join(', ').toUpperCase() || '-';
        monProgress.textContent = `URL ${data.current_url_index || 0} / ${data.total_urls || 0}`;
        monFindings.textContent = data.findings_so_far || 0;
        const pct = data.total_urls ? (data.current_url_index / data.total_urls) * 100 : 0;
        monProgressBar.style.width = `${pct}%`;
        monitorBadge.style.display = 'none';
    } else if (data.phase === 'react_loop') {
        monUrl.textContent = data.url || '-';
        monTestType.textContent = (data.test_type || '-').toUpperCase();
        monProgress.textContent = `Iteration ${data.iteration || 0} / ${data.max_iterations || 0}`;
        monTechniques.textContent = (data.techniques_tried || []).join(', ') || '-';
        monFindings.textContent = data.findings_count || 0;
        const pct = data.max_iterations ? (data.iteration / data.max_iterations) * 100 : 0;
        monProgressBar.style.width = `${pct}%`;

        // Loop detection: iteration >= 2 with 0 findings
        if ((data.iteration || 0) >= 2 && (data.findings_count || 0) === 0) {
            monitorBadge.style.display = 'inline-block';
        } else {
            monitorBadge.style.display = 'none';
        }
    }
}

async function sendIntervention(action, technique) {
    if (!currentJobId) return;

    const body = { action, reason: 'User intervention from dashboard' };
    if (technique) body.technique = technique;

    try {
        addLog(`[HITL] Sending intervention: ${action}${technique ? ' (' + technique + ')' : ''}`, 'warning');
        const response = await fetch(`${API_BASE}/scans/${currentJobId}/intervene`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        addLog(`[HITL] ${data.message}`, 'success');
    } catch (error) {
        addLog(`[HITL] Intervention failed: ${error.message}`, 'error');
    }
}

// ========== LOGGING ==========
function addLog(message, level = 'info') {
    const logLine = document.createElement('div');
    logLine.className = `log-line ${level}`;
    
    const timestamp = new Date().toLocaleTimeString();
    logLine.textContent = `[${timestamp}] ${message}`;
    
    logsContainer.appendChild(logLine);
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

function clearLogs() {
    logsContainer.innerHTML = '<div class="log-line">[SYSTEM] Logs cleared.</div>';
}

// ========== AGENT HITL CHECKPOINT ==========

let currentCheckpointId = null;
let _preAgentCheckpointId = null;
let _highRiskApprovalId = null;

function showAgentCheckpoint(data) {
    const panel = document.getElementById('checkpointPanel');
    if (!panel) return;

    // Avoid re-showing the same checkpoint
    if (currentCheckpointId === data.checkpoint_id) return;
    currentCheckpointId = data.checkpoint_id;

    panel.style.display = 'block';

    // Scroll checkpoint into view
    panel.scrollIntoView({ behavior: 'smooth', block: 'center' });

    // Agent name + index
    const el = (id) => document.getElementById(id);
    el('cpAgentName').textContent = data.completed_agent || '-';
    const remaining = data.remaining_agents || [];
    const totalAgents = (data.agent_index || 0) + remaining.length + 1;
    el('cpAgentIndex').textContent = `Step ${(data.agent_index || 0) + 1}/${totalAgents}`;

    // Severity counts
    const sev = data.findings_by_severity || {};
    el('cpCritical').textContent = `${sev.critical || 0} Critical`;
    el('cpHigh').textContent = `${sev.high || 0} High`;
    el('cpMedium').textContent = `${sev.medium || 0} Medium`;
    el('cpLow').textContent = `${sev.low || 0} Low`;

    // Key findings
    const kfContainer = el('cpKeyFindings');
    kfContainer.innerHTML = '';
    const keyFindings = data.key_findings || [];
    if (keyFindings.length === 0) {
        kfContainer.innerHTML = '<div class="cp-finding-item" style="color:var(--text-muted);">No critical/high findings</div>';
    } else {
        keyFindings.forEach(f => {
            const div = document.createElement('div');
            div.className = 'cp-finding-item';
            div.innerHTML = `<span class="cp-finding-sev" style="color:${f.severity === 'critical' ? '#ff0040' : '#ff6400'}">[${f.severity}]</span> ${escapeHtml(f.title)}`;
            kfContainer.appendChild(div);
        });
    }

    // Summary
    const summary = data.agent_summary || 'No summary available';
    el('cpSummaryText').textContent = summary.length > 800 ? summary.substring(summary.length - 800) : summary;

    // Recommendations
    const recList = el('cpRecList');
    recList.innerHTML = '';
    const recs = data.recommendations || [];
    if (recs.length === 0) {
        recList.innerHTML = '<div class="cp-rec-item" style="color:var(--text-muted);">No specific recommendations</div>';
    } else {
        recs.forEach(r => {
            const div = document.createElement('div');
            div.className = 'cp-rec-item';
            div.innerHTML = `<span class="cp-rec-agent">${escapeHtml(r.agent)}</span> — <span class="cp-rec-reason">${escapeHtml(r.reason)}</span>`;
            recList.appendChild(div);
        });
    }

    // Next agent
    el('cpNextAgent').textContent = data.next_agent || 'None (scan complete)';
    el('cpRemaining').textContent = `(${remaining.length} remaining)`;

    // Populate reorder dropdown
    const reorderSelect = el('cpReorderSelect');
    reorderSelect.innerHTML = '<option value="">Select agent...</option>';
    remaining.forEach(agent => {
        const opt = document.createElement('option');
        opt.value = agent;
        opt.textContent = agent;
        reorderSelect.appendChild(opt);
    });

    // Add log entry
    addLog(`[HITL] Checkpoint: ${data.completed_agent} complete (${data.findings_count} findings). Awaiting your decision...`, 'warning');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function respondToCheckpoint(action, overrides = {}) {
    if (!currentCheckpointId) return;

    const notes = document.getElementById('cpUserNotes')?.value || null;
    const body = {
        action: action,
        user_notes: notes,
        next_agent_override: overrides.next_agent_override || null,
        skip_agents: overrides.skip_agents || null,
    };

    try {
        const resp = await fetch(`/api/hitl/agent-checkpoint/${currentCheckpointId}/respond`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const result = await resp.json();

        if (resp.ok) {
            addLog(`[HITL] Checkpoint response: ${action}`, 'success');
            // Hide the checkpoint panel
            document.getElementById('checkpointPanel').style.display = 'none';
            currentCheckpointId = null;
        } else {
            addLog(`[HITL] Error: ${result.detail || 'Unknown error'}`, 'error');
        }
    } catch (err) {
        addLog(`[HITL] Network error: ${err.message}`, 'error');
    }
}

// ========== DIRECTOR PRE-AGENT CHECKPOINT ==========

const _VALID_COMMANDS = ['FOCUS', 'SKIP', 'INCLUDE', 'EXCLUDE', 'DEPTH', 'NOTE'];
const _VALID_DEPTH = ['shallow', 'normal', 'deep'];

function validateDirectiveText(text) {
    const errors = [];
    if (!text.trim()) return errors;
    const lines = text.trim().split('\n').filter(l => l.trim());
    if (lines.length > 5) errors.push('Too many commands (max 5)');
    lines.forEach((line, i) => {
        line = line.trim();
        if (!line) return;
        if (!line.includes(':')) { errors.push(`Line ${i+1}: missing colon`); return; }
        const [cmd, ...rest] = line.split(':');
        const cmdUpper = cmd.trim().toUpperCase();
        const value = rest.join(':').trim();
        if (!_VALID_COMMANDS.includes(cmdUpper)) errors.push(`Line ${i+1}: unknown command '${cmdUpper}'`);
        if (!value) errors.push(`Line ${i+1}: empty value for ${cmdUpper}`);
        if (cmdUpper === 'DEPTH' && !_VALID_DEPTH.includes(value.toLowerCase()))
            errors.push(`Line ${i+1}: DEPTH must be shallow, normal, or deep`);
    });
    return errors;
}

function showPreAgentCheckpoint(d) {
    _preAgentCheckpointId = d.checkpoint_id;

    document.getElementById('pre-agent-name').textContent = d.next_agent || '';
    document.getElementById('pre-agent-summary').textContent = d.cumulative_summary || 'No prior findings.';

    const toolsList = document.getElementById('pre-agent-tools-list');
    toolsList.innerHTML = '';
    const highRiskTools = ['run_sqlmap', 'test_xss_dalfox', 'run_nikto', 'run_nmap', 'test_tls_configuration'];
    (d.planned_tools || []).forEach(t => {
        const li = document.createElement('li');
        const isHR = highRiskTools.includes(t);
        li.innerHTML = isHR
            ? `<span style="color:#e74c3c">⚠ <strong>${t}</strong> [HIGH_RISK]</span>`
            : `<span>${t}</span>`;
        toolsList.appendChild(li);
    });

    document.getElementById('pre-agent-directive').value = '';
    document.getElementById('pre-agent-directive-errors').textContent = '';
    document.getElementById('pre-agent-panel').style.display = 'block';
    document.getElementById('high-risk-panel').style.display = 'none';

    document.getElementById('pre-agent-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
    addLog(`[HITL] PRE-AGENT checkpoint: about to run ${d.next_agent}. Awaiting Director...`, 'warning');
}

async function respondPreAgent(action, useDirective) {
    if (!_preAgentCheckpointId) return;
    let directiveText = null;
    if (useDirective) {
        directiveText = document.getElementById('pre-agent-directive').value;
        const errors = validateDirectiveText(directiveText);
        const errEl = document.getElementById('pre-agent-directive-errors');
        if (errors.length > 0) {
            errEl.textContent = errors.join(' | ');
            return;
        }
        errEl.textContent = '';
    }
    const body = { action, user_notes: null };
    if (directiveText && directiveText.trim()) body.directive_text = directiveText;
    try {
        const resp = await fetch(`/api/hitl/pre-agent-checkpoint/${_preAgentCheckpointId}/respond`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (resp.ok) {
            addLog(`[HITL] Director: ${action} for pre-agent checkpoint`, 'success');
            document.getElementById('pre-agent-panel').style.display = 'none';
            _preAgentCheckpointId = null;
        } else {
            const err = await resp.json();
            document.getElementById('pre-agent-directive-errors').textContent =
                'Error: ' + (err.detail || JSON.stringify(err));
        }
    } catch (e) {
        addLog(`[HITL] Pre-agent respond error: ${e.message}`, 'error');
    }
}

// ========== DIRECTOR HIGH_RISK TOOL REVIEW ==========

function showHighRiskReview(d) {
    _highRiskApprovalId = d.approval_id;

    document.getElementById('high-risk-tool-name').textContent = d.tool_name || '';
    document.getElementById('high-risk-agent-name').textContent = d.agent_name || '';
    const argsJson = JSON.stringify(d.generated_args || {}, null, 2);
    document.getElementById('high-risk-args-display').textContent = argsJson;
    document.getElementById('high-risk-args-edit').value = argsJson;
    document.getElementById('high-risk-args-edit').style.display = 'none';
    document.getElementById('high-risk-args-display').style.display = 'block';
    document.getElementById('btn-edit-args').textContent = '✎ Edit & Run';
    document.getElementById('high-risk-panel').style.display = 'block';
    document.getElementById('pre-agent-panel').style.display = 'none';

    document.getElementById('high-risk-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
    addLog(`[HITL] HIGH_RISK tool paused: ${d.tool_name} (${d.agent_name}). Review required.`, 'warning');
}

function toggleHighRiskEdit() {
    const display = document.getElementById('high-risk-args-display');
    const edit = document.getElementById('high-risk-args-edit');
    const btn = document.getElementById('btn-edit-args');
    if (edit.style.display === 'none') {
        display.style.display = 'none';
        edit.style.display = 'block';
        btn.textContent = '✓ Confirm edits';
    } else {
        try { JSON.parse(edit.value); } catch(e) {
            alert('Invalid JSON: ' + e.message); return;
        }
        display.textContent = edit.value;
        display.style.display = 'block';
        edit.style.display = 'none';
        btn.textContent = '✎ Edit & Run';
    }
}

async function respondHighRisk(action) {
    if (!_highRiskApprovalId) return;
    const body = { action };
    if (document.getElementById('high-risk-args-edit').style.display !== 'none') {
        const editVal = document.getElementById('high-risk-args-edit').value;
        try {
            body.action = 'edit';
            body.approved_arguments = JSON.parse(editVal);
        } catch(e) { alert('Invalid JSON: ' + e.message); return; }
    }
    try {
        const resp = await fetch(`/api/hitl/tool-approval/${_highRiskApprovalId}/director-review`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (resp.ok) {
            addLog(`[HITL] Director: ${body.action} for HIGH_RISK tool`, 'success');
            document.getElementById('high-risk-panel').style.display = 'none';
            _highRiskApprovalId = null;
        } else {
            const err = await resp.json();
            addLog(`[HITL] HIGH_RISK respond error: ${err.detail || JSON.stringify(err)}`, 'error');
        }
    } catch (e) {
        addLog(`[HITL] HIGH_RISK respond error: ${e.message}`, 'error');
    }
}

function showDirectiveHelp() {
    alert(
        'Director Directive Commands:\n\n' +
        'FOCUS: <path>      — Focus agent on specific endpoint\n' +
        'SKIP: <tool_name>  — Skip a planned tool\n' +
        'INCLUDE: <url>     — Add URL to agent scope\n' +
        'EXCLUDE: <pattern> — Exclude URL pattern\n' +
        'DEPTH: shallow|normal|deep  — Set scan intensity\n' +
        'NOTE: <text>       — Inject context note\n\n' +
        'Max 5 commands. One per line.'
    );
}

// Bind checkpoint action buttons
document.addEventListener('DOMContentLoaded', () => {
    const cpProceed = document.getElementById('cpProceed');
    const cpSkipNext = document.getElementById('cpSkipNext');
    const cpAuto = document.getElementById('cpAuto');
    const cpAbort = document.getElementById('cpAbort');
    const cpReorderConfirm = document.getElementById('cpReorderConfirm');
    const cpReorderSection = document.getElementById('cpReorderSection');

    if (cpProceed) cpProceed.addEventListener('click', () => respondToCheckpoint('proceed'));
    if (cpSkipNext) cpSkipNext.addEventListener('click', () => respondToCheckpoint('skip_next'));
    if (cpAuto) cpAuto.addEventListener('click', () => {
        if (confirm('Disable checkpoints and run all remaining agents automatically?')) {
            respondToCheckpoint('auto');
        }
    });
    if (cpAbort) cpAbort.addEventListener('click', () => {
        if (confirm('Abort the scan? This will stop all remaining agents.')) {
            respondToCheckpoint('abort');
        }
    });

    // Toggle reorder section
    const cpSkipNextBtn = document.getElementById('cpSkipNext');
    if (cpSkipNextBtn) {
        // Show reorder section on right-click or long-press
        cpSkipNextBtn.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            if (cpReorderSection) {
                cpReorderSection.style.display = cpReorderSection.style.display === 'none' ? 'flex' : 'none';
            }
        });
    }

    if (cpReorderConfirm) {
        cpReorderConfirm.addEventListener('click', () => {
            const selected = document.getElementById('cpReorderSelect')?.value;
            if (selected) {
                respondToCheckpoint('reorder', { next_agent_override: selected });
            } else {
                alert('Select an agent to run next');
            }
        });
    }
});

// ── Findings Validation ───────────────────────────────────────────────────

let _findingsLoaded = false;

function toggleFindingsPanel() {
    const panel = document.getElementById('findingsValidationPanel');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        if (!_findingsLoaded) loadFindings();
    } else {
        panel.style.display = 'none';
    }
}

async function loadFindings() {
    if (!currentJobId) return;
    const resp = await fetch(`${API_BASE}/scans/${currentJobId}/findings`);
    if (!resp.ok) return;
    const findings = await resp.json();
    renderFindingsList(findings);
    _findingsLoaded = true;
}

function renderFindingsList(findings) {
    const container = document.getElementById('findingsList');
    const total = findings.length;
    const reviewed = findings.filter(f => f.is_true_positive !== null && f.is_true_positive !== undefined).length;
    document.getElementById('validationProgress').textContent =
        `${reviewed}/${total} reviewed`;

    container.innerHTML = findings.map(f => {
        const sevColor = {critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#6b7280'}[f.severity] || '#6b7280';
        const tpActive  = f.is_true_positive === true  ? 'background:#16a34a;color:#fff;' : '';
        const fpActive  = f.is_true_positive === false ? 'background:#dc2626;color:#fff;' : '';
        return `
        <div style="display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid var(--border-color);" data-finding-id="${f.id}">
          <span style="font-size:10px;font-weight:700;color:${sevColor};min-width:56px;">${f.severity.toUpperCase()}</span>
          <span style="flex:1;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(f.title)}">${escapeHtml(f.title)}</span>
          <button onclick="markFinding(${f.id}, true)"  style="font-size:11px;padding:2px 8px;border:1px solid #16a34a;border-radius:4px;cursor:pointer;${tpActive}">TP</button>
          <button onclick="markFinding(${f.id}, false)" style="font-size:11px;padding:2px 8px;border:1px solid #dc2626;border-radius:4px;cursor:pointer;${fpActive}">FP</button>
        </div>`;
    }).join('');
}

function escapeHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function markFinding(findingId, isTP) {
    const token = localStorage.getItem('adminToken') || '';
    const resp = await fetch(`${API_BASE}/findings/${findingId}/validate`, {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-Admin-Token': token},
        body: JSON.stringify({is_true_positive: isTP}),
    });
    if (resp.ok) {
        _findingsLoaded = false;
        loadFindings();
    } else {
        alert('Validation failed — check admin token in browser localStorage (key: adminToken)');
    }
}

// ========== CLEANUP ==========
window.addEventListener('beforeunload', () => {
    stopStatusPolling();
    if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }
    wsReconnectAttempts = WS_MAX_RECONNECT_ATTEMPTS; // Prevent reconnect during close
    if (websocket) {
        websocket.close();
    }
});
