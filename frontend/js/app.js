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
});

// ========== SCAN OPERATIONS ==========
async function handleScanSubmit(e) {
    e.preventDefault();
    
    const targetUrl = document.getElementById('targetUrl').value.trim();
    const scanName = document.getElementById('scanName').value.trim();
    
    if (!targetUrl) {
        addLog('[ERROR] Target URL is required', 'error');
        return;
    }
    
    try {
        startBtn.disabled = true;
        startBtn.innerHTML = '<span class="btn-icon">⏳</span> Initializing...';
        addLog(`[SYSTEM] Initiating scan for ${targetUrl}...`, 'info');
        
        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: targetUrl,
                user_email: "researcher@telkomuniversity.ac.id",
                full_wstg_coverage: true  // ✅ COMPREHENSIVE MODE: 10x more test cases
            })
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
