// ========================================
// RAJDOLL Frontend Application
// Multi-Agent Vulnerability Scanner UI
// ========================================

const API_BASE = window.location.origin + '/api';
let currentJobId = null;
let statusPollInterval = null;
let websocket = null;

// DOM Elements
const scanForm = document.getElementById('scanForm');
const startBtn = document.getElementById('startBtn');
const cancelBtn = document.getElementById('cancelBtn');
const downloadBtn = document.getElementById('downloadBtn');
const downloadPdfBtn = document.getElementById('downloadPdfBtn');
const clearLogsBtn = document.getElementById('clearLogsBtn');

const statusPanel = document.getElementById('statusPanel');
const agentsPanel = document.getElementById('agentsPanel');
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
    
    // Disconnect WebSocket
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
    
    // Close existing connection
    if (websocket && websocket.readyState !== WebSocket.CLOSED) {
        console.log('[WebSocket] Closing existing connection');
        websocket.close();
    }
    
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/${currentJobId}`;
    
    console.log(`[WebSocket] Attempting to connect to: ${wsUrl}`);
    addLog(`[SYSTEM] Connecting to real-time log stream (Job ${currentJobId})...`, 'info');
    
    try {
        let suppressServerConnectedMessage = false;
        websocket = new WebSocket(wsUrl);
        
        websocket.onopen = () => {
            console.log('[WebSocket] Connection OPENED');
            addLog('[SYSTEM] ✅ Connected to log stream', 'success');
            suppressServerConnectedMessage = true;
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
                }
            } catch (error) {
                console.error('[WebSocket] Message parse error:', error);
                addLog(`[WebSocket] Raw message: ${event.data}`, 'info');
            }
        };
        
        websocket.onerror = (error) => {
            console.error('[WebSocket] ERROR:', error);
            addLog('[ERROR] ❌ WebSocket connection error - check browser console', 'error');
        };
        
        websocket.onclose = (event) => {
            console.log(`[WebSocket] Connection CLOSED - Code: ${event.code}, Reason: ${event.reason}`);
            addLog(`[SYSTEM] ⚠️ Log stream disconnected (code: ${event.code})`, 'warning');
        };
    } catch (error) {
        console.error('[WebSocket] Failed to create WebSocket:', error);
        addLog(`[ERROR] Failed to create WebSocket: ${error.message}`, 'error');
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
    if (websocket) {
        websocket.close();
    }
});
