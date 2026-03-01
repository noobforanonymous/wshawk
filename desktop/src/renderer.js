/**
 * WSHawk Renderer - Premium Linear-style Aesthetic
 */

// Window Controls
document.getElementById('btn-minimize')?.addEventListener('click', () => window.api.send('window:minimize'));
document.getElementById('btn-maximize')?.addEventListener('click', () => window.api.send('window:maximize'));
document.getElementById('btn-close')?.addEventListener('click', () => window.api.send('window:close'));

const targetUrlInput = document.getElementById('target-url');
const scanBtn = document.getElementById('scan-btn');
const connPill = document.getElementById('conn-pill');
const connText = document.getElementById('conn-text');

const valVulns = document.getElementById('val-vulns');
const valMsgs = document.getElementById('val-msgs');
const valRisk = document.getElementById('val-risk');
const valProgress = document.getElementById('val-progress');
const findingsContainer = document.getElementById('findings-container');
const systemLog = document.getElementById('system-log');
const historyTbody = document.getElementById('history-tbody');
const historyCount = document.getElementById('history-count');

// Navigation
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const toggleModeBtn = document.getElementById('toggle-mode-btn');
const advancedMenu = document.getElementById('advanced-menu');
const modeBadge = document.getElementById('mode-badge');
const btnModeText = document.getElementById('btn-mode-text');

let isAdvanced = false;

navItems.forEach(btn => {
    btn.addEventListener('click', () => {
        navItems.forEach(n => n.classList.remove('active'));
        views.forEach(v => {
            v.classList.remove('active', 'slide-up');
        });

        btn.classList.add('active');
        const target = btn.getAttribute('data-target');
        const view = document.getElementById(`view-${target}`);

        if (view) {
            view.classList.add('active');
            void view.offsetWidth; // trigger reflow
            view.classList.add('slide-up');
        }
    });
});

// Mode: 'standard' | 'advanced' | 'web'
let currentMode = 'standard';
const webMenu = document.getElementById('web-menu');

toggleModeBtn.addEventListener('click', () => {
    if (currentMode === 'standard') {
        currentMode = 'advanced';
        modeBadge.textContent = 'ADVANCED';
        modeBadge.className = 'badge advanced';
        btnModeText.textContent = 'Switch to Web';
        advancedMenu.style.display = 'block';
        webMenu.style.display = 'none';
    } else if (currentMode === 'advanced') {
        currentMode = 'web';
        modeBadge.textContent = 'WEB';
        modeBadge.className = 'badge web';
        btnModeText.textContent = 'Switch to Standard';
        advancedMenu.style.display = 'none';
        webMenu.style.display = 'block';
    } else {
        currentMode = 'standard';
        modeBadge.textContent = 'STANDARD';
        modeBadge.className = 'badge standard';
        btnModeText.textContent = 'Switch to Advanced';
        advancedMenu.style.display = 'none';
        webMenu.style.display = 'none';
        document.querySelector('.nav-item[data-target="dashboard"]').click();
    }
});

// Project Management State
let currentProject = {
    url: '',
    vulns: 0,
    msgs: 0,
    findingsHTML: '',
    logsHTML: '',
    historyHTML: ''
};

const welcomeModal = document.getElementById('welcome-modal');
const mainApp = document.getElementById('main-app');

function applyProjectState(data) {
    currentProject = data || {
        url: '', vulns: 0, msgs: 0, findingsHTML: '', logsHTML: '', historyHTML: ''
    };
    targetUrlInput.value = currentProject.url || '';
    valVulns.innerText = currentProject.vulns || '0';
    valMsgs.innerText = currentProject.msgs || '0';
    msgCount = currentProject.msgs || 0;
    historyCount.innerText = `${msgCount} frames`;

    if (currentProject.findingsHTML) {
        findingsContainer.innerHTML = currentProject.findingsHTML;
    } else {
        findingsContainer.innerHTML = '<div class="empty-state">No vulnerabilities detected on the target.</div>';
        valRisk.innerText = 'SECURE';
        valRisk.className = 'metric-value text-safe';
        valProgress.style.width = '0%';
    }

    if (currentProject.logsHTML) {
        systemLog.innerHTML = currentProject.logsHTML;
    } else {
        systemLog.innerHTML = '<div class="log-line text-muted">System initialization complete.</div>';
    }

    if (currentProject.historyHTML) {
        historyTbody.innerHTML = currentProject.historyHTML;
    } else {
        historyTbody.innerHTML = '<tr class="empty-tr"><td colspan="5">Awaiting traffic capture...</td></tr>';
    }

    welcomeModal.style.display = 'none';
    mainApp.style.display = 'flex';
}

function gatherProjectState() {
    return {
        url: targetUrlInput.value,
        vulns: parseInt(valVulns.innerText) || 0,
        msgs: msgCount,
        findingsHTML: findingsContainer.innerHTML,
        logsHTML: systemLog.innerHTML,
        historyHTML: historyTbody.innerHTML
    };
}

document.getElementById('btn-new-project').addEventListener('click', () => {
    applyProjectState(null); // empty state
});

document.getElementById('btn-open-project').addEventListener('click', async () => {
    const res = await window.api.invoke('dialog:openProject');
    if (res.success) {
        applyProjectState(res.data);
    } else if (!res.canceled) {
        alert('Failed to load project: ' + res.error);
    }
});

document.getElementById('btn-save-project').addEventListener('click', async () => {
    const data = gatherProjectState();
    const res = await window.api.invoke('dialog:saveProject', data);
    if (!res.success && !res.canceled) {
        alert('Failed to save project: ' + res.error);
    } else if (res.success) {
        appendLog('info', `Project saved successfully to ${res.path}`);
    }
});

document.getElementById('btn-export-report').addEventListener('click', async () => {
    const data = gatherProjectState();

    const htmlReport = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WSHawk Security Report</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
            h1 { color: #ef4444; border-bottom: 1px solid #334155; padding-bottom: 10px; }
            .metric { display: inline-block; padding: 20px; background: #1e293b; margin-right: 20px; border-radius: 8px; border: 1px solid #334155; }
            .metric strong { display: block; font-size: 24px; color: #60a5fa; }
            h2 { margin-top: 40px; color: #38bdf8; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
            th { background: #1e293b; }
            .finding-card { background: #1e293b; padding: 20px; margin-bottom: 20px; border-radius: 8px; border-left: 4px solid #ef4444; }
            .f-title { display: flex; justify-content: space-between; font-weight: bold; font-size: 18px; margin-bottom: 10px; }
            .f-desc { margin-bottom: 10px; color: #cbd5e1; }
            .f-payload { background: #0f172a; padding: 10px; font-family: monospace; color: #a78bfa; border-radius: 4px; }
            .sev-HIGH { color: #ef4444; }
            .sev-MEDIUM { color: #f59e0b; }
            .sev-LOW { color: #3b82f6; }
            .log-line { font-family: monospace; font-size: 12px; margin-bottom: 4px; border-bottom: 1px solid #1e293b; padding-bottom: 4px; }
        </style>
    </head>
    <body>
        <h1>WSHAWK Intelligence Report</h1>
        <p><strong>Target URL:</strong> ${data.url}</p>
        <p><strong>Date Generated:</strong> ${new Date().toLocaleString()}</p>
        
        <div>
            <div class="metric">Threats Detected: <strong>${data.vulns}</strong></div>
            <div class="metric">Frames Analyzed: <strong>${data.msgs}</strong></div>
        </div>

        <h2>Vulnerabilities Confirmed</h2>
        <div>${data.findingsHTML || '<p>No vulnerabilities detected.</p>'}</div>

        <h2>System Telemetry / Logs</h2>
        <div style="background: #1e293b; padding: 20px; border-radius: 8px; overflow-x: auto;">
            ${data.logsHTML}
        </div>

        <h2>Activity History (First 100 Frames)</h2>
        <table>
            <thead><tr><th>ID</th><th>DIR</th><th>TIMING</th><th>SIZE</th><th>PAYLOAD</th></tr></thead>
            <tbody>${data.historyHTML}</tbody>
        </table>
    </body>
    </html>
    `;

    const res = await window.api.invoke('dialog:exportReport', htmlReport);
    if (!res.success && !res.canceled) {
        alert('Failed to export report: ' + res.error);
    } else if (res.success) {
        appendLog('info', `HTML Report exported successfully to ${res.path}`);
    }
});

// Socket.IO Integration
let socket;
let msgCount = 0;

function connectBridge() {
    socket = io('http://127.0.0.1:8080', { reconnectionAttempts: 5 });
    // Expose on window so Team Mode and other modules can reuse the connection
    window.socket = socket;

    socket.on('connect', () => {
        connPill.className = 'connection-status online';
        connText.innerText = 'Connected';
        document.getElementById('status-dot')?.classList.add('online');
        document.getElementById('status-conn').innerText = 'Connected';
        appendLog('in', 'Bridge linkage established. Engine ready.');
    });

    socket.on('disconnect', () => {
        connPill.className = 'connection-status offline';
        connText.innerText = 'Disconnected';
        document.getElementById('status-dot')?.classList.remove('online');
        document.getElementById('status-conn').innerText = 'Disconnected';
        appendLog('vuln', 'Connection to core engine lost.');
    });

    // Feature 14: Auto-Reconnect UI
    socket.io.on('reconnect_attempt', (attempt) => {
        connPill.className = 'connection-status reconnecting';
        connText.innerText = `Reconnecting (${attempt})...`;
        document.getElementById('status-dot')?.classList.add('reconnecting');
        document.getElementById('status-dot')?.classList.remove('online');
        document.getElementById('status-conn').innerText = `Reconnecting...`;
    });

    socket.io.on('reconnect', () => {
        connPill.className = 'connection-status online';
        connText.innerText = 'Connected';
        document.getElementById('status-dot')?.classList.remove('reconnecting');
        document.getElementById('status-dot')?.classList.add('online');
        document.getElementById('status-conn').innerText = 'Connected';
        appendLog('success', 'Reconnected to core engine.');
    });

    socket.io.on('reconnect_failed', () => {
        connPill.className = 'connection-status offline';
        connText.innerText = 'Connection Failed';
        document.getElementById('status-dot')?.classList.remove('reconnecting');
        document.getElementById('status-conn').innerText = 'Failed';
        appendLog('vuln', 'All reconnection attempts failed. Restart the bridge.');
    });

    socket.on('scan_update', (data) => {
        if (data.status === 'running') {
            appendLog('out', `Initializing heuristic scan targeting: ${targetUrlInput.value}`);
        } else if (data.status === 'completed') {
            valProgress.style.width = '100%';
            appendLog('in', `Analysis complete. Vulnerabilities confirmed: ${data.vulnerabilities_count}`);
            scanBtn.innerText = 'Run Analysis';
            scanBtn.disabled = false;
            document.getElementById('scan-stop-btn').style.display = 'none';
            stopScanTimer();
        }
    });

    socket.on('scan_progress', (data) => {
        valProgress.style.width = `${data.progress}%`;
        appendLog('info', `Executing module [${data.phase}] — Progress: ${data.progress}%`);
    });

    socket.on('message_sent', (data) => {
        if (data.msg) {
            updateMsgCount(1);
            appendLog('out', `⟶ ${truncate(data.msg)}`);
            addHistoryRow('OUT', data.msg);
        }
        if (data.response) {
            updateMsgCount(1);
            appendLog('in', `⟵ ${truncate(data.response)}`);
            addHistoryRow('IN', data.response);
        }
    });

    socket.on('vulnerability_found', (vuln) => {
        addFinding(vuln);
        incVulns();
        appendLog('vuln', `THREAT IDENTIFIED: ${vuln.severity} - ${vuln.type} `);
    });

    socket.on('scan_error', (data) => {
        appendLog('vuln', `ABORT FATAL ERR: ${data.error} `);
        scanBtn.innerText = 'Run Analysis';
        scanBtn.disabled = false;
        document.getElementById('scan-stop-btn').style.display = 'none';
        valProgress.style.background = 'var(--danger)';
    });

    socket.on('blaster_progress', (data) => {
        addBlasterResult(data.payload, data.status, '...');
    });

    socket.on('blaster_result', (data) => {
        updateBlasterResult(data.payload, data.status, data.length, data.response,
            data.dom_verified, data.dom_evidence);
    });

    socket.on('dom_xss_confirmed', (data) => {
        appendLog('vuln', `[DOM INVADER] CONFIRMED XSS: ${truncate(data.payload, 60)} — ${data.evidence}`);
    });

    socket.on('blaster_completed', () => {
        appendLog('success', 'Payload blasting sequence complete.');
        const blasterBtn = document.getElementById('blaster-start-btn');
        if (blasterBtn) {
            blasterBtn.disabled = false;
            blasterBtn.innerText = "COMMENCE FUZZING";
        }
        const stopBtn = document.getElementById('blaster-stop-btn');
        if (stopBtn) stopBtn.style.display = 'none';
    });

    socket.on('intercepted_frame', (frame) => {
        handleInterceptedFrame(frame);
    });

    socket.on('new_handshake', (data) => {
        addHandshakeRow(data);
        appendLog('success', `Extension captured new handshake: ${truncate(data.url, 40)}`);
    });
}

function addHandshakeRow(data) {
    const tbody = document.getElementById('handshake-tbody');
    if (!tbody) return;
    if (tbody.querySelector('.empty-tr')) tbody.innerHTML = '';

    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${esc(time)}</td>
        <td><span class="text-accent" title="${esc(data.url)}">${esc(truncate(data.url, 50))}</span></td>
        <td>
            <button class="btn secondary small" style="font-size: 10px; padding: 2px 6px;" onclick='useHandshake(${JSON.stringify(data)})'>Use</button>
        </td>
    `;
    tbody.insertBefore(row, tbody.firstChild);
}

window.useHandshake = function (data) {
    if (targetUrlInput) targetUrlInput.value = data.url;
    const authInput = document.getElementById('auth-payload');
    if (authInput && data.headers) {
        // Simple heuristic: if there's an Authorization header or similar, try to use it
        const headersJson = JSON.stringify(data.headers, null, 2);
        authInput.value = headersJson;
        appendLog('info', 'Target URL and handshake headers synced to Interceptor.');
    }
    // Switch to Interceptor view
    document.querySelector('.nav-item[data-target="intercept"]')?.click();
};

let baselineLength = null;

function addBlasterResult(payload, status, resp) {
    const tableInfo = document.getElementById('blaster-tbody');
    if (tableInfo.querySelector('.empty-tr')) {
        tableInfo.innerHTML = '';
        baselineLength = null;
    }
    const domVerifying = document.getElementById('blaster-dom-verify')?.checked;
    const domCell = domVerifying
        ? `<td><span class="dom-verified-badge dom-badge-pending">Verifying...</span></td>`
        : `<td><span class="dom-verified-badge dom-badge-skipped">—</span></td>`;
    const html = `
        <tr id="fuzz-${hashString(payload)}">
            <td>${esc(truncate(payload, 30))}</td>
            <td class="status-cell">${esc(status)}</td>
            <td class="length-cell">-</td>
            ${domCell}
            <td class="diff-cell">-</td>
            <td class="resp-cell">${esc(resp)}</td>
        </tr>
        `;
    tableInfo.insertAdjacentHTML('afterbegin', html);
}

function updateBlasterResult(payload, status, length, resp, domVerified, domEvidence) {
    const row = document.getElementById(`fuzz-${hashString(payload)}`);
    if (row) {
        row.querySelector('.status-cell').innerText = status;
        row.querySelector('.status-cell').className = `status-cell sev-${status === 'success' ? 'LOW' : 'HIGH'}`;

        let diffHtml = '-';
        if (typeof length === 'number') {
            row.querySelector('.length-cell').innerText = length;
            if (baselineLength === null) {
                baselineLength = length;
                diffHtml = '<span style="color:var(--text-muted);">(baseline)</span>';
            } else {
                const diff = length - baselineLength;
                if (diff !== 0) {
                    const color = Math.abs(diff) > 20 ? 'var(--danger)' : 'var(--warning)';
                    diffHtml = `<span style="color:${color}; font-weight:bold;">${diff > 0 ? '+' : ''}${diff}</span>`;
                } else {
                    diffHtml = '<span style="color:var(--text-muted);">0</span>';
                }
            }
        }
        row.querySelector('.diff-cell').innerHTML = diffHtml;
        row.querySelector('.resp-cell').innerText = truncate(resp, 50);

        // DOM Verified badge
        const domCell = row.querySelector('.dom-verified-badge')?.parentElement;
        if (domCell && domVerified !== undefined) {
            if (domVerified === true) {
                domCell.innerHTML = `<span class="dom-verified-badge dom-badge-confirmed" title="${esc(domEvidence || '')}">CONFIRMED XSS</span>`;
            } else if (domVerified === false) {
                domCell.innerHTML = `<span class="dom-verified-badge dom-badge-unverified" title="${esc(domEvidence || 'No execution')}">Unverified</span>`;
            }
        }
    }
}

// We can't rely just on integer hashes for DOM IDs since some payloads might collide 
// or the ID selector might break if it starts with a number. Use a hex string.
// Prefixed to ensure it starts with a letter (for selector safety)
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = (hash << 5) - hash + str.charCodeAt(i);
        hash |= 0;
    }
    return 'f' + Math.abs(hash).toString(16) + str.length;
}

function truncate(str, len = 70) {
    if (!str) return '';
    const s = typeof str === 'string' ? str : JSON.stringify(str);
    return s.length > len ? s.substring(0, len) + '...' : s;
}

function appendLog(type, msg) {
    const div = document.createElement('div');
    div.className = `log-line ${type}`;
    div.innerText = `[${new Date().toLocaleTimeString('en-US', { hour12: false })}] ${msg}`;
    systemLog.appendChild(div);
    systemLog.scrollTop = systemLog.scrollHeight;
}

function updateMsgCount(inc) {
    msgCount += inc;
    valMsgs.innerText = msgCount;
    historyCount.innerText = `${msgCount} frames`;
}

function incVulns() {
    valVulns.innerText = (parseInt(valVulns.innerText) || 0) + 1;
    valRisk.innerText = 'COMPROMISED';
    valRisk.className = 'metric-value text-danger';
}

const globalVulns = {};

window.exportPoC = async function (id) {
    const vuln = globalVulns[id];
    if (!vuln) return;
    const url = targetUrlInput.value.trim() || "wss://target.api.com/";
    const authPayload = document.getElementById('auth-payload') ? document.getElementById('auth-payload').value.trim() : "";

    const exploitCode = `#!/usr/bin/env python3
# WSHawk Automated Exploit PoC
# Target: ${url}
# Vulnerability: ${vuln.type}
# Severity: ${vuln.severity}

import asyncio
import websockets
import json
import sys

TARGET = "${url}"
PAYLOAD = """${vuln.payload.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"""
AUTH_PAYLOAD = """${authPayload.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}""" if "${authPayload}" else None

async def exploit():
    print(f"[*] WSHawk Exploit Initialized")
    print(f"[*] Connecting to {TARGET}")
    
    try:
        async with websockets.connect(TARGET, ping_interval=None) as ws:
            print("[+] Connected successfully!")
            
            if AUTH_PAYLOAD:
                print(f"[*] Sending authentication sequence/skeleton key...")
                await ws.send(AUTH_PAYLOAD)
                await asyncio.sleep(0.5)
            
            print(f"[*] Sending malicious payload...")
            await ws.send(PAYLOAD)
            
            print("[*] Waiting for response...")
            while True:
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                print("\\n[+] Exploit successful! Server responded:")
                print("-" * 40)
                print(response)
                print("-" * 40)
                # For some vulns like blind SQLi or command injection, you might want to break here 
                # or keep listening depending on the reflection.
                break
                
    except asyncio.TimeoutError:
        print("[-] Exploit sent but no response received (could be a blind exploitation success or timeout).")
    except Exception as e:
        print(f"[-] Exploit failed or connection dropped: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(exploit())
    except KeyboardInterrupt:
        print("\\n[!] Exploit aborted by user.")
        sys.exit(0)
`;

    const res = await window.api.invoke('dialog:exportExploit', exploitCode);
    if (res && res.success) {
        appendLog('success', `Exported Python PoC saved to ${res.path}`);
    } else if (res && !res.canceled) {
        appendLog('vuln', 'Failed to save exploit.');
    }
};

function addFinding(vuln) {
    if (findingsContainer.querySelector('.empty-state')) {
        findingsContainer.innerHTML = '';
    }
    const vId = Math.random().toString(36).substr(2, 9);
    globalVulns[vId] = vuln;

    const html = `
        <div class="finding-card ${vuln.severity || 'LOW'}" data-severity="${vuln.severity || 'LOW'}">
            <div class="f-title" style="display: flex; gap: 8px; align-items: center;">
                <span class="f-name" style="flex: 1;">${esc(vuln.type)}</span>
                <button class="f-copy-btn" onclick="copyFinding('${vId}')">Copy</button>
                <button class="btn primary" style="background: var(--safe); font-size: 11px; padding: 4px 10px; border: none; cursor: pointer; border-radius: 4px;" onclick="exportPoC('${vId}')">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 4px;">
                        <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
                    </svg>
                    Export PoC
                </button>
                <span class="sev-badge sev-${vuln.severity || 'LOW'}">${esc(vuln.severity) || 'LOW'}</span>
            </div>
            <div class="f-desc">${esc(vuln.description)}</div>
            <div class="f-payload">${esc(vuln.payload)}</div>
        </div>
        `;
    findingsContainer.insertAdjacentHTML('afterbegin', html);
    updateSeverityChart();
}

let hIndex = 1;
const historyData = {};
function addHistoryRow(dir, data) {
    if (historyTbody.querySelector('.empty-tr')) {
        historyTbody.innerHTML = '';
    }
    const rowId = 'h' + hIndex;
    historyData[rowId] = typeof data === 'string' ? data : JSON.stringify(data);
    const html = `
        <tr>
            <td>#${hIndex++}</td>
            <td class="dir-${dir.toLowerCase()}">${dir}</td>
            <td>${new Date().toLocaleTimeString('en-US', { hour12: false })}</td>
            <td>${typeof data === 'string' ? new Blob([data]).size : JSON.stringify(data).length}B</td>
            <td>${esc(truncate(data, 90))}</td>
            <td><button class="history-replay-btn" onclick="sendToForge('${rowId}')">→ Forge</button></td>
        </tr>
        `;
    historyTbody.insertAdjacentHTML('afterbegin', html);
}


// Handlers
// History search filter
const historyFilterInput = document.getElementById('history-filter');
if (historyFilterInput) {
    historyFilterInput.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#history-tbody tr');
        rows.forEach(r => {
            if (r.classList.contains('empty-tr')) return;
            const text = r.innerText.toLowerCase();
            r.style.display = text.includes(term) ? '' : 'none';
        });
    });
}
scanBtn.addEventListener('click', async () => {
    const url = targetUrlInput.value.trim();
    const authPayload = document.getElementById('auth-payload').value.trim();
    if (!url) {
        appendLog('vuln', 'Input Error: Target WebSocket URL is required.');
        return;
    }

    // reset UI state
    findingsContainer.innerHTML = '<div class="empty-state">Analysis sequence engaged. Monitoring for vulnerabilities...</div>';
    valVulns.innerText = '0';
    msgCount = 0;
    valMsgs.innerText = '0';
    historyCount.innerText = '0 frames';
    valRisk.innerText = 'SCANNING';
    valRisk.className = 'metric-value';
    valProgress.style.width = '0%';
    valProgress.style.background = 'var(--text-primary)';

    scanBtn.disabled = true;
    scanBtn.innerText = 'Processing...';
    document.getElementById('scan-stop-btn').style.display = 'block';

    try {
        await fetch('http://127.0.0.1:8080/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url, auth_payload: authPayload, rate: 10 })
        });
        startScanTimer();
    } catch (e) {
        appendLog('vuln', 'Bridge Communication Failure. Is the Python sidecar running?');
        scanBtn.innerText = 'Run Analysis';
        scanBtn.disabled = false;
        document.getElementById('scan-stop-btn').style.display = 'none';
    }
});

const scanStopBtn = document.getElementById('scan-stop-btn');
if (scanStopBtn) {
    scanStopBtn.addEventListener('click', async () => {
        try {
            await fetch('http://127.0.0.1:8080/scan/stop', { method: 'POST' });
            appendLog('info', 'Commanded background scan to HALT.');
            scanBtn.innerText = 'Run Analysis';
            scanBtn.disabled = false;
            scanStopBtn.style.display = 'none';
        } catch (e) {
            appendLog('vuln', 'Failed to stop scan: ' + e.message);
        }
    });
}

document.getElementById('send-reqforge').addEventListener('click', async () => {
    const p = document.getElementById('reqforge-req').value;
    const r = document.getElementById('reqforge-res');
    const u = targetUrlInput.value.trim();
    if (!u) {
        r.value = "[!] Input Error: Please configure Target URL above first.";
        appendLog('vuln', 'Configuration Error: Target URL missing for Request Forge operation.');
        return;
    }
    r.value = "Executing payload transmission...";

    // Route through the local proxy if the interceptor is engaged
    const targetEndpoint = isIntercepting
        ? `ws://127.0.0.1:8080/proxy?url=${encodeURIComponent(u)}`
        : u;

    try {
        const res = await fetch('http://127.0.0.1:8080/reqforge/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: targetEndpoint, payload: p })
        });
        const data = await res.json();
        r.value = JSON.stringify(data, null, 2);
    } catch (e) {
        r.value = "[ERR] Inter-process transit failed: " + e.message;
    }
});

// ── Highlight-to-Hack: AI Exploit Context Menu ─────────────────
(function HighlightToHack() {
    'use strict';

    const BRIDGE = 'http://127.0.0.1:8080';
    const reqforgeEditor = document.getElementById('reqforge-req');
    const ctxMenu = document.getElementById('ai-exploit-menu');
    if (!reqforgeEditor || !ctxMenu) return;

    // ── Show context menu on right-click when text is selected ───
    reqforgeEditor.addEventListener('contextmenu', (e) => {
        const selection = reqforgeEditor.value.substring(
            reqforgeEditor.selectionStart,
            reqforgeEditor.selectionEnd
        );

        if (!selection || selection.trim().length === 0) return; // No selection → use native menu

        e.preventDefault();

        // Position the menu at cursor
        const menuW = 240, menuH = 400;
        let x = e.clientX;
        let y = e.clientY;
        if (x + menuW > window.innerWidth) x = window.innerWidth - menuW - 8;
        if (y + menuH > window.innerHeight) y = window.innerHeight - menuH - 8;

        ctxMenu.style.left = x + 'px';
        ctxMenu.style.top = y + 'px';
        ctxMenu.style.display = 'block';
    });

    // ── Hide menu on click elsewhere ────────────────────────────
    document.addEventListener('click', (e) => {
        if (!ctxMenu.contains(e.target)) {
            ctxMenu.style.display = 'none';
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') ctxMenu.style.display = 'none';
    });

    // ── Handle vuln type selection ──────────────────────────────
    ctxMenu.querySelectorAll('.ai-ctx-item').forEach(item => {
        item.addEventListener('click', async () => {
            const vulnType = item.getAttribute('data-vuln');
            ctxMenu.style.display = 'none';

            const fullText = reqforgeEditor.value;
            const selStart = reqforgeEditor.selectionStart;
            const selEnd = reqforgeEditor.selectionEnd;
            const selection = fullText.substring(selStart, selEnd);

            if (!selection.trim()) return;

            // Build request
            const payload = {
                full_text: fullText,
                selection: selection,
                cursor_pos: selStart,
                count: 12,
            };

            // "auto" means let the engine decide; otherwise send specific type
            if (vulnType !== 'auto') {
                payload.vuln_types = [vulnType];
            }

            // Show loading overlay on the ReqForge editor
            const editorParent = reqforgeEditor.closest('.panel') || reqforgeEditor.parentElement;
            const loader = document.createElement('div');
            loader.className = 'reqforge-ai-loading';
            loader.innerHTML = `
                <div class="ai-spinner"></div>
                <div class="ai-loading-text">Generating exploit payloads...</div>
            `;
            editorParent.style.position = 'relative';
            editorParent.appendChild(loader);

            try {
                const res = await fetch(`${BRIDGE}/ai/context-exploit`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                const data = await res.json();

                if (data.status !== 'success' || !data.payloads || data.payloads.length === 0) {
                    throw new Error(data.msg || 'No payloads generated');
                }

                // Populate Payload Blaster
                populateBlaster(data.blaster_template, data.payloads);

                // Log context info
                const ctx = data.context || {};
                const logMsg = `[AI Exploit] Detected ${ctx.format?.toUpperCase() || 'RAW'} context — ` +
                    `key: "${ctx.key || '?'}", type: ${ctx.data_type || '?'} — ` +
                    `Generated ${data.payloads.length} payloads for: ${(data.vuln_labels || []).join(', ')}`;
                if (typeof appendLog === 'function') appendLog('info', logMsg);

            } catch (err) {
                if (typeof appendLog === 'function') {
                    appendLog('vuln', `[AI Exploit] ${err.message}`);
                }
            } finally {
                loader.remove();
            }
        });
    });

    // ── Auto-navigate to Blaster and populate fields ────────────
    function populateBlaster(template, payloads) {
        // Set the template
        const templateEl = document.getElementById('blaster-template');
        if (templateEl) templateEl.value = template || '';

        // Set the payloads (one per line)
        const payloadsEl = document.getElementById('blaster-payloads');
        if (payloadsEl) payloadsEl.value = (payloads || []).join('\n');

        // Update payload count
        const countEl = document.getElementById('blaster-payload-count');
        if (countEl) {
            countEl.textContent = `${payloads.length} payloads`;
            countEl.style.display = 'inline';
        }

        // Navigate to the Blaster tab
        const blasterNav = document.querySelector('.nav-item[data-target="blaster"]');
        if (blasterNav) {
            blasterNav.click();
        }
    }
})();

let isIntercepting = false;
const interceptBtn = document.getElementById('toggle-intercept-btn');
const interceptOrb = document.getElementById('intercept-orb');
const interceptTitle = document.getElementById('intercept-title');
const queueTbody = document.getElementById('intercept-queue-tbody');
const editorPanel = document.getElementById('intercept-editor-panel');
const frameEditor = document.getElementById('intercept-editor');
const btnForward = document.getElementById('btn-intercept-forward');
const btnDrop = document.getElementById('btn-intercept-drop');

let interceptQueue = [];
let activeFrameId = null;

async function toggleInterceptor(enabled) {
    try {
        await fetch('http://127.0.0.1:8080/interceptor/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        isIntercepting = enabled;

        if (isIntercepting) {
            interceptOrb.classList.add('intercept-active');
            interceptTitle.innerText = "Interceptor: ENGAGED";
            interceptTitle.style.color = "var(--danger)";
            interceptBtn.innerText = "Disengage Hook";
            interceptBtn.className = "btn secondary small";
            queueTbody.innerHTML = '<tr class="empty-tr"><td colspan="3">Waiting for traffic...</td></tr>';
            appendLog('vuln', 'Local Interceptor Hook Activated.');
        } else {
            interceptOrb.classList.remove('intercept-active');
            interceptTitle.innerText = "Interceptor: Idle";
            interceptTitle.style.color = "var(--text-secondary)";
            interceptBtn.innerText = "Engage Interceptor";
            interceptBtn.className = "btn primary small";
            queueTbody.innerHTML = '<tr class="empty-tr"><td colspan="3">Interceptor is currently idle.</td></tr>';
            interceptQueue = [];
            loadNextFrame();
            appendLog('info', 'Interceptor hook removed.');
        }
    } catch (e) {
        appendLog('vuln', 'Failed to toggle interceptor: ' + e.message);
    }
}

interceptBtn.addEventListener('click', () => {
    const u = targetUrlInput.value.trim();
    if (!u && !isIntercepting) {
        appendLog('vuln', 'Input Error: Cannot engage interceptor without Target URL.');
        return;
    }
    toggleInterceptor(!isIntercepting);
});

// Handle incoming intercepted frames from socket
function handleInterceptedFrame(frame) {
    interceptQueue.push(frame);
    renderQueue();
    if (!activeFrameId) loadNextFrame();
}

function renderQueue() {
    if (interceptQueue.length === 0 && !activeFrameId) {
        queueTbody.innerHTML = '<tr class="empty-tr"><td colspan="3">Waiting for traffic...</td></tr>';
        return;
    }

    let html = '';
    interceptQueue.forEach((f, idx) => {
        html += `
            <tr style="cursor: pointer; opacity: 0.7;">
                <td class="dir-${f.direction.toLowerCase()}">${f.direction}</td>
                <td>${esc(truncate(f.url, 20))}</td>
                <td>${esc(truncate(f.payload, 30))}</td>
            </tr>
        `;
    });

    // Add active frame at top
    if (activeFrameId) {
        const activeHtml = `
            <tr style="background: rgba(59, 130, 246, 0.2);">
                <td class="dir-${activeFrame.direction.toLowerCase()}">${activeFrame.direction}</td>
                <td>${esc(truncate(activeFrame.url, 20))}</td>
                <td>${esc(truncate(activeFrame.payload, 30))}</td>
            </tr>
        `;
        queueTbody.innerHTML = activeHtml + html;
    } else {
        queueTbody.innerHTML = html;
    }
}

let activeFrame = null;

function loadNextFrame() {
    if (interceptQueue.length > 0) {
        activeFrame = interceptQueue.shift();
        activeFrameId = activeFrame.id;
        frameEditor.value = activeFrame.payload;

        editorPanel.style.opacity = '1';
        editorPanel.style.pointerEvents = 'auto';
        renderQueue();
    } else {
        activeFrame = null;
        activeFrameId = null;
        frameEditor.value = '';
        editorPanel.style.opacity = '0.5';
        editorPanel.style.pointerEvents = 'none';
        renderQueue();
    }
}

async function sendFrameAction(action) {
    if (!activeFrameId) return;
    const payload = frameEditor.value;
    const id = activeFrameId;

    try {
        await fetch('http://127.0.0.1:8080/interceptor/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, action, payload })
        });
        appendLog('info', `Frame ${action}ed`);
        loadNextFrame();
    } catch (e) {
        appendLog('vuln', `Action failed: ${e.message}`);
    }
}

btnForward.addEventListener('click', () => sendFrameAction('forward'));
btnDrop.addEventListener('click', () => sendFrameAction('drop'));

const payloadSelect = document.getElementById('blaster-payload-select');
if (payloadSelect) {
    payloadSelect.addEventListener('change', async (e) => {
        const category = e.target.value;
        const countSpan = document.getElementById('blaster-payload-count');
        if (!category) {
            countSpan.style.display = 'none';
            return;
        }

        try {
            const res = await fetch(`http://127.0.0.1:8080/blaster/payloads/${category}`);
            const data = await res.json();

            if (data.payloads) {
                const payloadsBox = document.getElementById('blaster-payloads');
                payloadsBox.value = data.payloads.join('\n');
                countSpan.innerText = `(~${data.count} payloads)`;
                countSpan.style.display = 'inline';
                appendLog('info', `Loaded ${data.count} elite payloads for ${category}`);
            }
        } catch (e) {
            appendLog('vuln', 'Failed to load payload list: ' + e.message);
        }
    });
}

const payloadsBox = document.getElementById('blaster-payloads');
if (payloadsBox) {
    payloadsBox.addEventListener('input', () => {
        const countSpan = document.getElementById('blaster-payload-count');
        const count = payloadsBox.value.split('\n').filter(p => p.trim() !== '').length;
        countSpan.innerText = `(~${count} payloads)`;
        countSpan.style.display = 'inline';
    });
}

const blasterBtn = document.getElementById('blaster-start-btn');
blasterBtn.addEventListener('click', async () => {
    const u = targetUrlInput.value.trim();
    const authPayload = document.getElementById('auth-payload').value.trim();
    if (!u) {
        appendLog('vuln', 'Input Error: Cannot start fuzzing without Target URL.');
        return;
    }

    const template = document.getElementById('blaster-template').value;
    const payloads = document.getElementById('blaster-payloads').value.split('\n');
    const speChecked = document.getElementById('blaster-spe-checkbox').checked;
    const domVerify = document.getElementById('blaster-dom-verify')?.checked || false;

    // Include saved auth flow if recorded
    const authFlow = window._domInvaderAuthFlow || null;

    document.getElementById('blaster-tbody').innerHTML = '<tr class="empty-tr"><td colspan="6">Fuzzing...</td></tr>';
    blasterBtn.disabled = true;
    blasterBtn.innerText = "BLASTING...";
    document.getElementById('blaster-stop-btn').style.display = 'block';

    if (domVerify) appendLog('info', '[DOM Invader] Headless XSS verification enabled — false positives eliminated.');
    if (authFlow) appendLog('info', '[DOM Invader] Auth flow active — will auto-replay on session expiry.');

    try {
        await fetch('http://127.0.0.1:8080/blaster/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: u,
                payloads: payloads,
                template: template,
                spe: speChecked,
                auth_payload: authPayload,
                dom_verify: domVerify,
                auth_flow: authFlow,
            })
        });
    } catch (e) {
        appendLog('vuln', '[ERR] Payload Blast Failed');
        blasterBtn.disabled = false;
        blasterBtn.innerText = "COMMENCE FUZZING";
        document.getElementById('blaster-stop-btn').style.display = 'none';
    }
});

const blasterStopBtn = document.getElementById('blaster-stop-btn');
if (blasterStopBtn) {
    blasterStopBtn.addEventListener('click', async () => {
        try {
            await fetch('http://127.0.0.1:8080/blaster/stop', { method: 'POST' });
            appendLog('info', 'Commanded Blaster to HALT.');
            blasterBtn.disabled = false;
            blasterBtn.innerText = "COMMENCE FUZZING";
            blasterStopBtn.style.display = 'none';
        } catch (e) {
            appendLog('vuln', 'Failed to stop blaster: ' + e.message);
        }
    });
}

// ── DOM Invader Frontend Module ──────────────────────────────────
(function DOMInvaderUI() {
    'use strict';

    const BRIDGE = 'http://127.0.0.1:8080';
    const statusPill = document.getElementById('dom-invader-status');
    const recordBtn = document.getElementById('dom-record-auth-btn');
    const replayBtn = document.getElementById('dom-replay-auth-btn');
    const authStatus = document.getElementById('dom-auth-status');

    // ── Check Playwright availability on load ────────────────────
    async function checkStatus() {
        try {
            const res = await fetch(`${BRIDGE}/dom/status`);
            const data = await res.json();
            if (!statusPill) return;
            if (data.playwright_installed) {
                statusPill.className = 'dom-status-pill dom-status-available';
                statusPill.textContent = 'Playwright Ready';
            } else {
                statusPill.className = 'dom-status-pill dom-status-unavailable';
                statusPill.textContent = 'Not Installed';
                statusPill.title = 'Run: pip install playwright && playwright install chromium';
            }
        } catch (_) {
            if (statusPill) {
                statusPill.className = 'dom-status-pill dom-status-unknown';
                statusPill.textContent = 'Offline';
            }
        }
    }

    // Check status when Blaster tab opens
    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.dataset.target === 'blaster') {
            item.addEventListener('click', () => setTimeout(checkStatus, 300));
        }
    });
    checkStatus();

    // ── Record Auth Flow ─────────────────────────────────────────
    if (recordBtn) {
        recordBtn.addEventListener('click', async () => {
            const loginUrl = prompt(
                'Enter the login URL to record auth flow:\n(e.g. https://app.example.com/login)',
                'https://'
            );
            if (!loginUrl || !loginUrl.startsWith('http')) return;

            const targetWs = targetUrlInput?.value.trim() || '';
            recordBtn.disabled = true;
            recordBtn.textContent = 'Recording...';
            if (authStatus) {
                authStatus.style.display = 'block';
                authStatus.textContent = 'Visible browser opened — complete your login. Auto-closes after 2 minutes.';
            }
            appendLog('info', `[DOM Invader] Recording auth flow at ${loginUrl}...`);

            try {
                const res = await fetch(`${BRIDGE}/dom/auth/record`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ login_url: loginUrl, target_ws_url: targetWs, timeout_s: 120 }),
                });
                const data = await res.json();
                if (data.status === 'success' && data.flow) {
                    window._domInvaderAuthFlow = data.flow;
                    const cookieCount = (data.flow.cookies || []).length;
                    const tokenCount = Object.keys(data.flow.extracted_tokens || {}).length;
                    recordBtn.textContent = 'Re-Record Auth';
                    recordBtn.disabled = false;
                    if (replayBtn) {
                        replayBtn.style.display = 'inline-flex';
                        replayBtn.textContent = `Auth Saved (${cookieCount} cookies, ${tokenCount} tokens)`;
                    }
                    if (authStatus) {
                        authStatus.textContent = `Captured: ${cookieCount} cookies, ${tokenCount} tokens. Active for this session.`;
                    }
                    appendLog('success', `[DOM Invader] Auth flow recorded: ${cookieCount} cookies, ${tokenCount} tokens`);
                } else {
                    throw new Error(data.msg || 'Recording failed');
                }
            } catch (err) {
                appendLog('vuln', `[DOM Invader] Auth recording failed: ${err.message}`);
                recordBtn.disabled = false;
                recordBtn.textContent = 'Record Auth Flow';
                if (authStatus) authStatus.style.display = 'none';
            }
        });
    }

    // ── Discard saved auth flow ──────────────────────────────────
    if (replayBtn) {
        replayBtn.addEventListener('click', () => {
            if (confirm('Discard the saved auth flow?')) {
                window._domInvaderAuthFlow = null;
                replayBtn.style.display = 'none';
                if (authStatus) {
                    authStatus.textContent = 'Auth flow cleared.';
                    setTimeout(() => { authStatus.style.display = 'none'; }, 2000);
                }
                appendLog('info', '[DOM Invader] Auth flow discarded.');
            }
        });
    }
})();

// --- Settings Modal Logic ---
const btnSettings = document.getElementById('btn-settings');
const settingsModal = document.getElementById('settings-modal');
const btnSettingsClose = document.getElementById('btn-settings-close');
const btnSettingsSave = document.getElementById('btn-settings-save');

console.log('[UI] Initializing Modals...', { btnSettings: !!btnSettings, settingsModal: !!settingsModal });

if (btnSettings && settingsModal) {
    btnSettings.addEventListener('click', async () => {
        console.log('[UI] Opening Settings Modal');
        settingsModal.style.display = 'flex';
        try {
            const res = await fetch('http://127.0.0.1:8080/config/get');
            const data = await res.json();
            if (data.status === 'success') {
                const fields = {
                    'cfg-jira-url': data.jiraUrl,
                    'cfg-jira-email': data.jiraEmail,
                    'cfg-jira-token': data.jiraToken,
                    'cfg-jira-project': data.jiraProject,
                    'cfg-dd-url': data.ddUrl,
                    'cfg-dd-key': data.ddKey,
                    // AI Settings
                    'cfg-ai-provider': data.ai_provider,
                    'cfg-ai-model': data.ai_model,
                    'cfg-ai-url': data.ai_base_url,
                    'cfg-ai-key': data.ai_api_key
                };
                for (const [id, val] of Object.entries(fields)) {
                    const el = document.getElementById(id);
                    if (el) el.value = val || '';
                }
            }
        } catch (e) {
            console.error('[UI] Fetch config failed:', e);
            if (typeof appendLog === 'function') appendLog('vuln', 'Bridge error: Failed to fetch integration config.');
        }
    });

    if (btnSettingsClose) {
        btnSettingsClose.addEventListener('click', () => {
            console.log('[UI] Closing Settings Modal');
            settingsModal.style.display = 'none';
        });
    }

    if (btnSettingsSave) {
        btnSettingsSave.addEventListener('click', async () => {
            const getVal = (id) => {
                const el = document.getElementById(id);
                return el ? el.value.trim() : '';
            };

            const payload = {
                jiraUrl: getVal('cfg-jira-url'),
                jiraEmail: getVal('cfg-jira-email'),
                jiraToken: getVal('cfg-jira-token'),
                jiraProject: getVal('cfg-jira-project'),
                ddUrl: getVal('cfg-dd-url'),
                ddKey: getVal('cfg-dd-key'),
                // AI Settings
                ai_provider: getVal('cfg-ai-provider'),
                ai_model: getVal('cfg-ai-model'),
                ai_base_url: getVal('cfg-ai-url'),
                ai_api_key: getVal('cfg-ai-key')
            };

            try {
                const res = await fetch('http://127.0.0.1:8080/config/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.status === 'success') {
                    if (typeof appendLog === 'function') appendLog('success', 'Enterprise settings saved correctly.');
                    settingsModal.style.display = 'none';
                } else {
                    if (typeof appendLog === 'function') appendLog('vuln', 'Save failed: ' + data.msg);
                }
            } catch (e) {
                console.error('[UI] Save config failed:', e);
                if (typeof appendLog === 'function') appendLog('vuln', 'Bridge error: Failed to save settings.');
            }
        });
    }
}

// Settings modal click outside to close
window.addEventListener('click', (e) => {
    if (e.target === settingsModal) {
        settingsModal.style.display = 'none';
    }
});

function showToS() {
    const agreed = localStorage.getItem('wshawk_tos_agreed');
    console.log('[UI] Checking ToS status:', agreed);
    if (!agreed) {
        const tosModal = document.getElementById('tos-modal');
        if (tosModal) {
            console.log('[UI] Displaying Legal Terms of Service');
            tosModal.style.display = 'flex';
        }
    }
}

const btnAgreeToS = document.getElementById('btn-agree-tos');
if (btnAgreeToS) {
    btnAgreeToS.addEventListener('click', () => {
        console.log('[UI] User agreed to terms');
        safeStore('wshawk_tos_agreed', 'true');
        const modal = document.getElementById('tos-modal');
        if (modal) modal.style.display = 'none';
    });
}

// Clear Blaster Button
const btnClearBlaster = document.getElementById('blaster-clear-btn');
if (btnClearBlaster) {
    btnClearBlaster.addEventListener('click', () => {
        const tbody = document.getElementById('blaster-tbody');
        if (tbody) tbody.innerHTML = '<tr class="empty-tr"><td colspan="5">Awaiting execution...</td></tr>';
        baselineLength = null;
    });
}

// ═══════════════════════════════════════════════════════════════
// SHARED UTILITIES
// ═══════════════════════════════════════════════════════════════

// Global sanitizer for innerHTML rendering — prevents XSS in dynamic content
function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Safe localStorage write — catches QuotaExceededError gracefully
function safeStore(key, value) {
    try {
        localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
        return true;
    } catch (e) {
        if (e.name === 'QuotaExceededError' || e.code === 22) {
            appendLog('vuln', `Storage quota exceeded. Cannot save ${key}. Clear old data to free space.`);
        } else {
            appendLog('vuln', `Storage error for ${key}: ${e.message}`);
        }
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════
// GLOBAL KEYBOARD SHORTCUTS
// ═══════════════════════════════════════════════════════════════
document.addEventListener('keydown', (e) => {
    // Ctrl+S — Save project
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        document.getElementById('btn-save-project')?.click();
        return;
    }

    // Ctrl+Enter — Execute active action based on current view
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        const activeView = document.querySelector('.view.active');
        if (!activeView) return;

        const viewId = activeView.id;
        switch (viewId) {
            case 'view-dashboard':
                scanBtn?.click();
                break;
            case 'view-reqforge':
                document.getElementById('send-reqforge')?.click();
                break;
            case 'view-comparer':
                document.getElementById('comparer-run-btn')?.click();
                break;
            case 'view-codec':
                document.getElementById('codec-smart-btn')?.click();
                break;
            case 'view-authbuilder':
                document.getElementById('auth-test-btn')?.click();
                break;
            case 'view-wsmap':
                document.getElementById('wsmap-scan-btn')?.click();
                break;
            case 'view-blaster':
                document.getElementById('blaster-start-btn')?.click();
                break;
            case 'view-mutationlab':
                document.getElementById('mutation-run-btn')?.click();
                break;
        }
        return;
    }

    // Ctrl+Shift+N — New note
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'N') {
        e.preventDefault();
        document.getElementById('notes-add-btn')?.click();
        // Switch to notes view
        document.querySelector('.nav-item[data-target="notes"]')?.click();
        return;
    }
    // Ctrl+K — Global search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        toggleGlobalSearch();
        return;
    }

    // Escape — Close modals
    if (e.key === 'Escape') {
        const gsModal = document.getElementById('global-search-modal');
        if (gsModal && gsModal.style.display === 'flex') {
            gsModal.style.display = 'none';
            return;
        }

        const picker = document.getElementById('sched-interval-picker');
        if (picker) { picker.remove(); return; }

        if (settingsModal && settingsModal.style.display === 'flex') {
            settingsModal.style.display = 'none';
            return;
        }
    }
});

// ═══════════════════════════════════════════════════════════════
// CODEC
// ═══════════════════════════════════════════════════════════════
(function initCodec() {
    const input = document.getElementById('codec-input');
    const output = document.getElementById('codec-output');
    const chainContainer = document.getElementById('codec-chain-container');
    const chainList = document.getElementById('codec-chain-list');
    const chainLabel = document.getElementById('codec-chain-label');
    if (!input) return;

    // Encode/Decode operations
    const ops = {
        'base64-encode': (s) => btoa(unescape(encodeURIComponent(s))),
        'base64-decode': (s) => decodeURIComponent(escape(atob(s.trim()))),
        'url-encode': (s) => encodeURIComponent(s),
        'url-decode': (s) => decodeURIComponent(s),
        'html-encode': (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
        'html-decode': (s) => { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; },
        'hex-encode': (s) => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, '0')).join(' '),
        'hex-decode': (s) => new TextCodec().decode(new Uint8Array(s.trim().split(/[\s,]+/).map(h => parseInt(h, 16)))),
        'unicode-encode': (s) => Array.from(s).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
        'unicode-decode': (s) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
        'gzip-decompress': (s) => {
            // Decode base64 input, then decompress using DecompressionStream API
            try {
                const binary = atob(s.trim());
                const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
                const ds = new DecompressionStream('gzip');
                const writer = ds.writable.getWriter();
                writer.write(bytes);
                writer.close();
                return new Response(ds.readable).text();
            } catch (e) {
                throw new Error('Gzip decompression failed. Input must be base64-encoded gzip data.');
            }
        },
    };

    // MD5 pure-JS implementation (SubtleCrypto doesn't support MD5)
    function md5(string) {
        function md5cycle(x, k) {
            let a = x[0], b = x[1], c = x[2], d = x[3];
            a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586); c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
            a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426); c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
            a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417); c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
            a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101); c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
            a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632); c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
            a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083); c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
            a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690); c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
            a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784); c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
            a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463); c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
            a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353); c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
            a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222); c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
            a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835); c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
            a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415); c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
            a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606); c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
            a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744); c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
            a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379); c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
            x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
        }
        function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
        function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
        function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
        function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
        function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
        function md5blk(s) { const md5blks = []; for (let i = 0; i < 64; i += 4)md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24); return md5blks; }
        function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
        function rhex(n) { let s = '', j; for (j = 0; j < 4; j++)s += '0123456789abcdef'.charAt((n >> (j * 8 + 4)) & 0x0F) + '0123456789abcdef'.charAt((n >> (j * 8)) & 0x0F); return s; }
        function hex(x) { for (let i = 0; i < x.length; i++)x[i] = rhex(x[i]); return x.join(''); }
        const n = string.length; let state = [1732584193, -271733879, -1732584194, 271733878], i;
        for (i = 64; i <= n; i += 64)md5cycle(state, md5blk(string.substring(i - 64, i)));
        string = string.substring(i - 64); const tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < string.length; i++)tail[i >> 2] |= string.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3); if (i > 55) { md5cycle(state, tail); for (i = 0; i < 16; i++)tail[i] = 0; }
        tail[14] = n * 8; md5cycle(state, tail); return hex(state);
    }

    // Hash via SubtleCrypto (SHA family)
    async function hashWith(algo, text) {
        const data = new TextEncoder().encode(text);
        const buf = await crypto.subtle.digest(algo, data);
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Button click handlers
    document.querySelectorAll('.codec-op-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const op = btn.dataset.op;
            const src = input.value;
            if (!src) return;

            try {
                let result;
                if (op === 'md5') result = md5(src);
                else if (op === 'sha1') result = await hashWith('SHA-1', src);
                else if (op === 'sha256') result = await hashWith('SHA-256', src);
                else if (op === 'sha512') result = await hashWith('SHA-512', src);
                else if (ops[op]) {
                    const r = ops[op](src);
                    result = (r instanceof Promise) ? await r : r;
                }
                else { output.value = '[ERR] Unknown operation'; return; }

                output.value = result;
                chainLabel.textContent = op;
            } catch (e) {
                output.value = `[ERR] ${e.message}`;
            }
        });
    });

    // Smart Decode: recursively peel layers
    document.getElementById('codec-smart-btn').addEventListener('click', () => {
        let data = input.value;
        if (!data) return;

        const layers = [];
        let maxIterations = 10;

        while (maxIterations-- > 0) {
            let decoded = null, type = null;

            // Try URL decode
            try {
                const d = decodeURIComponent(data);
                if (d !== data && d.length < data.length) { decoded = d; type = 'URL Decode'; }
            } catch (_) { }

            // Try Base64 decode
            if (!decoded) {
                try {
                    if (/^[A-Za-z0-9+/]+={0,2}$/.test(data.trim()) && data.trim().length > 3) {
                        const d = decodeURIComponent(escape(atob(data.trim())));
                        if (d.length > 0) { decoded = d; type = 'Base64 Decode'; }
                    }
                } catch (_) { }
            }

            // Try HTML entity decode
            if (!decoded) {
                const el = document.createElement('textarea');
                el.innerHTML = data;
                if (el.value !== data) { decoded = el.value; type = 'HTML Decode'; }
            }

            // Try Unicode unescape
            if (!decoded && data.includes('\\u')) {
                try {
                    const d = data.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
                    if (d !== data) { decoded = d; type = 'Unicode Unescape'; }
                } catch (_) { }
            }

            // Try Hex decode
            if (!decoded && /^([0-9a-fA-F]{2}[\s,]*)+$/.test(data.trim())) {
                try {
                    const d = new TextCodec().decode(new Uint8Array(data.trim().split(/[\s,]+/).map(h => parseInt(h, 16))));
                    if (d.length > 0) { decoded = d; type = 'Hex Decode'; }
                } catch (_) { }
            }

            if (!decoded) break;

            layers.push({ type, preview: decoded.substring(0, 80) });
            data = decoded;
        }

        output.value = data;

        if (layers.length > 0) {
            chainContainer.classList.add('visible');
            chainList.innerHTML = layers.map((l, i) =>
                `<div class="codec-chain-item">
                    <span class="chain-step">${i + 1}</span>
                    <span class="chain-type">${esc(l.type)}</span>
                    <span class="chain-preview">${esc(l.preview)}</span>
                </div>`
            ).join('');
            chainLabel.textContent = `${layers.length} layers`;
        } else {
            chainContainer.classList.remove('visible');
            chainLabel.textContent = 'No encoding detected';
        }
    });

    // Utility buttons
    document.getElementById('codec-copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(output.value);
        appendLog('info', 'Codec output copied to clipboard.');
    });

    document.getElementById('codec-swap-btn').addEventListener('click', () => {
        input.value = output.value;
        output.value = '';
        chainContainer.classList.remove('visible');
    });

    document.getElementById('codec-clear-btn').addEventListener('click', () => {
        input.value = '';
        output.value = '';
        chainLabel.textContent = '';
        chainContainer.classList.remove('visible');
        chainList.innerHTML = '';
    });
})();

// ═══════════════════════════════════════════════════════════════
// COMPARER
// ═══════════════════════════════════════════════════════════════
(function initComparer() {
    const inputA = document.getElementById('comparer-input-a');
    const inputB = document.getElementById('comparer-input-b');
    const diffOutput = document.getElementById('comparer-diff-output');
    const diffCount = document.getElementById('comparer-diff-count');
    const stats = document.getElementById('comparer-stats');
    if (!inputA) return;

    document.getElementById('comparer-paste-a').addEventListener('click', async () => {
        try { inputA.value = await navigator.clipboard.readText(); } catch (_) { }
    });
    document.getElementById('comparer-paste-b').addEventListener('click', async () => {
        try { inputB.value = await navigator.clipboard.readText(); } catch (_) { }
    });

    document.getElementById('comparer-run-btn').addEventListener('click', () => {
        const a = inputA.value;
        const b = inputB.value;
        if (!a && !b) { diffOutput.innerHTML = '<div class="empty-state">Paste data into both panels first.</div>'; return; }

        const linesA = a.split('\n');
        const linesB = b.split('\n');
        const maxLen = Math.max(linesA.length, linesB.length);

        let html = '';
        let differences = 0;

        for (let i = 0; i < maxLen; i++) {
            const la = linesA[i] !== undefined ? linesA[i] : '';
            const lb = linesB[i] !== undefined ? linesB[i] : '';

            if (la === lb) {
                html += `<div class="diff-line diff-same">${esc(la)}</div>`;
            } else {
                differences++;
                if (la) html += `<div class="diff-line diff-remove">- ${esc(la)}</div>`;
                if (lb) html += `<div class="diff-line diff-add">+ ${esc(lb)}</div>`;
            }
        }

        diffOutput.innerHTML = html || '<div class="empty-state">Responses are identical.</div>';
        diffCount.textContent = `${differences} difference${differences !== 1 ? 's' : ''}`;

        const sizeA = new Blob([a]).size;
        const sizeB = new Blob([b]).size;
        const sizeDiff = sizeB - sizeA;
        stats.innerHTML = `A: ${sizeA}B<br>B: ${sizeB}B<br>Δ: <span style="color:${Math.abs(sizeDiff) > 20 ? 'var(--danger)' : 'var(--text-muted)'}">${sizeDiff > 0 ? '+' : ''}${sizeDiff}B</span>`;
    });

    document.getElementById('comparer-clear-btn').addEventListener('click', () => {
        inputA.value = '';
        inputB.value = '';
        diffOutput.innerHTML = '<div class="empty-state">Run a comparison to see differences.</div>';
        diffCount.textContent = '';
        stats.innerHTML = '';
    });
})();

// ═══════════════════════════════════════════════════════════════
// NOTES
// ═══════════════════════════════════════════════════════════════
(function initNotes() {
    const listContainer = document.getElementById('notes-list-container');
    const editor = document.getElementById('notes-editor');
    const editorTitle = document.getElementById('notes-editor-title');
    if (!listContainer) return;

    let notes = JSON.parse(localStorage.getItem('wshawk_notes') || '[]');
    let activeNoteId = null;

    function saveNotes() {
        safeStore('wshawk_notes', notes);
    }

    function renderList() {
        if (notes.length === 0) {
            listContainer.innerHTML = '<div class="empty-state" style="padding: 20px;">No notes yet. Click + New.</div>';
            return;
        }
        listContainer.innerHTML = notes.map(n => `
            <div class="note-item ${n.id === activeNoteId ? 'active' : ''}" data-id="${n.id}">
                <div class="note-item-title">${esc(n.title) || 'Untitled'}</div>
                <div class="note-item-date">${esc(n.date)}</div>
                ${n.linkedFindings ? '<div class="note-item-linked">' + parseInt(n.linkedFindings) + ' finding(s) linked</div>' : ''}
            </div>
        `).join('');

        listContainer.querySelectorAll('.note-item').forEach(el => {
            el.addEventListener('click', () => {
                activeNoteId = el.dataset.id;
                const note = notes.find(n => n.id === activeNoteId);
                if (note) {
                    editor.value = note.content;
                    editorTitle.textContent = note.title || 'Untitled';
                }
                renderList();
            });
        });
    }

    // Auto-save on typing (debounced to prevent jank)
    let noteSaveTimer = null;
    editor.addEventListener('input', () => {
        if (!activeNoteId) return;
        const note = notes.find(n => n.id === activeNoteId);
        if (note) {
            note.content = editor.value;
            const firstLine = editor.value.split('\n')[0].trim();
            note.title = firstLine.substring(0, 50) || 'Untitled';
            editorTitle.textContent = note.title;
            clearTimeout(noteSaveTimer);
            noteSaveTimer = setTimeout(() => {
                saveNotes();
                renderList();
            }, 300);
        }
    });

    document.getElementById('notes-add-btn').addEventListener('click', () => {
        const id = 'n_' + Date.now();
        const newNote = {
            id,
            title: 'Untitled',
            content: '',
            date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
            linkedFindings: 0
        };
        notes.unshift(newNote);
        activeNoteId = id;
        editor.value = '';
        editorTitle.textContent = 'Untitled';
        saveNotes();
        renderList();
        editor.focus();
    });

    document.getElementById('notes-delete-btn').addEventListener('click', () => {
        if (!activeNoteId) return;
        notes = notes.filter(n => n.id !== activeNoteId);
        activeNoteId = null;
        editor.value = '';
        editorTitle.textContent = 'Select a note';
        saveNotes();
        renderList();
    });

    document.getElementById('notes-link-btn').addEventListener('click', () => {
        if (!activeNoteId) return;
        const note = notes.find(n => n.id === activeNoteId);
        if (!note) return;

        const findings = findingsContainer.querySelectorAll('.finding-card');
        if (findings.length === 0) {
            appendLog('info', 'No findings to link.');
            return;
        }

        let linked = '\n\n── Linked Findings ──\n';
        findings.forEach(f => {
            const name = f.querySelector('.f-name')?.textContent || 'Unknown';
            const sev = f.querySelector('.sev-badge')?.textContent || '';
            const payload = f.querySelector('.f-payload')?.textContent || '';
            linked += `[${sev}] ${name}: ${payload}\n`;
        });

        note.content += linked;
        note.linkedFindings = findings.length;
        editor.value = note.content;
        saveNotes();
        renderList();
        appendLog('info', `${findings.length} finding(s) linked to note.`);
    });

    renderList();
})();

// ═══════════════════════════════════════════════════════════════
// ENDPOINT MAP
// ═══════════════════════════════════════════════════════════════
(function initWSMap() {
    const treeContainer = document.getElementById('wsmap-tree-container');
    const detailBody = document.getElementById('wsmap-detail-body');
    const detailTitle = document.getElementById('wsmap-detail-title');
    const testBtn = document.getElementById('wsmap-test-btn');
    const attackBtn = document.getElementById('wsmap-attack-btn');
    if (!treeContainer) return;

    let endpoints = [];
    let selectedEndpoint = null;

    function renderTree() {
        if (endpoints.length === 0) {
            treeContainer.innerHTML = '<div class="empty-state">No endpoints discovered yet.</div>';
            return;
        }

        // Group by domain
        const groups = {};
        endpoints.forEach(ep => {
            try {
                const u = new URL(ep.url);
                const domain = u.hostname;
                if (!groups[domain]) groups[domain] = [];
                groups[domain].push(ep);
            } catch (_) {
                if (!groups['other']) groups['other'] = [];
                groups['other'].push(ep);
            }
        });

        let html = '';
        for (const [domain, eps] of Object.entries(groups)) {
            html += `<div style="padding: 8px 12px; font-size: 10px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(255,255,255,0.02);">${esc(domain)}</div>`;
            eps.forEach((ep, idx) => {
                const conf = (ep.confidence || 'medium').toLowerCase();
                const safeUrl = esc(ep.url);
                html += `
                    <div class="wsmap-node ${selectedEndpoint === ep.url ? 'active' : ''}" data-url="${safeUrl}" data-idx="${idx}">
                        <div class="wsmap-node-url">${safeUrl}</div>
                        <div class="wsmap-node-meta">
                            <span class="wsmap-confidence ${conf}">${esc(ep.confidence) || 'MEDIUM'}</span>
                            <span style="color: var(--text-muted);">${esc(ep.source) || ''}</span>
                        </div>
                    </div>
                `;
            });
        }
        treeContainer.innerHTML = html;

        treeContainer.querySelectorAll('.wsmap-node').forEach(node => {
            node.addEventListener('click', () => {
                selectedEndpoint = node.dataset.url;
                const ep = endpoints.find(e => e.url === selectedEndpoint);
                if (ep) showDetail(ep);
                renderTree();
            });
        });
    }

    function showDetail(ep) {
        detailTitle.textContent = ep.url;
        testBtn.disabled = false;
        attackBtn.disabled = false;

        detailBody.innerHTML = `
            <div class="wsmap-detail-row"><span class="label">URL</span><span class="value">${esc(ep.url)}</span></div>
            <div class="wsmap-detail-row"><span class="label">Protocol</span><span class="value">${ep.url.startsWith('wss') ? 'WSS (Secure)' : 'WS (Insecure)'}</span></div>
            <div class="wsmap-detail-row"><span class="label">Discovery Source</span><span class="value">${esc(ep.source) || 'N/A'}</span></div>
            <div class="wsmap-detail-row"><span class="label">Confidence</span><span class="value">${esc(ep.confidence) || 'N/A'}</span></div>
            <div class="wsmap-detail-row"><span class="label">Details</span><span class="value">${esc(ep.details) || 'No additional details'}</span></div>
            <div class="wsmap-detail-row"><span class="label">Status</span><span class="value" id="wsmap-probe-status">Not tested</span></div>
        `;
    }

    document.getElementById('wsmap-scan-btn').addEventListener('click', async () => {
        let target = targetUrlInput.value.trim();
        if (!target) {
            appendLog('vuln', 'Input Error: Enter a target URL to discover WebSocket endpoints.');
            return;
        }

        // Convert ws:// to http:// for discovery
        if (target.startsWith('ws://')) target = target.replace('ws://', 'http://');
        else if (target.startsWith('wss://')) target = target.replace('wss://', 'https://');
        else if (!target.startsWith('http')) target = 'https://' + target;

        treeContainer.innerHTML = '<div class="empty-state">Scanning for WebSocket endpoints...</div>';
        appendLog('info', `Endpoint discovery initiated for: ${target}`);

        try {
            const res = await fetch('http://127.0.0.1:8080/discovery/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });
            const data = await res.json();
            if (data.endpoints && data.endpoints.length > 0) {
                endpoints = data.endpoints;
                appendLog('success', `Discovered ${endpoints.length} WebSocket endpoint(s).`);
            } else {
                endpoints = [];
                appendLog('info', 'No WebSocket endpoints discovered on target.');
            }
        } catch (e) {
            endpoints = [];
            appendLog('vuln', 'Discovery failed: ' + e.message);
        }
        renderTree();
    });

    // Probe endpoint connectivity
    testBtn.addEventListener('click', async () => {
        if (!selectedEndpoint) return;
        const statusEl = document.getElementById('wsmap-probe-status');
        if (statusEl) statusEl.textContent = 'Probing...';

        try {
            const res = await fetch('http://127.0.0.1:8080/discovery/probe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: selectedEndpoint })
            });
            const data = await res.json();
            if (statusEl) statusEl.textContent = data.alive ? 'ALIVE' : 'UNREACHABLE';
            if (statusEl) statusEl.style.color = data.alive ? 'var(--safe)' : 'var(--danger)';
        } catch (e) {
            if (statusEl) statusEl.textContent = 'Error: ' + e.message;
        }
    });

    // Launch scan on selected endpoint
    attackBtn.addEventListener('click', () => {
        if (!selectedEndpoint) return;
        targetUrlInput.value = selectedEndpoint;
        document.querySelector('.nav-item[data-target="dashboard"]').click();
        appendLog('info', `Target updated to discovered endpoint: ${selectedEndpoint}`);
    });
})();

// ═══════════════════════════════════════════════════════════════
// AUTH BUILDER
// ═══════════════════════════════════════════════════════════════
(function initAuthBuilder() {
    const stepsContainer = document.getElementById('auth-steps-container');
    const rulesContainer = document.getElementById('auth-rules-container');
    const testOutput = document.getElementById('auth-test-output');
    if (!stepsContainer) return;

    let steps = JSON.parse(localStorage.getItem('wshawk_auth_steps') || '[]');
    let rules = JSON.parse(localStorage.getItem('wshawk_auth_rules') || '[]');

    function save() {
        safeStore('wshawk_auth_steps', steps);
        safeStore('wshawk_auth_rules', rules);
    }

    function renderSteps() {
        if (steps.length === 0) {
            stepsContainer.innerHTML = '<div class="empty-state">Define multi-step authentication sequences.<br>Click + Add Step to begin.</div>';
            return;
        }
        stepsContainer.innerHTML = steps.map((s, i) => `
            <div class="auth-step-card">
                <div class="step-header">
                    <span class="step-num">STEP ${i + 1}</span>
                    <button class="step-remove" data-idx="${i}">&times;</button>
                </div>
                <input class="auth-step-input step-action" data-idx="${i}" placeholder="Action (e.g. send, wait, connect)" value="${esc(s.action) || ''}">
                <textarea class="auth-step-input step-payload" data-idx="${i}" placeholder='Payload (e.g. {"type":"login","user":"admin","pass":"§token§"})' style="min-height: 60px; resize: vertical;">${esc(s.payload) || ''}</textarea>
                <input class="auth-step-input step-delay" data-idx="${i}" placeholder="Delay after (ms), default: 500" value="${esc(s.delay) || ''}">
            </div>
        `).join('');

        // Remove handlers
        stepsContainer.querySelectorAll('.step-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                steps.splice(parseInt(btn.dataset.idx), 1);
                save(); renderSteps();
            });
        });

        // Auto-save on input
        stepsContainer.querySelectorAll('.step-action').forEach(el => {
            el.addEventListener('input', () => { steps[el.dataset.idx].action = el.value; save(); });
        });
        stepsContainer.querySelectorAll('.step-payload').forEach(el => {
            el.addEventListener('input', () => { steps[el.dataset.idx].payload = el.value; save(); });
        });
        stepsContainer.querySelectorAll('.step-delay').forEach(el => {
            el.addEventListener('input', () => { steps[el.dataset.idx].delay = el.value; save(); });
        });
    }

    function renderRules() {
        if (rules.length === 0) {
            rulesContainer.innerHTML = '<div class="empty-state">Define token extraction rules.<br>Use regex or JSONPath to capture session tokens from responses.</div>';
            return;
        }
        rulesContainer.innerHTML = rules.map((r, i) => `
            <div class="auth-rule-card" style="position: relative;">
                <div class="rule-label">Rule ${i + 1} — ${esc(r.type) || 'regex'}</div>
                <input class="auth-step-input rule-name" data-idx="${i}" placeholder="Variable name (e.g. token)" value="${esc(r.name) || ''}">
                <input class="auth-step-input rule-pattern" data-idx="${i}" placeholder='Pattern (regex: "token":"(.*?)" | jsonpath: $.data.token)' value="${esc(r.pattern) || ''}">
                <button class="step-remove" data-idx="${i}" style="position: absolute; top: 8px; right: 8px;">&times;</button>
            </div>
        `).join('');

        rulesContainer.querySelectorAll('.rule-name').forEach(el => {
            el.addEventListener('input', () => { rules[el.dataset.idx].name = el.value; save(); });
        });
        rulesContainer.querySelectorAll('.rule-pattern').forEach(el => {
            el.addEventListener('input', () => { rules[el.dataset.idx].pattern = el.value; save(); });
        });
        rulesContainer.querySelectorAll('.step-remove').forEach(btn => {
            btn.addEventListener('click', () => { rules.splice(parseInt(btn.dataset.idx), 1); save(); renderRules(); });
        });
    }

    document.getElementById('auth-add-step').addEventListener('click', () => {
        steps.push({ action: 'send', payload: '', delay: '500' });
        save(); renderSteps();
    });

    document.getElementById('auth-clear-all').addEventListener('click', () => {
        steps = []; rules = [];
        save(); renderSteps(); renderRules();
        testOutput.value = '';
    });

    document.getElementById('auth-add-rule').addEventListener('click', () => {
        rules.push({ type: 'regex', name: '', pattern: '' });
        save(); renderRules();
    });

    document.getElementById('auth-test-btn').addEventListener('click', async () => {
        const url = targetUrlInput.value.trim();
        if (!url) { testOutput.value = '[ERR] Target URL is required.'; return; }
        if (steps.length === 0) { testOutput.value = '[ERR] No auth steps defined.'; return; }

        testOutput.value = 'Executing authentication sequence...';

        try {
            const res = await fetch('http://127.0.0.1:8080/auth/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, steps, rules })
            });
            const data = await res.json();
            testOutput.value = JSON.stringify(data, null, 2);

            if (data.extracted_tokens) {
                appendLog('success', `Auth sequence complete. Extracted ${Object.keys(data.extracted_tokens).length} token(s).`);
            }
        } catch (e) {
            testOutput.value = `[ERR] ${e.message}`;
        }
    });

    document.getElementById('auth-save-btn').addEventListener('click', () => {
        const preset = { steps, rules, saved: new Date().toISOString() };
        const presets = JSON.parse(localStorage.getItem('wshawk_auth_presets') || '[]');
        presets.push(preset);
        safeStore('wshawk_auth_presets', presets);
        appendLog('info', 'Auth sequence saved as preset.');
    });

    renderSteps();
    renderRules();
})();

// ═══════════════════════════════════════════════════════════════
// SCHEDULER
// ═══════════════════════════════════════════════════════════════
(function initScheduler() {
    const tbody = document.getElementById('sched-tbody');
    const deltaContainer = document.getElementById('sched-delta-container');
    if (!tbody) return;

    let schedules = JSON.parse(localStorage.getItem('wshawk_schedules') || '[]');
    let timers = {};

    function save() {
        safeStore('wshawk_schedules', schedules);
    }

    function renderTable() {
        if (schedules.length === 0) {
            tbody.innerHTML = '<tr class="empty-tr"><td colspan="6">No scheduled scans configured.</td></tr>';
            return;
        }
        tbody.innerHTML = schedules.map((s, i) => `
            <tr>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${esc(s.url)}">${esc(s.url)}</td>
                <td>${esc(s.interval)}</td>
                <td>${esc(s.lastRun) || 'Never'}</td>
                <td>${parseInt(s.lastFindings) || 0}</td>
                <td><span class="sched-status ${s.status || 'idle'}">${s.status || 'idle'}</span></td>
                <td style="white-space: nowrap;">
                    <button class="btn secondary small sched-toggle" data-idx="${i}" style="font-size:10px; padding: 2px 8px;">${s.status === 'active' ? 'Pause' : 'Start'}</button>
                    <button class="btn secondary small sched-view" data-idx="${i}" style="font-size:10px; padding: 2px 8px;">Delta</button>
                    <button class="btn secondary small sched-delete" data-idx="${i}" style="font-size:10px; padding: 2px 8px; color: var(--danger);">&times;</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.sched-toggle').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.dataset.idx);
                if (schedules[idx].status === 'active') {
                    schedules[idx].status = 'paused';
                    if (timers[idx]) { clearInterval(timers[idx]); delete timers[idx]; }
                } else {
                    schedules[idx].status = 'active';
                    startSchedule(idx);
                }
                save(); renderTable();
            });
        });

        tbody.querySelectorAll('.sched-view').forEach(btn => {
            btn.addEventListener('click', () => showDelta(parseInt(btn.dataset.idx)));
        });

        tbody.querySelectorAll('.sched-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.dataset.idx);
                if (timers[idx]) { clearInterval(timers[idx]); delete timers[idx]; }
                schedules.splice(idx, 1);
                save(); renderTable();
            });
        });
    }

    function startSchedule(idx) {
        const sched = schedules[idx];
        const ms = parseInterval(sched.interval);
        if (!ms) return;

        timers[idx] = setInterval(async () => {
            appendLog('info', `[Scheduler] Running scan: ${sched.url}`);
            sched.lastRun = new Date().toLocaleString();
            const prevFindings = sched.lastFindings || 0;

            try {
                const res = await fetch('http://127.0.0.1:8080/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: sched.url, rate: 10 })
                });
                const data = await res.json();
                sched.lastFindings = data.vulnerabilities_count || 0;

                // Track delta
                if (!sched.history) sched.history = [];
                sched.history.push({
                    time: sched.lastRun,
                    findings: sched.lastFindings,
                    delta: sched.lastFindings - prevFindings
                });
            } catch (e) {
                appendLog('vuln', `[Scheduler] Scan failed: ${e.message}`);
            }
            save(); renderTable();
        }, ms);
    }

    function parseInterval(str) {
        const map = { '1h': 3600000, '6h': 21600000, '12h': 43200000, '24h': 86400000, 'daily': 86400000, 'weekly': 604800000 };
        return map[str.toLowerCase()] || null;
    }

    function showDelta(idx) {
        const sched = schedules[idx];
        if (!sched.history || sched.history.length === 0) {
            deltaContainer.innerHTML = '<div class="empty-state">No scan history for this schedule yet.</div>';
            return;
        }

        deltaContainer.innerHTML = sched.history.slice(-10).reverse().map(h => `
            <div class="sched-delta-item">
                <div style="color: var(--text-primary); margin-bottom: 4px;">${h.time}</div>
                <div>Findings: ${h.findings} ${h.delta > 0 ? `<span class="delta-new">(+${h.delta} new)</span>` : h.delta < 0 ? `<span class="delta-resolved">(${h.delta} resolved)</span>` : '<span style="color: var(--text-muted);">(no change)</span>'}</div>
            </div>
        `).join('');
    }

    document.getElementById('sched-add-btn').addEventListener('click', () => {
        const url = targetUrlInput.value.trim();
        if (!url) {
            appendLog('vuln', 'Input Error: Target URL required for scheduling.');
            return;
        }

        // Build a temporary inline selector instead of prompt()
        const intervals = ['1h', '6h', '12h', '24h', 'daily', 'weekly'];
        const existing = document.getElementById('sched-interval-picker');
        if (existing) existing.remove();

        const picker = document.createElement('div');
        picker.id = 'sched-interval-picker';
        picker.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg-panel);border:1px solid var(--border-highlight);border-radius:var(--radius-lg);padding:24px;z-index:99999;box-shadow:var(--shadow-lg);min-width:280px;';
        picker.innerHTML = `
            <div style="font-size:14px;font-weight:600;margin-bottom:16px;color:var(--text-primary);">Schedule Scan</div>
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">Target: ${esc(url)}</div>
            <select id="sched-interval-select" class="modal-input" style="margin-bottom:16px;">
                ${intervals.map(iv => `<option value="${iv}">${iv === 'daily' ? 'Daily (24h)' : iv === 'weekly' ? 'Weekly' : 'Every ' + iv}</option>`).join('')}
            </select>
            <div style="display:flex;gap:8px;">
                <button id="sched-confirm" class="btn primary" style="flex:1;">Schedule</button>
                <button id="sched-cancel" class="btn secondary" style="flex:1;">Cancel</button>
            </div>
        `;
        document.body.appendChild(picker);

        document.getElementById('sched-cancel').addEventListener('click', () => picker.remove());
        document.getElementById('sched-confirm').addEventListener('click', () => {
            const interval = document.getElementById('sched-interval-select').value;
            schedules.push({
                url, interval,
                status: 'idle',
                lastRun: null,
                lastFindings: 0,
                history: []
            });
            save(); renderTable();
            appendLog('info', `Scheduled scan added: ${url} every ${interval}`);
            picker.remove();
        });
    });

    renderTable();

    // Auto-resume active schedules on startup
    schedules.forEach((s, idx) => {
        if (s.status === 'active') {
            startSchedule(idx);
            appendLog('info', `[Scheduler] Resumed: ${s.url} every ${s.interval}`);
        }
    });
})();

// Init
connectBridge();
setTimeout(() => {
    console.log('[UI] Running delayed init tasks...');
    showToS();
    updateStatusBar();
    loadProfiles();
}, 500);

// ═══════════════════════════════════════════════════════════════
// FEATURE 1: FINDINGS FILTER & SEARCH
// ═══════════════════════════════════════════════════════════════
(function initFindingsFilter() {
    const searchInput = document.getElementById('findings-search');
    const filterBtns = document.querySelectorAll('.sev-filter-btn');
    let activeSev = 'all';

    function applyFilter() {
        const term = (searchInput?.value || '').toLowerCase();
        const cards = findingsContainer.querySelectorAll('.finding-card');
        cards.forEach(card => {
            const sev = card.getAttribute('data-severity') || '';
            const text = card.innerText.toLowerCase();
            const matchSev = activeSev === 'all' || sev === activeSev;
            const matchSearch = !term || text.includes(term);
            card.style.display = (matchSev && matchSearch) ? '' : 'none';
        });
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeSev = btn.getAttribute('data-sev');
            applyFilter();
        });
    });

    if (searchInput) searchInput.addEventListener('input', applyFilter);
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 2 & 10: HISTORY → REQUEST FORGE BRIDGE
// ═══════════════════════════════════════════════════════════════
window.sendToForge = function (rowId) {
    const data = historyData[rowId];
    if (!data) return;
    document.getElementById('reqforge-req').value = data;
    document.querySelector('.nav-item[data-target="reqforge"]')?.click();
    appendLog('info', 'Frame sent to Request Forge for manual testing.');
};

// ═══════════════════════════════════════════════════════════════
// FEATURE 3: RESPONSE REGEX EXTRACTOR
// ═══════════════════════════════════════════════════════════════
(function initExtractor() {
    const runBtn = document.getElementById('extractor-run-btn');
    const regexInput = document.getElementById('extractor-regex');
    const resultsDiv = document.getElementById('extractor-results');
    const forgeRes = document.getElementById('reqforge-res');

    if (!runBtn || !regexInput || !resultsDiv || !forgeRes) return;

    runBtn.addEventListener('click', () => {
        const pattern = regexInput.value.trim();
        if (!pattern) {
            resultsDiv.innerHTML = '<div class="empty-state" style="padding:10px;">Enter a regex pattern first.</div>';
            return;
        }

        const text = forgeRes.value;
        if (!text || text === 'Awaiting execution...') {
            resultsDiv.innerHTML = '<div class="empty-state" style="padding:10px;">No response to extract from. Fire a payload first.</div>';
            return;
        }

        try {
            const re = new RegExp(pattern, 'g');
            let match;
            let html = '';
            let count = 0;

            while ((match = re.exec(text)) !== null && count < 50) {
                count++;
                html += `<div class="extractor-match">
                    <span class="match-idx">#${count}</span>
                    <span class="match-val">${esc(match[0])}</span>`;
                if (match.length > 1) {
                    for (let g = 1; g < match.length; g++) {
                        html += `<span class="match-group">Group ${g}: ${esc(match[g] || '')}</span>`;
                    }
                }
                html += '</div>';
                if (re.lastIndex === match.index) re.lastIndex++;
            }

            if (count === 0) {
                html = '<div class="empty-state" style="padding:10px;">No matches found.</div>';
            }

            resultsDiv.innerHTML = html;
        } catch (e) {
            resultsDiv.innerHTML = `<div class="empty-state" style="padding:10px; color:var(--danger);">Invalid regex: ${esc(e.message)}</div>`;
        }
    });

    // Request Forge copy button
    document.getElementById('reqforge-copy-btn')?.addEventListener('click', () => {
        navigator.clipboard.writeText(forgeRes.value).then(() => {
            appendLog('info', 'Response copied to clipboard.');
        });
    });
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 4: CONNECTION PROFILES
// ═══════════════════════════════════════════════════════════════
function loadProfiles() {
    const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
    const select = document.getElementById('profile-select');
    if (!select) return;

    // Keep "No Profile" option, clear rest
    select.innerHTML = '<option value="">No Profile</option>';
    profiles.forEach((p, i) => {
        const opt = document.createElement('option');
        opt.value = i;
        opt.textContent = p.name;
        select.appendChild(opt);
    });
}

(function initProfiles() {
    const select = document.getElementById('profile-select');
    const saveBtn = document.getElementById('profile-save-btn');
    const deleteBtn = document.getElementById('profile-delete-btn');

    if (!select || !saveBtn) return;

    select.addEventListener('change', () => {
        const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
        const idx = parseInt(select.value);
        if (isNaN(idx) || !profiles[idx]) return;

        targetUrlInput.value = profiles[idx].url || '';
        document.getElementById('auth-payload').value = profiles[idx].auth || '';
        appendLog('info', `Profile loaded: ${profiles[idx].name}`);
    });

    saveBtn.addEventListener('click', () => {
        const url = targetUrlInput.value.trim();
        if (!url) {
            appendLog('vuln', 'Enter a target URL before saving a profile.');
            return;
        }

        // Inline name picker instead of prompt()
        const existing = document.getElementById('profile-name-picker');
        if (existing) existing.remove();

        const picker = document.createElement('div');
        picker.id = 'profile-name-picker';
        picker.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;';
        picker.innerHTML = `
            <div style="background:var(--bg-panel);border:1px solid var(--border-color);border-radius:var(--radius);padding:20px;min-width:320px;">
                <h3 style="margin:0 0 12px;font-size:14px;color:var(--text-primary);">Save Connection Profile</h3>
                <input type="text" id="profile-name-input" placeholder="Profile name (e.g. Staging API)"
                    style="width:100%;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:var(--radius);padding:8px 12px;color:var(--text-primary);font-size:13px;margin-bottom:12px;box-sizing:border-box;">
                <div style="display:flex;gap:8px;justify-content:flex-end;">
                    <button class="btn secondary small" onclick="this.closest('#profile-name-picker').remove()">Cancel</button>
                    <button class="btn primary small" id="profile-name-confirm">Save</button>
                </div>
            </div>
        `;
        document.body.appendChild(picker);

        const nameInput = document.getElementById('profile-name-input');
        nameInput.focus();

        const confirmSave = () => {
            const name = nameInput.value.trim();
            if (!name) return;

            const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
            profiles.push({
                name: name,
                url: url,
                auth: document.getElementById('auth-payload').value.trim()
            });
            safeStore('wshawk_profiles', profiles);
            loadProfiles();
            appendLog('info', `Profile saved: ${name}`);
            picker.remove();
        };

        document.getElementById('profile-name-confirm').addEventListener('click', confirmSave);
        nameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') confirmSave();
            if (e.key === 'Escape') picker.remove();
        });
    });

    deleteBtn?.addEventListener('click', () => {
        const idx = parseInt(select.value);
        if (isNaN(idx)) {
            appendLog('vuln', 'Select a profile to delete.');
            return;
        }
        const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
        const removed = profiles.splice(idx, 1);
        safeStore('wshawk_profiles', profiles);
        loadProfiles();
        select.value = '';
        appendLog('info', `Profile deleted: ${removed[0]?.name}`);
    });
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 5: JSON & CSV EXPORT
// ═══════════════════════════════════════════════════════════════
document.getElementById('btn-export-json')?.addEventListener('click', async () => {
    const data = {
        target: targetUrlInput.value,
        generated: new Date().toISOString(),
        vulnerabilities: Object.values(globalVulns).map(v => ({
            type: v.type,
            severity: v.severity,
            description: v.description,
            payload: v.payload
        })),
        stats: {
            total_vulns: parseInt(valVulns.innerText) || 0,
            frames_analyzed: msgCount
        }
    };

    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wshawk_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    appendLog('info', 'JSON report downloaded.');
});

document.getElementById('btn-export-csv')?.addEventListener('click', async () => {
    const vulns = Object.values(globalVulns);
    if (vulns.length === 0) {
        appendLog('vuln', 'No findings to export.');
        return;
    }

    let csv = 'Type,Severity,Description,Payload\n';
    vulns.forEach(v => {
        const escape = (s) => '"' + String(s || '').replace(/"/g, '""') + '"';
        csv += `${escape(v.type)},${escape(v.severity)},${escape(v.description)},${escape(v.payload)}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wshawk_findings_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    appendLog('info', 'CSV report downloaded.');
});

// ═══════════════════════════════════════════════════════════════
// FEATURE 6: OAST CALLBACK PANEL
// ═══════════════════════════════════════════════════════════════
(function initOAST() {
    const listDiv = document.getElementById('oast-list');
    const detailDiv = document.getElementById('oast-detail');
    const pollBtn = document.getElementById('oast-poll-btn');
    const clearBtn = document.getElementById('oast-clear-btn');

    if (!listDiv || !pollBtn) return;

    let callbacks = [];

    pollBtn.addEventListener('click', async () => {
        try {
            const res = await fetch('http://127.0.0.1:8080/oast/poll');
            const data = await res.json();
            if (data.callbacks && data.callbacks.length > 0) {
                callbacks = callbacks.concat(data.callbacks);
                renderCallbacks();
                appendLog('info', `OAST: ${data.callbacks.length} new callback(s) received.`);
            } else {
                appendLog('info', 'OAST: No new callbacks.');
            }
        } catch (e) {
            appendLog('vuln', 'OAST poll failed: ' + e.message);
        }
    });

    clearBtn?.addEventListener('click', () => {
        callbacks = [];
        listDiv.innerHTML = '<div class="empty-state">No callbacks received yet.</div>';
        detailDiv.innerHTML = '<div class="empty-state">Select a callback to view details.</div>';
    });

    function renderCallbacks() {
        if (callbacks.length === 0) {
            listDiv.innerHTML = '<div class="empty-state">No callbacks received yet.</div>';
            return;
        }

        listDiv.innerHTML = callbacks.map((cb, i) => `
            <div class="oast-item" data-idx="${i}">
                <div class="oast-item-type">${esc(cb.type || 'DNS')}</div>
                <div>${esc(cb.subdomain || cb.id || 'callback-' + i)}</div>
                <div class="oast-item-time">${esc(cb.timestamp || new Date().toISOString())}</div>
            </div>
        `).join('');

        listDiv.querySelectorAll('.oast-item').forEach(item => {
            item.addEventListener('click', () => {
                listDiv.querySelectorAll('.oast-item').forEach(x => x.classList.remove('active'));
                item.classList.add('active');
                const idx = parseInt(item.getAttribute('data-idx'));
                const cb = callbacks[idx];
                detailDiv.innerHTML = `
                    <h4 style="color:var(--warning); margin-bottom: 10px;">${esc(cb.type || 'DNS')} Callback</h4>
                    <pre style="white-space: pre-wrap; word-break: break-all; color: var(--text-primary);">${esc(JSON.stringify(cb, null, 2))}</pre>
                `;
            });
        });
    }
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 7: COPY FINDING TO CLIPBOARD
// ═══════════════════════════════════════════════════════════════
window.copyFinding = function (id) {
    const vuln = globalVulns[id];
    if (!vuln) return;
    const text = `[${vuln.severity}] ${vuln.type}\n${vuln.description}\nPayload: ${vuln.payload}`;
    navigator.clipboard.writeText(text).then(() => {
        appendLog('info', 'Finding copied to clipboard.');
    });
};

// ═══════════════════════════════════════════════════════════════
// FEATURE 8: STATUS BAR
// ═══════════════════════════════════════════════════════════════
let scanStartTime = null;
let scanTimerInterval = null;

function startScanTimer() {
    scanStartTime = Date.now();
    scanTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        document.getElementById('status-timer').innerText = `${h}:${m}:${s}`;
    }, 1000);
}

function stopScanTimer() {
    if (scanTimerInterval) clearInterval(scanTimerInterval);
    scanTimerInterval = null;
}

function updateStatusBar() {
    // Storage usage
    try {
        let totalSize = 0;
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('wshawk_')) {
                totalSize += (localStorage.getItem(key) || '').length * 2; // UTF-16
            }
        }
        const kb = (totalSize / 1024).toFixed(1);
        document.getElementById('status-storage').innerText = `Storage: ${kb} KB`;
    } catch (e) { /* ignore */ }

    // Active schedulers count
    const schedules = JSON.parse(localStorage.getItem('wshawk_schedules') || '[]');
    const activeCount = schedules.filter(s => s.status === 'active').length;
    document.getElementById('status-schedulers').innerText = `${activeCount} scheduler${activeCount !== 1 ? 's' : ''}`;
}

// Update status bar every 5 seconds
setInterval(updateStatusBar, 5000);

// ═══════════════════════════════════════════════════════════════
// FEATURE 9: SEVERITY DISTRIBUTION CHART
// ═══════════════════════════════════════════════════════════════
function updateSeverityChart() {
    const cards = findingsContainer.querySelectorAll('.finding-card');
    let high = 0, medium = 0, low = 0;

    cards.forEach(card => {
        const sev = card.getAttribute('data-severity');
        if (sev === 'HIGH') high++;
        else if (sev === 'MEDIUM') medium++;
        else low++;
    });

    const total = high + medium + low;
    const maxBar = Math.max(high, medium, low, 1);

    document.getElementById('sev-count-high').innerText = high;
    document.getElementById('sev-count-medium').innerText = medium;
    document.getElementById('sev-count-low').innerText = low;

    document.getElementById('sev-bar-high').style.height = `${(high / maxBar) * 40}px`;
    document.getElementById('sev-bar-medium').style.height = `${(medium / maxBar) * 40}px`;
    document.getElementById('sev-bar-low').style.height = `${(low / maxBar) * 40}px`;
}

// ═══════════════════════════════════════════════════════════════
// FEATURE 11: PAYLOAD MUTATION LAB
// ═══════════════════════════════════════════════════════════════
(function initMutationLab() {
    const runBtn = document.getElementById('mutation-run-btn');
    const input = document.getElementById('mutation-input');
    const results = document.getElementById('mutation-results');
    const strategySelect = document.getElementById('mutation-strategy');
    const countInput = document.getElementById('mutation-count');

    if (!runBtn || !input || !results) return;

    const strategies = {
        case: function (payload) {
            const out = [];
            for (let i = 0; i < 5; i++) {
                let s = '';
                for (const ch of payload) {
                    s += Math.random() > 0.5 ? ch.toUpperCase() : ch.toLowerCase();
                }
                out.push({ strategy: 'CASE', value: s });
            }
            return out;
        },
        encode: function (payload) {
            return [
                { strategy: 'URL', value: encodeURIComponent(payload) },
                { strategy: 'B64', value: btoa(payload) },
                { strategy: 'HEX', value: Array.from(payload).map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('') },
                { strategy: 'HTML-ENT', value: Array.from(payload).map(c => '&#' + c.charCodeAt(0) + ';').join('') },
                { strategy: 'UNICODE', value: Array.from(payload).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') }
            ];
        },
        fragment: function (payload) {
            const out = [];
            const tags = ['<img src=x onerror=', '<svg onload=', '<body onload=', '<details open ontoggle=', '<marquee onstart='];
            tags.forEach(tag => {
                const inner = payload.replace(/<script>/gi, '').replace(/<\/script>/gi, '');
                out.push({ strategy: 'FRAG', value: `${tag}${inner}>` });
            });
            return out;
        },
        comment: function (payload) {
            const out = [];
            const insertComment = (s, pos) => s.slice(0, pos) + '/**/' + s.slice(pos);
            for (let i = 1; i < Math.min(payload.length, 6); i++) {
                out.push({ strategy: 'COMMENT', value: insertComment(payload, Math.floor(payload.length / (i + 1))) });
            }
            return out;
        },
        unicode: function (payload) {
            const subs = { '<': '\uFF1C', '>': '\uFF1E', '\'': '\u2019', '"': '\u201D', '/': '\u2215', '(': '\uFF08', ')': '\uFF09' };
            const out = [];
            // Single sub
            for (const [from, to] of Object.entries(subs)) {
                if (payload.includes(from)) {
                    out.push({ strategy: 'UNICODE', value: payload.replaceAll(from, to) });
                }
            }
            // All subs
            let full = payload;
            for (const [from, to] of Object.entries(subs)) full = full.replaceAll(from, to);
            if (full !== payload) out.push({ strategy: 'UNI-ALL', value: full });
            return out;
        },
        double: function (payload) {
            return [
                { strategy: 'DBL-URL', value: encodeURIComponent(encodeURIComponent(payload)) },
                { strategy: 'DBL-B64', value: btoa(btoa(payload)) },
                { strategy: 'URL+B64', value: encodeURIComponent(btoa(payload)) },
                { strategy: 'B64+URL', value: btoa(encodeURIComponent(payload)) }
            ];
        }
    };

    runBtn.addEventListener('click', async () => {
        const payload = input.value.trim();
        if (!payload) {
            results.innerHTML = '<div class="empty-state">Enter a base payload first.</div>';
            return;
        }

        const strategy = strategySelect.value;
        const maxCount = parseInt(countInput.value) || 10;
        let mutations = [];
        let engineUsed = 'CLIENT';

        // Try backend SPE engine first
        try {
            const res = await fetch('http://127.0.0.1:8080/mutate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload, strategy, count: maxCount })
            });
            const data = await res.json();
            if (data.status === 'success' && data.mutations.length > 0) {
                mutations = data.mutations;
                engineUsed = 'SPE';
            }
        } catch (e) {
            // Backend unavailable — fall through to client-side
        }

        // Client-side fallback
        if (mutations.length === 0) {
            if (strategy === 'all') {
                for (const fn of Object.values(strategies)) {
                    mutations = mutations.concat(fn(payload));
                }
            } else if (strategies[strategy]) {
                mutations = strategies[strategy](payload);
            }

            // Deduplicate and limit
            const seen = new Set();
            mutations = mutations.filter(m => {
                if (seen.has(m.value)) return false;
                seen.add(m.value);
                return true;
            }).slice(0, maxCount);
        }

        if (mutations.length === 0) {
            results.innerHTML = '<div class="empty-state">No mutations generated for this payload.</div>';
            return;
        }

        results.innerHTML = mutations.map((m, i) => `
            <div class="mutation-card">
                <span class="mut-idx">#${i + 1}</span>
                <span class="mut-strategy">${esc(m.strategy)}</span>
                <span class="mut-payload">${esc(m.value)}</span>
                <button class="mut-copy-btn" onclick="navigator.clipboard.writeText(this.parentElement.querySelector('.mut-payload').innerText).then(() => appendLog('info', 'Mutation copied.'))">Copy</button>
            </div>
        `).join('');

        appendLog('info', `Mutation Lab [${engineUsed}]: ${mutations.length} variants generated.`);
    });
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 12: GLOBAL SEARCH (Ctrl+K)
// ═══════════════════════════════════════════════════════════════
function toggleGlobalSearch() {
    const modal = document.getElementById('global-search-modal');
    if (!modal) return;

    if (modal.style.display === 'flex') {
        modal.style.display = 'none';
    } else {
        modal.style.display = 'flex';
        const input = document.getElementById('global-search-input');
        input.value = '';
        input.focus();
        document.getElementById('global-search-results').innerHTML = '<div class="empty-state" style="padding:20px;">Type to search across all data.</div>';
    }
}

(function initGlobalSearch() {
    const modal = document.getElementById('global-search-modal');
    const input = document.getElementById('global-search-input');
    const resultsDiv = document.getElementById('global-search-results');

    if (!modal || !input || !resultsDiv) return;

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.style.display = 'none';
    });

    let searchTimeout;
    input.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => performSearch(input.value.trim().toLowerCase()), 150);
    });

    function performSearch(term) {
        if (!term || term.length < 2) {
            resultsDiv.innerHTML = '<div class="empty-state" style="padding:20px;">Type at least 2 characters.</div>';
            return;
        }

        let html = '';
        let totalResults = 0;

        // Search findings
        const findingResults = [];
        for (const [id, v] of Object.entries(globalVulns)) {
            const text = `${v.type} ${v.description} ${v.payload} ${v.severity}`.toLowerCase();
            if (text.includes(term)) {
                findingResults.push({ id, vuln: v });
            }
        }
        if (findingResults.length > 0) {
            html += '<div class="gsearch-category">Findings</div>';
            findingResults.slice(0, 5).forEach(f => {
                html += `<div class="gsearch-item" onclick="document.querySelector('.nav-item[data-target=\\'dashboard\\']')?.click(); document.getElementById('global-search-modal').style.display='none';">
                    <div>[${esc(f.vuln.severity)}] ${esc(f.vuln.type)}</div>
                    <div class="gsearch-meta">${esc(truncate(f.vuln.description, 60))}</div>
                </div>`;
            });
            totalResults += findingResults.length;
        }

        // Search notes
        try {
            const notes = JSON.parse(localStorage.getItem('wshawk_notes') || '[]');
            const noteResults = notes.filter(n =>
                (n.title || '').toLowerCase().includes(term) ||
                (n.body || '').toLowerCase().includes(term)
            );
            if (noteResults.length > 0) {
                html += '<div class="gsearch-category">Notes</div>';
                noteResults.slice(0, 5).forEach(n => {
                    html += `<div class="gsearch-item" onclick="document.querySelector('.nav-item[data-target=\\'notes\\']')?.click(); document.getElementById('global-search-modal').style.display='none';">
                        <div>${esc(n.title || 'Untitled')}</div>
                        <div class="gsearch-meta">${esc(truncate(n.body || '', 60))}</div>
                    </div>`;
                });
                totalResults += noteResults.length;
            }
        } catch (e) { /* ignore */ }

        // Search history
        const histResults = [];
        for (const [id, data] of Object.entries(historyData)) {
            if (String(data).toLowerCase().includes(term)) {
                histResults.push({ id, data });
            }
        }
        if (histResults.length > 0) {
            html += '<div class="gsearch-category">History</div>';
            histResults.slice(0, 5).forEach(h => {
                html += `<div class="gsearch-item" onclick="sendToForge('${h.id}'); document.getElementById('global-search-modal').style.display='none';">
                    <div>${esc(truncate(h.data, 70))}</div>
                    <div class="gsearch-meta">Click to send to Request Forge</div>
                </div>`;
            });
            totalResults += histResults.length;
        }

        // Search endpoints (from discovery)
        try {
            const epContainer = document.getElementById('wsmap-results');
            if (epContainer) {
                const epItems = epContainer.querySelectorAll('.endpoint-card, .ep-card, tr');
                const epResults = [];
                epItems.forEach(el => {
                    if (el.innerText.toLowerCase().includes(term)) {
                        epResults.push(el.innerText.slice(0, 80));
                    }
                });
                if (epResults.length > 0) {
                    html += '<div class="gsearch-category">Endpoints</div>';
                    epResults.slice(0, 5).forEach(ep => {
                        html += `<div class="gsearch-item" onclick="document.querySelector('.nav-item[data-target=\\'wsmap\\']')?.click(); document.getElementById('global-search-modal').style.display='none';">
                            <div>${esc(truncate(ep, 70))}</div>
                        </div>`;
                    });
                    totalResults += epResults.length;
                }
            }
        } catch (e) { /* ignore */ }

        if (totalResults === 0) {
            html = `<div class="empty-state" style="padding:20px;">No results for "${esc(term)}".</div>`;
        }

        resultsDiv.innerHTML = html;
    }
})();

// ═══════════════════════════════════════════════════════════════
// WEB PENTEST TOOLS LOGIC
// ═══════════════════════════════════════════════════════════════
(function initWebPentest() {
    // 1. HTTP Forge
    const httpBtn = document.getElementById('http-send-btn');
    if (httpBtn) {
        httpBtn.addEventListener('click', async () => {
            const method = document.getElementById('http-method').value;
            const url = document.getElementById('http-url').value.trim();
            const headersStr = document.getElementById('http-headers').value;
            const bodyStr = document.getElementById('http-body').value;
            const statusBadge = document.getElementById('http-status-badge');
            const timeBadge = document.getElementById('http-time-badge');
            const resHeaders = document.getElementById('http-res-headers');
            const resBody = document.getElementById('http-res-body');

            if (!url) {
                appendLog('vuln', 'HTTP Forge: URL is required.');
                return;
            }

            resBody.value = "Sending request...";
            statusBadge.innerText = "—";
            timeBadge.innerText = "—";
            resHeaders.innerText = "—";

            try {
                // Future-proof: Try backend Web bridge first to bypass CORS
                const start = performance.now();
                const res = await fetch('http://127.0.0.1:8080/web/request', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ method, url, headers: headersStr, body: bodyStr })
                });

                if (!res.ok && res.status === 404) {
                    // Fallback to direct client-side fetch (will face CORS restrictions on many sites)
                    const dStart = performance.now();
                    const hdrs = {};
                    headersStr.split('\n').filter(l => l.includes(':')).forEach(l => {
                        const [k, ...v] = l.split(':');
                        hdrs[k.trim()] = v.join(':').trim();
                    });

                    const dRes = await fetch(url, { method, headers: hdrs, body: ['GET', 'HEAD'].includes(method) ? undefined : bodyStr });
                    const dText = await dRes.text();
                    const dTime = (performance.now() - dStart).toFixed(0) + 'ms';

                    statusBadge.innerText = dRes.status;
                    timeBadge.innerText = dTime;

                    let dHdrStr = '';
                    for (let [k, v] of dRes.headers.entries()) dHdrStr += `${k}: ${v}\n`;
                    resHeaders.innerText = dHdrStr || 'No headers captured (CORS)';
                    resBody.value = dText;
                    return;
                }

                const data = await res.json();
                const timeStr = (performance.now() - start).toFixed(0) + 'ms';
                statusBadge.innerText = data.status || "Error";
                timeBadge.innerText = timeStr;
                resHeaders.innerText = data.headers || "";
                resBody.value = data.body || "";

            } catch (err) {
                resBody.value = `Error: ${err.message}\n\nNote: Direct browser requests face CORS restrictions. Backend /web/request bridge is required for full proxying.`;
            }
        });

        document.getElementById('http-copy-res-btn')?.addEventListener('click', () => {
            navigator.clipboard.writeText(document.getElementById('http-res-body').value);
            appendLog('info', 'HTTP response copied to clipboard.');
        });
    }

    // 2. HTTP Fuzzer
    const fuzzBtn = document.getElementById('fuzz-start-btn');
    if (fuzzBtn) {
        fuzzBtn.addEventListener('click', async () => {
            const url = document.getElementById('fuzz-url').value;
            const method = document.getElementById('fuzz-method').value;
            const wordlist = document.getElementById('fuzz-wordlist').value;
            const customFile = document.getElementById('fuzz-custom-file').value;
            const encoder = document.getElementById('fuzz-encoder').value;
            const grepRegex = document.getElementById('fuzz-grep').value;

            const tbody = document.getElementById('fuzz-results-tbody');
            if (!url.includes('§FUZZ§')) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-danger" style="text-align:center;">URL must contain §FUZZ§ marker.</td></tr>`;
                return;
            }
            tbody.innerHTML = ``;
            appendLog('info', `Starting HTTP Fuzz on ${url}`);

            try {
                await fetch('http://127.0.0.1:8080/web/fuzz', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url, method, wordlist,
                        custom_file: customFile,
                        encoder: encoder,
                        grep_regex: grepRegex
                    })
                });
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-danger text-center">Backend unvailable: ${e.message}</td></tr>`;
            }
        });

        socket?.on('fuzz_result', (data) => {
            const tbody = document.getElementById('fuzz-results-tbody');
            let c = "text-muted";
            if (data.status >= 200 && data.status < 300) c = "text-safe";
            else if (data.status >= 300 && data.status < 400) c = "text-warning";
            else if (data.status >= 500) c = "text-danger";

            const tr = document.createElement('tr');
            if (data.grepped) tr.style.borderLeft = "3px solid var(--danger)";

            tr.innerHTML = `
                <td>${esc(data.payload)}</td>
                <td><span class="${c}" style="font-weight: 600;">${data.status}</span></td>
                <td>${data.length} bytes</td>
                <td style="color: var(--text-muted);">${data.time}</td>
                <td>${data.grepped ? '<span class="badge danger">REGEX MATCH</span>' : '—'}</td>
            `;
            tbody.appendChild(tr);
        });

        socket?.on('fuzz_done', () => {
            appendLog('info', 'Fuzzing task completed.');
        });
    }

    // 3. Dir Scanner
    const dirBtn = document.getElementById('dir-start-btn');
    if (dirBtn) {
        dirBtn.addEventListener('click', async () => {
            const prog = document.getElementById('dir-progress');
            const tbody = document.getElementById('dir-results-tbody');
            const url = document.getElementById('dir-target').value;
            const exts = document.getElementById('dir-exts')?.value || document.getElementById('dir-extensions').value;
            const customFile = document.getElementById('dir-custom-file').value;
            const throttleMs = document.getElementById('dir-throttle').value;
            const recursive = document.getElementById('dir-recursive').checked;

            if (!url) return;

            prog.innerText = `Scanning directories on ${url}...`;
            tbody.innerHTML = ``;

            try {
                await fetch('http://127.0.0.1:8080/web/dirscan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url, exts,
                        custom_file: customFile,
                        throttle_ms: throttleMs,
                        recursive: recursive
                    })
                });
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-danger text-center">Backend unvailable: ${e.message}</td></tr>`;
            }
        });

        socket?.on('dir_result', (data) => {
            const tbody = document.getElementById('dir-results-tbody');
            let c = "text-safe";
            if (data.status >= 300 && data.status < 400) c = "text-warning";
            else if (data.status >= 400) c = "text-danger";

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family: var(--font-mono);">${esc(data.path)}</td>
                <td><span class="${c}" style="font-weight: 600;">${data.status}</span></td>
                <td>${data.length} bytes</td>
                <td style="color: var(--text-muted);">${data.time}</td>
            `;
            tbody.appendChild(tr);
        });

        socket?.on('dir_progress', (data) => {
            const prog = document.getElementById('dir-progress');
            if (prog) prog.innerHTML += `<br/><span style="color: var(--warning);">${esc(data.msg)}</span>`;
            appendLog('info', data.msg);
        });

        socket?.on('dir_done', () => {
            const prog = document.getElementById('dir-progress');
            if (prog) prog.innerText = 'Directory scan complete.';
            appendLog('info', 'Directory scan completed.');
        });
    }

    // 4. Header Analyzer
    const headerBtn = document.getElementById('header-analyze-btn');
    if (headerBtn) {
        headerBtn.addEventListener('click', async () => {
            const url = document.getElementById('header-target-url').value;
            const resDiv = document.getElementById('header-results');
            if (!url) { resDiv.innerHTML = '<div class="empty-state">Please enter a target URL.</div>'; return; }
            resDiv.innerHTML = '<div class="empty-state">Analyzing headers via backend proxy...</div>';
            appendLog('info', `Analyzing security headers for ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/headers', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();

                if (data.status === 'error') {
                    resDiv.innerHTML = `<div class="empty-state text-danger">Analyzer failed: ${esc(data.error || data.detail)}</div>`;
                    return;
                }

                let html = '<div class="data-table" style="width:100%; border-radius: var(--radius); overflow: hidden;"><table style="width:100%; border-collapse: collapse;">';
                for (let [h, evalData] of Object.entries(data.headers)) {
                    let style = 'color: var(--text-muted);';
                    let badge = '';

                    if (evalData.value !== 'Missing') style = 'color: var(--text-primary); font-family: var(--font-mono); font-size: 11px; word-break: break-all;';

                    if (evalData.risk === 'High') badge = '<span class="badge danger" style="padding: 2px 4px; font-size: 9px; line-height: 1;">HIGH</span>';
                    else if (evalData.risk === 'Medium') badge = '<span class="badge warning" style="padding: 2px 4px; font-size: 9px; line-height: 1;">MED</span>';
                    else if (evalData.risk === 'Low') badge = '<span class="badge standard" style="padding: 2px 4px; font-size: 9px; line-height: 1;">LOW</span>';
                    else if (evalData.risk === 'Safe') badge = '<span class="badge safe" style="padding: 2px 4px; font-size: 9px; line-height: 1;">SAFE</span>';

                    html += `<tr>
                          <td style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-weight: 500; font-size: 12px; white-space: nowrap;">${h}</td>
                          <td style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); ${style}">${esc(evalData.value)}</td>
                          <td style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); white-space: nowrap;">${badge}</td>
                          <td style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted); width: 100%;">${esc(evalData.msg)}</td>
                      </tr>`;
                }
                html += '</table></div>';
                resDiv.innerHTML = html;
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Backend connect failed: ${e.message}</div>`;
            }
        });
    }

    // 5. JWT Analyzer
    const jwtBtn = document.getElementById('jwt-decode-btn');
    if (jwtBtn) {
        jwtBtn.addEventListener('click', () => {
            const token = document.getElementById('jwt-input').value.trim();
            const hOut = document.getElementById('jwt-header');
            const pOut = document.getElementById('jwt-payload');
            const sOut = document.getElementById('jwt-signature');
            if (!token) { hOut.innerText = "—"; pOut.innerText = "—"; sOut.innerText = "—"; return; }

            const parts = token.split('.');
            if (parts.length < 2) {
                hOut.innerText = "Invalid JWT Format";
                pOut.innerText = "—";
                sOut.innerText = "—";
                return;
            }

            try {
                const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
                const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

                hOut.innerText = JSON.stringify(header, null, 2);
                pOut.innerText = JSON.stringify(payload, null, 2);
                sOut.innerText = parts[2] ? `Signature Present (${parts[2].substring(0, 16)}...)` : "No Signature (None Alg)";
                appendLog('info', 'JWT Decoded successfully.');
            } catch (e) {
                hOut.innerText = `Decoding Error: ${e.message}`;
            }
        });

        document.getElementById('jwt-none-attack-btn')?.addEventListener('click', () => {
            const token = document.getElementById('jwt-input').value.trim();
            const parts = token.split('.');
            if (parts.length >= 2) {
                try {
                    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
                    header.alg = 'none';

                    // B64 URL encode
                    let newH = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                    const patched = `${newH}.${parts[1]}.`;

                    document.getElementById('jwt-attacks-output').innerHTML = `
                         <div style="background: var(--bg-hover); padding: 12px; border-radius: var(--radius); border-left: 3px solid var(--danger);">
                             <div style="font-size: 11px; font-weight: 600; margin-bottom: 6px; color: var(--danger);">ALG: NONE Attack Token Generated</div>
                             <div style="word-break: break-all; font-family: var(--font-mono); font-size: 11px; color: var(--text-primary); user-select: all;">${patched}</div>
                         </div>
                     `;
                    appendLog('vuln', 'Generated JWT alg:none fallback attack token.');
                } catch (e) { /* ignore parse error */ }
            }
        });
    }

    // 6. Subdomain Finder
    const subBtn = document.getElementById('subdomain-start-btn');
    if (subBtn) {
        subBtn.addEventListener('click', async () => {
            const target = document.getElementById('subdomain-target').value;
            const tbody = document.getElementById('subdomain-results-tbody');
            const prog = document.getElementById('subdomain-progress');
            if (!target) return;

            prog.innerText = `Resolving subdomains for ${target}...`;
            tbody.innerHTML = `<tr><td colspan="3" class="text-muted" style="text-align:center;">Querying passive DNS/CRT.sh via backend...</td></tr>`;
            appendLog('info', `Subdomain enumeration submitted for ${target}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/subdomains', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                const data = await res.json();

                if (data.status === 'error') {
                    tbody.innerHTML = `<tr><td colspan="3" class="text-danger text-center">Failed: ${esc(data.error || data.detail)}</td></tr>`;
                    prog.innerText = "Failed";
                    return;
                }

                prog.innerText = `Found ${data.subdomains.length} subdomains.`;
                if (data.subdomains.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="3" class="text-muted" style="text-align:center;">No subdomains found.</td></tr>`;
                    return;
                }

                tbody.innerHTML = '';
                data.subdomains.forEach((sub, i) => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${esc(sub)}</td>
                        <td style="font-family: var(--font-mono); font-weight: 500;">—</td>
                        <td><span class="badge safe">PASSIVE</span></td>
                     `;
                    tbody.appendChild(tr);
                });

                // Show orchestration buttons since we have results
                const wfBtn = document.getElementById('subdomain-workflow-btn');
                if (wfBtn) wfBtn.style.display = 'inline-block';

            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-danger text-center">Backend unvailable: ${e.message}</td></tr>`;
                prog.innerText = "Error";
            }
        });

        // Export logic
        document.getElementById('subdomain-export-btn')?.addEventListener('click', () => {
            const table = document.getElementById('subdomain-results-tbody');
            const rows = table.querySelectorAll('tr');
            if (rows.length === 0 || rows[0].classList.contains('empty-tr')) return;

            let out = "";
            rows.forEach(tr => {
                const td = tr.querySelectorAll('td');
                if (td.length >= 2) out += td[0].innerText + "\n";
            });
            navigator.clipboard.writeText(out);
            appendLog('info', 'Subdomains copied to clipboard.');
        });

        // Vuln Auto-Orchestrate Logic (Send to Dir Scanner)
        document.getElementById('subdomain-workflow-btn')?.addEventListener('click', () => {
            const table = document.getElementById('subdomain-results-tbody');
            const rows = table.querySelectorAll('tr');
            if (rows.length === 0 || rows[0].classList.contains('empty-tr')) return;

            // Get first valid subdomain just as an example of orchestration
            let targetSub = "";
            for (let tr of rows) {
                const td = tr.querySelectorAll('td');
                if (td.length >= 2 && td[0].innerText !== '1') {
                    targetSub = td[0].innerText;
                    break;
                }
            }

            if (targetSub) {
                // Pre-fill Directory Scanner
                document.getElementById('dir-target').value = `https://${targetSub}/`;
                // Switch view
                document.querySelectorAll('.view').forEach(v => {
                    v.classList.remove('active');
                    v.style.display = 'none';
                });
                document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));

                const dirView = document.getElementById('view-dirscanner');
                if (dirView) {
                    dirView.style.display = 'block';
                    setTimeout(() => dirView.classList.add('active'), 10);
                }
                const dirNavBtn = document.querySelector(`.nav-item[data-target="dirscanner"]`);
                if (dirNavBtn) dirNavBtn.classList.add('active');

                appendLog('vuln', `Workflow triggered: Extracted ${targetSub} to Directory Scanner.`);

                // Auto start scan
                document.getElementById('dir-start-btn')?.click();
            }
        });
    }

    // ─── 7. Web Crawler ────────────────────────────────────────────
    const crawlBtn = document.getElementById('crawl-start-btn');
    if (crawlBtn) {
        let crawlPageCount = 0;

        crawlBtn.addEventListener('click', async () => {
            const url = document.getElementById('crawl-target').value;
            const maxDepth = document.getElementById('crawl-depth').value;
            const maxPages = document.getElementById('crawl-max').value;
            const tbody = document.getElementById('crawl-results-tbody');
            const usePipeline = document.getElementById('crawl-sensitive-toggle')?.checked;

            if (!url) return;
            crawlPageCount = 0;
            tbody.innerHTML = '';
            document.getElementById('crawl-stat-pages').innerText = '0';
            document.getElementById('crawl-stat-forms').innerText = '0';
            document.getElementById('crawl-stat-scripts').innerText = '0';
            document.getElementById('crawl-stat-apis').innerText = '0';

            // Update nav dot
            const navDot = document.getElementById('nav-dot-crawler');
            if (navDot) { navDot.className = 'nav-status-dot running'; }

            const endpoint = usePipeline ? '/web/crawl-sensitive' : '/web/crawl';
            appendLog('info', `Starting ${usePipeline ? 'crawl + sensitive scan' : 'crawl'} on ${url}`);

            try {
                await fetch(`http://127.0.0.1:8080${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, max_depth: maxDepth, max_pages: maxPages })
                });
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-danger text-center">Backend unavailable: ${e.message}</td></tr>`;
                if (navDot) navDot.className = 'nav-status-dot error';
            }
        });

        socket?.on('crawl_page', (data) => {
            crawlPageCount++;
            document.getElementById('crawl-stat-pages').innerText = crawlPageCount;

            const tbody = document.getElementById('crawl-results-tbody');
            let c = 'text-safe';
            if (data.status >= 300 && data.status < 400) c = 'text-warning';
            else if (data.status >= 400) c = 'text-danger';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px; word-break: break-all;">${esc(data.url)}</td>
                <td><span class="${c}" style="font-weight: 600;">${data.status}</span></td>
                <td>${data.depth}</td>
                <td>${data.content_length} B</td>
            `;
            tbody.appendChild(tr);
        });

        socket?.on('crawl_done', (stats) => {
            document.getElementById('crawl-stat-pages').innerText = stats.pages_crawled || 0;
            document.getElementById('crawl-stat-forms').innerText = stats.forms_found || 0;
            document.getElementById('crawl-stat-scripts').innerText = stats.scripts_found || 0;
            document.getElementById('crawl-stat-apis').innerText = stats.api_endpoints_found || 0;
            appendLog('info', `Crawl complete: ${stats.pages_crawled} pages in ${stats.elapsed_seconds}s`);

            const navDot = document.getElementById('nav-dot-crawler');
            if (navDot) navDot.className = 'nav-status-dot done';
        });

        // ── Crawler → Sensitive Pipeline listeners ──
        socket?.on('pipeline_phase', (data) => {
            appendLog('info', `Pipeline [${data.phase}]: ${data.status}`);
        });

        socket?.on('pipeline_page_scanned', (data) => {
            appendLog('info', `[${data.progress}/${data.total}] ${data.url} — ${data.findings_count} findings`);
        });

        socket?.on('pipeline_complete', (data) => {
            const navDot = document.getElementById('nav-dot-crawler');
            if (navDot) navDot.className = 'nav-status-dot done';

            appendLog('info', `Pipeline complete: ${data.pages_crawled} pages crawled, ${data.pages_scanned} scanned, ${data.total_findings} secrets found`);

            // Show findings as rows in the crawl table
            if (data.findings && data.findings.length > 0) {
                const tbody = document.getElementById('crawl-results-tbody');
                const separator = document.createElement('tr');
                separator.innerHTML = `<td colspan="4" style="background: var(--bg-secondary); font-weight: 600; font-size: 11px; padding: 8px 12px; color: var(--danger);">Sensitive Data Findings (${data.total_findings})</td>`;
                tbody.appendChild(separator);

                data.findings.forEach(f => {
                    const tr = document.createElement('tr');
                    const sevColors = { High: 'text-danger', Medium: 'text-warning', Low: 'text-muted' };
                    tr.innerHTML = `
                        <td style="font-family: var(--font-mono); font-size: 11px;">${esc(f.url || '')}</td>
                        <td><span class="${sevColors[f.severity] || 'text-muted'}">${f.severity}</span></td>
                        <td>${esc(f.type)}</td>
                        <td style="font-family: var(--font-mono); font-size: 11px;">${esc(f.value)}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        });
    }

    // ─── 8. Vulnerability Scanner ──────────────────────────────────
    const vulnBtn = document.getElementById('vuln-start-btn');
    if (vulnBtn) {
        let lastVulnReport = null;
        let findingCount = 0;

        vulnBtn.addEventListener('click', async () => {
            const url = document.getElementById('vuln-target').value;
            const logDiv = document.getElementById('vuln-log');
            const tbody = document.getElementById('vuln-findings-tbody');

            if (!url) return;

            findingCount = 0;
            lastVulnReport = null;
            logDiv.innerHTML = '';
            tbody.innerHTML = '';

            // Reset phase badges
            ['crawl', 'headers', 'dirscan', 'fuzz'].forEach(p => {
                const el = document.getElementById(`vuln-phase-${p}`);
                if (el) { el.className = 'badge standard'; el.style.opacity = '0.4'; }
            });

            vulnBtn.style.display = 'none';
            document.getElementById('vuln-stop-btn').style.display = 'inline-block';
            appendLog('vuln', `Vuln scan launched on ${url}`);

            try {
                await fetch('http://127.0.0.1:8080/web/vulnscan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
            } catch (e) {
                logDiv.innerHTML += `<div style="color: var(--danger);">Backend error: ${e.message}</div>`;
            }
        });

        document.getElementById('vuln-stop-btn')?.addEventListener('click', async () => {
            try {
                await fetch('http://127.0.0.1:8080/web/vulnscan/stop', { method: 'POST' });
            } catch (_) { }
            document.getElementById('vuln-stop-btn').style.display = 'none';
            vulnBtn.style.display = 'inline-block';
            appendLog('info', 'Vuln scan stopped.');
        });

        // Phase progress
        socket?.on('vuln_phase', (data) => {
            const el = document.getElementById(`vuln-phase-${data.phase}`);
            if (!el) return;
            if (data.status === 'running') {
                el.className = 'badge warning';
                el.style.opacity = '1';
            } else if (data.status === 'done') {
                el.className = 'badge safe';
                el.style.opacity = '1';
            }
        });

        // Live log
        socket?.on('vuln_log', (data) => {
            const logDiv = document.getElementById('vuln-log');
            const color = data.level === 'error' ? 'var(--danger)' : 'var(--text-muted)';
            logDiv.innerHTML += `<div style="color:${color};">[${new Date().toLocaleTimeString()}] ${esc(data.msg)}</div>`;
            logDiv.scrollTop = logDiv.scrollHeight;
        });

        // Scan complete
        socket?.on('vuln_complete', (report) => {
            lastVulnReport = report;
            document.getElementById('vuln-stop-btn').style.display = 'none';
            vulnBtn.style.display = 'inline-block';

            const tbody = document.getElementById('vuln-findings-tbody');
            if (report.findings && report.findings.length > 0) {
                tbody.innerHTML = '';
                report.findings.forEach((f, i) => {
                    const sevColors = { High: 'danger', Medium: 'warning', Low: 'standard', Info: 'safe' };
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${i + 1}</td>
                        <td><span class="badge ${sevColors[f.severity] || 'standard'}">${f.severity}</span></td>
                        <td>${esc(f.type)}</td>
                        <td style="font-weight: 500;">${esc(f.title)}</td>
                        <td style="font-size: 11px; color: var(--text-muted);">${esc(f.detail)}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="text-muted" style="text-align:center;">No vulnerabilities found. Target appears secure.</td></tr>';
            }

            // ── Update severity chart & counters ──
            const counts = { High: 0, Medium: 0, Low: 0, Info: 0 };
            (report.findings || []).forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

            document.getElementById('vuln-count-high').innerText = counts.High;
            document.getElementById('vuln-count-medium').innerText = counts.Medium;
            document.getElementById('vuln-count-low').innerText = counts.Low;
            document.getElementById('vuln-count-info').innerText = counts.Info;
            document.getElementById('vuln-scan-time').innerText = `Completed in ${report.elapsed || '?'}s — ${report.total_findings || 0} total findings`;

            // Show charts area
            const chartsDiv = document.getElementById('vuln-charts');
            if (chartsDiv) chartsDiv.style.display = 'block';

            // Draw pie chart on canvas
            const canvas = document.getElementById('vuln-pie-chart');
            if (canvas) {
                const ctx = canvas.getContext('2d');
                const total = counts.High + counts.Medium + counts.Low + counts.Info;
                const cx = 60, cy = 60, r = 50;

                ctx.clearRect(0, 0, 120, 120);

                if (total === 0) {
                    // Empty circle
                    ctx.beginPath();
                    ctx.arc(cx, cy, r, 0, Math.PI * 2);
                    ctx.fillStyle = '#333';
                    ctx.fill();
                } else {
                    const slices = [
                        { count: counts.High, color: '#ef4444' },
                        { count: counts.Medium, color: '#f59e0b' },
                        { count: counts.Low, color: '#06b6d4' },
                        { count: counts.Info, color: '#6b7280' },
                    ];
                    let startAngle = -Math.PI / 2;
                    slices.forEach(s => {
                        if (s.count === 0) return;
                        const sweep = (s.count / total) * Math.PI * 2;
                        ctx.beginPath();
                        ctx.moveTo(cx, cy);
                        ctx.arc(cx, cy, r, startAngle, startAngle + sweep);
                        ctx.closePath();
                        ctx.fillStyle = s.color;
                        ctx.fill();
                        startAngle += sweep;
                    });

                    // Center hole for donut effect
                    ctx.beginPath();
                    ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
                    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--bg-primary').trim() || '#0f0f12';
                    ctx.fill();

                    // Center text
                    ctx.fillStyle = '#fff';
                    ctx.font = 'bold 18px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(total.toString(), cx, cy);
                }
            }

            // Update nav count badge
            const navBadge = document.getElementById('nav-count-vuln');
            if (navBadge) {
                navBadge.innerText = report.total_findings || 0;
                navBadge.className = (report.total_findings > 0) ? 'nav-count danger' : 'nav-count hidden';
            }

            appendLog('info', `Vuln scan complete: ${report.total_findings} findings in ${report.elapsed}s`);
        });

        // Export report
        document.getElementById('vuln-export-btn')?.addEventListener('click', async () => {
            const logDiv = document.getElementById('vuln-log');
            if (!lastVulnReport) {
                if (logDiv) logDiv.innerHTML += `<div style="color:var(--warning);">[!] No scan report to export. Run a scan first.</div>`;
                appendLog('error', 'No scan report to export. Run a scan first.');
                return;
            }

            try {
                const res = await fetch('http://127.0.0.1:8080/web/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ report: lastVulnReport, format: 'html' })
                });

                if (!res.ok) {
                    throw new Error(`HTTP error! status: ${res.status}`);
                }

                const data = await res.json();
                if (data.status === 'success') {
                    if (logDiv) {
                        logDiv.innerHTML += `<div style="color:var(--safe);">[+] Report successfully exported to:<br><code>${data.path}</code></div>`;
                        logDiv.scrollTop = logDiv.scrollHeight;
                    }
                    appendLog('info', `Report exported to: ${data.path}`);

                    if (navigator.clipboard) navigator.clipboard.writeText(data.path);
                    alert(`Vulnerability Report Exported Successfully!\n\nSaved to: ${data.path}\n\nPath copied to clipboard!`);
                } else {
                    throw new Error(data.detail || "Unknown error occurred.");
                }
            } catch (e) {
                if (logDiv) logDiv.innerHTML += `<div style="color:var(--danger);">[-] Report export failed: ${e.message}</div>`;
                appendLog('error', `Report export failed: ${e.message}`);
                alert(`Error exporting report:\n${e.message}`);
            }
        });
    }

    // ─── 9. Tech Fingerprint ───────────────────────────────────────
    const techBtn = document.getElementById('techfp-start-btn');
    if (techBtn) {
        techBtn.addEventListener('click', async () => {
            const url = document.getElementById('techfp-target').value;
            const resDiv = document.getElementById('techfp-results');
            if (!url) return;

            resDiv.innerHTML = '<div class="empty-state">Scanning...</div>';
            appendLog('info', `Tech fingerprinting ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/fingerprint', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();

                if (data.status !== 'success' || !data.technologies || data.technologies.length === 0) {
                    resDiv.innerHTML = '<div class="empty-state">No technologies detected.</div>';
                    return;
                }

                // Group by category
                const grouped = {};
                data.technologies.forEach(t => {
                    if (!grouped[t.category]) grouped[t.category] = [];
                    grouped[t.category].push(t);
                });

                const catColors = {
                    'Server': '#ef4444', 'Framework': '#8b5cf6', 'CMS': '#f59e0b',
                    'JS Library': '#3b82f6', 'Analytics': '#10b981', 'CDN/Infrastructure': '#06b6d4',
                    'Security': '#22c55e', 'Other': '#6b7280'
                };

                let html = `<div style="margin-bottom: 12px; font-size: 12px; color: var(--text-muted);">Detected <strong>${data.count}</strong> technologies</div>`;
                html += '<div style="display: flex; flex-wrap: wrap; gap: 12px;">';

                for (const [cat, techs] of Object.entries(grouped)) {
                    const color = catColors[cat] || '#6b7280';
                    html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 12px 16px; border-left: 3px solid ${color}; min-width: 200px; flex: 1;">`;
                    html += `<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: ${color}; margin-bottom: 8px; font-weight: 600;">${cat}</div>`;
                    techs.forEach(t => {
                        const conf = t.confidence === 'High' ? '●●●' : '●●○';
                        html += `<div style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid var(--border-color);">
                            <span style="font-weight: 500; font-size: 13px;">${esc(t.name)}</span>
                            <span style="font-size: 10px; color: var(--text-muted);" title="Confidence: ${t.confidence}">${conf}</span>
                        </div>`;
                    });
                    html += '</div>';
                }
                html += '</div>';

                // Meta generator
                if (data.meta_generator) {
                    html += `<div style="margin-top: 12px; font-size: 11px; color: var(--text-muted);">Meta Generator: <code>${esc(data.meta_generator)}</code></div>`;
                }

                resDiv.innerHTML = html;
                appendLog('info', `Fingerprint complete: ${data.count} technologies found`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });
    }

    // ─── 10. SSL/TLS Analyzer ──────────────────────────────────────
    const sslBtn = document.getElementById('ssl-start-btn');
    if (sslBtn) {
        sslBtn.addEventListener('click', async () => {
            const host = document.getElementById('ssl-target').value;
            const port = document.getElementById('ssl-port').value;
            const resDiv = document.getElementById('ssl-results');
            if (!host) return;

            resDiv.innerHTML = '<div class="empty-state">Analyzing SSL/TLS...</div>';
            appendLog('info', `SSL analysis on ${host}:${port}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/ssl', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host, port })
                });
                const data = await res.json();

                if (data.status !== 'success') {
                    resDiv.innerHTML = `<div class="empty-state text-danger">${esc(data.detail || 'Analysis failed')}</div>`;
                    return;
                }

                const cert = data.certificate || {};
                const riskColor = { High: 'var(--danger)', Medium: 'var(--warning)', Safe: 'var(--accent)' }[data.risk_score] || 'var(--text-muted)';

                let html = '';

                // Risk badge
                html += `<div style="margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 14px; font-weight: 700; color: ${riskColor};">Risk: ${data.risk_score}</span>
                </div>`;

                // Cert info card
                html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px; margin-bottom: 12px;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">Certificate Details</div>
                    <table style="width: 100%; font-size: 12px;">
                        <tr><td style="padding: 4px 0; color: var(--text-muted); width: 140px;">Subject</td><td style="font-weight: 500;">${esc(cert.subject || '—')}</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">Issuer</td><td>${esc(cert.issuer || '—')}</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">Valid From</td><td>${esc(cert.not_before || '—')}</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">Valid Until</td><td>${esc(cert.not_after || '—')}</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">Days Remaining</td><td style="font-weight: 600; color: ${(cert.days_remaining || 0) < 30 ? 'var(--danger)' : 'var(--accent)'};">${cert.days_remaining ?? '—'}</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">Protocol</td><td>${esc(cert.protocol || '—')}</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">Cipher</td><td style="font-family: var(--font-mono); font-size: 11px;">${esc(cert.cipher || '—')} (${cert.cipher_bits || '?'}-bit)</td></tr>
                        <tr><td style="padding: 4px 0; color: var(--text-muted);">SANs</td><td style="font-size: 11px; word-break: break-all;">${(cert.san || []).map(s => esc(s)).join(', ') || '—'}</td></tr>
                    </table>
                </div>`;

                // Protocol support
                if (data.protocols && data.protocols.length > 0) {
                    html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px; margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">Protocol Support</div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">`;
                    data.protocols.forEach(p => {
                        const isWeak = p.name === 'SSLv3' || p.name === 'TLSv1.0' || p.name === 'TLSv1.1';
                        const bg = p.supported ? (isWeak ? 'var(--danger)' : 'var(--accent)') : 'var(--bg-tertiary)';
                        const textCol = p.supported ? '#fff' : 'var(--text-muted)';
                        html += `<span style="background: ${bg}; color: ${textCol}; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">${p.name} ${p.supported ? '✓' : '✗'}</span>`;
                    });
                    html += '</div></div>';
                }

                // Issues
                if (data.issues && data.issues.length > 0) {
                    html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px;">
                        <div style="font-size: 11px; color: var(--danger); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">Issues (${data.issues.length})</div>`;
                    data.issues.forEach(i => {
                        const col = i.severity === 'High' ? 'var(--danger)' : 'var(--warning)';
                        html += `<div style="padding: 6px 0; border-bottom: 1px solid var(--border-color); font-size: 12px;">
                            <span style="color: ${col}; font-weight: 600;">[${i.severity}]</span> ${esc(i.msg)}
                        </div>`;
                    });
                    html += '</div>';
                }

                resDiv.innerHTML = html;
                appendLog('info', `SSL analysis done: Risk=${data.risk_score}, ${(data.issues || []).length} issues`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });
    }

    // ─── 11. Sensitive Data Finder ─────────────────────────────────
    const senBtn = document.getElementById('sensitive-start-btn');
    if (senBtn) {
        senBtn.addEventListener('click', async () => {
            const url = document.getElementById('sensitive-target').value;
            const tbody = document.getElementById('sensitive-results-tbody');
            const prog = document.getElementById('sensitive-progress');
            if (!url) return;

            prog.innerText = `Scanning ${url} for sensitive data...`;
            tbody.innerHTML = '';
            appendLog('info', `Sensitive data scan on ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/sensitive', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();

                if (data.status !== 'success') {
                    prog.innerText = 'Scan failed.';
                    return;
                }

                prog.innerText = `Found ${data.total} sensitive data patterns.`;

                if (data.findings && data.findings.length > 0) {
                    data.findings.forEach(f => {
                        const sevColors = { High: 'danger', Medium: 'warning', Low: 'standard' };
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td><span class="badge ${sevColors[f.severity] || 'standard'}">${f.severity}</span></td>
                            <td style="font-weight: 500; font-size: 12px;">${esc(f.type)}</td>
                            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--warning);">${esc(f.value)}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                } else {
                    tbody.innerHTML = '<tr><td colspan="3" class="text-muted" style="text-align:center;">No sensitive data found. Page appears clean.</td></tr>';
                }

                appendLog('info', `Sensitive data scan complete: ${data.total} findings`);
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-danger text-center">Backend error: ${e.message}</td></tr>`;
                prog.innerText = 'Error';
            }
        });
    }

    // ─── 12. WAF Detector ──────────────────────────────────────────
    const wafBtn = document.getElementById('waf-start-btn');
    if (wafBtn) {
        wafBtn.addEventListener('click', async () => {
            const url = document.getElementById('waf-target').value;
            const resDiv = document.getElementById('waf-results');
            if (!url) return;

            resDiv.innerHTML = '<div class="empty-state">Probing target for WAFs...</div>';

            try {
                const res = await fetch('http://127.0.0.1:8080/web/waf', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();

                let html = '';

                if (data.detected && data.detected.length > 0) {
                    // Blocked status
                    const blockedBadge = data.blocked
                        ? '<span class="badge danger" style="margin-left: 8px;">BLOCKED</span>'
                        : '<span class="badge safe" style="margin-left: 8px;">NOT BLOCKED</span>';

                    html += `<div style="margin-bottom: 16px; font-size: 13px;">
                        Detected <strong>${data.waf_count}</strong> WAF(s) ${blockedBadge}
                    </div>`;

                    // WAF cards
                    html += '<div style="display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">';
                    data.detected.forEach(w => {
                        const methodColor = w.method === 'active' ? 'var(--danger)' : 'var(--accent)';
                        html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 14px 18px; border-left: 3px solid ${methodColor}; flex: 1; min-width: 200px;">
                            <div style="font-weight: 700; font-size: 14px;">${esc(w.name)}</div>
                            <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">via ${w.matched_via.join(', ')} (${w.method})</div>
                        </div>`;
                    });
                    html += '</div>';

                    // Evidence log
                    html += '<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 12px; font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); max-height: 200px; overflow-y: auto;">';
                    data.evidence.forEach(e => {
                        html += `<div>${esc(e)}</div>`;
                    });
                    html += '</div>';
                } else {
                    html = '<div class="empty-state">No WAFs detected. Target appears unprotected.</div>';
                }

                resDiv.innerHTML = html;
                appendLog('info', `WAF detection complete: ${data.waf_count} WAF(s) found`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });
    }

    // ─── 13. CORS Tester ───────────────────────────────────────────
    const corsBtn = document.getElementById('cors-start-btn');
    if (corsBtn) {
        corsBtn.addEventListener('click', async () => {
            const url = document.getElementById('cors-target').value;
            const tbody = document.getElementById('cors-results-tbody');
            const summary = document.getElementById('cors-summary');
            if (!url) return;

            summary.innerText = 'Testing CORS configuration...';
            tbody.innerHTML = '';

            try {
                const res = await fetch('http://127.0.0.1:8080/web/cors', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();

                const riskColor = { High: 'var(--danger)', Medium: 'var(--warning)', Low: 'var(--text-muted)', Safe: 'var(--accent)' };
                summary.innerHTML = `Risk: <strong style="color: ${riskColor[data.risk_score] || 'inherit'};">${data.risk_score}</strong> — ${data.total} issue(s) found.`;

                if (data.findings && data.findings.length > 0) {
                    data.findings.forEach(f => {
                        const sevColors = { High: 'danger', Medium: 'warning', Low: 'standard' };
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td><span class="badge ${sevColors[f.severity] || 'standard'}">${f.severity}</span></td>
                            <td style="font-weight: 500;">${esc(f.test)}</td>
                            <td style="font-family: var(--font-mono); font-size: 11px;">${esc(f.origin_sent)}</td>
                            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--warning);">${esc(f.acao_received)}</td>
                            <td>${f.credentials ? '<span class="badge danger">Yes</span>' : 'No'}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-muted" style="text-align:center;">No CORS issues found. Policy appears secure.</td></tr>';
                }

                appendLog('info', `CORS test complete: ${data.risk_score} risk, ${data.total} issues`);
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="5" class="text-danger text-center">Error: ${e.message}</td></tr>`;
            }
        });
    }

    // ─── 14. Port Scanner ──────────────────────────────────────────
    const portBtn = document.getElementById('port-start-btn');
    if (portBtn) {
        portBtn.addEventListener('click', async () => {
            const host = document.getElementById('port-target').value;
            const preset = document.getElementById('port-preset').value;
            const customPorts = document.getElementById('port-custom').value;
            const tbody = document.getElementById('port-results-tbody');
            if (!host) return;

            tbody.innerHTML = '';
            document.getElementById('port-stat-open').innerText = '0';
            document.getElementById('port-stat-total').innerText = '...';
            document.getElementById('port-stat-time').innerText = 'scanning...';
            appendLog('info', `Port scan started on ${host}`);

            try {
                const payload = { host, preset };
                if (customPorts.trim()) payload.ports = customPorts;

                await fetch('http://127.0.0.1:8080/web/portscan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-danger text-center">Backend error: ${e.message}</td></tr>`;
            }
        });

        // Real-time port found
        socket?.on('port_found', (data) => {
            const tbody = document.getElementById('port-results-tbody');
            const openCount = parseInt(document.getElementById('port-stat-open').innerText) + 1;
            document.getElementById('port-stat-open').innerText = openCount;

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-weight: 600; font-family: var(--font-mono);">${data.port}</td>
                <td><span class="badge safe">open</span></td>
                <td>${esc(data.service)}</td>
                <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${esc(data.banner || '—')}</td>
            `;
            tbody.appendChild(tr);
        });

        // Scan complete
        socket?.on('portscan_done', (data) => {
            document.getElementById('port-stat-open').innerText = data.open_count;
            document.getElementById('port-stat-total').innerText = data.total_scanned;
            document.getElementById('port-stat-time').innerText = `${data.elapsed}s`;
            appendLog('info', `Port scan done: ${data.open_count} open / ${data.total_scanned} scanned in ${data.elapsed}s`);

            if (data.open_count === 0) {
                const tbody = document.getElementById('port-results-tbody');
                tbody.innerHTML = '<tr><td colspan="4" class="text-muted" style="text-align:center;">No open ports found.</td></tr>';
            }
        });
    }

    // ─── 15. DNS / WHOIS Lookup ────────────────────────────────────
    const dnsBtn = document.getElementById('dns-start-btn');
    if (dnsBtn) {
        dnsBtn.addEventListener('click', async () => {
            const domain = document.getElementById('dns-target').value;
            const resDiv = document.getElementById('dns-results');
            if (!domain) return;

            resDiv.innerHTML = '<div class="empty-state">Querying DNS records & WHOIS...</div>';

            try {
                const res = await fetch('http://127.0.0.1:8080/web/dns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                const data = await res.json();

                if (data.status !== 'success') {
                    resDiv.innerHTML = `<div class="empty-state text-danger">${esc(data.detail || 'Lookup failed')}</div>`;
                    return;
                }

                let html = '';

                // DNS Records
                const records = data.dns_records || {};
                html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px; margin-bottom: 12px;">
                    <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--accent); margin-bottom: 10px; font-weight: 600;">DNS Records</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 12px;">`;

                for (const [type, values] of Object.entries(records)) {
                    const vals = Array.isArray(values) ? values : [values];
                    if (vals.length === 0) continue;
                    html += `<div style="flex: 1; min-width: 160px; background: var(--bg-tertiary); border-radius: 6px; padding: 10px;">
                        <div style="font-size: 10px; color: var(--accent); font-weight: 700; margin-bottom: 6px;">${type}</div>`;
                    vals.forEach(v => {
                        html += `<div style="font-family: var(--font-mono); font-size: 11px; padding: 2px 0; word-break: break-all;">${esc(String(v))}</div>`;
                    });
                    html += '</div>';
                }
                html += '</div></div>';

                // Reverse DNS
                if (data.reverse_dns) {
                    html += `<div style="font-size: 12px; margin-bottom: 12px; color: var(--text-muted);">Reverse DNS: <code>${esc(data.reverse_dns)}</code></div>`;
                }

                // WHOIS
                const whois = data.whois || {};
                const parsed = whois.parsed || {};
                if (Object.keys(parsed).length > 0) {
                    html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px; margin-bottom: 12px;">
                        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--warning); margin-bottom: 10px; font-weight: 600;">WHOIS Information</div>
                        <table style="width: 100%; font-size: 12px;">`;

                    if (parsed.registrar) html += `<tr><td style="padding: 4px 0; color: var(--text-muted); width: 140px;">Registrar</td><td>${esc(parsed.registrar)}</td></tr>`;
                    if (parsed.created) html += `<tr><td style="padding: 4px 0; color: var(--text-muted);">Created</td><td>${esc(parsed.created)}</td></tr>`;
                    if (parsed.updated) html += `<tr><td style="padding: 4px 0; color: var(--text-muted);">Updated</td><td>${esc(parsed.updated)}</td></tr>`;
                    if (parsed.expires) html += `<tr><td style="padding: 4px 0; color: var(--text-muted);">Expires</td><td>${esc(parsed.expires)}</td></tr>`;
                    if (parsed.name_servers && parsed.name_servers.length) {
                        html += `<tr><td style="padding: 4px 0; color: var(--text-muted);">Name Servers</td><td style="font-family: var(--font-mono); font-size: 11px;">${parsed.name_servers.map(s => esc(s)).join('<br>')}</td></tr>`;
                    }
                    if (parsed.status && parsed.status.length) {
                        html += `<tr><td style="padding: 4px 0; color: var(--text-muted);">Status</td><td style="font-size: 11px;">${parsed.status.map(s => esc(s)).join('<br>')}</td></tr>`;
                    }
                    html += '</table></div>';
                }

                html += `<div style="font-size: 10px; color: var(--text-muted);">Completed in ${data.elapsed}s via ${esc(whois.server || 'default')}</div>`;

                resDiv.innerHTML = html;
                appendLog('info', `DNS/WHOIS lookup complete for ${domain} in ${data.elapsed}s`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });
    }

    // ─── 16. Session Save / Load ───────────────────────────────────
    const saveBtn = document.getElementById('session-save-btn');
    const loadBtn = document.getElementById('session-load-btn');

    if (saveBtn) {
        saveBtn.addEventListener('click', async () => {
            const name = prompt('Session name:', `session_${new Date().toISOString().slice(0, 10)}`);
            if (!name) return;

            // Collect all visible scan data from DOM
            const sessionData = {
                target: document.getElementById('target-url')?.value || '',
                // Snapshot all results TBodies as HTML
                snapshots: {},
            };

            // Capture all result tables
            const tables = [
                'crawl-results-tbody', 'vuln-findings-tbody', 'cors-results-tbody',
                'port-results-tbody', 'sensitive-results-tbody',
            ];
            tables.forEach(id => {
                const el = document.getElementById(id);
                if (el) sessionData.snapshots[id] = el.innerHTML;
            });

            // Capture result divs
            const divs = ['waf-results', 'dns-results', 'techfp-results', 'ssl-results'];
            divs.forEach(id => {
                const el = document.getElementById(id);
                if (el) sessionData.snapshots[id] = el.innerHTML;
            });

            // Capture stats
            const stats = [
                'crawl-stat-pages', 'crawl-stat-forms', 'crawl-stat-scripts', 'crawl-stat-apis',
                'port-stat-open', 'port-stat-total', 'port-stat-time',
                'vuln-count-high', 'vuln-count-medium', 'vuln-count-low', 'vuln-count-info',
            ];
            stats.forEach(id => {
                const el = document.getElementById(id);
                if (el) sessionData.snapshots[id] = el.innerText;
            });

            try {
                const res = await fetch('http://127.0.0.1:8080/session/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, session: sessionData })
                });
                const data = await res.json();
                if (data.status === 'success') {
                    appendLog('info', `Session saved: ${data.name} → ${data.path}`);
                } else {
                    appendLog('error', `Save failed: ${data.detail || 'Unknown error'}`);
                }
            } catch (e) {
                appendLog('error', `Session save failed: ${e.message}`);
            }
        });
    }

    if (loadBtn) {
        loadBtn.addEventListener('click', async () => {
            // Fetch session list
            try {
                const listRes = await fetch('http://127.0.0.1:8080/session/list');
                const listData = await listRes.json();

                if (!listData.sessions || listData.sessions.length === 0) {
                    appendLog('info', 'No saved sessions found.');
                    return;
                }

                // Simple prompt-based picker
                const names = listData.sessions.map((s, i) => `${i + 1}. ${s.name} (${s.created})`).join('\n');
                const choice = prompt(`Select session to load:\n${names}\n\nEnter number:`);
                if (!choice) return;

                const idx = parseInt(choice) - 1;
                if (idx < 0 || idx >= listData.sessions.length) {
                    appendLog('error', 'Invalid selection.');
                    return;
                }

                const selectedName = listData.sessions[idx].name;

                const loadRes = await fetch('http://127.0.0.1:8080/session/load', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: selectedName })
                });
                const loadData = await loadRes.json();

                if (loadData.status === 'success' && loadData.session?.data?.snapshots) {
                    const snaps = loadData.session.data.snapshots;

                    // Restore all captured elements
                    for (const [id, content] of Object.entries(snaps)) {
                        const el = document.getElementById(id);
                        if (el) {
                            // For TBodies and result divs, set innerHTML
                            if (id.includes('tbody') || id.includes('results')) {
                                el.innerHTML = content;
                            } else {
                                el.innerText = content;
                            }
                        }
                    }

                    // Restore target URL
                    if (loadData.session.data.target) {
                        const tgt = document.getElementById('target-url');
                        if (tgt) tgt.value = loadData.session.data.target;
                    }

                    // Show vuln charts if vuln data exists
                    if (snaps['vuln-count-high'] && parseInt(snaps['vuln-count-high']) > 0) {
                        const chartsDiv = document.getElementById('vuln-charts');
                        if (chartsDiv) chartsDiv.style.display = 'block';
                    }

                    appendLog('info', `Session "${selectedName}" loaded successfully.`);
                } else {
                    appendLog('error', 'Failed to parse session data.');
                }
            } catch (e) {
                appendLog('error', `Session load failed: ${e.message}`);
            }
        });
    }

    // ─── 17. CSRF Forge ────────────────────────────────────────────
    const csrfBtn = document.getElementById('csrf-gen-btn');
    if (csrfBtn) {
        let lastPocHtml = '';

        csrfBtn.addEventListener('click', async () => {
            const url = document.getElementById('csrf-url').value;
            const method = document.getElementById('csrf-method').value;
            const body = document.getElementById('csrf-body').value;
            const headers = document.getElementById('csrf-headers').value;
            const resDiv = document.getElementById('csrf-results');

            if (!url) return;
            resDiv.innerHTML = '<div class="empty-state">Generating...</div>';
            appendLog('info', `Generating CSRF PoC for ${method} ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/csrf', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, method, body, headers })
                });
                const data = await res.json();

                if (data.status !== 'success') {
                    resDiv.innerHTML = `<div class="empty-state text-danger">${data.detail || 'Error'}</div>`;
                    return;
                }

                lastPocHtml = data.poc_html || '';

                let html = '';

                // Warnings
                if (data.warnings && data.warnings.length > 0) {
                    html += '<div style="margin-bottom: 12px;">';
                    data.warnings.forEach(w => {
                        html += `<div style="background: rgba(245,158,11,0.1); border-left: 3px solid var(--warning); padding: 8px 12px; margin-bottom: 4px; font-size: 11px; border-radius: 4px; color: var(--warning);">⚠ ${esc(w)}</div>`;
                    });
                    html += '</div>';
                }

                // Status
                const exploitable = data.exploitable;
                html += `<div style="display: flex; gap: 12px; margin-bottom: 12px; font-size: 11px;">
                    <span class="badge ${exploitable ? 'danger' : 'safe'}">${exploitable ? 'EXPLOITABLE' : 'PROTECTED'}</span>
                    <span style="color: var(--text-muted);">Type: <strong>${esc(data.poc_type)}</strong></span>
                </div>`;

                // PoC code
                html += `<div style="background: var(--bg-secondary); border-radius: 6px; padding: 12px; overflow-x: auto;">
                    <pre style="margin: 0; font-size: 11px; color: var(--text-primary); white-space: pre-wrap;">${esc(lastPocHtml)}</pre>
                </div>`;

                resDiv.innerHTML = html;
                appendLog('info', `CSRF PoC generated (${data.poc_type})`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });

        document.getElementById('csrf-copy-btn')?.addEventListener('click', () => {
            if (lastPocHtml) {
                navigator.clipboard.writeText(lastPocHtml);
                appendLog('info', 'CSRF PoC HTML copied to clipboard');
            }
        });
    }

    // ─── 18. Blind Probe (SSRF) ────────────────────────────────────
    const ssrfBtn = document.getElementById('ssrf-start-btn');
    if (ssrfBtn) {
        let ssrfFindingCount = 0;

        ssrfBtn.addEventListener('click', async () => {
            const url = document.getElementById('ssrf-url').value;
            const param = document.getElementById('ssrf-param').value;
            const tbody = document.getElementById('ssrf-results-tbody');

            if (!url) return;
            ssrfFindingCount = 0;
            tbody.innerHTML = '';
            document.getElementById('ssrf-stat-sent').innerText = '0';
            document.getElementById('ssrf-stat-findings').innerText = '0';
            document.getElementById('ssrf-stat-params').innerText = param || 'auto';
            appendLog('info', `Starting SSRF probe on ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/ssrf', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, param })
                });
                const data = await res.json();
                if (data.status === 'started') {
                    appendLog('info', 'SSRF probe running in background...');
                }
            } catch (e) {
                appendLog('error', `SSRF probe failed: ${e.message}`);
            }
        });

        socket?.on('ssrf_finding', (f) => {
            ssrfFindingCount++;
            document.getElementById('ssrf-stat-findings').innerText = ssrfFindingCount;

            const tbody = document.getElementById('ssrf-results-tbody');
            const sevColors = { High: 'danger', Medium: 'warning', Low: 'standard' };
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><span class="badge ${sevColors[f.severity] || 'standard'}">${f.severity}</span></td>
                <td>${esc(f.category)}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${esc(f.param)}</td>
                <td style="font-family: var(--font-mono); font-size: 10px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${esc(f.payload)}</td>
                <td>${f.status}</td>
                <td style="font-size: 10px; color: var(--text-muted);">${(f.indicators || []).map(i => esc(i)).join('<br>')}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ─── 19. Redirect Hunter ───────────────────────────────────────
    const redirectBtn = document.getElementById('redirect-start-btn');
    if (redirectBtn) {
        redirectBtn.addEventListener('click', async () => {
            const url = document.getElementById('redirect-url').value;
            const param = document.getElementById('redirect-param').value;
            const tbody = document.getElementById('redirect-results-tbody');

            if (!url) return;
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">Scanning...</td></tr>';
            appendLog('info', `Starting redirect scan on ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/redirect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, param })
                });
                const data = await res.json();

                if (!data.findings || data.findings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No open redirects found. Target appears secure.</td></tr>';
                    appendLog('info', `Redirect scan complete: 0 findings in ${data.elapsed}s`);
                    return;
                }

                tbody.innerHTML = '';
                data.findings.forEach(f => {
                    const sevColors = { High: 'danger', Medium: 'warning', Low: 'standard' };
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><span class="badge ${sevColors[f.severity] || 'standard'}">${f.severity}</span></td>
                        <td>${esc(f.payload_name)}</td>
                        <td style="font-family: var(--font-mono); font-size: 11px;">${esc(f.param)}</td>
                        <td style="font-family: var(--font-mono); font-size: 10px; max-width: 180px; overflow: hidden; text-overflow: ellipsis;">${esc(f.payload)}</td>
                        <td>${esc(f.redirect_type)}</td>
                        <td style="font-family: var(--font-mono); font-size: 10px;">${esc(f.redirect_to)}</td>
                    `;
                    tbody.appendChild(tr);
                });

                appendLog('info', `Redirect scan complete: ${data.total_findings} findings in ${data.elapsed}s`);
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-danger">${e.message}</td></tr>`;
            }
        });
    }

    // ─── 20. Proto Polluter ────────────────────────────────────────
    const protoBtn = document.getElementById('proto-start-btn');
    if (protoBtn) {
        protoBtn.addEventListener('click', async () => {
            const url = document.getElementById('proto-url').value;
            const method = document.getElementById('proto-method').value;
            const tbody = document.getElementById('proto-results-tbody');

            if (!url) return;
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">Testing...</td></tr>';
            document.getElementById('proto-stat-tests').innerText = '0';
            document.getElementById('proto-stat-findings').innerText = '0';
            document.getElementById('proto-stat-baseline').innerText = '...';
            appendLog('info', `Starting prototype pollution test on ${url}`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/proto', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, method })
                });
                const data = await res.json();

                document.getElementById('proto-stat-tests').innerText = data.tests_run || 0;
                document.getElementById('proto-stat-findings').innerText = data.total_findings || 0;
                document.getElementById('proto-stat-baseline').innerText = `${data.baseline_length || 0} bytes`;

                if (!data.findings || data.findings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No prototype pollution detected.</td></tr>';
                    appendLog('info', `Proto pollution test complete: 0 findings in ${data.elapsed}s`);
                    return;
                }

                tbody.innerHTML = '';
                data.findings.forEach(f => {
                    const sevColors = { High: 'danger', Medium: 'warning', Low: 'standard' };
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><span class="badge ${sevColors[f.severity] || 'standard'}">${f.severity}</span></td>
                        <td>${esc(f.vector)}</td>
                        <td style="font-family: var(--font-mono); font-size: 10px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${esc(f.payload)}</td>
                        <td>${f.status}</td>
                        <td style="font-weight: 600; color: ${f.response_diff > 50 ? 'var(--warning)' : 'var(--text-muted)'};">${f.response_diff > 0 ? '+' + f.response_diff : '0'} bytes</td>
                        <td style="font-size: 10px; color: var(--text-muted);">${(f.indicators || []).map(i => esc(i)).join(', ')}</td>
                    `;
                    tbody.appendChild(tr);
                });

                appendLog('info', `Proto pollution test complete: ${data.total_findings} findings in ${data.elapsed}s`);
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-danger">${e.message}</td></tr>`;
            }
        });
    }

    // ─── 21. Proxy CA ──────────────────────────────────────────────
    const caGenBtn = document.getElementById('ca-generate-btn');
    if (caGenBtn) {
        caGenBtn.addEventListener('click', async () => {
            const resDiv = document.getElementById('ca-results');
            resDiv.innerHTML = '<div class="empty-state">Generating CA...</div>';
            appendLog('info', 'Generating WSHawk root CA...');

            try {
                const res = await fetch('http://127.0.0.1:8080/proxy/ca/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                const data = await res.json();

                let html = '';
                const isNew = data.status === 'generated';

                html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px; margin-bottom: 12px; border-left: 3px solid ${isNew ? 'var(--accent)' : 'var(--warning)'};">
                    <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px; color: ${isNew ? 'var(--accent)' : 'var(--warning)'};">
                        ${isNew ? '✓ CA Generated Successfully' : '⚠ CA Already Exists'}
                    </div>
                    <div style="font-size: 11px; color: var(--text-muted); line-height: 1.8;">
                        <div><strong>Subject:</strong> <code>${esc(data.subject || '')}</code></div>
                        <div><strong>Expires:</strong> ${esc(data.expires || '')}</div>
                        <div><strong>Cert Path:</strong> <code>${esc(data.ca_cert_path || '')}</code></div>
                        <div><strong>Fingerprint:</strong> <code style="font-size: 9px;">${esc(data.fingerprint || '')}</code></div>
                    </div>
                </div>`;

                if (data.install_instructions) {
                    const inst = data.install_instructions;
                    html += `<div style="background: var(--bg-secondary); border-radius: var(--radius); padding: 16px;">
                        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--accent); margin-bottom: 10px; font-weight: 600;">Browser Installation</div>`;

                    for (const [browser, cmd] of Object.entries(inst)) {
                        html += `<div style="margin-bottom: 8px;">
                            <div style="font-size: 10px; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">${esc(browser.replace('_', ' '))}</div>
                            <code style="font-size: 10px; background: var(--bg-tertiary); padding: 4px 8px; border-radius: 4px; display: block; margin-top: 4px; word-break: break-all;">${esc(cmd)}</code>
                        </div>`;
                    }
                    html += '</div>';
                }

                resDiv.innerHTML = html;
                appendLog('info', `CA ${isNew ? 'generated' : 'loaded'}: ${data.ca_cert_path}`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });

        document.getElementById('ca-host-btn')?.addEventListener('click', async () => {
            const hostname = document.getElementById('ca-host-input').value;
            if (!hostname) return;

            appendLog('info', `Generating host cert for ${hostname}...`);

            try {
                const res = await fetch('http://127.0.0.1:8080/proxy/ca/host', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hostname })
                });
                const data = await res.json();

                const resDiv = document.getElementById('ca-results');
                const existing = resDiv.innerHTML;

                const certHtml = `<div style="background: rgba(6,182,212,0.1); border-left: 3px solid var(--accent); padding: 10px 14px; margin-bottom: 8px; border-radius: 4px; font-size: 11px;">
                    <strong>${esc(data.hostname)}</strong> — ${data.status === 'cached' ? '(cached)' : '✓ generated'}
                    <div style="color: var(--text-muted); margin-top: 4px;">
                        Cert: <code>${esc(data.cert_path || '')}</code><br>
                        ${data.san ? 'SAN: ' + data.san.join(', ') : ''}
                    </div>
                </div>`;

                resDiv.innerHTML = certHtml + existing;
                appendLog('info', `Host cert for ${hostname}: ${data.cert_path}`);
            } catch (e) {
                appendLog('error', `Host cert failed: ${e.message}`);
            }
        });
    }

    // ─── 22. Attack Chainer ────────────────────────────────────────
    const chainExecBtn = document.getElementById('chain-exec-btn');
    if (chainExecBtn) {
        chainExecBtn.addEventListener('click', async () => {
            const editor = document.getElementById('chain-steps-editor');
            const resDiv = document.getElementById('chain-results');
            const varsDiv = document.getElementById('chain-variables');

            let steps;
            try {
                steps = JSON.parse(editor.value);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Invalid JSON: ${e.message}</div>`;
                return;
            }

            if (!Array.isArray(steps) || steps.length === 0) {
                resDiv.innerHTML = '<div class="empty-state text-danger">Steps must be a non-empty array.</div>';
                return;
            }

            resDiv.innerHTML = '<div class="empty-state">Executing chain...</div>';
            varsDiv.innerHTML = '<span style="opacity: 0.5;">Running...</span>';
            appendLog('info', `Executing attack chain with ${steps.length} steps...`);

            try {
                const res = await fetch('http://127.0.0.1:8080/web/chain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ steps })
                });
                const data = await res.json();

                if (data.status !== 'success') {
                    resDiv.innerHTML = `<div class="empty-state text-danger">${data.detail || 'Error'}</div>`;
                    return;
                }

                // Render results timeline
                let html = `<div style="font-size: 11px; padding: 8px 0; color: var(--text-muted); margin-bottom: 8px;">
                    ${data.completed}/${data.total_steps} completed · ${data.skipped} skipped · ${data.errors} errors · ${data.elapsed}s
                </div>`;

                (data.results || []).forEach((r, i) => {
                    const statusColor = r.status === 'success' ? 'var(--accent)' :
                        r.status === 'skipped' ? 'var(--warning)' : 'var(--danger)';
                    const statusIcon = r.status === 'success' ? '✓' :
                        r.status === 'skipped' ? '⏭' : '✗';

                    html += `<div style="background: var(--bg-secondary); border-radius: 6px; padding: 12px; margin-bottom: 8px; border-left: 3px solid ${statusColor};">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                            <span style="font-weight: 600; font-size: 12px; color: ${statusColor};">
                                ${statusIcon} ${esc(r.name || 'Step ' + r.step)}
                            </span>
                            <span style="font-size: 10px; color: var(--text-muted);">
                                ${r.http_status ? 'HTTP ' + r.http_status : ''} ${r.response_length ? '· ' + r.response_length + ' bytes' : ''}
                            </span>
                        </div>`;

                    if (r.method && r.url) {
                        html += `<div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); margin-bottom: 4px;">${esc(r.method)} ${esc(r.url)}</div>`;
                    }
                    if (r.reason) {
                        html += `<div style="font-size: 10px; color: var(--danger);">${esc(r.reason)}</div>`;
                    }
                    if (r.extracted && Object.keys(r.extracted).length > 0) {
                        html += '<div style="margin-top: 6px;">';
                        for (const [vName, vVal] of Object.entries(r.extracted)) {
                            html += `<div style="font-size: 10px;"><span style="color: var(--accent);">{{${esc(vName)}}}</span> = <code style="background: var(--bg-tertiary); padding: 2px 4px; border-radius: 3px;">${esc(String(vVal).substring(0, 80))}</code></div>`;
                        }
                        html += '</div>';
                    }
                    html += '</div>';
                });

                resDiv.innerHTML = html;

                // Show variables
                if (data.variables && Object.keys(data.variables).length > 0) {
                    let varHtml = '';
                    for (const [k, v] of Object.entries(data.variables)) {
                        varHtml += `<div><span style="color: var(--accent);">{{${esc(k)}}}</span> = <code>${esc(String(v).substring(0, 60))}</code></div>`;
                    }
                    varsDiv.innerHTML = varHtml;
                } else {
                    varsDiv.innerHTML = '<span style="opacity: 0.5;">No variables extracted.</span>';
                }

                appendLog('info', `Chain complete: ${data.completed}/${data.total_steps} in ${data.elapsed}s`);
            } catch (e) {
                resDiv.innerHTML = `<div class="empty-state text-danger">Error: ${e.message}</div>`;
            }
        });

        const chainAddStepBtn = document.getElementById('chain-add-step');
        if (chainAddStepBtn) {
            chainAddStepBtn.addEventListener('click', () => {
                const editor = document.getElementById('chain-steps-editor');
                let steps = [];
                try {
                    if (editor.value.trim() !== '') {
                        steps = JSON.parse(editor.value);
                    }
                } catch (e) {
                    // Start fresh if the JSON is currently invalid
                }

                steps.push({
                    "name": `Step ${steps.length + 1}`,
                    "method": "GET",
                    "url": "https://",
                    "headers": {},
                    "body": "",
                    "extract": []
                });

                editor.value = JSON.stringify(steps, null, 2);
            });
        }

        // Socket.IO live step updates
        socket?.on('chain_step', (r) => {
            appendLog('info', `Chain [${r.step}] ${r.name}: ${r.status}${r.http_status ? ' (HTTP ' + r.http_status + ')' : ''}`);
        });
    }

    // ─── 23. WSHawk Themes ─────────────────────────────────────────
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const theme = btn.dataset.theme;
            document.documentElement.setAttribute('data-theme', theme || '');
            localStorage.setItem('wshawk-theme', theme || '');
            // Highlight active theme button
            document.querySelectorAll('.theme-btn').forEach(b => {
                b.style.border = b === btn ? '2px solid var(--accent)' : '';
            });
            appendLog('info', `Theme switched to: ${theme || 'Midnight (default)'}`);
        });
    });

    // Restore saved theme
    const savedTheme = localStorage.getItem('wshawk-theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
        document.querySelectorAll('.theme-btn').forEach(b => {
            if (b.dataset.theme === savedTheme) b.style.border = '2px solid var(--accent)';
        });
    }

    // ─── 24. Quick Search (Ctrl+K) ─────────────────────────────────
    const hsOverlay = document.getElementById('hawksearch-overlay');
    const hsInput = document.getElementById('hawksearch-input');
    const hsResults = document.getElementById('hawksearch-results');

    if (hsOverlay && hsInput && hsResults) {
        // All searchable items — tools + actions
        const searchItems = [
            { icon: '>', label: 'Web Crawler', target: 'crawler', shortcut: '' },
            { icon: '>', label: 'Vuln Scanner', target: 'vulnscan', shortcut: '' },
            { icon: '>', label: 'HTTP Proxy', target: 'httpproxy', shortcut: '' },
            { icon: '>', label: 'Web Fuzzer', target: 'fuzzer', shortcut: '' },
            { icon: '>', label: 'Dir Scanner', target: 'dirscanner', shortcut: '' },
            { icon: '>', label: 'Header Analyzer', target: 'headeranalyzer', shortcut: '' },
            { icon: '>', label: 'Subdomain Finder', target: 'subdomains', shortcut: '' },
            { icon: '>', label: 'SSL Analyzer', target: 'sslanalyzer', shortcut: '' },
            { icon: '>', label: 'WAF Detector', target: 'wafdetect', shortcut: '' },
            { icon: '>', label: 'CORS Tester', target: 'corstester', shortcut: '' },
            { icon: '>', label: 'Port Scanner', target: 'portscanner', shortcut: '' },
            { icon: '>', label: 'DNS / WHOIS', target: 'dnslookup', shortcut: '' },
            { icon: '>', label: 'Tech Fingerprint', target: 'fingerprint', shortcut: '' },
            { icon: '>', label: 'Sensitive Finder', target: 'sensitive', shortcut: '' },
            { icon: '>', label: 'CSRF Forge', target: 'csrfforge', shortcut: '' },
            { icon: '>', label: 'Blind Probe (SSRF)', target: 'blindprobe', shortcut: '' },
            { icon: '>', label: 'Redirect Hunter', target: 'redirecthunter', shortcut: '' },
            { icon: '>', label: 'Proto Polluter', target: 'protopolluter', shortcut: '' },
            { icon: '>', label: 'Proxy CA', target: 'hawkproxyca', shortcut: '' },
            { icon: '>', label: 'Attack Chainer', target: 'attackchainer', shortcut: '' },
            { icon: '>', label: 'CyberNode Pipeline', target: 'cybernode', shortcut: '' },
            { icon: '>', label: 'Team Mode', target: 'teammode', shortcut: '' },
            { icon: '>', label: 'Reports', target: 'reports', shortcut: '' },
            { icon: '>', label: 'Settings & Themes', action: 'settings', shortcut: '' },
        ];

        let hsSelectedIndex = 0;
        let filteredItems = [...searchItems];

        function renderHSResults(items) {
            filteredItems = items;
            hsSelectedIndex = 0;
            if (items.length === 0) {
                hsResults.innerHTML = '<div class="hawksearch-empty">No results found</div>';
                return;
            }
            hsResults.innerHTML = items.map((item, i) => `
                <div class="hawksearch-item ${i === 0 ? 'selected' : ''}" data-index="${i}" style="${i === 0 ? 'background: var(--bg-hover);' : ''}">
                    <div class="hs-icon">${item.icon}</div>
                    <div class="hs-label">${item.label}</div>
                    ${item.shortcut ? `<div class="hs-shortcut">${item.shortcut}</div>` : ''}
                </div>
            `).join('');

            // Click handlers
            hsResults.querySelectorAll('.hawksearch-item').forEach(el => {
                el.addEventListener('click', () => {
                    selectHSItem(parseInt(el.dataset.index));
                });
            });
        }

        function selectHSItem(index) {
            if (index < 0 || index >= filteredItems.length) return;
            const item = filteredItems[index];

            // Close overlay
            hsOverlay.classList.remove('active');
            hsInput.value = '';

            if (item.action === 'settings') {
                document.getElementById('settings-modal')?.classList.add('active');
            } else if (item.target) {
                // Navigate to tool
                const navBtn = document.querySelector(`[data-target="${item.target}"]`);
                if (navBtn) navBtn.click();
            }
        }

        function updateHSSelection() {
            hsResults.querySelectorAll('.hawksearch-item').forEach((el, i) => {
                el.style.background = i === hsSelectedIndex ? 'var(--bg-hover)' : '';
            });
            // Scroll into view
            const selected = hsResults.children[hsSelectedIndex];
            if (selected) selected.scrollIntoView({ block: 'nearest' });
        }

        // Open/close
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                if (hsOverlay.classList.contains('active')) {
                    hsOverlay.classList.remove('active');
                } else {
                    hsOverlay.classList.add('active');
                    hsInput.value = '';
                    hsInput.focus();
                    renderHSResults(searchItems);
                }
            }

            if (e.key === 'Escape' && hsOverlay.classList.contains('active')) {
                hsOverlay.classList.remove('active');
            }
        });

        // Click outside to close
        hsOverlay.addEventListener('click', (e) => {
            if (e.target === hsOverlay) hsOverlay.classList.remove('active');
        });

        // Search filtering
        hsInput.addEventListener('input', () => {
            const q = hsInput.value.toLowerCase().trim();
            if (!q) {
                renderHSResults(searchItems);
                return;
            }
            const filtered = searchItems.filter(item =>
                item.label.toLowerCase().includes(q)
            );
            renderHSResults(filtered);
        });

        // Keyboard navigation
        hsInput.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                hsSelectedIndex = Math.min(hsSelectedIndex + 1, filteredItems.length - 1);
                updateHSSelection();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                hsSelectedIndex = Math.max(hsSelectedIndex - 1, 0);
                updateHSSelection();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                selectHSItem(hsSelectedIndex);
            }
        });
    }

    // ── Scan History (Database) ────────────────────────────────────────────────
    const scanHistoryTbody = document.getElementById('scanhistory-tbody');
    const scanHistoryVulnTbody = document.getElementById('scanhistory-vuln-tbody');
    const scanHistoryDetailTitle = document.getElementById('scanhistory-detail-title');
    const scanHistoryPocBox = document.getElementById('scanhistory-poc-box');
    const btnRefreshHistory = document.getElementById('btn-refresh-history');

    let currentScanHistory = [];

    async function loadScanHistory() {
        try {
            const res = await fetch(`${API_URL}/history`);
            const data = await res.json();
            if (data.status === 'success') {
                currentScanHistory = data.history;
                renderScanHistory();
            }
        } catch (err) {
            console.error('Failed to load scan history:', err);
        }
    }

    function renderScanHistory() {
        if (!scanHistoryTbody) return;
        scanHistoryTbody.innerHTML = '';
        currentScanHistory.forEach((scan, index) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${new Date(scan.timestamp).toLocaleString()}</td>
                <td class="text-ellipsis" style="max-width: 150px;" title="${scan.target}">${scan.target}</td>
                <td class="text-danger">${scan.high_count || 0}</td>
                <td class="text-warning">${scan.medium_count || 0}</td>
                <td class="text-info">${scan.low_count || 0}</td>
                <td>${scan.elapsed.toFixed(1)}</td>
                <td><button class="btn secondary small btn-compare" title="Compare with previous run">Diff</button></td>
            `;
            tr.style.cursor = 'pointer';

            // Diff handler
            const btnCompare = tr.querySelector('.btn-compare');
            btnCompare.addEventListener('click', async (e) => {
                e.stopPropagation();

                scanHistoryDetailTitle.textContent = `Diffing Target: ${scan.target}`;

                // Find next oldest scan for same target
                const prevScan = currentScanHistory.slice(index + 1).find(s => s.target === scan.target);
                if (!prevScan) {
                    scanHistoryPocBox.value = 'No previous scan found for this target to compare against.';
                    return;
                }

                scanHistoryPocBox.value = 'Loading scan diff...';

                try {
                    const res = await fetch(`${API_URL}/history/compare/${scan.id}/${prevScan.id}`);
                    const data = await res.json();
                    if (data.status === 'success') {
                        const diff = data.diff;
                        let output = `=== DIFF REPORT ===\n`;
                        output += `Comparing current scan (${new Date(scan.timestamp).toLocaleString()}) to previous (${new Date(prevScan.timestamp).toLocaleString()})\n\n`;
                        output += `[+] FIXED (${diff.fixed_count}):\n`;
                        diff.fixed.forEach(f => output += `    - ${f.type} at ${f.url} [${f.value}]\n`);
                        output += `\n[-] NEW / REGRESSED (${diff.new_count}):\n`;
                        diff.new_vulns.forEach(f => output += `    - ${f.type} at ${f.url} [${f.value}]\n`);

                        scanHistoryPocBox.value = output;
                    }
                } catch (err) {
                    scanHistoryPocBox.value = `Compare Error: ${err}`;
                }
            });

            // Allow clicking row to load details
            Array.from(tr.children).forEach(td => {
                if (!td.querySelector('button')) {
                    td.addEventListener('click', () => loadScanDetails(scan.id));
                }
            });

            scanHistoryTbody.appendChild(tr);
        });
    }

    async function loadScanDetails(scanId) {
        try {
            const res = await fetch(`${API_URL}/history/${scanId}`);
            const data = await res.json();
            if (data.status === 'success') {
                const scan = data.scan;
                scanHistoryDetailTitle.textContent = `Target: ${scan.target} | ${new Date(scan.timestamp).toLocaleString()}`;

                scanHistoryVulnTbody.innerHTML = '';
                scan.findings.forEach(f => {
                    const tr = document.createElement('tr');
                    const sevClass = f.severity === 'High' || f.severity === 'Critical' ? 'text-danger' :
                        f.severity === 'Medium' ? 'text-warning' : 'text-info';
                    tr.innerHTML = `
                        <td class="${sevClass}">[${f.severity}]</td>
                        <td>${f.title || f.type}</td>
                        <td class="text-ellipsis" style="max-width:200px;" title="${f.detail}">${f.detail}</td>
                        <td class="text-ellipsis" style="max-width:150px;" title="${f.value}">${f.value}</td>
                        <td><button class="btn secondary small btn-poc">View PoC</button></td>
                    `;
                    tr.querySelector('.btn-poc').addEventListener('click', () => {
                        scanHistoryPocBox.value = f.poc || 'No PoC available for this finding.';
                    });
                    scanHistoryVulnTbody.appendChild(tr);
                });
            }
        } catch (err) {
            console.error('Failed to load scan details:', err);
        }
    }

    if (btnRefreshHistory) {
        btnRefreshHistory.addEventListener('click', loadScanHistory);
    }

    // Auto load when tab clicked
    document.querySelector('.nav-item[data-target="scanhistory"]')?.addEventListener('click', loadScanHistory);

})();

// ═══════════════════════════════════════════════════════════════════
// CyberNode: Visual Attack Pipeline Engine
// ═══════════════════════════════════════════════════════════════════
(function CyberNodeEngine() {
    'use strict';

    // ── Node Type Registry ──────────────────────────────────────────
    const NODE_REGISTRY = {
        subdomain: { icon: 'SD', label: 'Subdomain Finder', endpoint: '/web/subdomains', inputField: 'target', outputKey: 'subdomains', color: '#06b6d4' },
        crawler: { icon: 'WC', label: 'Web Crawler', endpoint: '/web/crawl', inputField: 'url', outputKey: 'pages', color: '#8b5cf6' },
        techfp: { icon: 'TF', label: 'Tech Fingerprint', endpoint: '/web/fingerprint', inputField: 'url', outputKey: 'technologies', color: '#f59e0b' },
        dnslookup: { icon: 'DN', label: 'DNS / WHOIS', endpoint: '/web/dns', inputField: 'domain', outputKey: 'records', color: '#14b8a6' },
        portscan: { icon: 'PS', label: 'Port Scanner', endpoint: '/web/portscan', inputField: 'target', outputKey: 'open_ports', color: '#6366f1' },
        dirscan: { icon: 'DS', label: 'Dir Scanner', endpoint: '/web/dirscan', inputField: 'url', outputKey: 'found', color: '#22c55e' },
        headeranalyzer: { icon: 'HA', label: 'Header Analyzer', endpoint: '/web/headers', inputField: 'url', outputKey: 'headers', color: '#a855f7' },
        sslanalyzer: { icon: 'SS', label: 'SSL/TLS Analyzer', endpoint: '/web/ssl', inputField: 'url', outputKey: 'certificate', color: '#3b82f6' },
        sensitivefinder: { icon: 'SF', label: 'Sensitive Finder', endpoint: '/web/sensitive', inputField: 'url', outputKey: 'findings', color: '#ef4444' },
        vulnscan: { icon: 'VS', label: 'Vuln Scanner', endpoint: '/web/vulnscan', inputField: 'url', outputKey: 'findings', color: '#dc2626' },
        wafdetect: { icon: 'WF', label: 'WAF Detector', endpoint: '/web/waf', inputField: 'url', outputKey: 'results', color: '#f97316' },
        httpfuzzer: { icon: 'FZ', label: 'HTTP Fuzzer', endpoint: '/web/fuzz', inputField: 'url', outputKey: 'results', color: '#e11d48' },
        corstester: { icon: 'CR', label: 'CORS Tester', endpoint: '/web/cors', inputField: 'url', outputKey: 'findings', color: '#d946ef' },
        csrfforge: { icon: 'XF', label: 'CSRF Forge', endpoint: '/web/csrf', inputField: 'url', outputKey: 'result', color: '#f43f5e' },
        ssrfprobe: { icon: 'BP', label: 'Blind Probe', endpoint: '/web/ssrf', inputField: 'url', outputKey: 'findings', color: '#be123c' },
        redirect: { icon: 'RH', label: 'Redirect Hunter', endpoint: '/web/redirect', inputField: 'url', outputKey: 'redirects', color: '#fb923c' },
        protopollute: { icon: 'PP', label: 'Proto Polluter', endpoint: '/web/proto', inputField: 'url', outputKey: 'findings', color: '#7c3aed' },
        filter: { icon: 'FG', label: 'Filter / Grep', endpoint: null, inputField: 'pattern', outputKey: 'filtered', color: '#64748b' },
        note: { icon: 'NT', label: 'Note / Label', endpoint: null, inputField: null, outputKey: null, color: '#475569' },
    };

    // ── State ───────────────────────────────────────────────────────
    let nodes = [];
    let wires = [];
    let nextId = 1;
    let zoom = 1;
    let panX = 0, panY = 0;
    let selectedNode = null;
    let draggingNode = null;
    let dragOffX = 0, dragOffY = 0;
    let connectingFrom = null; // { nodeId, portType: 'output' }
    let tempWirePath = null;

    // ── DOM refs ────────────────────────────────────────────────────
    const canvas = document.getElementById('cn-canvas');
    const canvasWrap = document.getElementById('cn-canvas-wrap');
    const svgLayer = document.getElementById('cn-svg-layer');
    const minimapCanvas = document.getElementById('cn-minimap-canvas');
    const execPanel = document.getElementById('cn-exec-panel');
    const execLog = document.getElementById('cn-exec-log');
    const zoomLabel = document.getElementById('cn-zoom-level');

    if (!canvas) return; // Guard: only init if CyberNode panel exists

    // ── Helpers ─────────────────────────────────────────────────────
    function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

    function getNodeById(id) { return nodes.find(n => n.id === id); }

    function getCanvasOffset() {
        const r = canvasWrap.getBoundingClientRect();
        return { x: r.left, y: r.top };
    }

    function screenToCanvas(sx, sy) {
        const off = getCanvasOffset();
        return {
            x: (sx - off.x - panX) / zoom,
            y: (sy - off.y - panY) / zoom
        };
    }

    // ── Create Node DOM ─────────────────────────────────────────────
    function createNodeElement(node) {
        const reg = NODE_REGISTRY[node.type] || {};
        const el = document.createElement('div');
        el.className = 'cn-node';
        el.dataset.nodeId = node.id;
        el.style.left = node.x + 'px';
        el.style.top = node.y + 'px';
        el.style.transform = `scale(${zoom})`;
        el.style.transformOrigin = 'top left';

        const isLogic = node.type === 'filter' || node.type === 'note';

        let bodyHTML = '';
        if (node.type === 'note') {
            bodyHTML = `<label>Note</label><textarea class="cn-node-input" data-field="note" rows="3" placeholder="Write a note...">${esc(node.config.note || '')}</textarea>`;
        } else if (node.type === 'filter') {
            bodyHTML = `
                <label>Grep Pattern</label>
                <input class="cn-node-input" data-field="pattern" placeholder="e.g. status:200" value="${esc(node.config.pattern || '')}">
                <label>Field Path</label>
                <input class="cn-node-input" data-field="field" placeholder="e.g. url or ." value="${esc(node.config.field || '')}">
            `;
        } else {
            bodyHTML = `<label>Target</label><input class="cn-node-input" data-field="target" placeholder="e.g. https://target.com" value="${esc(node.config.target || '')}">`;
        }

        el.innerHTML = `
            <div class="cn-node-status idle"></div>
            <div class="cn-node-header" style="background: ${reg.color || '#333'};">
                <span class="cn-node-icon">${reg.icon || '●'}</span>
                <span class="cn-node-title">${esc(reg.label || node.type)}</span>
                <button class="cn-node-delete" title="Remove node">✕</button>
            </div>
            <div class="cn-node-body">${bodyHTML}</div>
            <div class="cn-node-footer">
                ${node.type !== 'note' ? '<div class="cn-port input" data-port="input" title="Input"></div>' : '<div></div>'}
                ${node.type !== 'note' ? '<div class="cn-port output" data-port="output" title="Output"></div>' : '<div></div>'}
            </div>
        `;

        // ── Input change handlers ──
        el.querySelectorAll('.cn-node-input').forEach(inp => {
            inp.addEventListener('input', () => {
                node.config[inp.dataset.field] = inp.value;
            });
            // Prevent canvas drag when typing
            inp.addEventListener('mousedown', e => e.stopPropagation());
        });

        // ── Delete button ──
        el.querySelector('.cn-node-delete').addEventListener('click', (e) => {
            e.stopPropagation();
            removeNode(node.id);
        });

        // ── Node drag ──
        el.addEventListener('mousedown', (e) => {
            if (e.target.classList.contains('cn-port') || e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'BUTTON') return;
            e.preventDefault();
            draggingNode = node;
            const pos = screenToCanvas(e.clientX, e.clientY);
            dragOffX = pos.x - node.x;
            dragOffY = pos.y - node.y;
            el.classList.add('dragging');
            selectNode(node.id);
        });

        // ── Port connection start ──
        el.querySelectorAll('.cn-port').forEach(port => {
            port.addEventListener('mousedown', (e) => {
                e.stopPropagation();
                e.preventDefault();
                const portType = port.dataset.port;
                if (portType === 'output') {
                    connectingFrom = { nodeId: node.id };
                    canvasWrap.classList.add('connecting');
                    // Create temp wire
                    const svgNS = 'http://www.w3.org/2000/svg';
                    tempWirePath = document.createElementNS(svgNS, 'path');
                    tempWirePath.setAttribute('class', 'cn-wire');
                    tempWirePath.setAttribute('stroke-dasharray', '6 3');
                    tempWirePath.style.opacity = '0.4';
                    svgLayer.appendChild(tempWirePath);
                }
            });

            port.addEventListener('mouseup', (e) => {
                e.stopPropagation();
                const portType = port.dataset.port;
                if (connectingFrom && portType === 'input' && connectingFrom.nodeId !== node.id) {
                    // Prevent duplicate wires
                    const exists = wires.some(w => w.from === connectingFrom.nodeId && w.to === node.id);
                    if (!exists) {
                        wires.push({ from: connectingFrom.nodeId, to: node.id });
                        updateAllWires();
                        updatePortStyles();
                    }
                }
            });
        });

        // ── Click select ──
        el.addEventListener('click', (e) => {
            if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'BUTTON') {
                selectNode(node.id);
            }
        });

        return el;
    }

    // ── Add Node ────────────────────────────────────────────────────
    function addNode(type, x, y) {
        const node = {
            id: nextId++,
            type,
            x: x || 100,
            y: y || 100,
            config: {},
            _result: null,
            _status: 'idle' // idle | running | done | error
        };
        nodes.push(node);
        const el = createNodeElement(node);
        canvas.appendChild(el);
        applyTransform();
        updateMinimap();
        return node;
    }

    // ── Remove Node ─────────────────────────────────────────────────
    function removeNode(id) {
        wires = wires.filter(w => w.from !== id && w.to !== id);
        nodes = nodes.filter(n => n.id !== id);
        const el = canvas.querySelector(`[data-node-id="${id}"]`);
        if (el) el.remove();
        updateAllWires();
        updatePortStyles();
        updateMinimap();
        if (selectedNode === id) selectedNode = null;
    }

    // ── Select Node ─────────────────────────────────────────────────
    function selectNode(id) {
        selectedNode = id;
        canvas.querySelectorAll('.cn-node').forEach(el => {
            el.classList.toggle('selected', parseInt(el.dataset.nodeId) === id);
        });
    }

    // ── Wire Drawing ────────────────────────────────────────────────
    function getPortPosition(nodeId, portType) {
        const el = canvas.querySelector(`[data-node-id="${nodeId}"]`);
        if (!el) return { x: 0, y: 0 };
        const port = el.querySelector(`.cn-port.${portType}`);
        if (!port) return { x: 0, y: 0 };

        const node = getNodeById(nodeId);
        const portRect = port.getBoundingClientRect();
        const wrapRect = canvasWrap.getBoundingClientRect();

        return {
            x: (portRect.left + portRect.width / 2 - wrapRect.left - panX) / zoom,
            y: (portRect.top + portRect.height / 2 - wrapRect.top - panY) / zoom
        };
    }

    function drawWire(from, to, wireEl) {
        const dx = Math.abs(to.x - from.x) * 0.5;
        const d = `M ${from.x} ${from.y} C ${from.x + dx} ${from.y}, ${to.x - dx} ${to.y}, ${to.x} ${to.y}`;
        wireEl.setAttribute('d', d);
    }

    function updateAllWires() {
        // Remove old wire paths
        svgLayer.querySelectorAll('.cn-wire:not([data-temp])').forEach(p => p.remove());

        const svgNS = 'http://www.w3.org/2000/svg';
        wires.forEach((w, idx) => {
            const fromPos = getPortPosition(w.from, 'output');
            const toPos = getPortPosition(w.to, 'input');
            const path = document.createElementNS(svgNS, 'path');
            path.setAttribute('class', 'cn-wire');
            path.dataset.wireIdx = idx;

            // Double-click to delete wire
            path.style.pointerEvents = 'stroke';
            path.addEventListener('dblclick', (e) => {
                e.stopPropagation();
                wires.splice(idx, 1);
                updateAllWires();
                updatePortStyles();
            });

            drawWire(fromPos, toPos, path);
            svgLayer.appendChild(path);
        });
    }

    function updatePortStyles() {
        canvas.querySelectorAll('.cn-port').forEach(port => {
            port.classList.remove('connected');
        });
        wires.forEach(w => {
            const fromEl = canvas.querySelector(`[data-node-id="${w.from}"] .cn-port.output`);
            const toEl = canvas.querySelector(`[data-node-id="${w.to}"] .cn-port.input`);
            if (fromEl) fromEl.classList.add('connected');
            if (toEl) toEl.classList.add('connected');
        });
    }

    // ── Canvas Mouse Events ─────────────────────────────────────────
    let isPanning = false;
    let panStartX = 0, panStartY = 0;

    canvasWrap.addEventListener('mousedown', (e) => {
        if (e.target === canvasWrap || e.target === canvas || e.target.classList.contains('cn-canvas')) {
            // Deselect
            selectNode(null);
            // Start panning (middle click or if no node is being dragged)
            if (e.button === 1 || (e.button === 0 && !draggingNode)) {
                isPanning = true;
                panStartX = e.clientX - panX;
                panStartY = e.clientY - panY;
                canvasWrap.classList.add('panning');
            }
        }
    });

    window.addEventListener('mousemove', (e) => {
        // Node dragging
        if (draggingNode) {
            const pos = screenToCanvas(e.clientX, e.clientY);
            draggingNode.x = Math.round((pos.x - dragOffX) / 12) * 12; // Snap to 12px grid
            draggingNode.y = Math.round((pos.y - dragOffY) / 12) * 12;
            const el = canvas.querySelector(`[data-node-id="${draggingNode.id}"]`);
            if (el) {
                el.style.left = draggingNode.x + 'px';
                el.style.top = draggingNode.y + 'px';
            }
            updateAllWires();
            updateMinimap();
        }

        // Panning
        if (isPanning) {
            panX = e.clientX - panStartX;
            panY = e.clientY - panStartY;
            applyTransform();
            updateAllWires();
            updateMinimap();
        }

        // Temp wire while connecting
        if (connectingFrom && tempWirePath) {
            const fromPos = getPortPosition(connectingFrom.nodeId, 'output');
            const toPos = screenToCanvas(e.clientX, e.clientY);
            drawWire(fromPos, toPos, tempWirePath);
        }
    });

    window.addEventListener('mouseup', () => {
        if (draggingNode) {
            const el = canvas.querySelector(`[data-node-id="${draggingNode.id}"]`);
            if (el) el.classList.remove('dragging');
            draggingNode = null;
        }
        if (isPanning) {
            isPanning = false;
            canvasWrap.classList.remove('panning');
        }
        if (connectingFrom) {
            connectingFrom = null;
            canvasWrap.classList.remove('connecting');
            if (tempWirePath) {
                tempWirePath.remove();
                tempWirePath = null;
            }
        }
    });

    // ── Zoom ────────────────────────────────────────────────────────
    canvasWrap.addEventListener('wheel', (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? -0.05 : 0.05;
        zoom = Math.min(2, Math.max(0.25, zoom + delta));
        zoomLabel.textContent = Math.round(zoom * 100) + '%';
        applyTransform();
        updateAllWires();
        updateMinimap();
    }, { passive: false });

    document.getElementById('cn-zoom-in')?.addEventListener('click', () => {
        zoom = Math.min(2, zoom + 0.1);
        zoomLabel.textContent = Math.round(zoom * 100) + '%';
        applyTransform(); updateAllWires(); updateMinimap();
    });
    document.getElementById('cn-zoom-out')?.addEventListener('click', () => {
        zoom = Math.max(0.25, zoom - 0.1);
        zoomLabel.textContent = Math.round(zoom * 100) + '%';
        applyTransform(); updateAllWires(); updateMinimap();
    });
    document.getElementById('cn-zoom-fit')?.addEventListener('click', () => {
        zoom = 1; panX = 0; panY = 0;
        zoomLabel.textContent = '100%';
        applyTransform(); updateAllWires(); updateMinimap();
    });

    function applyTransform() {
        canvas.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
        canvas.style.transformOrigin = '0 0';
        svgLayer.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
        svgLayer.style.transformOrigin = '0 0';
    }

    // ── Drag & Drop from Toolbox ────────────────────────────────────
    canvasWrap.addEventListener('dragover', (e) => {
        e.preventDefault();
        canvasWrap.classList.add('drag-over');
    });

    canvasWrap.addEventListener('dragleave', () => {
        canvasWrap.classList.remove('drag-over');
    });

    canvasWrap.addEventListener('drop', (e) => {
        e.preventDefault();
        canvasWrap.classList.remove('drag-over');
        const type = e.dataTransfer.getData('text/plain');
        if (!NODE_REGISTRY[type]) return;

        const pos = screenToCanvas(e.clientX, e.clientY);
        addNode(type, pos.x, pos.y);
    });

    document.querySelectorAll('.cn-tool-node').forEach(toolEl => {
        toolEl.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', toolEl.dataset.nodeType);
            e.dataTransfer.effectAllowed = 'copy';
        });
    });

    // ── Minimap ─────────────────────────────────────────────────────
    function updateMinimap() {
        if (!minimapCanvas) return;
        const ctx = minimapCanvas.getContext('2d');
        const w = minimapCanvas.width;
        const h = minimapCanvas.height;
        ctx.clearRect(0, 0, w, h);

        if (nodes.length === 0) return;

        // Compute bounds
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        nodes.forEach(n => {
            if (n.x < minX) minX = n.x;
            if (n.y < minY) minY = n.y;
            if (n.x + 180 > maxX) maxX = n.x + 180;
            if (n.y + 100 > maxY) maxY = n.y + 100;
        });

        const padding = 50;
        minX -= padding; minY -= padding; maxX += padding; maxY += padding;
        const rangeX = maxX - minX || 1;
        const rangeY = maxY - minY || 1;
        const scale = Math.min(w / rangeX, h / rangeY);

        // Draw wires
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.4;
        wires.forEach(wire => {
            const fromNode = getNodeById(wire.from);
            const toNode = getNodeById(wire.to);
            if (!fromNode || !toNode) return;
            const fx = (fromNode.x + 90 - minX) * scale;
            const fy = (fromNode.y + 50 - minY) * scale;
            const tx = (toNode.x + 90 - minX) * scale;
            const ty = (toNode.y + 50 - minY) * scale;
            ctx.beginPath();
            ctx.moveTo(fx, fy);
            ctx.lineTo(tx, ty);
            ctx.stroke();
        });

        // Draw nodes
        ctx.globalAlpha = 0.8;
        nodes.forEach(n => {
            const reg = NODE_REGISTRY[n.type] || {};
            ctx.fillStyle = reg.color || '#555';
            const nx = (n.x - minX) * scale;
            const ny = (n.y - minY) * scale;
            const nw = 180 * scale;
            const nh = 60 * scale;
            ctx.fillRect(nx, ny, Math.max(nw, 4), Math.max(nh, 3));
        });

        ctx.globalAlpha = 1;
    }

    // ── Pipeline Execution ──────────────────────────────────────────
    document.getElementById('cn-exec-btn')?.addEventListener('click', executePipeline);

    async function executePipeline() {
        // Build execution order via topological sort
        const order = topologicalSort();
        if (!order) {
            alert('Pipeline contains a cycle! Please remove circular connections.');
            return;
        }

        // Show execution panel
        execPanel.style.display = 'flex';
        execLog.innerHTML = '';

        // Reset all node statuses
        nodes.forEach(n => { n._status = 'idle'; n._result = null; setNodeStatus(n.id, 'idle'); });

        const results = {};

        for (const nodeId of order) {
            const node = getNodeById(nodeId);
            if (!node) continue;
            const reg = NODE_REGISTRY[node.type];
            if (!reg) continue;

            // Skip note nodes
            if (node.type === 'note') continue;

            setNodeStatus(node.id, 'running');
            addExecLog(node, 'running', 'Executing...');

            try {
                // Gather input from upstream wires
                const upstreamWires = wires.filter(w => w.to === node.id);
                let inputTargets = [];

                if (upstreamWires.length > 0) {
                    upstreamWires.forEach(w => {
                        const upstream = getNodeById(w.from);
                        if (upstream && upstream._result) {
                            const data = upstream._result;
                            // Try to extract URLs or targets from upstream results
                            if (Array.isArray(data)) {
                                data.forEach(item => {
                                    if (typeof item === 'string') inputTargets.push(item);
                                    else if (item && item.url) inputTargets.push(item.url);
                                    else if (item && item.hostname) inputTargets.push(item.hostname);
                                });
                            }
                        }
                    });
                }

                // Filter node: apply grep locally
                if (node.type === 'filter') {
                    const pattern = (node.config.pattern || '').toLowerCase();
                    const field = node.config.field || '';
                    let filtered = inputTargets;
                    if (pattern) {
                        filtered = inputTargets.filter(item => {
                            const str = typeof item === 'string' ? item : JSON.stringify(item);
                            return str.toLowerCase().includes(pattern);
                        });
                    }
                    node._result = filtered;
                    node._status = 'done';
                    results[node.id] = filtered;
                    setNodeStatus(node.id, 'done');
                    addExecLog(node, 'done', `Filtered: ${filtered.length} items passed`, filtered);
                    renderNodeResults(node.id, filtered);
                    setWireStatus(node.id, 'active');
                    continue;
                }

                // If no upstream and no manual target, use config target
                let target = node.config.target || '';
                if (inputTargets.length > 0 && !target) {
                    target = inputTargets[0]; // Use first upstream result as target
                }

                if (!target && !reg.endpoint) {
                    node._status = 'done';
                    setNodeStatus(node.id, 'done');
                    addExecLog(node, 'skipped', 'No target and no endpoint');
                    continue;
                }

                if (!reg.endpoint) {
                    node._status = 'done';
                    setNodeStatus(node.id, 'done');
                    continue;
                }

                // Call the backend
                const payload = {};
                payload[reg.inputField] = target;

                // Add optional params from config
                Object.entries(node.config).forEach(([k, v]) => {
                    if (k !== 'target' && v) payload[k] = v;
                });

                const resp = await fetch(`http://127.0.0.1:8080${reg.endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await resp.json();

                if (data.status === 'error' || resp.status >= 400) {
                    throw new Error(data.detail || data.error || 'Request failed');
                }

                // Store result
                const output = data[reg.outputKey] || data;
                node._result = output;
                node._status = 'done';
                results[node.id] = output;

                const count = Array.isArray(output) ? output.length : (typeof output === 'object' ? Object.keys(output).length : 1);
                setNodeStatus(node.id, 'done');
                addExecLog(node, 'done', `✓ ${count} results`, output);
                renderNodeResults(node.id, output);
                crossPopulateTab(node.type, output, target);
                setWireStatus(node.id, 'active');

            } catch (err) {
                node._status = 'error';
                setNodeStatus(node.id, 'error');
                addExecLog(node, 'error', err.message);
                setWireStatus(node.id, 'error');
            }
        }

        addExecLog(null, 'done', '— Pipeline Complete —');
    }

    function topologicalSort() {
        const inDegree = {};
        const adj = {};
        nodes.forEach(n => { inDegree[n.id] = 0; adj[n.id] = []; });
        wires.forEach(w => {
            adj[w.from].push(w.to);
            inDegree[w.to] = (inDegree[w.to] || 0) + 1;
        });

        const queue = nodes.filter(n => inDegree[n.id] === 0).map(n => n.id);
        const order = [];

        while (queue.length > 0) {
            const curr = queue.shift();
            order.push(curr);
            (adj[curr] || []).forEach(next => {
                inDegree[next]--;
                if (inDegree[next] === 0) queue.push(next);
            });
        }

        return order.length === nodes.length ? order : null; // null = cycle
    }

    function setNodeStatus(nodeId, status) {
        const el = canvas.querySelector(`[data-node-id="${nodeId}"]`);
        if (!el) return;
        const dot = el.querySelector('.cn-node-status');
        if (dot) { dot.className = 'cn-node-status ' + status; }
        el.classList.remove('running', 'done', 'error');
        if (status !== 'idle') el.classList.add(status);
    }

    function setWireStatus(nodeId, status) {
        wires.forEach((w, idx) => {
            if (w.from === nodeId) {
                const wireEl = svgLayer.querySelector(`[data-wire-idx="${idx}"]`);
                if (wireEl) {
                    wireEl.classList.remove('active', 'error');
                    if (status !== 'idle') wireEl.classList.add(status);
                }
            }
        });
    }

    function addExecLog(node, status, msg, resultData) {
        const reg = node ? (NODE_REGISTRY[node.type] || {}) : {};
        const entry = document.createElement('div');
        entry.className = 'cn-exec-entry ' + status;

        let resultHTML = '';
        if (resultData && status === 'done') {
            const items = formatResultItems(resultData);
            if (items.length > 0) {
                const preview = items.slice(0, 30).map(item =>
                    `<div style="padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.04); word-break: break-all;">${esc(item)}</div>`
                ).join('');
                const moreText = items.length > 30 ? `<div style="color: var(--accent); padding-top: 4px;">... and ${items.length - 30} more</div>` : '';
                resultHTML = `
                    <div class="cn-exec-results" style="margin-top: 6px; max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: 4px; padding: 6px 8px; font-size: 9.5px; color: var(--text-secondary);">
                        ${preview}${moreText}
                    </div>
                `;
            }
        }

        entry.innerHTML = `
            <div class="cn-exec-name">${node ? esc(reg.label || node.type) : 'Pipeline'}</div>
            <div class="cn-exec-detail">${esc(msg)}</div>
            ${resultHTML}
        `;
        execLog.appendChild(entry);
        execLog.scrollTop = execLog.scrollHeight;
    }

    function formatResultItems(data) {
        if (Array.isArray(data)) {
            return data.map(item => {
                if (typeof item === 'string') return item;
                if (item && item.url) return item.url;
                if (item && item.hostname) return item.hostname;
                if (item && item.subdomain) return item.subdomain;
                if (item && item.domain) return item.domain;
                if (item && item.name) return item.name;
                if (item && item.title) return item.title;
                return JSON.stringify(item);
            });
        } else if (typeof data === 'object' && data !== null) {
            return Object.entries(data).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
        }
        return [String(data)];
    }

    function renderNodeResults(nodeId, data) {
        const el = canvas.querySelector(`[data-node-id="${nodeId}"]`);
        if (!el) return;

        // Remove any existing result preview
        const existing = el.querySelector('.cn-node-results');
        if (existing) existing.remove();

        const items = formatResultItems(data);
        if (items.length === 0) return;

        const resultsDiv = document.createElement('div');
        resultsDiv.className = 'cn-node-results';
        resultsDiv.style.cssText = 'max-height: 120px; overflow-y: auto; padding: 4px 12px 8px; font-family: var(--font-mono); font-size: 9.5px; border-top: 1px solid var(--border-color); color: var(--text-secondary);';

        const header = document.createElement('div');
        header.style.cssText = 'font-size: 9px; font-weight: 700; color: var(--safe); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; display: flex; justify-content: space-between;';
        header.innerHTML = `<span>✓ ${items.length} Results</span><span style="color: var(--text-muted); cursor: pointer;" class="cn-results-toggle">▼</span>`;
        resultsDiv.appendChild(header);

        const listDiv = document.createElement('div');
        listDiv.className = 'cn-results-list';
        items.slice(0, 20).forEach(item => {
            const row = document.createElement('div');
            row.style.cssText = 'padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.04); word-break: break-all; cursor: pointer;';
            row.textContent = item;
            row.title = 'Click to copy';
            row.addEventListener('click', (e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(item);
                row.style.color = 'var(--safe)';
                setTimeout(() => { row.style.color = ''; }, 600);
            });
            listDiv.appendChild(row);
        });
        if (items.length > 20) {
            const more = document.createElement('div');
            more.style.cssText = 'color: var(--accent); padding-top: 4px; font-size: 9px;';
            more.textContent = `... and ${items.length - 20} more`;
            listDiv.appendChild(more);
        }
        resultsDiv.appendChild(listDiv);

        // Toggle collapse
        header.querySelector('.cn-results-toggle').addEventListener('click', (e) => {
            e.stopPropagation();
            const isHidden = listDiv.style.display === 'none';
            listDiv.style.display = isHidden ? '' : 'none';
            e.target.textContent = isHidden ? '▼' : '▶';
        });

        // Insert before the footer (ports)
        const footer = el.querySelector('.cn-node-footer');
        if (footer) {
            el.insertBefore(resultsDiv, footer);
        } else {
            el.appendChild(resultsDiv);
        }
    }

    // ── Cross-populate regular sidebar tabs with CyberNode results ──
    function crossPopulateTab(nodeType, output, target) {
        try {
            if (nodeType === 'subdomain' && Array.isArray(output)) {
                const tbody = document.getElementById('subdomain-results-tbody');
                const prog = document.getElementById('subdomain-progress');
                const targetInput = document.getElementById('subdomain-target');
                if (!tbody) return;

                if (targetInput && target) targetInput.value = target;
                if (prog) prog.innerText = `Found ${output.length} subdomains (via CyberNode pipeline).`;

                tbody.innerHTML = '';
                output.forEach(sub => {
                    const subText = typeof sub === 'string' ? sub : (sub.hostname || sub.subdomain || JSON.stringify(sub));
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${esc(subText)}</td>
                        <td style="font-family: var(--font-mono); font-weight: 500;">—</td>
                        <td><span class="badge safe">PASSIVE</span></td>
                    `;
                    tbody.appendChild(tr);
                });

                const wfBtn = document.getElementById('subdomain-workflow-btn');
                if (wfBtn) wfBtn.style.display = 'inline-block';
            }

            if (nodeType === 'headeranalyzer' && output) {
                const tbody = document.getElementById('header-results-tbody');
                if (tbody && typeof output === 'object') {
                    tbody.innerHTML = '';
                    const headers = output.headers || output;
                    Object.entries(headers).forEach(([k, v]) => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `<td>${esc(k)}</td><td>${esc(String(v))}</td>`;
                        tbody.appendChild(tr);
                    });
                }
            }

            if (nodeType === 'sslanalyzer' && output) {
                const box = document.getElementById('ssl-results-box');
                if (box) {
                    box.innerHTML = `<pre style="white-space: pre-wrap; font-size: 11px;">${esc(JSON.stringify(output, null, 2))}</pre>`;
                }
            }

            if (nodeType === 'wafdetect' && output) {
                const box = document.getElementById('waf-results-box');
                if (box) {
                    box.innerHTML = `<pre style="white-space: pre-wrap; font-size: 11px;">${esc(JSON.stringify(output, null, 2))}</pre>`;
                }
            }
        } catch (e) {
            console.warn('[CyberNode] Cross-populate failed for', nodeType, e);
        }
    }

    // ── Exec Panel close ────────────────────────────────────────────
    document.getElementById('cn-exec-close')?.addEventListener('click', () => {
        execPanel.style.display = 'none';
    });

    // ── Clear Canvas ────────────────────────────────────────────────
    document.getElementById('cn-clear-btn')?.addEventListener('click', () => {
        if (!confirm('Clear all nodes and connections?')) return;
        nodes = [];
        wires = [];
        canvas.innerHTML = '';
        svgLayer.innerHTML = '';
        updateMinimap();
    });

    // ── Export .hawkchain ────────────────────────────────────────────
    document.getElementById('cn-export-btn')?.addEventListener('click', () => {
        const data = {
            version: '1.0',
            created: new Date().toISOString(),
            nodes: nodes.map(n => ({ id: n.id, type: n.type, x: n.x, y: n.y, config: n.config })),
            wires: wires.map(w => ({ from: w.from, to: w.to }))
        };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pipeline-${Date.now()}.hawkchain`;
        a.click();
        URL.revokeObjectURL(url);
    });

    // ── Import .hawkchain ───────────────────────────────────────────
    const importBtn = document.getElementById('cn-import-btn');
    const importFile = document.getElementById('cn-import-file');
    if (importBtn && importFile) {
        importBtn.addEventListener('click', () => importFile.click());
        importFile.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                try {
                    const data = JSON.parse(ev.target.result);
                    // Clear existing
                    nodes = [];
                    wires = [];
                    canvas.innerHTML = '';
                    svgLayer.innerHTML = '';

                    // Load nodes
                    let maxId = 0;
                    (data.nodes || []).forEach(n => {
                        const node = { id: n.id, type: n.type, x: n.x, y: n.y, config: n.config || {}, _result: null, _status: 'idle' };
                        nodes.push(node);
                        if (n.id > maxId) maxId = n.id;
                        const el = createNodeElement(node);
                        canvas.appendChild(el);
                    });
                    nextId = maxId + 1;

                    // Load wires
                    wires = (data.wires || []).map(w => ({ from: w.from, to: w.to }));
                    updateAllWires();
                    updatePortStyles();
                    updateMinimap();
                } catch (err) {
                    alert('Invalid .hawkchain file: ' + err.message);
                }
            };
            reader.readAsText(file);
            importFile.value = '';
        });
    }

    // ── Keyboard shortcuts ──────────────────────────────────────────
    document.addEventListener('keydown', (e) => {
        // Delete selected node
        if ((e.key === 'Delete' || e.key === 'Backspace') && selectedNode && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            removeNode(selectedNode);
        }
    });

    // ── Add CyberNode to HawkSearch ─────────────────────────────────
    // (it will be auto-included via the nav-item data-target system)

    // ── Init ────────────────────────────────────────────────────────
    updateMinimap();

})();

// ═══════════════════════════════════════════════════════════════════
// Team Mode: Frontend Collaboration Client
// Architecture mirrors the backend:
//   team_engine.py (logic) <-> gui_bridge.py (transport)
//   TeamController (logic)  <-> TeamClient (transport via global socket)
// ═══════════════════════════════════════════════════════════════════
(function TeamModeEngine() {
    'use strict';

    const BRIDGE_URL = 'http://127.0.0.1:8080';

    // ── Guard: only initialize if the Team Mode panel exists ────────
    const connectSection = document.getElementById('team-connect-section');
    if (!connectSection) return;

    // ── Utility ─────────────────────────────────────────────────────
    function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
    function log(type, msg) { if (typeof window.appendLog === 'function') window.appendLog(type, msg); }

    // ─────────────────────────────────────────────────────────────────
    // TeamClient: Transport layer
    // Wraps REST calls (via gui_bridge) and Socket.IO events
    // using the EXISTING global `socket` from connectBridge().
    // ─────────────────────────────────────────────────────────────────
    const TeamClient = {
        // Returns the global bridge socket (created in connectBridge)
        _socket() {
            return window.socket || null;
        },

        // REST: Create a new room on the backend engine
        async createRoom(operatorName, target) {
            const res = await fetch(`${BRIDGE_URL}/team/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: operatorName, target })
            });
            return res.json();
        },

        // REST: Validate room exists before Socket.IO join
        async validateRoom(roomCode) {
            const res = await fetch(`${BRIDGE_URL}/team/join`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room_code: roomCode })
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || 'Room not found');
            }
            return res.json();
        },

        // REST: Get room diagnostics
        async getStats() {
            const res = await fetch(`${BRIDGE_URL}/team/stats`);
            return res.json();
        },

        // Socket.IO: Join room for real-time sync
        emitJoin(roomCode, name) {
            const s = this._socket();
            if (s) s.emit('team_join', { room_code: roomCode, name });
        },

        // Socket.IO: Leave room
        emitLeave() {
            const s = this._socket();
            if (s) s.emit('team_leave', {});
        },

        // Socket.IO: Broadcast notes update
        emitNotesUpdate(content, cursorPos) {
            const s = this._socket();
            if (s) s.emit('team_notes_update', { content, cursor_pos: cursorPos });
        },

        // Socket.IO: Broadcast cursor position
        emitCursorMove(position, tab) {
            const s = this._socket();
            if (s) s.emit('team_cursor_move', { position, tab });
        },

        // Socket.IO: Broadcast scan event
        emitScanEvent(scanType, target, status, resultsCount) {
            const s = this._socket();
            if (s) s.emit('team_scan_event', { scan_type: scanType, target, status, results_count: resultsCount || 0 });
        },

        // Socket.IO: Broadcast finding
        emitFinding(finding) {
            const s = this._socket();
            if (s) s.emit('team_finding', { finding });
        },

        // Socket.IO: Broadcast endpoint discovery
        emitEndpoint(endpoint) {
            const s = this._socket();
            if (s) s.emit('team_endpoint_add', { endpoint });
        },

        // Register all team event listeners on the global socket
        registerListeners(handlers) {
            const s = this._socket();
            if (!s) {
                console.warn('[Team] Global socket not available yet. Retrying in 1s...');
                setTimeout(() => this.registerListeners(handlers), 1000);
                return;
            }

            s.on('team_roster', handlers.onRoster);
            s.on('team_activity', handlers.onActivity);
            s.on('team_state', handlers.onState);
            s.on('team_notes_sync', handlers.onNotesSync);
            s.on('team_endpoint_sync', handlers.onEndpointSync);
            s.on('team_cursor_sync', handlers.onCursorSync);
            s.on('team_error', handlers.onError);
        },
    };

    // ─────────────────────────────────────────────────────────────────
    // TeamUI: DOM rendering
    // Pure rendering functions — no transport or state logic.
    // ─────────────────────────────────────────────────────────────────
    const TeamUI = {
        refs: {
            connectSection: connectSection,
            connectedSection: document.getElementById('team-connected-section'),
            activeCode: document.getElementById('team-active-code'),
            roster: document.getElementById('team-roster'),
            activityFeed: document.getElementById('team-activity-feed'),
            roomBadge: document.getElementById('team-room-badge'),
            onlineDot: document.getElementById('team-online-dot'),
            nameInput: document.getElementById('team-operator-name'),
        },

        showConnected(roomCode) {
            this.refs.connectSection.style.display = 'none';
            this.refs.connectedSection.style.display = 'flex';
            this.refs.activeCode.textContent = roomCode;
            if (this.refs.roomBadge) { this.refs.roomBadge.style.display = 'block'; this.refs.roomBadge.textContent = roomCode; }
            if (this.refs.onlineDot) this.refs.onlineDot.style.display = 'block';
            this.refs.activityFeed.innerHTML = '';
        },

        showDisconnected() {
            this.refs.connectSection.style.display = 'block';
            this.refs.connectedSection.style.display = 'none';
            if (this.refs.roomBadge) this.refs.roomBadge.style.display = 'none';
            if (this.refs.onlineDot) this.refs.onlineDot.style.display = 'none';
            this.refs.roster.innerHTML = '';
            this.refs.activityFeed.innerHTML = '<div class="empty-state" style="flex-direction: column; gap: 8px;"><span>Create or join a room to start collaborating.</span></div>';
        },

        renderRoster(operators, myName) {
            const el = this.refs.roster;
            if (!el) return;
            el.innerHTML = '';

            operators.forEach(op => {
                const row = document.createElement('div');
                row.style.cssText = 'display: flex; align-items: center; gap: 10px; padding: 8px 10px; background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border-color);';
                const isMe = op.name === myName;
                row.innerHTML = `
                    <div style="width: 32px; height: 32px; border-radius: 50%; background: ${op.color}; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; color: #fff; flex-shrink: 0;">
                        ${esc(op.name.charAt(0).toUpperCase())}
                    </div>
                    <div style="flex: 1; min-width: 0;">
                        <div style="font-size: 12px; font-weight: 600; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            ${esc(op.name)} ${isMe ? '<span style="font-size: 9px; color: var(--accent); font-weight: 400;">(you)</span>' : ''}
                        </div>
                        <div style="font-size: 10px; color: var(--text-muted);">Online</div>
                    </div>
                    <div style="width: 8px; height: 8px; border-radius: 50%; background: var(--safe); flex-shrink: 0;"></div>
                `;
                el.appendChild(row);
            });
        },

        addActivityEntry(data) {
            const feed = this.refs.activityFeed;
            if (!feed) return;

            const emptyState = feed.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            const entry = document.createElement('div');
            entry.style.cssText = 'display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--border-color); animation: slideUp 0.3s ease;';

            const time = data.time ? new Date(data.time).toLocaleTimeString() : '';
            let icon = '-';
            let message = '';

            switch (data.type) {
                case 'join':
                    icon = '+'; message = `<strong>${esc(data.operator)}</strong> joined the room`; break;
                case 'leave':
                    icon = '-'; message = `<strong>${esc(data.operator)}</strong> left the room`; break;
                case 'scan':
                    icon = data.status === 'started' ? '>' : 'ok';
                    message = `<strong>${esc(data.operator)}</strong> ${data.status === 'started' ? 'started' : 'completed'} <span style="color: var(--accent);">${esc(data.scan_type)}</span> on ${esc(data.target)}`;
                    if (data.results_count) message += ` (${data.results_count} results)`;
                    break;
                case 'finding':
                    icon = '!!';
                    const sev = data.finding?.severity || 'INFO';
                    const sevColor = sev === 'CRITICAL' ? 'var(--danger)' : sev === 'HIGH' ? '#f97316' : 'var(--warning)';
                    message = `<strong>${esc(data.operator)}</strong> found <span style="color: ${sevColor};">[${sev}]</span> ${esc(data.finding?.title || 'vulnerability')}`;
                    break;
                case 'endpoint':
                    icon = 'ep';
                    message = `<strong>${esc(data.operator)}</strong> discovered endpoint: <span style="color: var(--accent); font-family: var(--font-mono);">${esc(data.endpoint?.url || data.endpoint || '')}</span>`;
                    break;
                case 'system':
                    icon = '--'; message = data.message || 'System event'; break;
                default:
                    message = `<strong>${esc(data.operator || 'Unknown')}</strong>: ${data.type || 'event'}`;
            }

            entry.innerHTML = `
                <div style="width: 24px; height: 24px; border-radius: 50%; background: ${data.color || '#333'}; display: flex; align-items: center; justify-content: center; font-size: 9px; font-weight: 700; flex-shrink: 0; color: #fff; font-family: var(--font-mono);">
                    ${icon}
                </div>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">${message}</div>
                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">${time}</div>
                </div>
            `;

            feed.appendChild(entry);
            feed.scrollTop = feed.scrollHeight;
        },
    };

    // ─────────────────────────────────────────────────────────────────
    // TeamController: Coordinates TeamClient and TeamUI
    // Manages state, wires events, handles user actions.
    // ─────────────────────────────────────────────────────────────────
    const state = {
        connected: false,
        roomCode: null,
        operatorName: '',
        operators: [],
    };

    // Register Socket.IO event listeners on the existing global socket
    TeamClient.registerListeners({
        onRoster(data) {
            state.operators = data.operators || [];
            TeamUI.renderRoster(state.operators, state.operatorName);
            // Update status bar operator count
            const el = document.getElementById('status-schedulers');
            if (el && state.connected) el.textContent = `${state.operators.length} operators`;
        },

        onActivity(data) {
            TeamUI.addActivityEntry(data);
        },

        onState(data) {
            // Sync shared state when first joining a room
            if (data.shared_notes) {
                const editor = document.getElementById('notes-editor');
                if (editor) editor.value = data.shared_notes;
            }
        },

        onNotesSync(data) {
            const editor = document.getElementById('notes-editor');
            if (editor) {
                const pos = editor.selectionStart;
                editor.value = data.content;
                editor.selectionStart = pos;
                editor.selectionEnd = pos;
            }
        },

        onEndpointSync(data) {
            TeamUI.addActivityEntry({
                type: 'endpoint',
                operator: data.operator,
                color: data.color,
                endpoint: data.endpoint,
                time: new Date().toISOString(),
            });
        },

        onCursorSync(data) {
            // Future: render remote cursors on the notes editor
        },

        onError(data) {
            log('vuln', `[Team] Error: ${data.error || 'Unknown error'}`);
        },
    });

    // ── Create Room ─────────────────────────────────────────────────
    document.getElementById('team-create-btn')?.addEventListener('click', async () => {
        const name = TeamUI.refs.nameInput?.value?.trim() || 'Operator';
        state.operatorName = name;

        try {
            const data = await TeamClient.createRoom(name, document.getElementById('target-url')?.value || '');
            if (data.status === 'success') {
                enterRoom(data.room_code, name);
            }
        } catch (e) {
            log('vuln', `[Team] Failed to create room: ${e.message}`);
        }
    });

    // ── Join Room ───────────────────────────────────────────────────
    document.getElementById('team-join-btn')?.addEventListener('click', async () => {
        const code = document.getElementById('team-join-code')?.value?.trim().toUpperCase();
        const name = TeamUI.refs.nameInput?.value?.trim() || 'Operator';
        if (!code || code.length < 4) return;

        state.operatorName = name;

        try {
            const data = await TeamClient.validateRoom(code);
            if (data.status === 'success') {
                enterRoom(data.room_code, name);
            }
        } catch (e) {
            log('vuln', `[Team] ${e.message}`);
        }
    });

    function enterRoom(roomCode, name) {
        state.connected = true;
        state.roomCode = roomCode;

        TeamUI.showConnected(roomCode);
        TeamClient.emitJoin(roomCode, name);
        hookNotesSync();
        log('info', `[Team] Joined room ${roomCode} as ${name}`);
    }

    // ── Leave Room ──────────────────────────────────────────────────
    document.getElementById('team-leave-btn')?.addEventListener('click', () => {
        TeamClient.emitLeave();
        state.connected = false;
        state.roomCode = null;
        state.operators = [];
        TeamUI.showDisconnected();
        log('info', '[Team] Left the team room.');
    });

    // ── Copy Room Code ──────────────────────────────────────────────
    document.getElementById('team-share-room')?.addEventListener('click', () => {
        if (!state.roomCode) return;
        navigator.clipboard.writeText(state.roomCode);
        const btn = document.getElementById('team-share-room');
        const orig = btn.textContent;
        btn.textContent = 'Copied';
        btn.style.color = 'var(--safe)';
        setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
    });

    // ── Notes Real-Time Sync ────────────────────────────────────────
    let _notesHooked = false;
    function hookNotesSync() {
        if (_notesHooked) return;
        _notesHooked = true;

        const editor = document.getElementById('notes-editor');
        if (!editor) return;

        let debounce = null;
        editor.addEventListener('input', () => {
            if (!state.connected) return;
            clearTimeout(debounce);
            debounce = setTimeout(() => {
                TeamClient.emitNotesUpdate(editor.value, editor.selectionStart);
            }, 300);
        });
    }

    // ── Public API: expose to other modules ─────────────────────────
    // Other tools (CyberNode, scanners, etc.) call these to broadcast
    // events to the team without knowing about Socket.IO internals.
    window.WSHawkTeam = {
        isConnected: () => state.connected,
        broadcastScanEvent: (scanType, target, status, resultsCount) => {
            if (!state.connected) return;
            TeamClient.emitScanEvent(scanType, target, status, resultsCount);
        },
        broadcastFinding: (finding) => {
            if (!state.connected) return;
            TeamClient.emitFinding(finding);
        },
        broadcastEndpoint: (endpoint) => {
            if (!state.connected) return;
            TeamClient.emitEndpoint(endpoint);
        },
    };

})();
