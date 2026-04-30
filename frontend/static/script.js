// API Base URL
const API_BASE = 'http://localhost:5000/api';

// Global variables
let currentLogData = null;
let currentNetworkData = null;
let currentPortData = null;
let currentPacketData = null;
let currentCaptureData = null;
let currentIpReputationData = null;
let currentThreatAnalysisData = null;
let currentScrapedData = null;

// Dashboard Stats (stored in localStorage for persistence)
let dashboardStats = {
    logs_processed: parseInt(localStorage.getItem('logs_processed') || '0'),
    threats_detected: parseInt(localStorage.getItem('threats_detected') || '0'),
    networks_scanned: parseInt(localStorage.getItem('networks_scanned') || '0'),
    packets_analyzed: parseInt(localStorage.getItem('packets_analyzed') || '0')
};

// Update dashboard stat and show animation
function updateDashboardStat(statName, increment = 1) {
    dashboardStats[statName] += increment;
    localStorage.setItem(statName, dashboardStats[statName]);
    
    const statMap = {
        'logs_processed': 'stat-logs',
        'threats_detected': 'stat-threats',
        'networks_scanned': 'stat-networks',
        'packets_analyzed': 'stat-packets'
    };
    
    const statElement = document.getElementById(statMap[statName]);
    if (statElement) {
        statElement.textContent = dashboardStats[statName];
        // Add pulse animation
        statElement.style.animation = 'none';
        setTimeout(() => {
            statElement.style.animation = 'statPulse 0.6s ease-out';
        }, 10);
    }
}

// Initialize dashboard stats from localStorage
function initDashboardStats() {
    document.getElementById('stat-logs').textContent = dashboardStats.logs_processed;
    document.getElementById('stat-threats').textContent = dashboardStats.threats_detected;
    document.getElementById('stat-networks').textContent = dashboardStats.networks_scanned;
    document.getElementById('stat-packets').textContent = dashboardStats.packets_analyzed;
}

// Matrix Rain Animation
function initMatrixRain() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = '01アイウエオカキクケコサシスセソタチツテト';
    const charSize = 14;
    const columns = Math.floor(canvas.width / charSize);
    const drops = Array(columns).fill(0);
    
    function draw() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = 'rgba(0, 255, 0, 0.1)';
        ctx.font = charSize + 'px monospace';
        
        for (let i = 0; i < columns; i++) {
            const char = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(char, i * charSize, drops[i] * charSize);
            
            if (drops[i] * charSize > canvas.height && Math.random() > 0.95) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(draw, 50);
}

window.addEventListener('resize', () => {
    const canvas = document.getElementById('matrix-canvas');
    if (canvas) {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
});

// Download JSON
function downloadJSON(name, data) {
    if (!data) {
        alert('No data available to download');
        return;
    }
    
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${name}_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Tab Management
function showTab(tabName) {
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    const navLinks = document.querySelectorAll('.nav-links a');
    navLinks.forEach(link => link.classList.remove('nav-link-active'));
    
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }
    
    event.target.classList.add('nav-link-active');
}

// File name display
document.getElementById('log-file')?.addEventListener('change', function() {
    const fileNameDisplay = document.getElementById('log-filename');
    const fileNameText = document.getElementById('log-filename-text');
    
    if (this.files && this.files[0]) {
        fileNameText.textContent = this.files[0].name;
        fileNameDisplay.style.display = 'block';
    } else {
        fileNameDisplay.style.display = 'none';
    }
});

document.getElementById('packet-file')?.addEventListener('change', function() {
    const fileNameDisplay = document.getElementById('packet-file-display');
    const fileNameText = document.getElementById('packet-file-name');
    
    if (this.files && this.files[0]) {
        fileNameText.textContent = this.files[0].name;
        fileNameDisplay.classList.remove('hidden');
    } else {
        fileNameDisplay.classList.add('hidden');
    }
});

// Log Analysis
document.getElementById('log-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('log-file').files[0];
    if (!file) {
        alert('Please select a file');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    const loading = document.getElementById('log-loading');
    const results = document.getElementById('log-results');
    
    loading.classList.remove('hidden');
    
    try {
        const response = await fetch(`${API_BASE}/analyze-log`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        loading.classList.add('hidden');
        
        if (data.status === 'success') {
            displayLogResults(data.analysis);
            results.classList.remove('hidden');
            // Update dashboard
            updateDashboardStat('logs_processed');
        } else {
            alert('Error: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        loading.classList.add('hidden');
        alert('Failed to analyze log file');
    }
});

function displayLogResults(analysis) {
    currentLogData = analysis;
    
    document.getElementById('log-total-lines').textContent = analysis.total_lines || 0;
    document.getElementById('log-threats-count').textContent = 
        (analysis.threat_levels?.critical || 0) + (analysis.threat_levels?.high || 0) || 0;
    document.getElementById('log-unique-ips').textContent = analysis.stats?.total_unique_ips || 0;
    document.getElementById('log-errors').textContent = analysis.stats?.total_errors || 0;
    
    // Calculate and display risk score
    const critical = analysis.threat_levels?.critical || 0;
    const high = analysis.threat_levels?.high || 0;
    const medium = analysis.threat_levels?.medium || 0;
    const low = analysis.threat_levels?.low || 0;
    
    const riskScore = Math.min(100, (critical * 25 + high * 15 + medium * 8 + low * 2));
    document.getElementById('log-risk-score').textContent = Math.round(riskScore) + '/100';
    document.getElementById('log-risk-bar').style.width = Math.round(riskScore) + '%';
    
    // Update severity display
    document.getElementById('log-severity-critical').textContent = critical;
    document.getElementById('log-severity-high').textContent = high;
    document.getElementById('log-severity-medium').textContent = medium;
    document.getElementById('log-severity-low').textContent = low;
    
    const patternDiv = document.getElementById('log-patterns');
    patternDiv.innerHTML = '';
    for (const [pattern, count] of Object.entries(analysis.matched_patterns || {})) {
        const item = document.createElement('div');
        item.className = 'pattern-item';
        item.innerHTML = `<h5>${pattern}</h5><p>Found: <strong>${count}</strong> matches</p>`;
        patternDiv.appendChild(item);
    }
    
    const suspiciousDiv = document.getElementById('log-suspicious');
    suspiciousDiv.innerHTML = '';
    if (analysis.suspicious_activity && analysis.suspicious_activity.length > 0) {
        analysis.suspicious_activity.forEach(activity => {
            const item = document.createElement('div');
            item.className = `activity-item ${activity.severity}`;
            item.innerHTML = `
                <p><strong>Type:</strong> ${activity.type}</p>
                <p><strong>Severity:</strong> ${activity.severity}</p>
                <p><strong>Content:</strong> ${activity.line}</p>
            `;
            suspiciousDiv.appendChild(item);
        });
    } else {
        suspiciousDiv.innerHTML = '<p class="empty-state">No suspicious activity detected</p>';
    }
    
    const ipsDiv = document.getElementById('log-ips');
    ipsDiv.innerHTML = '';
    if (analysis.unique_ips && analysis.unique_ips.length > 0) {
        analysis.unique_ips.forEach(ip => {
            const item = document.createElement('div');
            item.className = 'ip-item';
            item.innerHTML = `<p><strong>IP:</strong> ${ip}</p>`;
            ipsDiv.appendChild(item);
        });
    } else {
        ipsDiv.innerHTML = '<p class="empty-state">No IPs found</p>';
    }
}

function clearLogResults() {
    document.getElementById('log-results').classList.add('hidden');
    document.getElementById('log-form').reset();
    document.getElementById('log-filename').style.display = 'none';
    currentLogData = null;
}

// Network Scanning
document.getElementById('network-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('scan-target').value.trim();
    const scanType = document.getElementById('scan-type').value;
    const loading = document.getElementById('network-loading');
    const results = document.getElementById('network-results');
    
    // Validate input
    if (!target) {
        alert('Please enter a target IP or network');
        return;
    }
    
    loading.classList.remove('hidden');
    results.classList.add('hidden');
    
    try {
        const response = await fetch(`${API_BASE}/scan-network`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: scanType })
        });
        
        const data = await response.json();
        loading.classList.add('hidden');
        
        if (data.status === 'success') {
            displayNetworkResults(data.results);
            results.classList.remove('hidden');
            // Update dashboard
            updateDashboardStat('networks_scanned');
        } else {
            alert('Network Scan Error:\n' + (data.error || 'Unknown error occurred'));
        }
    } catch (error) {
        console.error('Error:', error);
        loading.classList.add('hidden');
        alert('Failed to scan network:\n' + error.message);
    }
});

function displayNetworkResults(results) {
    currentNetworkData = results;
    const hostsDiv = document.getElementById('network-hosts');
    hostsDiv.innerHTML = '';
    
    // Handle both old and new response formats
    const hosts = results.hosts || results.active_hosts || [];
    
    // Update summary stats
    const openPortsCount = hosts.reduce((sum, h) => sum + (h.open_ports?.length || 0), 0);
    const vulnerableCount = hosts.reduce((sum, h) => sum + ((h.vulnerabilities || []).length), 0);
    
    document.getElementById('network-active-count').textContent = hosts.length;
    document.getElementById('network-open-ports').textContent = openPortsCount;
    document.getElementById('network-vulnerable').textContent = vulnerableCount;
    
    // Calculate risk level
    const riskLevel = Math.min(100, openPortsCount * 8 + vulnerableCount * 15);
    document.getElementById('network-risk-bar').style.width = riskLevel + '%';
    
    if (riskLevel < 30) {
        document.getElementById('network-risk-level').textContent = 'LOW';
        document.getElementById('network-risk-level').style.color = '#00bb00';
    } else if (riskLevel < 60) {
        document.getElementById('network-risk-level').textContent = 'MEDIUM';
        document.getElementById('network-risk-level').style.color = '#ffbb00';
    } else {
        document.getElementById('network-risk-level').textContent = 'HIGH';
        document.getElementById('network-risk-level').style.color = '#ff6b6b';
    }
    
    if (hosts && hosts.length > 0) {
        hosts.forEach(host => {
            const item = document.createElement('div');
            item.className = 'host-item';
            
            const ip = host.target || host.ip || 'Unknown';
            const hostname = host.hostname || 'N/A';
            const status = host.alive ? '✓ ALIVE' : '✗ OFFLINE';
            
            let portsHtml = '';
            if (host.open_ports && host.open_ports.length > 0) {
                portsHtml = host.open_ports.map(p => `${p.port}/${p.service}`).join(', ');
            }
            
            item.innerHTML = `
                <p><strong>IP:</strong> ${ip}</p>
                <p><strong>Status:</strong> ${status}</p>
                ${hostname !== 'N/A' ? `<p><strong>Hostname:</strong> ${hostname}</p>` : ''}
                ${portsHtml ? `<p><strong>Open Ports:</strong> ${portsHtml}</p>` : ''}
            `;
            hostsDiv.appendChild(item);
        });
    } else {
        hostsDiv.innerHTML = '<p class="empty-state">No active hosts found</p>';
    }
}

// Port Scanning
// Port Scanning
document.getElementById('port-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('port-target').value.trim();
    const ports = document.getElementById('port-range').value.trim();
    const loading = document.getElementById('port-loading');
    const results = document.getElementById('port-results');
    
    // Validate inputs
    if (!target) {
        alert('Please enter a target IP address');
        return;
    }
    
    // Simple IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(target)) {
        alert('Please enter a valid IP address (e.g., 192.168.1.1)');
        return;
    }
    
    loading.classList.remove('hidden');
    results.classList.add('hidden');
    
    try {
        const response = await fetch(`${API_BASE}/scan-port`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, ports })
        });
        
        const data = await response.json();
        loading.classList.add('hidden');
        
        if (data.status === 'success') {
            displayPortResults(data.results);
            results.classList.remove('hidden');
        } else {
            alert('Port Scan Error:\n' + (data.error || 'Unknown error occurred'));
        }
    } catch (error) {
        console.error('Error:', error);
        loading.classList.add('hidden');
        alert('Failed to scan ports:\n' + error.message);
    }
});

function displayPortResults(results) {
    currentPortData = results;
    const portDiv = document.getElementById('port-list');
    portDiv.innerHTML = '';
    
    // Display summary
    const summary = document.createElement('div');
    summary.className = 'results-summary';
    summary.innerHTML = `
        <p><strong>Target:</strong> ${results.target}</p>
        <p><strong>Ports Scanned:</strong> ${results.total_scanned}</p>
        <p><strong>Open Ports Found:</strong> ${results.open_ports_count}</p>
        <p><strong>Scan Range:</strong> ${results.scan_range || 'N/A'}</p>
    `;
    portDiv.appendChild(summary);
    
    // Display ports
    if (results.open_ports && results.open_ports.length > 0) {
        results.open_ports.forEach(port => {
            const item = document.createElement('div');
            item.className = 'port-item';
            item.innerHTML = `
                <p><strong>Port:</strong> ${port.port}</p>
                <p><strong>Service:</strong> ${port.service}</p>
                <p><strong>Status:</strong> <span style="color: #0f0;">${port.status}</span></p>
            `;
            portDiv.appendChild(item);
        });
    } else {
        portDiv.innerHTML += '<p class="empty-state">No open ports found in the specified range</p>';
    }
}

// Packet Analysis
document.getElementById('packet-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('packet-file').files[0];
    
    if (!file) {
        alert('Please select a PCAP or packet capture file');
        return;
    }
    
    // Check file size (limit to 100MB)
    if (file.size > 100 * 1024 * 1024) {
        alert('File is too large (max 100MB)');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    const filter = document.getElementById('packet-filter').value || 'all';
    formData.append('filter', filter);
    const loading = document.getElementById('packet-loading');
    const results = document.getElementById('packet-results');
    
    loading.classList.remove('hidden');
    results.classList.add('hidden');
    
    try {
        const response = await fetch(`${API_BASE}/analyze-packets`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        loading.classList.add('hidden');
        
        if (data.status === 'success') {
            displayPacketResults(data.analysis || data.results || data, data.filename);
            results.classList.remove('hidden');
            // Update dashboard
            updateDashboardStat('packets_analyzed');
        } else {
            alert('Packet Analysis Error:\n' + (data.error || 'Unknown error occurred'));
        }
    } catch (error) {
        console.error('Error:', error);
        loading.classList.add('hidden');
        alert('Failed to analyze packets:\n' + error.message);
    }
});

function displayPacketResults(analysis, filename) {
    currentPacketData = analysis;
    
    // Display filename
    if (filename) {
        document.getElementById('packet-filename').textContent = filename;
    }
    
    document.getElementById('packet-count').textContent = analysis.total_packets || 0;
    document.getElementById('packet-tcp').textContent = analysis.protocol_count?.TCP || 0;
    document.getElementById('packet-udp').textContent = analysis.protocol_count?.UDP || 0;
    document.getElementById('packet-dns').textContent = analysis.protocol_count?.DNS || 0;
    
    // Calculate summary stats
    const maliciousCount = (analysis.detections || []).length;
    const suspiciousCount = Math.floor((maliciousCount * 0.5)) || 0;
    const protocolCount = Object.keys(analysis.protocol_count || {}).length;
    
    document.getElementById('packet-malicious-count').textContent = maliciousCount;
    document.getElementById('packet-suspicious-count').textContent = suspiciousCount;
    document.getElementById('packet-protocols-count').textContent = protocolCount;
    
    // Calculate threat level
    const threatScore = Math.min(100, maliciousCount * 12 + suspiciousCount * 5);
    document.getElementById('packet-threat-bar').style.width = threatScore + '%';
    
    if (threatScore < 20) {
        document.getElementById('packet-threat-level').textContent = 'LOW';
        document.getElementById('packet-threat-level').style.color = '#00bb00';
    } else if (threatScore < 50) {
        document.getElementById('packet-threat-level').textContent = 'MEDIUM';
        document.getElementById('packet-threat-level').style.color = '#ffbb00';
    } else {
        document.getElementById('packet-threat-level').textContent = 'HIGH';
        document.getElementById('packet-threat-level').style.color = '#ff6b6b';
    }
    
    // Display source IPs
    const srcDiv = document.getElementById('packet-src-ips');
    srcDiv.innerHTML = '';
    if (analysis.top_source_ips) {
        analysis.top_source_ips.forEach(ip => {
            const item = document.createElement('div');
            item.className = 'ip-item';
            item.innerHTML = `<p><strong>${ip}</strong></p>`;
            srcDiv.appendChild(item);
        });
    }
    
    // Display destination IPs
    const dstDiv = document.getElementById('packet-dst-ips');
    dstDiv.innerHTML = '';
    if (analysis.top_dest_ips) {
        analysis.top_dest_ips.forEach(ip => {
            const item = document.createElement('div');
            item.className = 'ip-item';
            item.innerHTML = `<p><strong>${ip}</strong></p>`;
            dstDiv.appendChild(item);
        });
    }
}

// Clear Packet Results
function clearPacketResults() {
    currentPacketData = null;
    
    // Reset file display
    document.getElementById('packet-filename').textContent = '-';
    
    // Clear statistics
    document.getElementById('packet-count').textContent = '-';
    document.getElementById('packet-tcp').textContent = '-';
    document.getElementById('packet-udp').textContent = '-';
    document.getElementById('packet-dns').textContent = '-';
    
    // Clear IP lists
    document.getElementById('packet-src-ips').innerHTML = '';
    document.getElementById('packet-dst-ips').innerHTML = '';
    
    // Hide results
    document.getElementById('packet-results').classList.add('hidden');
    
    // Clear file input
    document.getElementById('packet-file').value = '';
}

// IP Reputation Check
document.getElementById('ip-reputation-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = document.getElementById('ip-check').value.trim();
    
    // Validate IP
    if (!ip) {
        alert('Please enter an IP address');
        return;
    }
    
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        alert('Please enter a valid IP address (e.g., 192.168.1.1)');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/check-ip-reputation`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            currentIpReputationData = data.reputation;
            displayIPReputation(data.reputation, ip);
            document.getElementById('ip-reputation-result').classList.remove('hidden');
            // Update dashboard for threat detection
            updateDashboardStat('threats_detected');
        } else {
            alert('IP Reputation Error:\n' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to check IP reputation:\n' + error.message);
    }
});

function displayIPReputation(reputation, ip) {
    const content = document.getElementById('ip-reputation-content');
    const isClean = reputation.status === 'clean' || reputation.status === 'safe';
    const statusColor = isClean ? '#0f0' : '#ff0000';
    
    content.innerHTML = `
        <div class="result-card">
            <p><strong>IP Address:</strong> ${ip}</p>
            <p><strong>Reputation:</strong> <span style="color: ${statusColor};">${reputation.status || 'UNKNOWN'}</span></p>
            <p><strong>Threat Level:</strong> ${reputation.threat_level || 'LOW'}</p>
        </div>
        <div class="result-card">
            <p style="color: var(--text-secondary); font-size: 12px;">
                ${reputation.details || reputation.description || 'IP address reputation check completed'}
            </p>
        </div>
    `;
}

// Threat Analysis
document.getElementById('threat-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const threatType = document.getElementById('threat-type').value.trim();
    
    if (!threatType) {
        alert('Please select a threat type');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/threat-analysis/${threatType}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            currentThreatAnalysisData = data.analysis;
            displayThreatAnalysis(data.analysis, threatType);
            document.getElementById('threat-analysis-result').classList.remove('hidden');
            
            // Show threat detection results with summary
            document.getElementById('threat-detection-results').classList.remove('hidden');
            updateThreatSummary(data.analysis);
        } else {
            alert('Threat Analysis Error:\n' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to get threat analysis:\n' + error.message);
    }
});

function updateThreatSummary(analysis) {
    // Update threat intel summary stats (placeholder values for demo)
    document.getElementById('threat-ips-checked').textContent = Math.floor(Math.random() * 150) + 50;
    document.getElementById('threat-blacklisted-count').textContent = Math.floor(Math.random() * 15) + 2;
    document.getElementById('threat-urls-count').textContent = Math.floor(Math.random() * 100) + 20;
    
    // Set threat level based on severity
    const severity = (analysis.severity || 'low').toLowerCase();
    let threatScore = 30;
    let threatColor = '#00bb00';
    let threatText = 'LOW';
    
    if (severity === 'critical') {
        threatScore = 85;
        threatColor = '#ff4444';
        threatText = 'CRITICAL';
    } else if (severity === 'high') {
        threatScore = 65;
        threatColor = '#ff6b6b';
        threatText = 'HIGH';
    } else if (severity === 'medium') {
        threatScore = 45;
        threatColor = '#ffbb00';
        threatText = 'MEDIUM';
    }
    
    document.getElementById('threat-level-bar').style.width = threatScore + '%';
    document.getElementById('threat-overall-level').textContent = threatText;
    document.getElementById('threat-overall-level').style.color = threatColor;
}

function displayThreatAnalysis(analysis, threatType) {
    const content = document.getElementById('threat-analysis-content');
    const severity = (analysis.severity || 'medium').toUpperCase();
    const severityColor = severity === 'CRITICAL' || severity === 'HIGH' ? '#ff0000' : '#ffaa00';
    
    content.innerHTML = `
        <div class="threat-item critical">
            <p><strong>Threat Type:</strong> ${threatType || 'N/A'}</p>
            <p><strong>Severity:</strong> <span style="color: ${severityColor};">${severity}</span></p>
            <p><strong>Category:</strong> ${analysis.category || 'General'}</p>
            <p><strong>Description:</strong> ${analysis.description || 'No description available'}</p>
        </div>
        <div class="threat-item" style="margin-top: 15px;">
            <p><strong>Attack Patterns:</strong></p>
            <ul style="margin-left: 20px; color: #0f0;">
                ${(analysis.patterns || []).map(p => `<li>${p}</li>`).join('') || '<li>No known patterns</li>'}
            </ul>
        </div>
        <div class="threat-item" style="margin-top: 15px;">
            <p><strong>Mitigation Steps:</strong></p>
            <ul style="margin-left: 20px; color: #0f0;">
                ${(analysis.mitigation_steps || analysis.recommendations || []).map(m => `<li>${m}</li>`).join('') || '<li>Apply security best practices</li>'}
            </ul>
        </div>
        </div>
    `;
}

// Website Scraper
document.getElementById('scrape-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('scrape-url').value.trim();
    
    if (!url) {
        alert('Please enter a URL');
        return;
    }
    
    const loading = document.getElementById('scrape-loading');
    const results = document.getElementById('scrape-results');
    
    loading.classList.remove('hidden');
    results.classList.add('hidden');
    
    try {
        const response = await fetch(`${API_BASE}/scrape-website`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        loading.classList.add('hidden');
        
        if (data.status === 'success') {
            currentScrapedData = data.data;
            displayScrapedWebsite(data.data);
            results.classList.remove('hidden');
        } else {
            alert('Scraping Error:\n' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        loading.classList.add('hidden');
        alert('Failed to scrape website:\n' + error.message);
    }
});

function displayScrapedWebsite(data) {
    const content = document.getElementById('scrape-content');
    
    // Build summary
    const summary = data.summary || {};
    const title = data.title || 'No title found';
    
    let html = `
        <div class="result-card">
            <h4>📄 Website Information</h4>
            <p style="text-align: left; word-break: break-all; font-size: 12px;"><strong>URL:</strong> ${data.url || 'N/A'}</p>
            <p style="font-size: 14px;"><strong>Status Code:</strong> ${data.status_code || 'N/A'}</p>
            <p style="text-align: left; word-break: break-word; font-size: 13px;"><strong>Title:</strong> ${title}</p>
        </div>
        
        <div class="result-card">
            <h4>📊 Summary Statistics</h4>
            <p><strong>Total Links:</strong> <span style="color: #0f0;">${summary.total_links || 0}</span></p>
            <p><strong>Total Images:</strong> <span style="color: #0f0;">${summary.total_images || 0}</span></p>
            <p><strong>Total Forms:</strong> <span style="color: #ff0;">${summary.total_forms || 0}</span></p>
            <p><strong>Total Headings:</strong> <span style="color: #0f0;">${summary.total_headings || 0}</span></p>
        </div>
    `;
    
    // Headings
    if (data.headings && Object.keys(data.headings).length > 0) {
        html += `<div class="result-card">
            <h4>📑 Headings</h4>`;
        for (const [level, headings] of Object.entries(data.headings)) {
            if (headings.length > 0) {
                html += `<p style="text-align: left;"><strong>${level.toUpperCase()}:</strong></p>
                <ul style="margin-left: 20px; color: #0f0; font-size: 12px; text-align: left;">
                    ${headings.map(h => `<li style="word-break: break-word; margin-bottom: 5px;">${h}</li>`).join('')}
                </ul>`;
            }
        }
        html += `</div>`;
    }
    
    // Links
    if (data.links && data.links.length > 0) {
        html += `<div class="result-card">
            <h4>🔗 Links Found (${data.links.length})</h4>
            <div style="max-height: 300px; overflow-y: auto; text-align: left;">
            <ul style="margin-left: 20px; color: #0f0; font-size: 11px;">
                ${data.links.slice(0, 20).map(link => `
                    <li style="word-break: break-all; margin-bottom: 5px;">
                        <a href="${link.url}" target="_blank" style="color: #0f0; text-decoration: none;">
                            ${link.text || 'Link'}
                        </a>
                        <br><span style="color: #00aa00; font-size: 10px;">${link.url}</span>
                    </li>
                `).join('')}
                ${data.links.length > 20 ? `<li>... and ${data.links.length - 20} more links</li>` : ''}
            </ul>
            </div>
        </div>`;
    }
    
    // Images
    if (data.images && data.images.length > 0) {
        html += `<div class="result-card">
            <h4>🖼️ Images Found (${data.images.length})</h4>
            <div style="max-height: 300px; overflow-y: auto; text-align: left;">
            <ul style="margin-left: 20px; color: #0f0; font-size: 11px;">
                ${data.images.slice(0, 15).map(img => `
                    <li style="margin-bottom: 10px; word-break: break-all;">
                        <strong>Alt:</strong> ${img.alt} <br>
                        <strong>Src:</strong> <span style="color: #00aa00; font-size: 10px;">${img.src}</span>
                    </li>
                `).join('')}
                ${data.images.length > 15 ? `<li>... and ${data.images.length - 15} more images</li>` : ''}
            </ul>
            </div>
        </div>`;
    }
    
    // Forms
    if (data.forms && data.forms.length > 0) {
        html += `<div class="result-card alert">
            <h4>⚠️ Forms Found (${data.forms.length})</h4>
            ${data.forms.map((form, idx) => `
                <div style="margin-top: 10px; padding: 10px; background: rgba(255,0,0,0.1); border-left: 3px solid #ff0; text-align: left; word-break: break-all;">
                    <p><strong>Form #${idx + 1}</strong></p>
                    <p style="font-size: 11px;"><strong>Action:</strong> <span style="color: #ff0;">${form.action || '#'}</span></p>
                    <p><strong>Method:</strong> ${form.method}</p>
                    <p><strong>Fields:</strong></p>
                    <ul style="margin-left: 20px; color: #ff0; font-size: 12px;">
                        ${form.fields.map(field => `
                            <li>
                                <strong>${field.name || 'unnamed'}</strong> 
                                (${field.input_type})
                                ${field.required ? ' <span style="color: red;">[REQUIRED]</span>' : ''}
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `).join('')}
        </div>`;
    }
    
    content.innerHTML = html;
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initMatrixRain();
    initDashboardStats();
    
    // Load packet interfaces
    fetch(`${API_BASE}/packet-interfaces`)
        .then(r => r.json())
        .then(data => {
            const select = document.getElementById('capture-interface');
            if (select && data.interfaces) {
                select.innerHTML = '';
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    select.appendChild(option);
                });
            }
        })
        .catch(e => console.log('Could not load interfaces:', e));
    
    // Initialize dashboard stats
    updateDashboardStats();
});

function updateDashboardStats() {
    fetch(`${API_BASE}/dashboard-stats`)
        .then(r => r.json())
        .then(data => {
            document.getElementById('stat-logs').textContent = data.total_logs_processed || 0;
            document.getElementById('stat-threats').textContent = data.threats_detected || 0;
            document.getElementById('stat-networks').textContent = data.networks_scanned || 0;
            document.getElementById('stat-packets').textContent = data.packets_analyzed || 0;
        })
        .catch(e => console.log('Could not load stats:', e));
}

// Set active nav link on page load
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.nav-links a')[0]?.classList.add('nav-link-active');
});
