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

// ==================== SUSPICIOUS IP ALERT SYSTEM ====================
function generateBeep(frequency = 800, duration = 300) {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = frequency;
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + duration / 1000);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + duration / 1000);
    } catch (e) {
        console.log('Audio context not available, beep skipped');
    }
}

function playAlertBeep() {
    // Play triple beep for alert
    generateBeep(900, 200);
    setTimeout(() => generateBeep(900, 200), 250);
    setTimeout(() => generateBeep(900, 300), 500);
}

function showAlertModal(ipAddress, threatType, severity, details) {
    const overlay = document.getElementById('alert-modal-overlay');
    if (overlay) {
        // Update modal content
        document.getElementById('alert-ip-text').textContent = ipAddress;
        document.getElementById('alert-type-text').textContent = threatType;
        document.getElementById('alert-severity-text').textContent = severity;
        document.getElementById('alert-details-text').textContent = details;
        
        // Show overlay
        overlay.classList.add('show');
        
        // Prevent background scrolling
        document.body.style.overflow = 'hidden';
        
        // Play beep sound
        playAlertBeep();
        
        // Auto-close after 15 seconds
        setTimeout(() => {
            closeAlertModal();
        }, 15000);
    }
}

function closeAlertModal() {
    const overlay = document.getElementById('alert-modal-overlay');
    if (overlay) {
        overlay.classList.remove('show');
        // Re-enable background scrolling
        document.body.style.overflow = 'auto';
    }
}

function investigateIP() {
    const ipText = document.getElementById('alert-ip-text').textContent;
    closeAlertModal();
    // Switch to network scan tab
    showTab('network-scan');
    document.getElementById('scan-target').value = ipText;
    alert(`Switched to Network Scan tab. You can now scan IP: ${ipText}`);
}

// Dashboard Stats (initialize to 0 at session start)
let dashboardStats = {
    logs_processed: 0,
    threats_detected: 0,
    networks_scanned: 0,
    packets_analyzed: 0
};

// Helper function to get auth token
function getAuthToken() {
    return localStorage.getItem('authToken') || '';
}

// Helper function to make API requests with auth
async function apiRequest(url, options = {}) {
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${getAuthToken()}`
    };
    
    return fetch(url, {
        ...options,
        headers
    });
}

// Update dashboard stat and show animation
function updateDashboardStat(statName, increment = 1) {
    dashboardStats[statName] += increment;
    
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
    const statLogs = document.getElementById('stat-logs');
    const statThreats = document.getElementById('stat-threats');
    const statNetworks = document.getElementById('stat-networks');
    const statPackets = document.getElementById('stat-packets');
    
    if (statLogs) statLogs.textContent = dashboardStats.logs_processed;
    if (statThreats) statThreats.textContent = dashboardStats.threats_detected;
    if (statNetworks) statNetworks.textContent = dashboardStats.networks_scanned;
    if (statPackets) statPackets.textContent = dashboardStats.packets_analyzed;
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
        const response = await apiRequest(`${API_BASE}/analyze-log`, {
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
    
    // Enhanced pattern display with threat indicators
    const patternDiv = document.getElementById('log-patterns');
    patternDiv.innerHTML = '';
    
    // Define threat severity for patterns
    const patternThreatMap = {
        'sql_injection': 'CRITICAL',
        'xss_attack': 'CRITICAL',
        'malware': 'CRITICAL',
        'command_injection': 'CRITICAL',
        'port_scan': 'HIGH',
        'brute_force': 'HIGH',
        'dos_attack': 'HIGH',
        'unauthorized_access': 'HIGH',
        'suspicious_login': 'MEDIUM',
        'failed_login': 'MEDIUM'
    };
    
    const patternEmojis = {
        'sql_injection': '💉',
        'xss_attack': '🧬',
        'malware': '🦠',
        'command_injection': '⚙️',
        'port_scan': '🔍',
        'brute_force': '🔐',
        'dos_attack': '💥',
        'unauthorized_access': '⛔',
        'suspicious_login': '⚠️',
        'failed_login': '❌'
    };
    
    const sortedPatterns = Object.entries(analysis.matched_patterns || {})
        .sort((a, b) => b[1] - a[1]);
    
    sortedPatterns.forEach(([pattern, count]) => {
        const item = document.createElement('div');
        item.className = 'pattern-item';
        const threatLevel = patternThreatMap[pattern] || 'MEDIUM';
        const emoji = patternEmojis[pattern] || '⚡';
        const percentage = ((count / (critical + high + medium + low)) * 100).toFixed(1);
        
        item.innerHTML = `<h5>${emoji} ${pattern.toUpperCase().replace(/_/g, ' ')}</h5>\n                        <p>Detections: <strong>${count}</strong> (${percentage}%)</p>\n                        <p>Threat Level: <strong>${threatLevel}</strong></p>`;
        patternDiv.appendChild(item);
    });
    
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
    const suspiciousIPs = {
        '192.168.1.1': { type: 'Port Scanner', severity: 'MEDIUM' },
        '10.0.0.1': { type: 'Botnet Command', severity: 'HIGH' }
    };
    
    if (analysis.unique_ips && analysis.unique_ips.length > 0) {
        analysis.unique_ips.forEach(ip => {
            const item = document.createElement('div');
            item.className = 'ip-item';
            
            // Check if IP is suspicious
            if (suspiciousIPs[ip]) {
                item.innerHTML = `<p><strong>⚠️ SUSPICIOUS IP:</strong> ${ip}</p>`;
                // Show alert modal for suspicious IP
                setTimeout(() => {
                    showAlertModal(
                        ip,
                        suspiciousIPs[ip].type,
                        suspiciousIPs[ip].severity,
                        `IP ${ip} detected as ${suspiciousIPs[ip].type} in log analysis`
                    );
                }, 500);
            } else {
                item.innerHTML = `<p><strong>IP:</strong> ${ip}</p>`;
            }
            
            ipsDiv.appendChild(item);
        });
    } else {
        ipsDiv.innerHTML = '<p class="empty-state">No IPs found</p>';
    }
    
    // Render charts
    setTimeout(() => {
        renderThreatLevelsChart(analysis);
        renderPatternMatchesChart(analysis);
        renderThreatSummaryChart(analysis);
    }, 100);
    
    // Display filename
    document.getElementById('log-filename').textContent = 'File analyzed successfully';
    document.getElementById('log-filename').style.display = 'block';
}

// Chart rendering functions for Log Analysis
window.logChartsInstances = {};

function renderThreatLevelsChart(analysis) {
    const ctx = document.getElementById('log-threats-chart');
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.logChartsInstances.threatLevels) {
        window.logChartsInstances.threatLevels.destroy();
    }
    
    const critical = analysis.threat_levels?.critical || 0;
    const high = analysis.threat_levels?.high || 0;
    const medium = analysis.threat_levels?.medium || 0;
    const low = analysis.threat_levels?.low || 0;
    const total = critical + high + medium + low;
    
    const criticalPct = total > 0 ? ((critical / total) * 100).toFixed(1) : 0;
    const highPct = total > 0 ? ((high / total) * 100).toFixed(1) : 0;
    const mediumPct = total > 0 ? ((medium / total) * 100).toFixed(1) : 0;
    const lowPct = total > 0 ? ((low / total) * 100).toFixed(1) : 0;
    
    window.logChartsInstances.threatLevels = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [
                `🔴 CRITICAL\n${critical} (${criticalPct}%)`,
                `🟠 HIGH\n${high} (${highPct}%)`,
                `🟡 MEDIUM\n${medium} (${mediumPct}%)`,
                `🟢 LOW\n${low} (${lowPct}%)`
            ],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: [
                    '#ff4444',
                    '#ff8800',
                    '#ffbb00',
                    '#00bb00'
                ],
                borderColor: '#0a0a0a',
                borderWidth: 3,
                hoverBorderColor: '#00ff00',
                hoverBorderWidth: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#00ff00',
                        font: { size: 14, family: "'Courier New', monospace", weight: 'bold' },
                        padding: 20,
                        generateLabels: (chart) => {
                            const data = chart.data;
                            return data.labels.map((label, i) => ({
                                text: label,
                                fillStyle: data.datasets[0].backgroundColor[i],
                                hidden: false,
                                index: i
                            }));
                        }
                    }
                },
                tooltip: {
                    enabled: true,
                    backgroundColor: 'rgba(0, 0, 0, 0.9)',
                    titleColor: '#00ff00',
                    bodyColor: '#00ff00',
                    borderColor: '#00ff00',
                    borderWidth: 2,
                    padding: 15,
                    titleFont: { size: 15, weight: 'bold' },
                    bodyFont: { size: 14 },
                    displayColors: true,
                    callbacks: {
                        title: (context) => `THREAT LEVEL: ${context[0].label.split('\n')[0]}`,
                        label: (context) => {
                            const value = context.parsed;
                            const pct = ((value / total) * 100).toFixed(1);
                            return `Count: ${value} | Percentage: ${pct}%`;
                        }
                    }
                }
            }
        }
    });
}

function renderPatternMatchesChart(analysis) {
    const ctx = document.getElementById('log-patterns-chart');
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.logChartsInstances.patternMatches) {
        window.logChartsInstances.patternMatches.destroy();
    }
    
    const patterns = analysis.matched_patterns || {};
    const entries = Object.entries(patterns).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const labels = entries.map(e => e[0]);
    const data = entries.map(e => e[1]);
    const total = data.reduce((a, b) => a + b, 0);
    
    // Dynamic colors based on threat severity
    const patternColors = {
        'sql_injection': '#ff0000',
        'xss_attack': '#ff4444',
        'port_scan': '#ff8800',
        'brute_force': '#ffbb00',
        'malware': '#ff0000',
        'dos_attack': '#ff5500',
        'command_injection': '#ff2222',
        'unauthorized_access': '#ff9900',
        'suspicious_login': '#ffaa00',
        'failed_login': '#ffcc00'
    };
    
    const backgroundColors = labels.map(label => patternColors[label] || '#00bbff');
    
    window.logChartsInstances.patternMatches = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.map(l => l.toUpperCase().replace(/_/g, ' ')),
            datasets: [{
                label: 'Total Detections',
                data: data,
                backgroundColor: backgroundColors,
                borderColor: '#ffffff',
                borderWidth: 2,
                hoverBackgroundColor: '#00ff00',
                hoverBorderColor: '#00ff00'
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff00',
                        font: { size: 14, weight: 'bold', family: "'Courier New', monospace" },
                        padding: 15
                    }
                },
                tooltip: {
                    enabled: true,
                    backgroundColor: 'rgba(0, 0, 0, 0.9)',
                    titleColor: '#00ff00',
                    bodyColor: '#00ff00',
                    borderColor: '#00ff00',
                    borderWidth: 2,
                    padding: 15,
                    titleFont: { size: 15, weight: 'bold' },
                    bodyFont: { size: 14 },
                    callbacks: {
                        title: (context) => `⚠️ ${context[0].label}`,
                        label: (context) => {
                            const value = context.parsed.x;
                            const pct = ((value / total) * 100).toFixed(1);
                            return [`Detections: ${value}`, `Percentage: ${pct}%`];
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        color: '#00ff00',
                        font: { family: "'Courier New', monospace", weight: 'bold', size: 13 },
                        callback: (value) => value + ''
                    },
                    grid: {
                        color: 'rgba(0, 255, 0, 0.1)',
                        drawBorder: true,
                        borderColor: '#00ff00'
                    }
                },
                y: {
                    ticks: {
                        color: '#00ff00',
                        font: { family: "'Courier New', monospace", size: 12, weight: 'bold' }
                    },
                    grid: {
                        color: 'rgba(0, 255, 0, 0.05)',
                        drawBorder: true
                    }
                }
            }
        }
    });
}

function renderThreatSummaryChart(analysis) {
    const ctx = document.getElementById('log-summary-chart');
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.logChartsInstances.threatSummary) {
        window.logChartsInstances.threatSummary.destroy();
    }
    
    const totalLines = analysis.total_lines || 1;
    const critical = analysis.threat_levels?.critical || 0;
    const high = analysis.threat_levels?.high || 0;
    const medium = analysis.threat_levels?.medium || 0;
    const low = analysis.threat_levels?.low || 0;
    const clean = Math.max(0, totalLines - (critical + high + medium + low));
    
    const criticalPct = ((critical / totalLines) * 100).toFixed(1);
    const highPct = ((high / totalLines) * 100).toFixed(1);
    const mediumPct = ((medium / totalLines) * 100).toFixed(1);
    const lowPct = ((low / totalLines) * 100).toFixed(1);
    const cleanPct = ((clean / totalLines) * 100).toFixed(1);
    
    const threatCount = critical + high + medium + low;
    const threatRiskScore = Math.min(100, Math.round((critical * 25 + high * 15 + medium * 8 + low * 2) / totalLines * 100));
    
    window.logChartsInstances.threatSummary = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [
                `🔴 CRITICAL\n${critical} (${criticalPct}%)`,
                `🟠 HIGH\n${high} (${highPct}%)`,
                `🟡 MEDIUM\n${medium} (${mediumPct}%)`,
                `🟢 LOW\n${low} (${lowPct}%)`,
                `✅ CLEAN\n${clean} (${cleanPct}%)`
            ],
            datasets: [{
                label: 'Log Lines Distribution',
                data: [critical, high, medium, low, clean],
                backgroundColor: [
                    '#ff4444',
                    '#ff8800',
                    '#ffbb00',
                    '#00bb00',
                    '#004400'
                ],
                borderColor: [
                    '#ff0000',
                    '#ff5500',
                    '#ffaa00',
                    '#00aa00',
                    '#003300'
                ],
                borderWidth: 2,
                hoverBackgroundColor: [
                    '#ff6666',
                    '#ffaa33',
                    '#ffdd33',
                    '#33ff33',
                    '#00aa00'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff00',
                        font: { size: 14, weight: 'bold', family: "'Courier New', monospace" },
                        padding: 15
                    }
                },
                title: {
                    display: true,
                    text: `RISK SCORE: ${threatRiskScore}/100 | THREATS: ${threatCount}/${totalLines}`,
                    color: threatRiskScore > 70 ? '#ff4444' : threatRiskScore > 40 ? '#ffbb00' : '#00ff00',
                    font: { size: 15, weight: 'bold', family: "'Courier New', monospace" },
                    padding: 20
                },
                tooltip: {
                    enabled: true,
                    backgroundColor: 'rgba(0, 0, 0, 0.9)',
                    titleColor: '#00ff00',
                    bodyColor: '#00ff00',
                    borderColor: '#00ff00',
                    borderWidth: 2,
                    padding: 15,
                    titleFont: { size: 15, weight: 'bold' },
                    bodyFont: { size: 14 },
                    callbacks: {
                        title: (context) => `${context[0].label.split('\n')[0]}`,
                        label: (context) => {
                            const value = context.parsed.y;
                            const pct = ((value / totalLines) * 100).toFixed(1);
                            return `Lines: ${value} (${pct}% of total)`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#00ff00',
                        font: { family: "'Courier New', monospace", weight: 'bold', size: 13 },
                        callback: (value) => value + ''
                    },
                    grid: {
                        color: 'rgba(0, 255, 0, 0.1)',
                        drawBorder: true,
                        borderColor: '#00ff00'
                    }
                },
                x: {
                    ticks: {
                        color: '#00ff00',
                        font: { family: "'Courier New', monospace", size: 12, weight: 'bold' }
                    },
                    grid: {
                        color: 'rgba(0, 255, 0, 0.05)',
                        drawBorder: true
                    }
                }
            }
        }
    });
}

function clearLogResults() {
    document.getElementById('log-results').classList.add('hidden');
    document.getElementById('log-form').reset();
    document.getElementById('log-filename').style.display = 'none';
    currentLogData = null;
    
    // Destroy charts if they exist
    if (window.logChartsInstances) {
        Object.values(window.logChartsInstances).forEach(chart => {
            if (chart) chart.destroy();
        });
        window.logChartsInstances = {};
    }
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
        const response = await apiRequest(`${API_BASE}/scan-network`, {
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
    
    // List of known suspicious IPs
    const suspiciousIPs = {
        '192.168.1.1': { type: 'Port Scanner', severity: 'MEDIUM' },
        '10.0.0.1': { type: 'Botnet Command', severity: 'HIGH' }
    };
    
    if (hosts && hosts.length > 0) {
        hosts.forEach(host => {
            const item = document.createElement('div');
            item.className = 'host-item';
            
            const ip = host.target || host.ip || 'Unknown';
            const hostname = host.hostname || 'N/A';
            const status = host.alive ? '✓ ALIVE' : '✗ OFFLINE';
            
            // Check if IP is suspicious
            let isSuspicious = false;
            let suspiciousMarker = '';
            if (suspiciousIPs[ip]) {
                isSuspicious = true;
                suspiciousMarker = '⚠️ ';
            }
            
            let portsHtml = '';
            if (host.open_ports && host.open_ports.length > 0) {
                portsHtml = host.open_ports.map(p => `${p.port}/${p.service}`).join(', ');
            }
            
            item.innerHTML = `
                <p><strong>${suspiciousMarker}IP:</strong> ${ip}</p>
                <p><strong>Status:</strong> ${status}</p>
                ${hostname !== 'N/A' ? `<p><strong>Hostname:</strong> ${hostname}</p>` : ''}
                ${portsHtml ? `<p><strong>Open Ports:</strong> ${portsHtml}</p>` : ''}
            `;
            hostsDiv.appendChild(item);
            
            // Show alert for suspicious IP
            if (isSuspicious && host.alive) {
                setTimeout(() => {
                    showAlertModal(
                        ip,
                        suspiciousIPs[ip].type,
                        suspiciousIPs[ip].severity,
                        `Suspicious IP ${ip} detected during network scan with ${portsHtml ? 'open ports: ' + portsHtml : 'no open ports'}`
                    );
                }, 800);
            }
        });
    } else {
        hostsDiv.innerHTML = '<p class="empty-state">No active hosts found</p>';
    }
}

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
        const response = await apiRequest(`${API_BASE}/scan-port`, {
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
    
    // List of known suspicious IPs
    const suspiciousIPs = {
        '192.168.1.1': { type: 'Port Scanner', severity: 'MEDIUM' },
        '10.0.0.1': { type: 'Botnet Command', severity: 'HIGH' }
    };
    
    // Check if the scanned target is suspicious
    const targetIP = results.target;
    if (suspiciousIPs[targetIP]) {
        setTimeout(() => {
            showAlertModal(
                targetIP,
                suspiciousIPs[targetIP].type,
                suspiciousIPs[targetIP].severity,
                `Port scan of suspicious IP ${targetIP} found ${results.open_ports_count} open ports`
            );
        }, 500);
    }
    
    // Display summary
    const summary = document.createElement('div');
    summary.className = 'results-summary';
    summary.innerHTML = `
        <p><strong>${suspiciousIPs[targetIP] ? '⚠️ ' : ''}Target:</strong> ${results.target}</p>
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
        const response = await apiRequest(`${API_BASE}/analyze-packets`, {
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

// Live Packet Capture Form Handler
document.getElementById('capture-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const interfaceSelect = document.getElementById('capture-interface');
    const interface_name = interfaceSelect.value;
    
    if (!interface_name) {
        alert('Please select a network interface');
        return;
    }
    
    const packet_count = parseInt(document.getElementById('capture-count').value) || 50;
    const duration = parseInt(document.getElementById('capture-duration').value) || 30;
    const loading = document.getElementById('capture-loading');
    const results = document.getElementById('capture-results');
    
    loading.classList.remove('hidden');
    if (results) results.classList.add('hidden');
    
    try {
        const response = await fetch(`${API_BASE}/capture-packets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                interface: interface_name,
                count: packet_count,
                duration: duration
            })
        });
        
        const data = await response.json();
        loading.classList.add('hidden');
        
        if (data.status === 'success' || data.packets_captured !== undefined) {
            currentCaptureData = data;
            displayCaptureResults(data);
            if (results) results.classList.remove('hidden');
            updateDashboardStat('packets_analyzed');
        } else {
            const errorMsg = data.error || data.message || 'Unknown error occurred';
            alert('Packet Capture Error:\n' + errorMsg);
        }
    } catch (error) {
        console.error('Capture Error:', error);
        loading.classList.add('hidden');
        alert('Failed to capture packets:\n' + error.message);
    }
});

function displayCaptureResults(data) {
    // Update packet count
    const countEl = document.getElementById('capture-packet-count');
    if (countEl) countEl.textContent = data.packets_captured || 0;
    
    // Display protocol distribution
    const protocols = data.protocols || {};
    const protocolsDiv = document.getElementById('capture-protocols');
    if (protocolsDiv) {
        protocolsDiv.innerHTML = Object.entries(protocols)
            .map(([protocol, count]) => `
                <div class="pattern-item">
                    <span class="pattern-name">${protocol}</span>
                    <span class="pattern-count">${count}</span>
                </div>
            `).join('') || '<p>No protocols captured</p>';
    }
    
    // Display source IPs
    const srcIps = data.src_ips || {};
    const srcDiv = document.getElementById('capture-src-ips');
    if (srcDiv) {
        srcDiv.innerHTML = Object.entries(srcIps).slice(0, 10)
            .map(([ip, count]) => `<div><strong>${ip}</strong>: ${count} packets</div>`)
            .join('') || '<p>No source IPs captured</p>';
    }
    
    // Display destination IPs
    const dstIps = data.dst_ips || {};
    const dstDiv = document.getElementById('capture-dst-ips');
    if (dstDiv) {
        dstDiv.innerHTML = Object.entries(dstIps).slice(0, 10)
            .map(([ip, count]) => `<div><strong>${ip}</strong>: ${count} packets</div>`)
            .join('') || '<p>No destination IPs captured</p>';
    }
    
    // Display detailed packets
    const packets = data.detailed_packets || [];
    const packetsDiv = document.getElementById('capture-detailed-packets');
    if (packetsDiv) {
        packetsDiv.innerHTML = packets.slice(0, 20)
            .map(packet => `
                <div class="packet-item">
                    <strong>${packet.protocol || 'Unknown'}</strong> - 
                    ${packet.src_ip || 'Unknown'} → ${packet.dst_ip || 'Unknown'}
                    ${packet.dns_query ? ` (DNS: ${packet.dns_query})` : ''}
                    <br><small>Size: ${packet.size || 0} bytes</small>
                </div>
            `).join('') || '<p>No packets captured</p>';
    }
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
        const response = await apiRequest(`${API_BASE}/check-ip-reputation`, {
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
        const response = await apiRequest(`${API_BASE}/threat-analysis/${threatType}`, {
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
        const response = await apiRequest(`${API_BASE}/scrape-website`, {
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

// Initialize - Only run if dashboard is visible
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're in dashboard view
    const dashboardContainer = document.getElementById('dashboard-container');
    if (!dashboardContainer || dashboardContainer.classList.contains('hidden')) {
        return; // Don't initialize dashboard functions while on login
    }
    
    initMatrixRain();
    initDashboardStats();
    
    // Load packet interfaces with error handling
    fetch(`${API_BASE}/packet-interfaces`)
        .then(r => r.json())
        .then(data => {
            const select = document.getElementById('capture-interface');
            if (select) {
                select.innerHTML = '';
                
                if (data.interfaces && data.interfaces.length > 0) {
                    // Add default option
                    const defaultOption = document.createElement('option');
                    defaultOption.value = '';
                    defaultOption.textContent = '-- Select Network Interface --';
                    defaultOption.disabled = true;
                    defaultOption.selected = true;
                    select.appendChild(defaultOption);
                    
                    // Add available interfaces
                    data.interfaces.forEach(iface => {
                        const option = document.createElement('option');
                        option.value = iface;
                        option.textContent = iface;
                        select.appendChild(option);
                    });
                    
                    // Remove loading text
                    const loadingOption = select.querySelector('option[disabled][selected]');
                    if (loadingOption && loadingOption.textContent.includes('Loading')) {
                        loadingOption.remove();
                    }
                } else {
                    // No interfaces found - provide help
                    const helpOption = document.createElement('option');
                    helpOption.value = '';
                    helpOption.textContent = '❌ No interfaces detected';
                    helpOption.disabled = true;
                    select.appendChild(helpOption);
                }
            }
        })
        .catch(err => {
            console.log('Packet interfaces unavailable:', err);
            const select = document.getElementById('capture-interface');
            if (select) {
                select.innerHTML = '';
                const errorOption = document.createElement('option');
                errorOption.value = '';
                errorOption.textContent = '⚠️ Backend not running - Start Python backend first';
                errorOption.disabled = true;
                select.appendChild(errorOption);
            }
        });
});

function updateDashboardStats() {
    apiRequest(`${API_BASE}/dashboard-stats`)
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

// Show dashboard after login
function showDashboard() {
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    
    if (loginContainer) {
        loginContainer.classList.add('hidden');
    }
    if (dashboardContainer) {
        dashboardContainer.classList.remove('hidden');
        
        // Initialize dashboard
        initMatrixRain();
        initDashboardStats();
        
        // Load packet interfaces immediately
        loadPacketInterfaces();
        
        // Trigger dashboard loaded event to start auto-packet capture
        document.dispatchEvent(new Event('dashboardLoaded'));
    }
}

// New function to load packet interfaces
function loadPacketInterfaces() {
    const captureInterface = document.getElementById('capture-interface');
    if (!captureInterface) return;
    
    fetch(`${API_BASE}/packet-interfaces`)
        .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        })
        .then(data => {
            if (data.interfaces && data.interfaces.length > 0) {
                // Clear dropdown completely
                captureInterface.innerHTML = '';
                
                // Add each interface
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    captureInterface.appendChild(option);
                });
                
                console.log('Packet interfaces loaded successfully:', data.interfaces);
            } else {
                captureInterface.innerHTML = '<option value="">No interfaces available</option>';
                console.warn('No packet interfaces available from backend');
            }
        })
        .catch(err => {
            console.error('Failed to load packet interfaces:', err);
            captureInterface.innerHTML = '<option value="">Error loading interfaces</option>';
        });
}

// Logout function
function logout() {
    // Clear stored authentication
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    
    // Show login and hide dashboard
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    
    if (loginContainer) {
        loginContainer.classList.remove('hidden');
    }
    if (dashboardContainer) {
        dashboardContainer.classList.add('hidden');
    }
    
    // Reset dashboard stats
    dashboardStats = {
        logs_processed: 0,
        threats_detected: 0,
        networks_scanned: 0,
        packets_analyzed: 0
    };
    
    // Reset form
    if (window.authController) {
        window.authController.loginForm.reset();
        window.authController.signupForm.reset();
    }
}

// ==================== LIVE PACKET CAPTURE AUTO-START ====================

// Auto-start packet capture when dashboard is shown
let autoCapture = {
    isRunning: false,
    interval: null,
    capturedPackets: [],
    googleSearchDetected: false
};

// Monitor browser network requests for Google searches
function monitorBrowserNetworkActivity() {
    // Intercept fetch requests
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        const url = args[0];
        if (typeof url === 'string' && (
            url.includes('google.com') || 
            url.includes('search?') || 
            url.includes('accounts.google')
        )) {
            console.log('Google search/activity detected:', url);
            triggerGoogleActivityCapture();
        }
        return originalFetch.apply(this, args);
    };
}

function triggerGoogleActivityCapture() {
    // When Google activity is detected, capture current packets
    if (currentCaptureData && currentCaptureData.detailed_packets) {
        const googlePackets = currentCaptureData.detailed_packets.filter(packet => {
            const isGoogle = packet.dns_query && (
                packet.dns_query.toLowerCase().includes('google') ||
                packet.dns_query.toLowerCase().includes('search')
            );
            return isGoogle;
        });
        
        if (googlePackets.length > 0) {
            showGoogleSearchNotification(googlePackets);
        }
    }
}

// Function to show notification when Google search is detected
function showGoogleSearchNotification(packets) {
    const notification = document.createElement('div');
    notification.id = 'google-search-notification';
    notification.style.cssText = `
        position: fixed;
        top: 120px;
        right: 20px;
        background: linear-gradient(135deg, #ff6b35 0%, #ff4500 100%);
        color: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 0 20px rgba(255, 107, 53, 0.6);
        z-index: 1000;
        font-size: 14px;
        font-weight: bold;
        animation: slideIn 0.5s ease-out;
        max-width: 350px;
    `;
    
    const packetCount = packets.length;
    const dnsQueries = packets.map(p => p.dns_query).filter(Boolean).join(', ');
    
    notification.innerHTML = `
        <div style="margin-bottom: 10px;">🔍 GOOGLE SEARCH DETECTED</div>
        <div style="font-size: 12px; margin-bottom: 8px;">
            <strong>Packets Captured:</strong> ${packetCount}
        </div>
        <div style="font-size: 11px; color: #ffe0cc; word-break: break-word; margin-bottom: 8px;">
            <strong>DNS Queries:</strong><br>${dnsQueries}
        </div>
        <div style="display: flex; gap: 10px;">
            <button onclick="switchToPacketAnalysis()" style="flex: 1; padding: 8px; background: #ff8c42; border: none; color: white; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: bold;">View Packets</button>
            <button onclick="dismissNotification('google-search-notification')" style="flex: 1; padding: 8px; background: rgba(255,255,255,0.2); border: 1px solid white; color: white; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: bold;">Dismiss</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-dismiss after 10 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOut 0.5s ease-in forwards';
            setTimeout(() => notification.remove(), 500);
        }
    }, 10000);
}

function switchToPacketAnalysis() {
    showTab('packet-analysis');
    dismissNotification('google-search-notification');
}

function dismissNotification(id) {
    const notification = document.getElementById(id);
    if (notification) {
        notification.style.animation = 'slideOut 0.5s ease-in forwards';
        setTimeout(() => notification.remove(), 500);
    }
}

// Add CSS animations if not already present
function addNotificationStyles() {
    if (!document.querySelector('style[data-notification]')) {
        const style = document.createElement('style');
        style.setAttribute('data-notification', 'true');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(400px);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
}

// Initialize auto-packet capture on dashboard load
document.addEventListener('dashboardLoaded', () => {
    addNotificationStyles();
    startAutoPacketCapture();
});

function startAutoPacketCapture() {
    if (autoCapture.isRunning) return;
    
    autoCapture.isRunning = true;
    
    // Load available interfaces and start capture
    fetch(`${API_BASE}/packet-interfaces`)
        .then(res => res.json())
        .then(data => {
            if (data.interfaces && data.interfaces.length > 0) {
                // Auto-select first available interface
                const selectedInterface = data.interfaces[0];
                
                // Start capture with moderate settings
                performAutoCapture(selectedInterface);
            }
        })
        .catch(err => console.log('Could not start auto packet capture:', err));
}

function performAutoCapture(interfaceName) {
    // Capture packets in the background
    fetch(`${API_BASE}/capture-packets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            interface: interfaceName,
            count: 100,
            duration: 60
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            currentCaptureData = data;
            
            // Check for Google search activity in captured packets
            if (data.detailed_packets && data.detailed_packets.length > 0) {
                const googlePackets = data.detailed_packets.filter(packet => {
                    const query = packet.dns_query || '';
                    return query.toLowerCase().includes('google') || 
                           query.toLowerCase().includes('search');
                });
                
                if (googlePackets.length > 0) {
                    console.log(`Detected ${googlePackets.length} Google-related packets`);
                    showGoogleSearchNotification(googlePackets);
                }
            }
            
            // Continue capturing in intervals
            if (autoCapture.isRunning) {
                setTimeout(() => {
                    performAutoCapture(interfaceName);
                }, 65000); // Restart capture after 65 seconds
            }
        }
    })
    .catch(err => console.log('Auto capture error:', err));
}

function stopAutoPacketCapture() {
    autoCapture.isRunning = false;
    if (autoCapture.interval) {
        clearInterval(autoCapture.interval);
    }
}
