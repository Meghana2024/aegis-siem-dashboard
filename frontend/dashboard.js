// State variables
const BACKEND_URL = "http://127.0.0.1:5000";
let sseSource = null;
let streamPaused = false;

// Chart references
let trafficChart = null;
let alertPieChart = null;
let protocolBarChart = null;
let vulnChart = null;

// Cumulative counts for charts
let packetHistory = Array(30).fill(0);
let timeLabels = Array(30).fill("");
let protocolCounts = { TCP: 0, UDP: 0, ICMP: 0 };
let alertCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

// Radar map active threats
let mapThreats = [];

// Initialize everything on DOM Load
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initCharts();
    initRadarMap();
    connectSSE();
    setupEventListeners();
    fetchInitialStatus();
});

// 1. TABS MANAGEMENT
function initTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.tab;
            
            tabButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(target).classList.add("active");
        });
    });

    // Scanner Results Tabs
    const resTabButtons = document.querySelectorAll(".results-tab-btn");
    const resSubpanels = document.querySelectorAll(".results-subpanel");

    resTabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.resTab;
            
            resTabButtons.forEach(b => b.classList.remove("active"));
            resSubpanels.forEach(s => s.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(target).classList.add("active");
        });
    });
}

// 2. CHART.JS CONFIGURATIONS
function initCharts() {
    // Traffic Chart (Line)
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [{
                label: 'Throughput (Packets/Sec)',
                data: packetHistory,
                borderColor: '#00f0ff',
                backgroundColor: 'rgba(0, 240, 255, 0.05)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8', font: { size: 9 } } },
                y: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8', font: { size: 9 } } }
            }
        }
    });

    // Alerts Pie Chart
    const ctxPie = document.getElementById('alertPieChart').getContext('2d');
    alertPieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#ff0055', '#ffaa00', '#00f0ff', '#ae00ff'],
                borderColor: '#060913',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#e2e8f0', font: { size: 10 } }
                }
            },
            cutout: '60%'
        }
    });

    // Protocol Horizontal Bar Chart
    const ctxBar = document.getElementById('protocolBarChart').getContext('2d');
    protocolBarChart = new Chart(ctxBar, {
        type: 'bar',
        data: {
            labels: ['TCP', 'UDP', 'ICMP'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['rgba(0, 240, 255, 0.65)', 'rgba(189, 0, 255, 0.65)', 'rgba(255, 170, 0, 0.65)'],
                borderColor: ['#00f0ff', '#ae00ff', '#ffaa00'],
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.02)' }, ticks: { color: '#94a3b8', font: { size: 9 } } },
                y: { grid: { display: false }, ticks: { color: '#e2e8f0', font: { size: 9 } } }
            }
        }
    });

    // Scanner Severity Chart
    const ctxVuln = document.getElementById('vulnSeverityChart').getContext('2d');
    vulnChart = new Chart(ctxVuln, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#ff0055', '#ffaa00', '#00f0ff', '#ae00ff'],
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 9 } } },
                y: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8', font: { size: 9 } } }
            }
        }
    });
}

// 3. TACTICAL RADAR MAP SIMULATOR
function initRadarMap() {
    const canvas = document.getElementById("threat-map-canvas");
    const ctx = canvas.getContext("2d");
    
    // Fit canvas resolution to parent
    function resizeCanvas() {
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height;
    }
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    let angle = 0;

    // Animation Loop
    function drawRadar() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        const radius = Math.min(cx, cy) * 0.9;
        
        // Draw concentric circles
        ctx.strokeStyle = "rgba(0, 240, 255, 0.08)";
        ctx.lineWidth = 1;
        for (let r = 0.2; r <= 1.0; r += 0.2) {
            ctx.beginPath();
            ctx.arc(cx, cy, radius * r, 0, Math.PI * 2);
            ctx.stroke();
        }
        
        // Crosshairs
        ctx.beginPath();
        ctx.moveTo(cx - radius, cy);
        ctx.lineTo(cx + radius, cy);
        ctx.moveTo(cx, cy - radius);
        ctx.lineTo(cx, cy + radius);
        ctx.stroke();
        
        // Sweep Line (Radar sweep)
        angle += 0.015;
        const sweepX = cx + Math.cos(angle) * radius;
        const sweepY = cy + Math.sin(angle) * radius;
        
        let grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, radius);
        grad.addColorStop(0, "rgba(0, 240, 255, 0.02)");
        grad.addColorStop(1, "rgba(0, 240, 255, 0.15)");
        
        ctx.strokeStyle = "rgba(0, 240, 255, 0.35)";
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(sweepX, sweepY);
        ctx.stroke();
        
        // Draw threat locations & vectors
        mapThreats.forEach((t, index) => {
            // Map lat/lon to radar coordinates
            // lat: [-90, 90] mapped to Y, lon: [-180, 180] mapped to X
            const x = cx + (t.lon / 180) * radius;
            const y = cy - (t.lat / 90) * radius; // inverted Y axis
            
            // Draw path curve from threat to center server
            ctx.strokeStyle = t.severity === "Critical" ? "rgba(255, 0, 85, 0.25)" : "rgba(255, 170, 0, 0.25)";
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.moveTo(x, y);
            // Draw curve arc
            const ctrlX = (x + cx) / 2;
            const ctrlY = (y + cy) / 2 - 50;
            ctx.quadraticCurveTo(ctrlX, ctrlY, cx, cy);
            ctx.stroke();
            
            // Draw attacker node point
            const age = Date.now() - t.timestamp;
            const decay = Math.max(0, 1 - age / 15000); // 15 second decay
            
            if (decay <= 0) {
                mapThreats.splice(index, 1);
                return;
            }
            
            // Attacker Node Glow
            ctx.fillStyle = t.severity === "Critical" ? `rgba(255, 0, 85, ${decay})` : `rgba(255, 170, 0, ${decay})`;
            ctx.beginPath();
            ctx.arc(x, y, 6, 0, Math.PI * 2);
            ctx.fill();
            
            // Pinging pulse
            const pulseRadius = 6 + (1 - decay) * 20;
            ctx.strokeStyle = t.severity === "Critical" ? `rgba(255, 0, 85, ${decay * 0.4})` : `rgba(255, 170, 0, ${decay * 0.4})`;
            ctx.beginPath();
            ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
            ctx.stroke();
            
            // Label
            ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
            ctx.font = "8px 'Share Tech Mono'";
            ctx.fillText(`${t.ip} (${t.location})`, x + 10, y - 4);
        });

        // Center Host (Local Shield Logo target)
        ctx.fillStyle = "#00f0ff";
        ctx.shadowColor = "#00f0ff";
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(cx, cy, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0; // reset shadow
        
        ctx.fillStyle = "#fff";
        ctx.font = "8px 'Outfit'";
        ctx.fillText("AEGIS HOST", cx - 22, cy - 10);
        
        requestAnimationFrame(drawRadar);
    }
    
    requestAnimationFrame(drawRadar);
    
    // Mouse hover coordinates overlay
    canvas.addEventListener("mousemove", (e) => {
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        
        // Reverse mapping to estimated Lat/Lon coordinates
        const radius = Math.min(cx, cy) * 0.9;
        const lon = (((x - cx) / radius) * 180).toFixed(4);
        const lat = (((cy - y) / radius) * 90).toFixed(4);
        
        if (Math.abs(x - cx) < radius && Math.abs(y - cy) < radius) {
            document.getElementById("map-coords").innerText = `LOCATOR: LAT ${lat} | LON ${lon}`;
        } else {
            document.getElementById("map-coords").innerText = `CURSOR: OFF-MAP`;
        }
    });
}

// 4. WEBSOCKET / SSE STREAM LISTENER
function connectSSE() {
    if (sseSource) {
        sseSource.close();
    }

    sseSource = new EventSource(`${BACKEND_URL}/api/stream`);

    // Helper: calculate packets/sec
    let intervalPacketCount = 0;
    setInterval(() => {
        // Shift history left
        packetHistory.shift();
        packetHistory.push(intervalPacketCount);
        
        timeLabels.shift();
        let timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        timeLabels.push(timeStr);
        
        // Update Chart
        trafficChart.data.datasets[0].data = packetHistory;
        trafficChart.data.labels = timeLabels;
        trafficChart.update('none'); // silent update
        
        // Update current throughput meter
        document.getElementById("stat-pps").innerText = intervalPacketCount;
        
        intervalPacketCount = 0;
    }, 1000);

    sseSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // 1. Process Raw Packets
        if (data.packets && !streamPaused) {
            intervalPacketCount += data.packets.length;
            const currentTotal = parseInt(document.getElementById("stat-packets").innerText);
            document.getElementById("stat-packets").innerText = currentTotal + data.packets.length;
            
            const tbody = document.getElementById("packet-stream-body");
            
            // Remove placeholder row if present
            const placeholder = tbody.querySelector(".placeholder-row");
            if (placeholder) {
                placeholder.remove();
            }
            
            data.packets.forEach(pkt => {
                // Increment Protocol count
                if (protocolCounts[pkt.protocol] !== undefined) {
                    protocolCounts[pkt.protocol]++;
                }
                
                // Construct Row
                const row = document.createElement("tr");
                const timeFormatted = new Date(pkt.timestamp * 1000).toLocaleTimeString([], { hour12: false });
                
                // Highlight red if flags/ports are malicious (simplistic display rule)
                const isThreatPort = [21, 22, 3306, 6200].includes(pkt.dst_port);
                const flagClass = pkt.flags.includes("SYN") || isThreatPort ? "alert-flag" : "";
                const rowHighlight = isThreatPort ? 'style="background: rgba(255, 0, 85, 0.02)"' : '';
                
                row.innerHTML = `
                    <td>${timeFormatted}</td>
                    <td>${pkt.src_ip}</td>
                    <td>${pkt.dst_ip}</td>
                    <td><span class="proto-tag ${pkt.protocol.toLowerCase()}">${pkt.protocol}</span></td>
                    <td>${pkt.dst_port}</td>
                    <td class="flag-tag ${flagClass}">${pkt.flags}</td>
                    <td title="${pkt.payload || ''}">${pkt.payload || '-'}</td>
                `;
                
                tbody.insertBefore(row, tbody.firstChild);
            });
            
            // Cap table rows at 60 to prevent browser slowdown
            while (tbody.children.length > 60) {
                tbody.lastChild.remove();
            }
            
            // Update Protocol Chart
            protocolBarChart.data.datasets[0].data = [protocolCounts.TCP, protocolCounts.UDP, protocolCounts.ICMP];
            protocolBarChart.update('none');
        }
        
        // 2. Process Alerts & Security Anomalies
        if (data.alerts) {
            const currentTotalAlerts = parseInt(document.getElementById("stat-alerts").innerText);
            document.getElementById("stat-alerts").innerText = currentTotalAlerts + data.alerts.length;
            
            data.alerts.forEach(alert => {
                // Increment alert metrics
                if (alertCounts[alert.severity] !== undefined) {
                    alertCounts[alert.severity]++;
                }
                
                // Display Incident Feed card
                addAlertToFeed(alert);
                
                // Show Popup Toast
                showToast(alert);
                
                // Add to tactical radar map if coordinates exist
                if (alert.latitude && alert.longitude) {
                    mapThreats.push({
                        ip: alert.src_ip,
                        location: alert.location,
                        lat: alert.latitude,
                        lon: alert.longitude,
                        severity: alert.severity,
                        timestamp: Date.now()
                    });
                    
                    // Add to map legend sidebar
                    addTelemetryItem(alert);
                }
            });
            
            // Update Alerts Pie Chart
            alertPieChart.data.datasets[0].data = [
                alertCounts.Critical,
                alertCounts.High,
                alertCounts.Medium,
                alertCounts.Low
            ];
            alertPieChart.update();
        }

        // 3. Update global threat level status text
        if (data.threat_level) {
            updateThreatLevelUI(data.threat_level);
        }
    };

    sseSource.onerror = (err) => {
        console.error("SSE Connection broken. Reconnecting...", err);
        document.getElementById("engine-status-lbl").innerText = "OFFLINE";
        document.getElementById("engine-status-lbl").className = "text-red";
        setTimeout(connectSSE, 3000);
    };
}

// Helper: Add alarm to feed list
function addAlertToFeed(alert) {
    const feed = document.getElementById("alerts-feed-container");
    
    // Remove placeholder
    const placeholder = feed.querySelector(".empty-feed-placeholder");
    if (placeholder) {
        placeholder.remove();
    }
    
    const card = document.createElement("div");
    card.className = `alert-card ${alert.severity.toLowerCase()}`;
    
    let detailsHTML = "";
    if (alert.details && Object.keys(alert.details).length > 0) {
        detailsHTML = `<div class="alert-details-box">PAYLOAD SIGNATURE METADATA: ${JSON.stringify(alert.details)}</div>`;
    }
    
    card.innerHTML = `
        <div class="alert-card-header">
            <div class="alert-title-block">
                <span class="alert-badge">${alert.severity}</span>
                <span class="alert-title">${alert.alert_type}</span>
            </div>
            <span class="alert-time">${alert.timestamp}</span>
        </div>
        <p class="alert-desc">${alert.description}</p>
        <div class="alert-meta">
            <span>SOURCE IP: <b>${alert.src_ip}</b></span>
            <span>PORT: <b>${alert.src_port}</b></span>
            <span>TARGET IP: <b>${alert.dst_ip}</b></span>
            <span>TARGET PORT: <b>${alert.dst_port}</b></span>
            <span>PROTOCOL: <b>${alert.protocol}</b></span>
            <span>LOCATION: <b>${alert.location}</b></span>
        </div>
        ${detailsHTML}
    `;
    
    feed.insertBefore(card, feed.firstChild);
    
    // Cap feed items at 50
    while (feed.children.length > 50) {
        feed.lastChild.remove();
    }
}

// Helper: Display Alert Toast Popup
function showToast(alert) {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    
    let typeClass = "info";
    let iconClass = "fa-circle-info";
    
    if (alert.severity === "Critical") {
        typeClass = "crit";
        iconClass = "fa-radiation";
    } else if (alert.severity === "High") {
        typeClass = "warn";
        iconClass = "fa-triangle-exclamation";
    }
    
    toast.className = `toast ${typeClass}`;
    toast.innerHTML = `
        <i class="fa-solid ${iconClass} toast-icon"></i>
        <div class="toast-content">
            <h5>${alert.alert_type} (${alert.severity})</h5>
            <p>${alert.description}</p>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// Helper: Add item to map telemetry log
function addTelemetryItem(alert) {
    const log = document.getElementById("map-telemetry-feed");
    
    // Remove placeholder
    const placeholder = log.querySelector(".telemetry-placeholder");
    if (placeholder) {
        placeholder.remove();
    }
    
    const item = document.createElement("div");
    const isCrit = alert.severity === "Critical";
    item.className = `map-telemetry-item ${isCrit ? 'crit' : 'warn'}`;
    
    item.innerHTML = `
        [ALERT] IP: <b>${alert.src_ip}</b><br>
        LOC: ${alert.location}<br>
        LAT: ${alert.latitude.toFixed(2)} / LON: ${alert.longitude.toFixed(2)}<br>
        TYPE: <span class="${isCrit ? 'text-red' : 'text-yellow'}">${alert.alert_type}</span>
    `;
    
    log.insertBefore(item, log.firstChild);
    
    // Cap items
    while (log.children.length > 10) {
        log.lastChild.remove();
    }
}

// Helper: updates main threat indicator banner colors
function updateThreatLevelUI(level) {
    const badge = document.getElementById("global-threat-level");
    badge.innerText = `THREAT LEVEL: ${level}`;
    badge.className = "threat-level-badge"; // reset classes
    
    if (level === "CRITICAL") {
        badge.classList.add("critical");
    } else if (level === "HIGH") {
        badge.classList.add("high");
    } else if (level === "MEDIUM") {
        badge.classList.add("medium");
    }
}

// 5. VULNERABILITY SCANNER REQUEST HANDLER
function setupEventListeners() {
    // Port stream control buttons
    document.getElementById("pause-stream-btn").addEventListener("click", (e) => {
        streamPaused = !streamPaused;
        const btn = e.currentTarget;
        if (streamPaused) {
            btn.innerHTML = `<i class="fa-solid fa-play"></i> Resume`;
            btn.className = "action-btn text-green";
        } else {
            btn.innerHTML = `<i class="fa-solid fa-pause"></i> Pause`;
            btn.className = "action-btn text-cyan";
        }
    });

    document.getElementById("clear-stream-btn").addEventListener("click", () => {
        const tbody = document.getElementById("packet-stream-body");
        tbody.innerHTML = `
            <tr class="placeholder-row">
                <td colspan="7">Awaiting packet stream logs...</td>
            </tr>
        `;
        protocolCounts = { TCP: 0, UDP: 0, ICMP: 0 };
        protocolBarChart.data.datasets[0].data = [0, 0, 0];
        protocolBarChart.update();
    });

    document.getElementById("clear-alerts-btn").addEventListener("click", () => {
        const feed = document.getElementById("alerts-feed-container");
        feed.innerHTML = `
            <div class="empty-feed-placeholder">
                <i class="fa-solid fa-circle-check text-green"></i>
                <p>No security anomalies detected. System secure.</p>
            </div>
        `;
        document.getElementById("stat-alerts").innerText = "0";
        alertCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        alertPieChart.data.datasets[0].data = [0, 0, 0, 0];
        alertPieChart.update();
        
        // Clear map log too
        document.getElementById("map-telemetry-feed").innerHTML = `<div class="telemetry-placeholder">No external attack signatures geolocated.</div>`;
        mapThreats = [];
    });

    // Preset scan buttons
    document.querySelectorAll(".preset-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.getElementById("scan-ip").value = e.target.dataset.ip;
        });
    });

    // Scanner Submit
    const scanForm = document.getElementById("scan-form");
    scanForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const targetIp = document.getElementById("scan-ip").value.trim();
        if (!targetIp) return;
        
        triggerScan(targetIp);
    });

    // Simulator Trigger Buttons
    document.querySelectorAll(".sim-trigger-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const attackType = e.target.dataset.attack;
            fetch(`${BACKEND_URL}/api/trigger`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ attack_type: attackType })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    showUINotification("Sandbox Engine Active", data.message, attackType === "none" ? "info" : "warn");
                }
            })
            .catch(err => console.error("Error triggering simulator attack:", err));
        });
    });

    // IDS Config Apply Parameters
    const idsForm = document.getElementById("ids-config-form");
    idsForm.addEventListener("submit", (e) => {
        e.preventDefault();
        
        const configData = {
            ddos_threshold: document.getElementById("cfg-ddos-th").value,
            port_scan_threshold: document.getElementById("cfg-scan-th").value,
            brute_force_threshold: document.getElementById("cfg-bf-th").value,
            enabled_signatures: {
                sqli: document.getElementById("cfg-sig-sqli").checked,
                xss: document.getElementById("cfg-sig-xss").checked,
                path_traversal: document.getElementById("cfg-sig-pt").checked,
                malicious_dns: document.getElementById("cfg-sig-dns").checked
            }
        };

        fetch(`${BACKEND_URL}/api/config`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(configData)
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                showUINotification("Rules Confirmed", "IDS thresholds and patterns updated.", "info");
            }
        })
        .catch(err => console.error("Error saving rules parameters:", err));
    });
}

// Local UI Toast Utility for Custom updates
function showUINotification(title, msg, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    
    let iconClass = "fa-circle-info";
    if (type === "crit") iconClass = "fa-radiation";
    else if (type === "warn") iconClass = "fa-triangle-exclamation";
    
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fa-solid ${iconClass} toast-icon"></i>
        <div class="toast-content">
            <h5>${title}</h5>
            <p>${msg}</p>
        </div>
    `;
    container.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 5000);
}

// Active scanning function
function triggerScan(targetIp) {
    const scanBtn = document.getElementById("run-scan-btn");
    const progressPanel = document.getElementById("scan-status-panel");
    const progressFill = document.getElementById("scan-progress-fill");
    const progressText = document.getElementById("scan-status-text");
    const percentText = document.getElementById("scan-percent-text");
    const summaryPanel = document.getElementById("vuln-summary-panel");
    
    // Reset and Show Progress panel
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<i class="fa-solid fa-radar fa-spin"></i> AUDITING...`;
    scanBtn.classList.add("scanning");
    
    progressPanel.classList.remove("hidden");
    summaryPanel.classList.add("hidden");
    progressFill.style.width = "0%";
    percentText.innerText = "0%";
    progressText.innerText = `Establishing mapping for target ${targetIp}...`;
    
    // Start dummy intervals for progress bar visual feedback
    let fakeProgress = 0;
    const progressTimer = setInterval(() => {
        if (fakeProgress < 90) {
            fakeProgress += Math.floor(Math.random() * 8) + 2;
            fakeProgress = Math.min(fakeProgress, 90);
            progressFill.style.width = `${fakeProgress}%`;
            percentText.innerText = `${fakeProgress}%`;
            
            if (fakeProgress > 60) {
                progressText.innerText = "Banner grabbing services and cross-referencing CVE database...";
            } else if (fakeProgress > 30) {
                progressText.innerText = "Connecting target host TCP sockets...";
            }
        }
    }, 150);

    // Call API scan endpoint
    fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_ip: targetIp })
    })
    .then(res => res.json())
    .then(results => {
        clearInterval(progressTimer);
        
        // Push progress to 100%
        progressFill.style.width = "100%";
        percentText.innerText = "100%";
        progressText.innerText = `Scan completed for target host!`;
        
        setTimeout(() => {
            progressPanel.classList.add("hidden");
            scanBtn.disabled = false;
            scanBtn.innerHTML = `<i class="fa-solid fa-radar"></i> INITIALIZE SCAN`;
            scanBtn.classList.remove("scanning");
            
            renderScanResults(results);
        }, 500);
    })
    .catch(err => {
        clearInterval(progressTimer);
        console.error("Scanning request failed:", err);
        progressText.innerText = "ERROR: Scan request failed.";
        scanBtn.disabled = false;
        scanBtn.innerHTML = `<i class="fa-solid fa-radar"></i> INITIALIZE SCAN`;
        scanBtn.classList.remove("scanning");
    });
}

function renderScanResults(results) {
    const summaryPanel = document.getElementById("vuln-summary-panel");
    summaryPanel.classList.remove("hidden");
    
    // Fill stats counts
    document.getElementById("count-critical").innerText = results.summary.critical;
    document.getElementById("count-high").innerText = results.summary.high;
    document.getElementById("count-medium").innerText = results.summary.medium;
    document.getElementById("count-low").innerText = results.summary.low;
    
    // Update chart
    vulnChart.data.datasets[0].data = [
        results.summary.critical,
        results.summary.high,
        results.summary.medium,
        results.summary.low
    ];
    vulnChart.update();
    
    // RENDER PORTS TABLE
    const portsBody = document.getElementById("scan-ports-body");
    portsBody.innerHTML = "";
    
    if (results.open_ports.length === 0) {
        portsBody.innerHTML = `<tr><td colspan="4" class="no-data">Scan finished. No open ports identified.</td></tr>`;
    } else {
        results.open_ports.forEach(item => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td><b>${item.port}</b></td>
                <td><span class="proto-tag tcp">${item.service.toUpperCase()}</span></td>
                <td><span class="text-green">${item.state.toUpperCase()}</span></td>
                <td>${item.banner || '-'}</td>
            `;
            portsBody.appendChild(row);
        });
    }
    
    // RENDER VULNERABILITIES LIST
    const vulnList = document.getElementById("scan-vuln-list");
    vulnList.innerHTML = "";
    
    if (results.vulnerabilities.length === 0) {
        vulnList.innerHTML = `
            <div class="no-data-msg">
                <i class="fa-solid fa-shield-halved text-green"></i>
                <p>Perfect score! No known CVE matching vulnerabilities detected.</p>
            </div>
        `;
    } else {
        results.vulnerabilities.forEach(v => {
            const card = document.createElement("div");
            card.className = `vuln-item ${v.severity.toLowerCase()}`;
            
            card.innerHTML = `
                <div class="vuln-item-header">
                    <span class="vuln-item-title">${v.title}</span>
                    <span class="vuln-item-cvss">CVSS ${v.cvss.toFixed(1)} (${v.severity})</span>
                </div>
                <div class="vuln-item-meta">
                    <span>CVE: <b>${v.cve}</b></span>
                    <span>PORT: <b>${v.port}</b></span>
                    <span>SERVICE: <b>${v.service.toUpperCase()}</b></span>
                </div>
                <p class="vuln-item-desc">${v.description}</p>
                <div class="vuln-item-mitigation">
                    <b>RECOMMENDED MITIGATION:</b><br>${v.mitigation}
                </div>
            `;
            vulnList.appendChild(card);
        });
    }
}

// 6. INITIAL STATUS LOADER
function fetchInitialStatus() {
    fetch(`${BACKEND_URL}/api/status`)
    .then(res => res.json())
    .then(data => {
        document.getElementById("stat-sim").innerText = data.simulation ? "ACTIVE" : "OFFLINE";
        document.getElementById("engine-status-lbl").innerText = "ONLINE";
        document.getElementById("engine-status-lbl").className = "text-green";
        
        // Fill initial IDS parameters
        document.getElementById("cfg-ddos-th").value = data.rules.ddos_threshold;
        document.getElementById("cfg-scan-th").value = data.rules.port_scan_threshold;
        document.getElementById("cfg-bf-th").value = data.rules.brute_force_threshold;
        document.getElementById("cfg-sig-sqli").checked = data.rules.enabled_signatures.sqli;
        document.getElementById("cfg-sig-xss").checked = data.rules.enabled_signatures.xss;
        document.getElementById("cfg-sig-pt").checked = data.rules.enabled_signatures.path_traversal;
        document.getElementById("cfg-sig-dns").checked = data.rules.enabled_signatures.malicious_dns;
        
        updateThreatLevelUI(data.threat_level);
    })
    .catch(err => {
        console.error("Could not fetch engine status", err);
        document.getElementById("engine-status-lbl").innerText = "OFFLINE";
        document.getElementById("engine-status-lbl").className = "text-red";
    });
}
