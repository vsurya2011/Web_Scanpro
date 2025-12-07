document.addEventListener('DOMContentLoaded', () => {
    
    // --- 1. THEME TOGGLE ---
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) {
        const body = document.body;
        const icon = themeBtn.querySelector('i');
        themeBtn.addEventListener('click', () => {
            body.classList.toggle('dark-mode');
            if (body.classList.contains('dark-mode')) {
                icon.classList.replace('fa-moon', 'fa-sun');
            } else {
                icon.classList.replace('fa-sun', 'fa-moon');
            }
        });
    }

    // --- 2. NAVIGATION ---
    const navLinks = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.page-section');
    window.navigateTo = (id) => switchPage(id);

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            switchPage(link.getAttribute('data-target'));
        });
    });

    function switchPage(targetId) {
        sections.forEach(sec => sec.classList.remove('active'));
        navLinks.forEach(nav => nav.classList.remove('active'));
        
        const targetSection = document.getElementById(targetId);
        if(targetSection) targetSection.classList.add('active');
        
        const activeNav = document.querySelector(`.nav-item[data-target="${targetId}"]`);
        if (activeNav) activeNav.classList.add('active');
    }

    // --- 3. VULNERABILITY DATABASE ---
    const vulnDatabase = {
        sqli: [
            { type: "SQL Injection", technique: "Payload Injector", param: "id=1' OR '1'='1", sev: "Critical" },
            { type: "Blind SQLi", technique: "Time-Based Analysis", param: "user_id=sleep(10)", sev: "High" },
            { type: "Union Based SQLi", technique: "Union Select Testing", param: "category=-1 UNION SELECT 1,version()", sev: "Critical" }
        ],
        xss: [
            { type: "Reflected XSS", technique: "Script Injection", param: "q=<script>alert(1)</script>", sev: "High" },
            { type: "Stored XSS", technique: "DOM Analysis", param: "comment=<b>payload</b>", sev: "Critical" },
            { type: "DOM XSS", technique: "Source Sink Analysis", param: "location.hash", sev: "Medium" }
        ],
        auth: [
            { type: "Weak Password", technique: "Brute Force Simulation", param: "/admin/login", sev: "High" },
            { type: "Missing 2FA", technique: "Login Analysis", param: "/login", sev: "Medium" },
            { type: "Session Fixation", technique: "Token Validator", param: "PHPSESSID", sev: "High" }
        ],
        idor: [
            { type: "IDOR", technique: "Access Control Check", param: "/api/users/105", sev: "High" },
            { type: "Privilege Escalation", technique: "Role Manipulation", param: "/admin/settings", sev: "Critical" }
        ]
    };

    // --- 4. SIMULATION UTILITIES ---
    function generateHash(string) {
        let hash = 0;
        if (string.length === 0) return hash;
        for (let i = 0; i < string.length; i++) {
            const char = string.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash);
    }

    function seededRandom(seed) {
        const x = Math.sin(seed++) * 10000;
        return x - Math.floor(x);
    }

    let currentScanResults = []; 

    // --- 5. SCANNING ENGINE ---
    const scanForm = document.getElementById('scan-form');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const logWindow = document.getElementById('log-window');
    let scanInterval;

    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            startSimulation();
        });
    }

    document.getElementById('stop-btn').addEventListener('click', () => {
        clearInterval(scanInterval);
        logMessage("Scan stopped by user.", true);
    });

    function startSimulation() {
        switchPage('scan-progress');
        resetScanUI();
        
        const urlInput = document.getElementById('target-url').value;
        const scanType = document.getElementById('scan-type').value;
        
        const cleanUrl = urlInput.replace(/(^\w+:|^)\/\//, '').replace('www.', '');
        let seed = generateHash(cleanUrl);

        logMessage(`[INIT] Target: ${urlInput}`);
        logMessage(`[CONF] Scan Configuration: ${scanType.toUpperCase()}`);

        currentScanResults = [];
        let potentialFindings = [];

        // Generate potential findings
        if (seededRandom(seed + 1) > 0.3) potentialFindings.push(vulnDatabase.sqli[Math.floor(seededRandom(seed + 2) * vulnDatabase.sqli.length)]);
        if (seededRandom(seed + 3) > 0.2) potentialFindings.push(vulnDatabase.xss[Math.floor(seededRandom(seed + 4) * vulnDatabase.xss.length)]);
        if (seededRandom(seed + 5) > 0.4) potentialFindings.push(vulnDatabase.auth[Math.floor(seededRandom(seed + 6) * vulnDatabase.auth.length)]);
        if (seededRandom(seed + 7) > 0.5) potentialFindings.push(vulnDatabase.idor[Math.floor(seededRandom(seed + 8) * vulnDatabase.idor.length)]);

        // Filter results
        if (scanType === 'full') {
            currentScanResults = potentialFindings;
        } else {
            if (scanType === 'sqli') currentScanResults = potentialFindings.filter(f => f.type.includes('SQL'));
            else if (scanType === 'xss') currentScanResults = potentialFindings.filter(f => f.type.includes('XSS'));
            else if (scanType === 'auth') currentScanResults = potentialFindings.filter(f => f.technique.includes('Brute') || f.technique.includes('Token') || f.technique.includes('Login'));
            else if (scanType === 'idor') currentScanResults = potentialFindings.filter(f => f.type.includes('IDOR') || f.type.includes('Privilege'));
        }

        // Safety Override
        if (cleanUrl.includes('google') || cleanUrl.includes('microsoft') || cleanUrl.includes('example')) {
            currentScanResults = [];
            logMessage(`[INFO] Known secure domain detected.`);
        }
        else if ((cleanUrl.includes('test') || cleanUrl.includes('vuln') || cleanUrl.includes('juice')) && currentScanResults.length === 0) {
            if(scanType === 'full' || scanType === 'xss') currentScanResults.push(vulnDatabase.xss[0]);
            if(scanType === 'full' || scanType === 'sqli') currentScanResults.push(vulnDatabase.sqli[0]);
        }

        let progress = 0;
        scanInterval = setInterval(() => {
            progress += Math.floor(Math.random() * 5) + 1;
            if (progress > 100) progress = 100;

            progressFill.style.width = `${progress}%`;
            progressText.innerText = `${progress}%`;

            if (progress < 20) {
                 if(Math.random() > 0.7) logMessage(`[CRAWLER] Indexing path /${Math.random().toString(36).substring(7)}...`);
            } else if (progress < 60) {
                 if(Math.random() > 0.8) logMessage(`[MODULE] Running ${scanType.toUpperCase()} heuristics...`);
            } else if (progress < 90) {
                 if(Math.random() > 0.8 && currentScanResults.length > 0) logMessage(`[ALERT] Potential vulnerability identified!`);
            }

            if (progress >= 100) {
                clearInterval(scanInterval);
                logMessage("[SUCCESS] Scan Finished. Report Generated.");
                setTimeout(() => {
                    displayResults();
                    switchPage('results');
                }, 1200);
            }
        }, 150);
    }

    function logMessage(msg, isError = false) {
        if(!logWindow) return;
        const p = document.createElement('p');
        p.innerText = `${new Date().toLocaleTimeString()} ${msg}`;
        p.style.color = isError ? '#ff4444' : '#00ff00';
        logWindow.appendChild(p);
        logWindow.scrollTop = logWindow.scrollHeight;
    }

    function resetScanUI() {
        progressFill.style.width = '0%';
        logWindow.innerHTML = '';
    }

    // --- 6. RESULTS & CHARTING ---
    let chart1, chart2;

    function escapeHtml(text) {
        if (!text) return text;
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function displayResults() {
        const count = currentScanResults.length;
        document.getElementById('total-vulns-count').innerText = count;
        
        const hasCritical = currentScanResults.some(v => v.sev === 'Critical');
        document.getElementById('risk-score').innerText = hasCritical ? "Critical" : (count > 0 ? "Medium" : "Safe");

        const tbody = document.getElementById('results-table-body');
        tbody.innerHTML = '';
        
        if(count === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 2rem;">No vulnerabilities found.</td></tr>`;
        } else {
            currentScanResults.forEach(v => {
                tbody.innerHTML += `
                    <tr>
                        <td>${v.type}</td>
                        <td>${v.technique}</td>
                        <td style="font-family:monospace; color:#666;">${escapeHtml(v.param)}</td>
                        <td><span class="badge ${v.sev.toLowerCase()}">${v.sev}</span></td>
                    </tr>`;
            });
        }

        renderCharts(currentScanResults);
    }

    function renderCharts(data) {
        const ctx1 = document.getElementById('vulnTypeChart');
        const ctx2 = document.getElementById('severityChart');

        if (chart1) chart1.destroy();
        if (chart2) chart2.destroy();

        if (ctx1 && ctx2 && data.length > 0) {
            const high = data.filter(x => x.sev === 'High' || x.sev === 'Critical').length;
            const med = data.filter(x => x.sev === 'Medium').length;
            const low = data.filter(x => x.sev === 'Low').length;

            chart1 = new Chart(ctx1, {
                type: 'bar',
                data: {
                    labels: ['Critical/High', 'Medium', 'Low'],
                    datasets: [{ label: 'Count', data: [high, med, low], backgroundColor: ['#ff4444', '#ffbb33', '#00C851'] }]
                },
                options: { animation: false } // Disable animation for better image export
            });

            const typeCounts = {};
            data.forEach(d => { typeCounts[d.type] = (typeCounts[d.type] || 0) + 1; });
            
            chart2 = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(typeCounts),
                    datasets: [{ data: Object.values(typeCounts), backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF'] }]
                },
                options: { animation: false }
            });
        }
    }

    // --- 7. DOWNLOADS WITH CHARTS ---
    window.downloadReport = (type) => {
        if (currentScanResults.length === 0) {
            alert("No vulnerabilities to report.");
            return;
        }
        const url = document.getElementById('target-url').value;
        const scanType = document.getElementById('scan-type').value;
        const filename = `WebScanPro_${scanType}_${url.replace(/[^a-z0-9]/gi, '_')}`;

        // CAPTURE CHARTS AS IMAGES
        const canvas1 = document.getElementById('vulnTypeChart');
        const canvas2 = document.getElementById('severityChart');
        const imgData1 = canvas1 ? canvas1.toDataURL("image/png") : null;
        const imgData2 = canvas2 ? canvas2.toDataURL("image/png") : null;

        if (type === 'json') {
            // JSON contains raw data, which is used to rebuild charts
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanResults, null, 2));
            const a = document.createElement('a');
            a.href = dataStr; a.download = `${filename}.json`; a.click();
        } 
        else if (type === 'html') {
            const html = `
            <html><head><title>Scan Report</title>
            <style>
                body{font-family:sans-serif; padding:20px; max-width:800px; margin:0 auto;} 
                table{border-collapse:collapse; width:100%; margin-top:20px;} 
                th,td{border:1px solid #ddd; padding:8px; text-align:left;} th{background:#f2f2f2;}
                .charts { display: flex; gap: 20px; margin: 20px 0; justify-content: center; }
                .chart-img { width: 45%; border: 1px solid #eee; padding: 10px; }
                h1 { color: #333; }
            </style>
            </head><body>
            <h1>WebScanPro Security Report</h1>
            <p><strong>Target:</strong> ${url}</p>
            <p><strong>Scan Profile:</strong> ${scanType.toUpperCase()}</p>
            <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
            <hr>
            
            <h3>Visual Analysis</h3>
            <div class="charts">
                ${imgData1 ? `<div class="chart-img"><h4>Severity Dist</h4><img src="${imgData1}" width="100%"></div>` : ''}
                ${imgData2 ? `<div class="chart-img"><h4>Type Dist</h4><img src="${imgData2}" width="100%"></div>` : ''}
            </div>

            <h3>Detailed Findings</h3>
            <table>
            <tr><th>Vulnerability</th><th>Technique</th><th>Parameter/Location</th><th>Severity</th></tr>
            ${currentScanResults.map(r=>`<tr><td>${r.type}</td><td>${r.technique}</td><td>${escapeHtml(r.param)}</td><td>${r.sev}</td></tr>`).join('')}
            </table>
            </body></html>`;
            
            const blob = new Blob([html], {type: 'text/html'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = `${filename}.html`; a.click();
        }
        else if (type === 'pdf') {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            // Title
            doc.setFontSize(18); doc.text(`WebScanPro Security Report`, 10, 10);
            doc.setFontSize(12); doc.text(`Target: ${url}`, 10, 20);
            doc.text(`Profile: ${scanType.toUpperCase()}`, 10, 30);
            
            // Add Charts to PDF
            // We place them side by side at Y=40
            if (imgData1) {
                doc.text("Severity Distribution:", 10, 40);
                doc.addImage(imgData1, 'PNG', 10, 45, 80, 50); // x, y, width, height
            }
            if (imgData2) {
                doc.text("Vulnerability Types:", 100, 40);
                doc.addImage(imgData2, 'PNG', 100, 45, 80, 50);
            }

            // Start Table below charts
            doc.text("Detailed Findings:", 10, 110);
            let y = 120;
            
            currentScanResults.forEach((r,i) => {
                // Check if we need a new page
                if(y > 270) { doc.addPage(); y=20; }
                
                doc.setFont("helvetica", "bold");
                doc.text(`${i+1}. ${r.type} [${r.sev}]`, 10, y);
                doc.setFont("helvetica", "normal");
                doc.text(`   Tech: ${r.technique}`, 10, y+6);
                doc.text(`   Loc: ${r.param}`, 10, y+12);
                y+=20;
            });
            doc.save(`${filename}.pdf`);
        }
    };
});