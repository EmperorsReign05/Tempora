import json

def generate_html_dashboard(report_data: dict) -> str:
    json_data = json.dumps(report_data)
    html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tempora Forensic Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0; --text-main: #0f172a;
            --text-muted: #64748b; --primary: #2563eb;
            --danger: #dc2626; --warning: #f59e0b; --success: #10b981;
            --font-mono: ui-monospace, SFMono-Regular, Consolas, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
        }}
        body {{ font-family: var(--font-sans); background-color: var(--bg); color: var(--text-main); margin: 0; padding: 2.5rem 4rem; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 1.5rem; }}
        
        .header {{ display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 0.5rem; }}
        .header-title h1 {{ margin: 0; font-size: 2rem; font-weight: 800; color: #1e293b; letter-spacing: -0.025em; }}
        .header-title p {{ margin: 0.25rem 0 0 0; color: var(--text-muted); font-size: 1rem; }}
        .export-group {{ display: flex; gap: 0.75rem; }}
        .btn {{ display: inline-flex; align-items: center; justify-content: center; padding: 0.6rem 1.25rem; font-size: 0.85rem; font-weight: 600; border-radius: 6px; cursor: pointer; border: none; color: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.05); transition: opacity 0.2s; }}
        .btn:hover {{ opacity: 0.9; }}
        .btn-primary {{ background-color: var(--primary); }}
        .btn-success {{ background-color: var(--success); }}

        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .card-title {{ margin: 0 0 1.25rem 0; font-size: 0.9rem; text-transform: none; font-weight: 700; color: #0f172a; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }}
        
        .status-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }}
        .status-box {{ padding-right: 1.5rem; border-right: 1px solid var(--border); }}
        .status-box:last-child {{ border-right: none; }}
        .status-box .label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-main); font-weight: 700; margin-bottom: 0.25rem; letter-spacing: 0.05em; }}
        .status-box .value {{ font-size: 2.5rem; font-weight: 800; display: flex; align-items: center; letter-spacing: -0.025em; line-height: 1.2; }}
        .status-box .value.danger {{ color: var(--danger); }}
        .status-box .value.warning {{ color: var(--warning); }}
        .status-box .value.success {{ color: var(--success); }}
        .status-box .value.neutral {{ color: var(--text-main); }}

        .chart-container {{ width: 100%; height: 300px; position: relative; }}

        .panels-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
        
        .diag-box {{ background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 1rem; font-size: 0.9rem; margin-bottom: 1rem; color: #1e3a8a; }}
        .diag-box strong {{ color: #1e40af; }}
        .trigger-list {{ margin: 0; padding-left: 1.25rem; font-size: 0.9rem; color: var(--text-main); }}
        
        .alibi-box {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 1rem; font-size: 0.95rem; font-weight: 600; color: #166534; margin-bottom: 0.75rem; }}
        .alibi-desc {{ font-size: 0.9rem; color: var(--text-main); line-height: 1.5; }}
        .alibi-box.danger {{ background: #fef2f2; border-color: #fecaca; color: #991b1b; }}
        
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th, td {{ text-align: left; padding: 0.75rem 1rem; }}
        th {{ color: var(--text-main); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; border-bottom: 1px solid var(--border); letter-spacing: 0.05em; }}
        td {{ border-bottom: 1px solid #f1f5f9; color: var(--text-main); }}
        tr:last-child td {{ border-bottom: none; }}
        
        .badge {{ display: inline-flex; align-items: center; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .badge-danger {{ background: #fef2f2; color: #b91c1c; }}
        .badge-warning {{ background: #fffbeb; color: #d97706; }}
        .badge-success {{ background: #f0fdf4; color: #15803d; }}

        .glossary-section {{ margin-top: 1rem; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 2rem; }}
        .glossary-item h4 {{ margin: 0 0 0.5rem 0; font-size: 0.85rem; font-weight: 700; color: var(--text-main); }}
        .glossary-item p {{ margin: 0; font-size: 0.8rem; color: var(--text-muted); line-height: 1.5; }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-title">
                <h1>Tempora Forensic Audit Report</h1>
                <p>Enterprise Integrity Matrix & Audit Report <br/><span style="font-size: 0.85rem; font-family: var(--font-mono); color: var(--success);" id="shaHash"></span></p>
            </div>
            <div class="export-group">
                <button class="btn btn-primary" onclick="exportJSON()">&#x2193; Export JSON</button>
                <button class="btn btn-success" onclick="exportCSV()">&#x2193; Export CSV</button>
            </div>
        </header>

        <div class="card">
            <h2 class="card-title">System Status Overview</h2>
            <div class="status-grid">
                <div class="status-box">
                    <div class="label">Primary Assessment</div>
                    <div class="value" id="statusValue">
                        <svg id="statusIcon" style="width:32px;height:32px;margin-right:8px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        <span id="statusText"></span>
                    </div>
                </div>
                <div class="status-box">
                    <div class="label">Trust Confidence</div>
                    <div class="value neutral" id="trustValue">0%</div>
                </div>
                <div class="status-box">
                    <div class="label">Total Logs Analyzed</div>
                    <div class="value neutral" id="linesValue">0</div>
                </div>
                <div class="status-box">
                    <div class="label">Total Interventions</div>
                    <div class="value neutral" id="gapsValue">0</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2 class="card-title">Chronological Anomaly Distribution</h2>
            <div class="chart-container">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>

        <div class="panels-row">
            <div class="card">
                <h2 class="card-title">Forensic Triggers (Investigation Details)</h2>
                <div class="diag-box">
                    <strong>Diagnostic:</strong> <span id="flaggedReason"></span>
                </div>
                <ul class="trigger-list" id="anomalyList"></ul>
            </div>
            <div class="card">
                <h2 class="card-title">The Alibi Protocol Status</h2>
                <div id="alibiBox" class="alibi-box"></div>
                <div id="alibiDesc" class="alibi-desc"></div>
            </div>
        </div>

        <div class="card">
            <h2 class="card-title" style="border-bottom:none; margin-bottom:0;">Detailed Anomaly Ledger</h2>
            <table style="margin: 0 -1.5rem; width: calc(100% + 3rem);">
                <thead>
                    <tr>
                        <th style="padding-left: 1.5rem;">Severity</th>
                        <th>Start Timestamp</th>
                        <th>End Timestamp</th>
                        <th>Duration (s)</th>
                        <th style="padding-right: 1.5rem;">Alibi Protocol</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>

        <div>
            <h2 class="card-title" style="border-bottom: none; margin-bottom: 0;">Forensic Terminology Reference</h2>
            <div class="glossary-section">
                <div class="glossary-item">
                    <h4>Causality Violation</h4>
                    <p>Triggered when a log entry's timestamp occurs <em>before</em> the preceding entry's timestamp. This strongly indicates deliberate tampering (e.g., NTP spoofing), clock desynchronization, or out-of-order writes used to mask true event timelines.</p>
                </div>
                <div class="glossary-item">
                    <h4>Shannon Entropy Collapse</h4>
                    <p>A mathematical measurement of text randomness. Abnormally low entropy in log payloads indicates synthetic or script-generated content (e.g., an automated attacker injecting repetitive dummy logs to bury their tracks in "noise").</p>
                </div>
                <div class="glossary-item">
                    <h4>The Alibi Protocol</h4>
                    <p>A cross-referencing technique that compares a missing timeframe (gap) in the primary log against activity in an immutable secondary log (like <code>auth.log</code>). Activity in the secondary log mathematically proves the primary log gap was intentional deletion.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const reportData = {json_data};
        const m = reportData.metadata;
        const a = reportData.anomalies;
        const t = reportData.trust_metrics;
        const gaps = reportData.detailed_gaps;

        // Status
        const stText = document.getElementById('statusText');
        const stValueBox = document.getElementById('statusValue');
        const trustVal = document.getElementById('trustValue');
        
        stText.textContent = t.system_status;
        if (t.system_status === 'COMPROMISED') {{
            stValueBox.className = 'value danger';
            document.getElementById('statusIcon').style.display = 'block';
        }} else if (t.system_status === 'SUSPICIOUS') {{
            stValueBox.className = 'value warning';
            document.getElementById('statusIcon').style.display = 'block';
        }} else {{
            stValueBox.className = 'value success';
            document.getElementById('statusIcon').style.display = 'none';
        }}

        trustVal.textContent = t.log_trust_confidence_percent + '%';
        document.getElementById('linesValue').textContent = m.total_lines_processed.toLocaleString();
        document.getElementById('gapsValue').textContent = a.total_gaps_found;
        
        if (m.chain_of_custody_sha256 && m.chain_of_custody_sha256 !== "N/A") {{
            document.getElementById('shaHash').innerHTML = '<strong>[✓] Chain of Custody (SHA-256):</strong> ' + m.chain_of_custody_sha256;
        }}

        // Triggers
        document.getElementById('flaggedReason').textContent = t.suspicion_reason;
        const anList = document.getElementById('anomalyList');
        let listHTML = '';
        if (a.causality_violations_detected > 0) listHTML += '<li>Causality Violations (Time Jumps): ' + a.causality_violations_detected + '</li>';
        if (a.shannon_entropy_collapses > 0) listHTML += '<li>Shannon Entropy Collapses: ' + a.shannon_entropy_collapses + '</li>';
        if (a.malformed_lines_skipped > 0) listHTML += '<li>Malformed Lines Skipped: ' + a.malformed_lines_skipped + '</li>';
        
        if (a.cloud_alerts && a.cloud_alerts.length > 0) {
            listHTML += '<li style="color:var(--danger); font-weight:bold; margin-top:0.5rem; list-style:none; margin-left:-1.25rem;">Cloud Forensic Alerts:</li>';
            a.cloud_alerts.forEach(alert => {
                listHTML += '<li style="color:var(--danger)">' + alert + '</li>';
            });
        }
        
        if (listHTML === '') listHTML = '<li style="color:var(--success)">No advanced anomalous behaviors detected. System appears stable.</li>';
        anList.innerHTML = listHTML;

        // Alibi
        const abBox = document.getElementById('alibiBox');
        const abDesc = document.getElementById('alibiDesc');
        if (a.alibi_failures_detected > 0) {{
            abBox.textContent = 'Evidence of Tampering Found';
            abBox.className = 'alibi-box danger';
            abDesc.innerHTML = 'Cross-referencing detected <strong>' + a.alibi_failures_detected + '</strong> instances where secondary logs confirm background activity during primary log gaps.';
        }} else {{
            abBox.textContent = 'Protocol Passed / Inactive';
            abBox.className = 'alibi-box';
            abDesc.textContent = 'No conflicting background activity was detected during missing timeframes, or the protocol was not utilized.';
        }}

        // Table
        const tb = document.getElementById('tableBody');
        if (gaps.length === 0) {{
            tb.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted)">No anomalies detected.</td></tr>';
        }} else {{
            gaps.forEach(g => {{
                const bClass = g.severity === 'HIGH' ? 'badge-danger' : (g.severity === 'MEDIUM' ? 'badge-warning' : 'badge-success');
                tb.innerHTML += '<tr>' +
                    '<td style="padding-left: 1.5rem;"><span class="badge ' + bClass + '">' + g.severity + '</span></td>' +
                    '<td>' + g.start_time.replace("T", " ").split(".")[0] + '</td>' +
                    '<td>' + g.end_time.replace("T", " ").split(".")[0] + '</td>' +
                    '<td>' + g.duration_seconds.toLocaleString() + 's</td>' +
                    '<td style="padding-right: 1.5rem;">' + (g.alibi_events_caught > 0 ? "<span style=\\"color:var(--danger); font-weight: bold\\">Failed</span>" : "—") + '</td>' +
                '</tr>';
            }});
        }}

        // Chart.js
        if (gaps.length > 0) {{
            const ctx = document.getElementById('timelineChart').getContext('2d');
            
            // To loosely scale the x-axis, let's inject filler 0 duration bars before/after gap 
            // for pure layout matching the image (which has an X axis representing real timeline with an isolated orange bar).
            // Image shows X-axis "Time (seconds)" with interval values like 0, 200, 400 ... 1800, 
            // and an orange bar somewhere in the middle. We'll plot X correctly if it's scatter or standard bar with labels.
            const labelsStr = [];
            const dVals = [];
            gaps.forEach((g) => {{
                // we'll just plot all gaps
                labelsStr.push(g.start_time.replace('T', ' ').split('.')[0]);
                dVals.push(g.duration_seconds);
            }});

            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labelsStr,
                    datasets: [{{
                        label: 'Duration',
                        data: dVals,
                        backgroundColor: '#f59e0b',
                        maxBarThickness: 40
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            title: {{ display: true, text: 'Time (Timestamp)', color: '#64748b' }},
                            grid: {{ display: false }}
                        }},
                        y: {{
                            title: {{ display: true, text: 'Duration (seconds)', color: '#64748b' }},
                            beginAtZero: true,
                            grid: {{ color: '#f1f5f9' }}
                        }}
                    }},
                    plugins: {{ legend: {{ display: false }} }}
                }}
            }});
        }} else {{
            document.querySelector('.chart-container').innerHTML = '<div style="color: var(--text-muted); padding: 4rem 0; text-align: center;">No anomaly data to plot.</div>';
        }}

        function exportJSON() {{
            const blob = new Blob([JSON.stringify(reportData, null, 2)], {{type: 'application/json'}});
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'tempora_report.json'; a.click();
        }}
        function exportCSV() {{
            let csv = "severity,start_time,end_time,duration_seconds,alibi_caught\\n";
            gaps.forEach(g => {{ csv += g.severity + ',' + g.start_time + ',' + g.end_time + ',' + g.duration_seconds + ',' + g.alibi_events_caught + '\\n'; }});
            const blob = new Blob([csv], {{type: 'text/csv'}});
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'tempora_report.csv'; a.click();
        }}
    </script>
</body>
</html>'''
    return html_template.replace('{json_data}', json_data)

