# Tempora: Analyst Walkthrough

This demo walks an Analyst through setting up the tool and evaluating core forensic log scenarios.

### Scenario 1: The Interactive "Wow Factor" Setup
Evaluate a severely compromised web server containing Advanced Persistent Threat (APT) data poisoning.
```bash
python integrity_check.py --interactive
```
**Execution Flow**: 
- **Primary log:** `server.log`
- **Threshold:** `60`
- **Alibi Protocol log:** `auth.log`

**Expected Outcome**: 
Tempora explodes into a glowing cyan Matrix. It declares a **0% Trust Confidence Score** and immediately flags the hacker's evasion attempt natively:
`CAUSALITY VIOLATION: 1 reverse-time jumps detected | SYNTHETIC FORGERY: 21 instances of Shannon Entropy collapse`
You will see the red `[X]` brackets perfectly highlighting the massive intrusion on the normalized ASCII Timeline.

### Scenario 2: The Core Requirement (HDFS Support)
Prove the tool natively processes the highly unusual format requested in the baseline challenge without modifying regex flags manually.
```bash
python integrity_check.py sample_logs\hdfs_sample.log --threshold 60
```
**Expected Outcome**:
The system perfectly parses the `081109 203615` string, identifying the exact 523-second anomaly expected. It guarantees a `NORMAL` status and a 95% trust score, confirming the gap is a benign system timeout rather than a deliberate cyberattack.

### Scenario 3: Automation via JSON Export 
You finished triage and need the detailed metrics actively piped to your SIEM (e.g., Splunk / ElasticSearch).
```bash
python integrity_check.py server.log --format json > report.json
cat report.json
```
**Expected Outcome**: 
Outputs highly deterministic, strictly structured JSON arrays capturing gap intervals, line indices, severity enums, and the fully calculated mathematical trust heuristics.

### Scenario 4: The Executive HTML Dashboard
You need to present your mathematical findings to non-technical stakeholders in an air-gapped room without an active backend server.
```bash
python integrity_check.py server.log --format html > presentation_dashboard.html
```
**Expected Outcome**: 
Outputs a enterprise-grade HTML dashboard natively. It features a standalone `Chart.js` chronological anomaly distribution block, Trust Confidence scores, explicitly formatted Alibi Protocol pass/fail modules, and an educational terminology glossary. All metrics mapped natively via the initial $O(1)$ Python pipeline.

