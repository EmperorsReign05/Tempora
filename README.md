# Tempora: Automated Log Integrity Monitor

**Tempora** is a production-quality, modular forensic tool designed for security analysts to process large-scale log files and detect suspicious temporal anomalies (e.g., manipulated timestamps, missing entries, dropped connections).

It runs efficiently on GB-scale log files leveraging Python generators, identifying gaps between entries, categorizing them intelligently by severity, and providing global suspicion scores to quickly aid triage.

## Features

- **Stream Processing Strategy**: Processes logs iteratively without loading the entire file into memory, keeping the footprint minimal.
- **The Alibi Protocol (Cross-Log Sync)**: Compares primary logs against secondary/background logs to mathematically prove intentional deletion instances when time gaps match background file activities.
- **Shannon Entropy Forgery Catcher**: Dynamically calculates the informational randomness of text payloads in $O(1)$ memory. Automatically catches hackers who inject repetitive synthetic logs to mask their tracks.
- **Causality Violation Engine**: Detects reverse-time anomalies where timestamps move backwards chronologically, instantly catching out-of-order writes or systemic NTP Spoofing (Time Travel).
- **Adaptive Data-Poisoning Defense**: Freezes the rolling statistical baseline when anomalies are detected, preventing adversaries from slowly reducing system sensitivity using iterative pollution payloads.
- **Log Integrity Confidence**: Evaluates the global mathematical Trust percentage of the audit trail, degrading points for frequency of anomalies and max threshold violations.
- **Dynamic Severity Scoring**: Categorizes missing time intervals into `LOW`, `MEDIUM`, or `HIGH` severity cleanly.
- **Robust Multi-format Parsing**: Fallback strategies cleanly extract timestamps and bypass completely malformed corruption gracefully.
- **Normalized ASCII Timeline**: Analyzes gap frequencies graphically across a relative timeline string.

---

## Installation

No external dependencies are required. The tool operates using only the Python standard library.

```bash
git clone https://github.com/EmperorsReign05/Tempora.git
cd Tempora
python main.py --help
```

---

## Usage Examples

Run the analyzer with default settings and metrics:
```bash
python main.py sample_logs\gaps.log --summary --timeline
```

Run the Alibi Protocol against a secondary immutable log (e.g. syslog):
```bash
python main.py sample_logs\gaps.log --alibi sample_logs\clean.log --summary --timeline
```

Include the Summary Metrics:
```bash
python log_analyzer/main.py app.log --summary
```

Generate an Interactive Timeline & Verbose Output (Shows skipped lines):
```bash
python log_analyzer/main.py app.log --summary --timeline --verbose
```

Export results to JSON for automation pipelines:
```bash
python log_analyzer/main.py app.log --format json > report.json
```

Adjust the gap detection threshold (default is 60 seconds):
```bash
# Flags gaps larger than 120 seconds
python main.py sample_logs\gaps.log --threshold 120
```

*Note: Changing the threshold fundamentally alters the detected gaps. For example, running `python main.py logs.txt` (default 60s) might detect 3 gaps, while `python main.py logs.txt --threshold 120` might detect only 2 gaps, ignoring smaller anomalies entirely.*

---

## Sample Output

```text
Running Alibi Protocol against secondary log: sample_logs\clean.log
=== Tempora: Forensic Log Analysis ===
=== Configuration ===
Threshold: 60 seconds
Execution Mode: CLI
Configuration Source: Default
=====================
Note: Gaps below threshold are ignored

Gap Detected #1:
  Start:    2024-10-14 10:00:18 (Line 10)
  End:      2024-10-14 10:01:40 (Line 11)
  Duration: 1m 22s
  Severity: LOW
  [!] ALIBI FAILURE: Secondary log confirmed 40 events during this silent gap.       
      -> Confirms intentional log deletion/tampering.

Gap Detected #2:
  Start:    2024-10-14 10:01:50 (Line 16)
  End:      2024-10-14 10:10:10 (Line 17)
  Duration: 8m 20s
  Severity: MEDIUM
  [!] ALIBI FAILURE: Secondary log confirmed 44 events during this silent gap.       
      -> Confirms intentional log deletion/tampering.

Gap Detected #3:
  Start:    2024-10-14 10:10:20 (Line 22)
  End:      2024-10-14 11:17:00 (Line 23)
  Duration: 1h 6m 40s
  Severity: HIGH

=== ANALYSIS SUMMARY ===
Total Lines Parsed:  23
Total Gaps:          3
Longest Gap:         1h 6m 40s
Suspicion Score:     0.2609
System Status:       COMPROMISED
Log Integrity Confidence: 28%
Reason:              CRITICAL: 2 Alibi Failures detected (Proven tampering) | Major timeline disruptions (HIGH gaps)

--- Intelligent Insights ---
1. Clustered anomalies detected (gaps occurring in close temporal proximity). This may indicate coordinated tampering or systemic cascading failures.
========================

=== TIMELINE NORMALIZATION VISUALIZATION ===
Start: 2024-10-14 10:00:00
[!xxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX]
End:   2024-10-14 11:17:00
Legend: [.] OK   [!] LOW gap   [x] MEDIUM gap   [X] HIGH gap
Visualization reflects only gaps above configured threshold
==============================
```
