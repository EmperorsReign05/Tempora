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
python integrity_check.py --help
```

---

## Usage Examples

**The easiest way to run the tool is using the Interactive Wizard:**
```bash
python integrity_check.py --interactive
```

**Run standard analysis via CLI arguments:**
```bash
python integrity_check.py sample_logs\gaps.log
```

**Run the Alibi Protocol against a secondary immutable log (e.g. syslog):**
```bash
python integrity_check.py sample_logs\gaps.log --alibi sample_logs\clean.log
```

**Export strict structural metrics to JSON for automation/SIEM pipelines:**
```bash
python integrity_check.py sample_logs\gaps.log --format json > report.json
```

**Adjust the gap detection threshold (default is 60 seconds):**
```bash
python integrity_check.py sample_logs\gaps.log --threshold 120
```

*Note: Changing the threshold fundamentally alters the detected gaps. For example, running `python integrity_check.py logs.txt` (default 60s) might detect 3 gaps, while `python integrity_check.py logs.txt --threshold 120` might detect only 2 gaps, ignoring smaller anomalies entirely.*

---

## Sample Output

```text
Gap Detected
Start: 07:53:42
End: 08:23:42
Duration: 1800 seconds

Total Gaps Found: 1

========================================
=== TEMPORA ADVANCED INTEGRITY MATRIX ===
========================================
Total Lines Processed: 103
System Status:         COMPROMISED
Log Trust Confidence:  0%
Reason:                CAUSALITY VIOLATION: 1 reverse-time jumps detected | SYNTHETIC FORGERY: 21 instances of Shannon Entropy collapse

=== TIMELINE NORMALIZATION VISUALIZATION ===
Start: 2024-10-15 08:00:02
[xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx]
End:   2024-10-15 08:23:42
Legend: [.] OK   [!] LOW gap   [x] MEDIUM gap   [X] HIGH gap
============================================
```
