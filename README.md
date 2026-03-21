# Tempora: Automated Log Integrity Monitor

**Tempora** is a production-quality, modular forensic tool designed for security analysts to process large-scale log files and detect suspicious temporal anomalies (e.g., manipulated timestamps, missing entries, dropped connections).

It runs efficiently on GB-scale log files leveraging Python generators, identifying gaps between entries, categorizing them intelligently by severity, and providing global suspicion scores to quickly aid triage.

## Features

- **Stream Processing Strategy**: Processes logs iteratively without loading the entire file into memory, keeping the footprint minimal.
- **Dynamic Severity Scoring**: Categorizes missing time intervals into `LOW`, `MEDIUM`, or `HIGH` severity.
- **Global Suspicion Intelligence**: Scores an entire log file based on clustering patterns and the ratio of anomalous intervals.
- **Robust Multi-format Parsing**: Fallback strategies cleanly extract timestamps from common string formats automatically.
- **Graceful Error Handling**: Skips completely malformed or unparseable text without halting analysis.
- **ASCII Timeline Visualization**: Quickly map anomalous activity to temporal intervals via text.

---

## Installation

No external dependencies are required. The tool operates using only the Python standard library.

```bash
git clone https://github.com/your-repo/the-evidence-protector.git
cd the-evidence-protector
python log_analyzer/main.py --help
```

---

## Usage Examples

Run the analyzer with default settings and metrics:
```bash
python main.py sample_logs\gaps.log --summary --timeline
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
=== Tempora: Forensic Log Analysis ===
=== Configuration ===
Threshold: 60 seconds
Mode: Default CLI
=====================
Note: Gaps below threshold are ignored

Gap Detected #1:
  Start:    2024-10-14 10:00:18 (Line 10)
  End:      2024-10-14 10:01:38 (Line 11)
  Duration: 80.0 seconds
  Severity: LOW

=== ANALYSIS SUMMARY ===
Total Lines Parsed: 11
Total Gaps:         1
Longest Gap:        80.0 seconds
Suspicion Score:    LOW
========================

=== TIMELINE VISUALIZATION ===
Start: 2024-10-14 10:00:00
[...!........................................................]
End:   2024-10-14 10:01:38
Legend: [.] OK   [!] LOW gap   [x] MEDIUM gap   [X] HIGH gap
==============================
```
