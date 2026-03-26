# Tempora: Analyst Walkthrough

This demo walks an Analyst through setting up the tool and evaluating three common real-world log scenarios.

### Prerequisites
Navigate to the root project:
```bash
cd log_analyzer
```
Ensure you have generated the test suite mock data:
```bash
python testing_scripts/generate_test_logs.py
```

### Scenario 1: A Clean Production Log
You need to verify that a web server has run unbroken natively during a shift.
```bash
python integrity_check.py sample_logs/clean.log --summary --timeline
```
**Expected Outcome**: 
The console will simply print:
`No suspicious gaps detected. Log appears contiguous.`
Summary will identify Suspicion Score as LOW.

### Scenario 2: Finding Network Outages with Visualizations
An analyst suspects connection drops.
```bash
python integrity_check.py sample_logs/gaps.log --summary --timeline
```
**Expected Outcome**:
You will observe three localized breaks:
1. `80.0 seconds` (LOW - Connection Drop)
2. `500.0 seconds` (MEDIUM - Timeout Sequence)
3. `4000.0 seconds` (HIGH - Crash Window)

The timeline outputs as an ASCII progress bar, placing an `!`, `x`, and `X` proportionately across the runtime, proving immediate insight without filtering.

### Scenario 2B: Custom Threshold Analysis (Filtering Confidence)
By default, the analysis looks for any gap > 60 seconds. However, noisy systems might throw false positives. We can restrict analysis intelligently:
```bash
python integrity_check.py sample_logs/gaps.log --threshold 120 --summary --timeline
```
**Expected Outcome**: 
Notice how the output only flags **2 gaps** (`500s` and `4000s`), intentionally ignoring the `80s` LOW severity connection drop. The CLI explicitly warns you via its configuration header that your results differ from default outputs because smaller gaps are mathematically suppressed!

### Scenario 3: Corrupted Intrusions & Parsing Evasions
The adversary has deleted several lines, intentionally overwrote standard formatting, and replaced headers with blank spaces. You want to see the gaps without the tool crashing.
```bash
python integrity_check.py sample_logs/malformed.log --summary --timeline --verbose
```
**Expected Outcome**: 
Because `--verbose` is provided, `WARNING` tags explicitly print to `stderr` notifying the analyst of the malformed strings `This line has no timestamp and should be skipped`.
The tool recovers its sequence upon the string `sume after large gap and malformed lines`, correctly flagging the missing time space!

### Scenario 4: JSON Export to Splunk/SIEM
You finished triage and need the results piped to your aggregator.
```bash
python integrity_check.py sample_logs/gaps.log --format json > report.json
cat report.json
```
**Expected Outcome**: 
Outputs deterministic machine-readable schemas capturing durations, line indices, and computed heuristics.
