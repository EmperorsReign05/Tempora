# Design Decisions and Tradeoffs

## Strict Core Modules Pipeline

The application parses each log line and passes a state incrementally through small modules rather than holding strings locally until logic completes.

### Tradeoff #1: Accuracy vs Component Complexity
- **Choice**: Separate the `parser.py` Regex functionality strictly from the `detector.py` Time Delta logic.
- **Rationale**: An analyst must trust the output format. Having all extraction semantics in `parser.py` allows expanding the script to support Syslog, ISO, Apache, etc., simply by dropping new templates into the `__init__` Config object without affecting scoring.
- **Cost**: The log parser runs a sequential array of regex strategies continuously, degrading CPU performance slightly per-line, rather than locking to a globally matched static format.

### Tradeoff #2: Stateless Output vs Buffered Arrays
- **Choice**: Only saving the anomaly `Gap` object rather than every parsed timestamp.
- **Rationale**: The core requirement strictly mandated memory stability with scalable processing. Retaining 5,000,000 perfect timestamps creates useless heap objects.
- **Cost**: The ASCII Timeline generator loses sub-second clustering fidelity because it cannot replay identical lines; it can only project the ratio of the duration.

### Tradeoff #3: Configurable Severity Heuristics & Filtering
- **Choice**: The `severity.py` file categorizes duration statistically, but dynamically computes "Suspicion" probabilistically. Gaps beneath specific thresholds are entirely suppressed from computation to prevent analysis noise.
- **Rationale**: Single arbitrary timeouts (1 hour maintenance script) might be benign, whereas 150 mini gaps (4 minutes each) trigger HIGH suspicion representing a malicious intermittent beacon. Filtering allows an analyst to suppress irrelevant noise.
- **Cost**: The visual timeline and total severity counts only reflect anomalies passing the designated threshold, masking smaller original gaps which might technically exist but fall outside the parameters. To alleviate this, Tempora outputs explicit transparency warnings within its UI declaring active thresholds.

## Limitations

- **Multithreading**: Because the integrity of the stream relies on chronological string continuity, logs cannot be efficiently fanned out to worker processes without complex sequence tagging. Operations are bound to a single thread.
- **Unstructured Payloads**: Fuzzing timestamp locations may spoof the regex templates if the raw message payload unexpectedly starts with an ISO date.
