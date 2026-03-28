# Design Decisions and Tradeoffs

## Strict Object-Oriented Pipeline

The application parses each log line and passes a state incrementally through small class modules rather than holding strings locally until logic completes.

### Tradeoff #1: Accuracy vs Regex Complexity
- **Choice**: The `LogParser` class utilizes a multi-layered Regex fallback array rather than a single hardcoded timestamp map.
- **Rationale**: An analyst must trust the system natively against unstructured datasets. Supporting HDFS (`081109 203615`) alongside standard ISO or Syslog dynamically guarantees the tool works unconditionally across different enterprise servers.
- **Cost**: The log parser runs sequential regex strategies continuously, degrading CPU performance slightly per-line compared to a globally locked format block.

### Tradeoff #2: Stateless Output vs Buffered Arrays
- **Choice**: Storing strictly mathematical `Gap` objects rather than retaining every valid `LogLine` in a massive list.
- **Rationale**: The core requirement strictly mandated memory stability ($O(1)$) with scalable processing. Retaining 5,000,000 perfect timestamps creates useless heap objects that immediately trigger Out-of-Memory crashes on multi-gigabyte logs.
- **Cost**: The visual ASCII Timeline generator loses sub-second discrete clustering fidelity because it cannot replay identical lines; it mathematically projects the ratio of the duration based on start and end scalars instead natively.

### Tradeoff #3: Configurable Severity Heuristics & Filtering
- **Choice**: The `calculate_severity` function categorizes duration statistically, but computes "Suspicion" probabilistically. Gaps beneath thresholds are logically suppressed.
- **Rationale**: Single arbitrary timeouts (1 hour maintenance script) might be benign, whereas 150 mini gaps (4 minutes each) trigger HIGH suspicion representing a malicious intermittent beacon. Filtering suppresses irrelevant noise for the Incident Response team.
- **Cost**: The visual timeline only reflects anomalies passing the designated boundary threshold.

## Known Limitations

- **Multithreading**: Because the integrity of the forensic stream relies on precise chronological string continuity, logs cannot be efficiently fanned out to parallel worker processes without complex structural sequence tagging. Operations are explicitly bound to a single thread.
