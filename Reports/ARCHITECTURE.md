# Tempora Architecture

Tempora employs a strictly pipelined architecture tailored for scale, separation of concerns, and mathematical resilience against data poisoning.

## System Workflow & Data Flow

```mermaid
graph TD;
    A[integrity_check.py CLI] -->|Provides Config & Threshold| B[Log Generator]
    B -->|Yields raw strings| C[Regex Parser Array]
    C -->|Extracts datetime, Yields LogLine| D[Anomaly Detection Engine]
    D -->|Rolling Shannon Entropy| E[Data Poisoning Defense]
    D -->|Negative Time Deltas| F[Causality Tracker]
    D -->|O(1) Scan Payload| J[PII Sweeper]
    D -->|Standard Gaps| G[Severity Scorer]
    E -.->|Updates Trust Score| H[Reporter Sink]
    F -.->|Updates Trust Score| H
    G -.->|Calculates Durations| H
    J -.->|Flags MITRE Leakage| H
    H -->|Outputs CLI/JSON/ASCII/HTML| I[Standard Output]
```

### Logic Modules (Single File Deliverable)

While Tempora is legally distributed as a single automated script (`integrity_check.py`) to conform perfectly to the Ideathon requirements, it is architected under the hood using strictly decoupled object-oriented logic blocks:

1. **Orchestrator (`main`)**: Handles user arguments via `argparse`, sets up config overrides, and initializes the pipeline loop. Supports Interactive Mode natively.
2. **Configuration Block (`Config`)**: Stores runtime fallbacks, Regex parsing templates (HDFS/ISO), default gap thresholds, and severity boundaries. Now fully supports dynamic `load_from_json()` initialization to bypass script edits completely while remaining strictly zero-dependency.
3. **LogParser Class**: Iterates over regex strategies rapidly. Generates fully typed `LogLine` dataclass objects natively resolving payload text and timestamps flawlessly without crashing on malformed corruption.
4. **PIISweeper Class**: Acts sequentially on unformatted string payloads extracting indicators of compromise (Email, IPv4, API tokens) natively using pre-compiled regex strategies, dynamically mapping them to MITRE T1005 logic hooks.
5. **GapDetector Class**: Maintains internal strict mathematical state ($O(1)$ memory constraint). Explicitly tracks Causality Violations, limits Time Travel, and runs the rolling Shannon Entropy logic dynamically on the string payloads.
6. **Severity Engine**: Assess duration scalars assigning static Severity Enum tags (`LOW`, `HIGH`). Deducts Trust Confidence penalties based on Alibi failures and Entropy limits.
6. **Reporter Class**: Aggregates verified anomalies and gracefully sinks them to the deterministic string models required, executing the visual ASCII timeline, robust JSON/CSV pipelines, and rendering the highly structured HTML forensic dashboard.

## Stream Processing Strategy

Common log parsing utilities invoke `readlines()`, holding huge structures in program memory. A 10GB file causes traditional DOM-style analysis to OOM crash.

Tempora strictly employs **Generators (`yield`)**, ensuring memory usage remains statically bound entirely to configuration overhead. A 500GB server log runs on the exact same micro-footprint of RAM as a 50KB text file.
