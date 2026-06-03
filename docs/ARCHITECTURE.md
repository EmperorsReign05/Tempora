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

### Core Package Structure & File Responsibilities

Tempora has been refactored into a professional-grade modular Python package. Below is the file structure and the responsibility of each module:

- **`tempora/cli.py`**: The Orchestrator. Handles user arguments via `argparse`, sets up config overrides, initializes the pipeline loop, and provides the Interactive Setup Wizard natively.
- **`tempora/core/analyzer.py`** (`TemporaAnalyzer`): The central intelligence hub. It wires together the parser, gap detector, and PII sweeper to analyze log streams efficiently using generators.
- **`tempora/core/models.py`**: Defines strict, typed `dataclass` objects ensuring type safety across the pipeline (e.g., `NormalizedEvent`, `Gap`, `SystemStatus`, `Severity`).
- **`tempora/core/exceptions.py`**: Contains custom exceptions (like `LogParseError`, `ConfigurationError`) for graceful error handling.
- **`tempora/parsers/regex_parser.py`** (`RegexParser`): Iterates over regex strategies rapidly to extract `datetime` payloads flawlessly without crashing on malformed corruption. Inherits from `parsers/base.py`.
- **`tempora/intelligence/threshold.py`** (`GapDetector`): Maintains internal mathematical state with an $O(1)$ memory footprint. Tracks Causality Violations, catches time travel, and feeds payloads into the entropy calculator.
- **`tempora/intelligence/entropy.py`**: Runs rolling Shannon Entropy logic dynamically on string payloads to catch synthetic script-generated logs.
- **`tempora/intelligence/pii.py`** (`PIISweeper`): Acts sequentially on unformatted string payloads to extract indicators of compromise (Email, IPv4, API tokens) using pre-compiled regex strategies (MITRE T1005).
- **`tempora/intelligence/scoring.py`**: Evaluates gap duration scalars and mathematically deducts Trust Confidence penalties based on causality, alibi failures, and entropy limits to compute a global system score.
- **`tempora/reporting/reporter.py`** (`Reporter`): Aggregates verified anomalies and gracefully sinks them to the visual ASCII timeline, JSON/CSV pipelines, and rendering the highly structured HTML forensic dashboard.
- **`tempora/config/settings.py`** (`Config`): Stores runtime fallbacks, default gap thresholds, and safe intervals. Supports dynamic `load_from_json()`.

## Stream Processing Strategy

Common log parsing utilities invoke `readlines()`, holding huge structures in program memory. A 10GB file causes traditional DOM-style analysis to OOM crash.

Tempora strictly employs **Generators (`yield`)**, ensuring memory usage remains statically bound entirely to configuration overhead. A 500GB server log runs on the exact same micro-footprint of RAM as a 50KB text file.
