import hashlib
from typing import List, Iterator, Optional
from datetime import datetime

from tempora.core.models import Gap
from tempora.parsers.base import BaseParser
from tempora.intelligence.threshold import GapDetector
from tempora.intelligence.pii import PIISweeper
from tempora.intelligence.cloud.iam_analysis import IAMAnalyzer
from tempora.intelligence.cloud.impossible_travel import ImpossibleTravelDetector
from tempora.config.settings import Config
from tempora.reporting.reporter import Reporter
import sys


def print_warning(msg: str):
    print(msg, file=sys.stderr)


class TemporaAnalyzer:
    """
    Core execution engine for Tempora. Orchestrates the flow of log events
    through the underlying intelligence processors (GapDetector, IAMAnalyzer, etc.).
    """

    def __init__(self, parser: BaseParser, config: Config, scan_pii: bool = False):
        self.parser = parser
        self.config = config
        self.scan_pii = scan_pii
        self.pii_sweeper = PIISweeper() if scan_pii else None
        self.detector = GapDetector(
            min_threshold=config.min_gap_threshold,
            max_gap=config.max_reasonable_gap,
            safe_intervals=config.safe_intervals,
            business_hours=config.business_hours,
        )
        self.iam_analyzer = IAMAnalyzer(config)
        self.travel_detector = ImpossibleTravelDetector(config)

        self.gaps: List[Gap] = []
        self.cloud_alerts: List[str] = []
        self.total_lines = 0
        self.malformed_count = 0
        self.max_gap_violations = 0
        self.file_start: Optional[datetime] = None
        self.file_end: Optional[datetime] = None

    def analyze_stream(
        self,
        lines: Iterator[str],
        source_name: str = "stream",
        live_output: bool = False,
    ) -> Reporter:
        """
        Processes an iterative stream of raw log lines in O(1) memory.
        """
        for line_num, line in enumerate(lines, 1):
            log_line = self.parser.parse_line(line, line_num)
            if log_line:
                if self.pii_sweeper:
                    self.pii_sweeper.scan(log_line.raw_payload)
                if not self.file_start:
                    self.file_start = log_line.timestamp
                self.file_end = log_line.timestamp

                if (
                    self.detector.last_log_line
                    and (
                        log_line.timestamp - self.detector.last_log_line.timestamp
                    ).total_seconds()
                    > self.detector.max_gap
                ):
                    self.max_gap_violations += 1

                for gap in self.detector.process_line(log_line):
                    if live_output:
                        print(
                            f"⚠️ [STREAM] GAP DETECTED: {gap.start_time.strftime('%H:%M:%S')} -> {gap.end_time.strftime('%H:%M:%S')} ({int(gap.duration_seconds)}s) [{gap.severity.value}]"
                        )
                    self.gaps.append(gap)

                iam_alert = self.iam_analyzer.process_event(log_line)
                if iam_alert:
                    self.cloud_alerts.append(iam_alert)
                    if live_output:
                        print(iam_alert)

                travel_alert = self.travel_detector.process_event(log_line)
                if travel_alert:
                    self.cloud_alerts.append(travel_alert)
                    if live_output:
                        print(travel_alert)
            else:
                self.malformed_count += 1

            self.total_lines = line_num

        return self.generate_reporter(source_name)

    def generate_reporter(self, source_name: str, file_hash: str = "N/A") -> Reporter:
        pii_leaks = getattr(self.pii_sweeper, "total_leaks", 0) if self.scan_pii else 0
        return Reporter(
            gaps=self.gaps,
            total_lines=self.total_lines,
            file_start=self.file_start,
            file_end=self.file_end,
            threshold=self.config.min_gap_threshold,
            malformed_count=self.malformed_count,
            max_gap_violations=self.max_gap_violations,
            causality_count=len(self.detector.causality_violations),
            forgery_count=len(self.detector.forgeries),
            source_file=source_name,
            file_hash=file_hash,
            pii_leaks=pii_leaks,
            cloud_alerts=self.cloud_alerts,
        )

    def analyze_file(self, filepath: str) -> Reporter:
        """
        Analyzes a static local file, automatically calculating its SHA-256 hash.
        """
        file_hash = "N/A"
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            file_hash = h.hexdigest()
        except Exception:
            pass

        def line_generator():
            is_pretty_json = False
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline().strip()
                # If the line is just '{' or starts with '{' but doesn't end with '}', it's likely pretty-printed
                if first_line == "{" or (first_line.startswith("{") and not first_line.endswith("}")):
                    is_pretty_json = True

            if is_pretty_json:
                import json
                print_warning("\n[!] PRETTY-PRINTED JSON DETECTED: Falling back to in-memory JSON parser. O(1) memory guarantees are disabled.")
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    try:
                        data = json.load(f)
                        records = data.get("Records", []) if isinstance(data, dict) else []
                        if not records:
                            records = data if isinstance(data, list) else [data]
                        for r in records:
                            # Yield as JSON-Lines strings so the downstream parser works normally
                            yield json.dumps(r)
                    except Exception as e:
                        print_warning(f"[!] Failed to parse pretty JSON: {e}")
                return

            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line

        reporter = self.analyze_stream(line_generator(), source_name=filepath)
        reporter.file_hash = file_hash
        return reporter

    def run_alibi_protocol(self, alibi_files: List[str]):
        """
        The Alibi Protocol cross-references primary gaps against secondary logs
        to cryptographically prove intentional timeline suppression.
        """
        if not self.gaps:
            return

        for alibi_file in alibi_files:
            try:
                with open(alibi_file, "r", encoding="utf-8", errors="replace") as f:
                    for alibi_line_num, line in enumerate(f, 1):
                        alibi_log = self.parser.parse_line(line, alibi_line_num)
                        if alibi_log:
                            for gap in self.gaps:
                                if gap.start_time < alibi_log.timestamp < gap.end_time:
                                    gap.alibi_evidence_count += 1
            except FileNotFoundError:
                print_warning(
                    f"[!] ALIBI PROTOCOL SKIPPED: Secondary log not found '{alibi_file}'"
                )
            except PermissionError:
                print_warning(
                    f"[!] ALIBI PROTOCOL SKIPPED: Insufficient permissions to read '{alibi_file}'"
                )
            except Exception as e:
                print_warning(
                    f"[!] ALIBI PROTOCOL FAILED: Unhandled exception during cross-reference on '{alibi_file}': {e}"
                )
