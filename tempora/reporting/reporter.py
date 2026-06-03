import sys
import json
import csv
import statistics
from datetime import datetime
from typing import List, Dict, Any, Optional
from tempora.core.models import Gap, SystemStatus, Severity, Colors
from tempora.intelligence.scoring import calculate_global_suspicion
from tempora.intelligence.threshold import calculate_severity


def format_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    parts = []
    if d > 0:
        parts.append(f"{d}d")
    if h > 0:
        parts.append(f"{h}h")
    if m > 0:
        parts.append(f"{m}m")
    if s > 0 or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


class Reporter:
    def __init__(
        self,
        gaps: List[Gap],
        total_lines: int,
        file_start: Optional[datetime],
        file_end: Optional[datetime],
        threshold: int,
        malformed_count: int,
        max_gap_violations: int,
        causality_count: int,
        forgery_count: int,
        source_file: str,
        file_hash: str,
        pii_leaks: int,
        cloud_alerts: List[str] = None,
    ):
        self.gaps = gaps
        self.total_lines = total_lines
        self.file_start = file_start
        self.file_end = file_end
        self.threshold = threshold
        self.malformed_count = malformed_count
        self.max_gap_violations = max_gap_violations
        self.causality_count = causality_count
        self.forgery_count = forgery_count
        self.source_file = source_file
        self.file_hash = file_hash
        self.pii_leaks = pii_leaks
        self.cloud_alerts = cloud_alerts or []
        self.gap_durations = [g.duration_seconds for g in self.gaps]

    def _build_enriched_payload(self) -> Dict[str, Any]:
        """Builds the enriched JSON payload used by all output formats."""
        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations,
            self.total_lines,
            self.malformed_count,
            self.max_gap_violations,
            alibi_failures,
            self.causality_count,
            self.forgery_count,
        )

        total_span = 0
        if self.file_start and self.file_end:
            total_span = (self.file_end - self.file_start).total_seconds()

        high_c = sum(
            1 for d in self.gap_durations if calculate_severity(d) == Severity.HIGH
        )
        med_c = sum(
            1 for d in self.gap_durations if calculate_severity(d) == Severity.MEDIUM
        )
        low_c = sum(
            1 for d in self.gap_durations if calculate_severity(d) == Severity.LOW
        )

        # Build trust deduction breakdown
        deductions = []
        if low_c > 0:
            deductions.append(f"LOW gaps ({low_c}x): -{low_c * 2}")
        if med_c > 0:
            deductions.append(f"MEDIUM gaps ({med_c}x): -{med_c * 5}")
        if high_c > 0:
            deductions.append(f"HIGH gaps ({high_c}x): -{high_c * 15}")
        if self.max_gap_violations > 0:
            deductions.append(
                f"Max gap violations ({self.max_gap_violations}x): -{self.max_gap_violations * 20}"
            )
        if self.causality_count > 0:
            deductions.append(
                f"Causality violations ({self.causality_count}x): -{self.causality_count * 30}"
            )
        if self.forgery_count > 0:
            deductions.append(
                f"Entropy collapses ({self.forgery_count}x): -{self.forgery_count * 20}"
            )
        if alibi_failures > 0:
            deductions.append("Alibi failures: -50")
        if self.malformed_count > 0:
            deductions.append(
                f"Malformed lines ({self.malformed_count}x): -{self.malformed_count * 0.1:.1f}"
            )

        return {
            "metadata": {
                "analysis_timestamp": datetime.now().isoformat(),
                "source_file": self.source_file,
                "chain_of_custody_sha256": self.file_hash,
                "file_start": self.file_start.isoformat() if self.file_start else None,
                "file_end": self.file_end.isoformat() if self.file_end else None,
                "total_lines_processed": self.total_lines,
                "threshold_seconds": self.threshold,
                "total_timespan_seconds": int(total_span) if total_span else 0,
            },
            "anomalies": {
                "total_gaps_found": len(self.gaps),
                "severity_breakdown": {"HIGH": high_c, "MEDIUM": med_c, "LOW": low_c},
                "malformed_lines_skipped": self.malformed_count,
                "causality_violations_detected": self.causality_count,
                "shannon_entropy_collapses": self.forgery_count,
                "alibi_failures_detected": alibi_failures,
                "pii_leakage_events": getattr(self, "pii_leaks", 0),
                "cloud_alerts": self.cloud_alerts,
            },
            "trust_metrics": {
                "system_status": status.value,
                "log_trust_confidence_percent": trust,
                "suspicion_reason": reason,
                "trust_deduction_breakdown": deductions,
            },
            "detailed_gaps": [
                {
                    "start_time": g.start_time.isoformat(),
                    "end_time": g.end_time.isoformat(),
                    "duration_seconds": int(g.duration_seconds),
                    "duration_human": format_duration(g.duration_seconds),
                    "severity": g.severity.value,
                    "start_line": g.start_line_num,
                    "end_line": g.end_line_num,
                    "position_percent": (
                        round(
                            (
                                (g.start_time - self.file_start).total_seconds()
                                / total_span
                            )
                            * 100,
                            1,
                        )
                        if total_span > 0
                        else 0
                    ),
                    "width_percent": (
                        round((g.duration_seconds / total_span) * 100, 1)
                        if total_span > 0
                        else 0
                    ),
                    "alibi_events_caught": g.alibi_evidence_count,
                }
                for g in self.gaps
            ],
        }

    def print_core_report(self):
        """Prints the STRICT REQUIRED deliverable format."""
        print(f"{Colors.BOLD}Source:{Colors.ENDC}    {self.source_file}")
        print(f"{Colors.BOLD}SHA-256:{Colors.ENDC}   {self.file_hash}")
        print(f"{Colors.BOLD}Threshold:{Colors.ENDC} {self.threshold}s")
        print(
            f"{Colors.BOLD}Scanned:{Colors.ENDC}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print()

        if not self.gaps:
            print(f"{Colors.OKGREEN}No Gaps Detected.{Colors.ENDC}")
            return

        for gap in self.gaps:
            color = Colors.OKCYAN
            if gap.severity == Severity.HIGH:
                color = Colors.FAIL
            elif gap.severity == Severity.MEDIUM:
                color = Colors.WARNING

            print(f"{color}Gap Detected [{gap.severity.value}]{Colors.ENDC}")
            print(
                f"  Start:    {gap.start_time.strftime('%H:%M:%S')} (line {gap.start_line_num})"
            )
            print(
                f"  End:      {gap.end_time.strftime('%H:%M:%S')} (line {gap.end_line_num})"
            )
            print(
                f"  Duration: {int(gap.duration_seconds)}s ({format_duration(gap.duration_seconds)})"
            )
            if gap.alibi_evidence_count > 0:
                print(
                    f"  {Colors.FAIL}[ALIBI FAILED: {gap.alibi_evidence_count} cross-log events in this window]{Colors.ENDC}"
                )
            print()

        print(f"{Colors.BOLD}Total Gaps Found: {len(self.gaps)}{Colors.ENDC}")

    def print_advanced_summary(self):
        print("\n" + Colors.OKCYAN + "=" * 40 + Colors.ENDC)
        print(f"{Colors.BOLD}=== TEMPORA ADVANCED INTEGRITY MATRIX ==={Colors.ENDC}")
        print(Colors.OKCYAN + "=" * 40 + Colors.ENDC)
        print(f"[✓] Chain of Custody (SHA-256): {self.file_hash}")

        mad_median = statistics.median(self.gap_durations) if self.gap_durations else 0
        mad = (
            statistics.median([abs(x - mad_median) for x in self.gap_durations])
            if self.gap_durations
            else 0
        )

        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations,
            self.total_lines,
            self.malformed_count,
            self.max_gap_violations,
            alibi_failures,
            self.causality_count,
            self.forgery_count,
        )

        status_color = Colors.OKGREEN
        if status == SystemStatus.COMPROMISED:
            status_color = Colors.FAIL
        elif status == SystemStatus.SUSPICIOUS:
            status_color = Colors.WARNING

        print(f"Total Lines Processed: {self.total_lines}")
        print(f"System Status:         {status_color}{status.value}{Colors.ENDC}")
        print(f"Log Trust Confidence:  {status_color}{trust}%{Colors.ENDC}")

        from tempora.reporting.narrative import NarrativeEngine

        engine = NarrativeEngine()
        narrative = engine.generate_narrative(self.gaps, self.cloud_alerts)

        print("\n[!] INCIDENT NARRATIVE & MITRE MAPPING")
        print(narrative)

        if self.cloud_alerts:
            print("\n=== CLOUD ALERTS ===")
            for alert in self.cloud_alerts:
                print(alert)

        print(f"\n{Colors.BOLD}=== ANOMALY BREAKDOWN ==={Colors.ENDC}")
        if self.gaps or self.causality_count > 0 or self.forgery_count > 0:
            for i, gap in enumerate(self.gaps, 1):
                print(
                    f"ID: GAP-{i:02d} | {gap.start_time.strftime('%H:%M:%S')} -> {gap.end_time.strftime('%H:%M:%S')} ({int(gap.duration_seconds)}s)"
                )

                if gap.duration_seconds > (mad * 3) and mad > 0:
                    print(
                        f"[CAUSE]    Statistical threshold explicitly violated (Deviation exceeds MAD limit: {mad:.1f}s)."
                    )
                else:
                    print(
                        f"[CAUSE]    Static threshold violated (Minimum enforced: {self.threshold}s)."
                    )

                if gap.alibi_evidence_count > 0:
                    print(
                        f"[ALIBI]    {gap.alibi_evidence_count} Background events contradicted silence (Consensus Failure)."
                    )

            if self.forgery_count > 0:
                print(
                    f"[EVIDENCE] Entropy collapse computed globally for {self.forgery_count} instances."
                )
            if self.causality_count > 0:
                print(
                    f"[EVIDENCE] Causality violated globally {self.causality_count} times."
                )
            if getattr(self, "pii_leaks", 0) > 0:
                print(
                    f"[LEAKAGE]  PII Exfiltration filter triggered {self.pii_leaks} times."
                )

        if not self.file_start or not self.file_end:
            return
        total_span = (self.file_end - self.file_start).total_seconds()
        if total_span <= 0:
            return

        print("\n=== TIMELINE NORMALIZATION VISUALIZATION ===")
        print(f"Start: {self.file_start.strftime('%Y-%m-%d %H:%M:%S')}")

        timeline_buckets = ["."] * 60
        bucket_size = total_span / 60

        for gap in self.gaps:
            span_start = max(0, (gap.start_time - self.file_start).total_seconds())
            bucket_idx = min(59, int(span_start / bucket_size))
            if gap.severity == Severity.HIGH:
                timeline_buckets[bucket_idx] = f"{Colors.FAIL}X{Colors.ENDC}"
            elif gap.severity == Severity.MEDIUM:
                timeline_buckets[bucket_idx] = f"{Colors.WARNING}x{Colors.ENDC}"
            else:
                timeline_buckets[bucket_idx] = f"{Colors.OKCYAN}!{Colors.ENDC}"

        timeline_str = "".join(timeline_buckets)
        print(f"[{timeline_str}]")
        print(f"End:   {self.file_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(
            f"Legend: [.] OK   {Colors.OKCYAN}[!] LOW gap{Colors.ENDC}   {Colors.WARNING}[x] MEDIUM gap{Colors.ENDC}   {Colors.FAIL}[X] HIGH gap{Colors.ENDC}"
        )
        print(
            Colors.OKCYAN + "============================================" + Colors.ENDC
        )

    def print_json(self):
        print(json.dumps(self._build_enriched_payload(), indent=2))

    def print_csv(self):
        writer = csv.writer(sys.stdout, lineterminator="\n")

        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations,
            self.total_lines,
            self.malformed_count,
            self.max_gap_violations,
            alibi_failures,
            self.causality_count,
            self.forgery_count,
        )

        writer.writerow(
            [
                "start_time",
                "end_time",
                "duration_seconds",
                "severity",
                "alibi_events_caught",
                "total_causality_violations",
                "shannon_entropy_collapses",
                "system_trust_confidence",
                "system_status",
            ]
        )

        for g in self.gaps:
            writer.writerow(
                [
                    g.start_time.isoformat(),
                    g.end_time.isoformat(),
                    int(g.duration_seconds),
                    g.severity.value,
                    g.alibi_evidence_count,
                    self.causality_count,
                    self.forgery_count,
                    f"{trust}%",
                    status.value,
                ]
            )

    def print_html(self):
        from tempora.reporting.html_reporter import generate_html_dashboard

        print(generate_html_dashboard(self._build_enriched_payload()))
