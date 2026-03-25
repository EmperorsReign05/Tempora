"""
Reporting and visualization of detection results.
"""
import json
from typing import List, Dict, Any
from datetime import datetime

from detector import Gap
from severity import calculate_global_suspicion, Severity
from utils import format_duration

class Reporter:
    """Consolidates gaps and renders them in various formats."""
    def __init__(self, gaps: List[Gap], total_lines: int, file_start: datetime, file_end: datetime, threshold: int, is_interactive: bool, malformed_count: int, max_gap_violations: int):
        self.gaps = gaps
        self.total_lines = total_lines
        self.file_start = file_start
        self.file_end = file_end
        self.threshold = threshold
        self.is_interactive = is_interactive
        self.malformed_count = malformed_count
        self.max_gap_violations = max_gap_violations
        self.gap_durations = [g.duration_seconds for g in self.gaps]

    def _generate_insights(self) -> List[str]:
        """Generate intelligent pattern insights from the gap data."""
        insights = []
        if not self.gaps:
            return ["No anomalies detected. Log patterns are consistent."]
            
        # Count severities
        low_gaps = sum(1 for g in self.gaps if g.severity == Severity.LOW)
        medium_gaps = sum(1 for g in self.gaps if g.severity == Severity.MEDIUM)
        
        # 1. Frequent short gaps
        if low_gaps >= 3:
            insights.append(f"Frequent short gaps detected ({low_gaps} occurrences). This pattern may indicate beaconing behavior or intermittent endpoint failures.")
            
        # 2. Clustered gaps checking
        if len(self.gaps) > 1:
            # check the time between gaps natively.
            clusters = 0
            for i in range(1, len(self.gaps)):
                time_between = (self.gaps[i].start_time - self.gaps[i-1].end_time).total_seconds()
                if time_between < 600: # 10 minutes between gaps
                    clusters += 1
            if clusters >= 2:
                insights.append(f"Clustered anomalies detected (gaps occurring in close temporal proximity). This may indicate coordinated tampering or systemic cascading failures.")

        if not insights:
            insights.append("Gaps detected appear isolated without obvious clustering.")
            
        return insights

    def _generate_summary_dict(self) -> Dict[str, Any]:
        """Generate structured summary dictionary."""
        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations, 
            self.total_lines, 
            self.malformed_count, 
            self.max_gap_violations, 
            alibi_failures
        )
        insights = self._generate_insights()
        
        return {
            "total_lines_analyzed": self.total_lines,
            "total_gaps_detected": len(self.gaps),
            "longest_gap_seconds": max(self.gap_durations) if self.gap_durations else 0,
            "longest_gap_formatted": format_duration(max(self.gap_durations)) if self.gap_durations else "0s",
            "suspicion_score": round(score, 4),
            "system_status": status.value,
            "trust_percentage": trust,
            "reason": reason,
            "insights": insights
        }

    def print_cli_report(self):
        """Print a human-readable report to console."""
        print("=== Tempora: Forensic Log Analysis ===")
        print("=== Configuration ===")
        print(f"Threshold: {self.threshold} seconds")
        print(f"Execution Mode: {'Interactive' if self.is_interactive else 'CLI'}")
        
        config_source = "Custom (CLI override)" if self.threshold != 60 else "Default"
        print(f"Configuration Source: {config_source}")
        print("=====================")
        print("Note: Gaps below threshold are ignored\n")

        if not self.gaps:
            print("No suspicious gaps detected. Log appears contiguous.\n")
            return

        for idx, gap in enumerate(self.gaps, 1):
            print(f"Gap Detected #{idx}:")
            print(f"  Start:    {gap.start_time.strftime('%Y-%m-%d %H:%M:%S')} (Line {gap.start_line_num})")
            print(f"  End:      {gap.end_time.strftime('%Y-%m-%d %H:%M:%S')} (Line {gap.end_line_num})")
            print(f"  Duration: {format_duration(gap.duration_seconds)}")
            print(f"  Severity: {gap.severity.value}")
            
            if gap.alibi_evidence_count > 0:
                print(f"  [!] ALIBI FAILURE: Secondary log confirmed {gap.alibi_evidence_count} events during this silent gap.")
                print(f"      -> Confirms intentional log deletion/tampering.")
            print("")

    def print_summary(self):
        """Print summary metrics."""
        summary = self._generate_summary_dict()
        print("=== ANALYSIS SUMMARY ===")
        print(f"Total Lines Parsed:  {summary['total_lines_analyzed']}")
        print(f"Total Gaps:          {summary['total_gaps_detected']}")
        if self.gaps:
            print(f"Longest Gap:         {summary['longest_gap_formatted']}")
        print(f"Suspicion Score:     {summary['suspicion_score']}")
        print(f"System Status:       {summary['system_status']}")
        print(f"Trust Confidence:    {summary['trust_percentage']}%")
        print(f"Reason:              {summary['reason']}")
        
        print("\n--- Intelligent Insights ---")
        for idx, insight in enumerate(summary['insights'], 1):
            print(f"{idx}. {insight}")
        print("========================", end="\n\n")

    def print_json(self):
        """Output all data as a structured JSON."""
        output = {
            "summary": self._generate_summary_dict(),
            "gaps": [
                {
                    "start_time": gap.start_time.isoformat(),
                    "end_time": gap.end_time.isoformat(),
                    "duration_seconds": gap.duration_seconds,
                    "severity": gap.severity.value,
                    "start_line": gap.start_line_num,
                    "end_line": gap.end_line_num,
                }
                for gap in self.gaps
            ]
        }
        print(json.dumps(output, indent=2))

    def print_ascii_timeline(self, width: int = 60):
        """
        Generate a normalized ASCII timeline representing the log file duration.
        Buckets the total duration into 'width' slots.
        The highest severity gap occurring within a bucket determines its character.
        """
        if not self.file_start or not self.file_end:
            print("[Timeline unavailable: missing start/end markers]")
            return
            
        total_duration = (self.file_end - self.file_start).total_seconds()
        if total_duration <= 0:
            print("[Timeline unavailable: duration is zero or negative]")
            return

        print("=== TIMELINE NORMALIZATION VISUALIZATION ===")
        print(f"Start: {self.file_start.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Initialize an empty timeline array of the given width
        timeline_buckets = ['.'] * width
        bucket_duration = total_duration / width
        
        for gap in self.gaps:
            # A gap spans from gap.start_time to gap.end_time
            # We color all buckets it touches
            start_offset = (gap.start_time - self.file_start).total_seconds()
            end_offset = (gap.end_time - self.file_start).total_seconds()
            
            start_idx = int(start_offset / bucket_duration)
            end_idx = int(end_offset / bucket_duration)
            
            # Bound safely
            start_idx = max(0, min(width - 1, start_idx))
            end_idx = max(start_idx, min(width - 1, end_idx))
            
            char = '!' if gap.severity == Severity.LOW else 'x'
            if gap.severity == Severity.HIGH:
                char = 'X'
                
            for i in range(start_idx, end_idx + 1):
                # Ensure we only upgrade severity, never downgrade a previous gap's bucket
                current_char = timeline_buckets[i]
                if char == 'X':
                    timeline_buckets[i] = 'X'
                elif char == 'x' and current_char != 'X':
                    timeline_buckets[i] = 'x'
                elif char == '!' and current_char == '.':
                    timeline_buckets[i] = '!'
            
        timeline_str = "".join(timeline_buckets)
        print(f"[{timeline_str}]")
        print(f"End:   {self.file_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Legend: [.] OK   [!] LOW gap   [x] MEDIUM gap   [X] HIGH gap")
        print("Visualization reflects only gaps above configured threshold")
        print("==============================", end="\n\n")
