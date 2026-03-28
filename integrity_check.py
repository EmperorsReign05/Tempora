"""
Tempora: Automated Log Integrity Monitor
Deliverable: integrity_check.py
"""
import sys
import os
import argparse
import re
import math
import json
import csv
from typing import Iterator, List, Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter
from enum import Enum

class LogAnalyzerError(Exception):
    pass
class ConfigurationError(LogAnalyzerError):
    pass
class LogParseError(LogAnalyzerError):
    pass
class MalformedLineWarning(Warning):
    pass

def print_warning(msg: str):
    print(msg, file=sys.stderr)

def print_error(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)

def generate_lines(file_path: str) -> Iterator[str]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield line

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class SystemStatus(Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"

@dataclass
class Config:
    min_gap_threshold: int = 60
    max_reasonable_gap: int = 172800 
    timestamp_formats: List[str] = field(default_factory=lambda: [
        "%y%m%d %H%M%S",        
        "%Y-%m-%d %H:%M:%S,%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%b %d %H:%M:%S"
    ])
    safe_intervals: List[Tuple[datetime, datetime]] = field(default_factory=list)

DEFAULT_CONFIG = Config()

@dataclass
class LogLine:
    timestamp: datetime
    raw_payload: str
    line_number: int

class LogParser:
    def __init__(self, custom_formats=None):
        self.formats = custom_formats or DEFAULT_CONFIG.timestamp_formats
        self._pattern = re.compile(
            r'^(?P<time_str>\d{2,4}[-/]?\d{2}[-/]?\d{2}[T\s]?\d{2}:\d{2}:\d{2}(?:\.\d+)?|' 
            r'\d{6}\s+\d{6}|' 
            r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        )

    def _parse_timestamp(self, time_str: str) -> Optional[datetime]:
        for fmt in self.formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return None

    def parse_line(self, line: str, line_num: int) -> Optional[LogLine]:
        line = line.strip()
        if not line: return None
        match = self._pattern.search(line)
        if match:
            time_str = match.group('time_str')
            timestamp = self._parse_timestamp(time_str)
            if timestamp:
                return LogLine(timestamp=timestamp, raw_payload=line, line_number=line_num)
        return None

def calculate_severity(duration_seconds: float) -> Severity:
    if duration_seconds > 3600: return Severity.HIGH
    if duration_seconds > 300: return Severity.MEDIUM
    return Severity.LOW

@dataclass
class CausalityViolation:
    timestamp_before: datetime
    timestamp_after: datetime
    line_num: int

@dataclass
class Forgery:
    timestamp: datetime
    line_num: int
    entropy: float
    raw_text: str

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    p, lns = Counter(text), float(len(text))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

@dataclass
class Gap:
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    severity: Severity
    start_line_num: int
    end_line_num: int
    alibi_evidence_count: int = 0

class GapDetector:
    def __init__(self, min_threshold: int = 60, max_gap: int = 172800, safe_intervals=None):
        self.min_threshold = min_threshold
        self.max_gap = max_gap
        self.safe_intervals = safe_intervals or []
        self.last_log_line = None
        
        self.total_lines_processed = 0
        self.causality_violations: List[CausalityViolation] = []
        self.forgeries: List[Forgery] = []
        self.rolling_entropy = 0.0
        self.entropy_count = 0

    def _is_in_safe_interval(self, start: datetime, end: datetime) -> bool:
        for safe_start, safe_end in self.safe_intervals:
            if start >= safe_start and end <= safe_end: return True
        return False

    def process_line(self, log_line: LogLine) -> Iterator[Gap]:
        self.total_lines_processed += 1
        
        payload_text = log_line.raw_payload[20:]
        text_entropy = calculate_entropy(payload_text)
        is_forged = False
        if self.entropy_count > 50 and len(payload_text) > 20:
             if text_entropy < (self.rolling_entropy * 0.75) or text_entropy < 3.0: 
                 self.forgeries.append(Forgery(log_line.timestamp, log_line.line_number, text_entropy, log_line.raw_payload[:60]))
                 is_forged = True
                 
        if not is_forged:
            self.rolling_entropy = (self.rolling_entropy * self.entropy_count + text_entropy) / (self.entropy_count + 1)
        self.entropy_count += 1
        
        if self.last_log_line:
            delta = log_line.timestamp - self.last_log_line.timestamp
            duration = delta.total_seconds()
            
            if duration < 0:
                self.causality_violations.append(CausalityViolation(self.last_log_line.timestamp, log_line.timestamp, log_line.line_number))
                self.last_log_line = log_line
                return
            
            if duration > self.max_gap:
                print_warning(f"⚠️ Detected unrealistic time jump ({duration}s). Possible validation error.")
            elif duration >= self.min_threshold:
                if not self._is_in_safe_interval(self.last_log_line.timestamp, log_line.timestamp):
                    severity = calculate_severity(duration)
                    yield Gap(
                        start_time=self.last_log_line.timestamp,
                        end_time=log_line.timestamp,
                        duration_seconds=duration,
                        severity=severity,
                        start_line_num=self.last_log_line.line_number,
                        end_line_num=log_line.line_number
                    )
        self.last_log_line = log_line

def calculate_global_suspicion(gap_durations: List[float], total_lines: int, malformed_count: int = 0, max_gap_violations: int = 0, alibi_failures: int = 0, causality_count: int = 0, forgery_count: int = 0) -> Tuple[float, SystemStatus, int, str]:
    if total_lines == 0: return 0.0, SystemStatus.NORMAL, 100, "Log file implies normal contiguous structure"

    high_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.HIGH)
    medium_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.MEDIUM)
    low_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.LOW)
    
    trust = 100.0
    trust -= (low_count * 2)
    trust -= (medium_count * 5)
    trust -= (high_count * 15)
    trust -= (max_gap_violations * 20)
    trust -= (causality_count * 30)
    trust -= (forgery_count * 20)
    trust -= (malformed_count * 0.1) 
    
    if alibi_failures > 0: trust -= 50
    trust = max(0, min(100, int(trust)))

    reasons = []
    if alibi_failures > 0: reasons.append(f"CRITICAL: {alibi_failures} Alibi Failures detected (Proven tampering)")
    if causality_count > 0: reasons.append(f"CAUSALITY VIOLATION: {causality_count} reverse-time jumps detected")
    if forgery_count > 0: reasons.append(f"SYNTHETIC FORGERY: {forgery_count} instances of Shannon Entropy collapse")
    if high_count > 0: reasons.append("Major timeline disruptions (HIGH gaps)")
    if max_gap_violations > 0: reasons.append(f"{max_gap_violations} instances of catastrophic timestamp inconsistency")
    if malformed_count > (total_lines * 0.01): reasons.append("Unusually high volume of malformed/corrupted lines")
    
    if not reasons and trust < 100: reasons.append("Minor temporal inconsistencies degrading reliability")
    elif not reasons: reasons.append("Perfect contiguous structural integrity")

    reason_str = " | ".join(reasons)
    score = (high_count * 3 + medium_count * 2 + low_count * 1) / total_lines
    
    if alibi_failures > 0 or trust < 50: status = SystemStatus.COMPROMISED
    elif trust < 85: status = SystemStatus.SUSPICIOUS
    else: status = SystemStatus.NORMAL
        
    return score, status, trust, reason_str

def format_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    parts = []
    if d > 0: parts.append(f"{d}d")
    if h > 0: parts.append(f"{h}h")
    if m > 0: parts.append(f"{m}m")
    if s > 0 or not parts: parts.append(f"{s}s")
    return " ".join(parts)

class Reporter:
    def __init__(self, gaps: List[Gap], total_lines: int, file_start: datetime, file_end: datetime, threshold: int, malformed_count: int, max_gap_violations: int, causality_count: int, forgery_count: int):
        self.gaps = gaps
        self.total_lines = total_lines
        self.file_start = file_start
        self.file_end = file_end
        self.threshold = threshold
        self.malformed_count = malformed_count
        self.max_gap_violations = max_gap_violations
        self.causality_count = causality_count
        self.forgery_count = forgery_count
        self.gap_durations = [g.duration_seconds for g in self.gaps]

    def print_core_report(self):
        """Prints the STRICT REQUIRED deliverable format."""
        if not self.gaps:
            print("No Gaps Detected.")
            return
            
        for gap in self.gaps:
            print("Gap Detected")
            print(f"Start: {gap.start_time.strftime('%H:%M:%S')}")
            print(f"End: {gap.end_time.strftime('%H:%M:%S')}")
            print(f"Duration: {int(gap.duration_seconds)} seconds")
            if gap.alibi_evidence_count > 0:
                print(f"[ALIBI FAILED: Cross-log events detected in this window]")
            print()
            
        print(f"Total Gaps Found: {len(self.gaps)}")

    def print_advanced_summary(self):
        print("\n" + "="*40)
        print("=== TEMPORA ADVANCED INTEGRITY MATRIX ===")
        print("="*40)
        
        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations, self.total_lines, self.malformed_count, 
            self.max_gap_violations, alibi_failures, self.causality_count, self.forgery_count
        )
        
        print(f"Total Lines Processed: {self.total_lines}")
        print(f"System Status:         {status.value}")
        print(f"Log Trust Confidence:  {trust}%")
        print(f"Reason:                {reason}")
        
        if not self.file_start or not self.file_end: return
        total_span = (self.file_end - self.file_start).total_seconds()
        if total_span <= 0: return
        
        print("\n=== TIMELINE NORMALIZATION VISUALIZATION ===")
        print(f"Start: {self.file_start.strftime('%Y-%m-%d %H:%M:%S')}")
        
        timeline_buckets = ['.'] * 60
        bucket_size = total_span / 60
        
        for gap in self.gaps:
            span_start = max(0, (gap.start_time - self.file_start).total_seconds())
            bucket_idx = min(59, int(span_start / bucket_size))
            if gap.severity == Severity.HIGH: timeline_buckets[bucket_idx] = 'X'
            elif gap.severity == Severity.MEDIUM: timeline_buckets[bucket_idx] = 'x'
            else: timeline_buckets[bucket_idx] = '!'
            
        timeline_str = "".join(timeline_buckets)
        print(f"[{timeline_str}]")
        print(f"End:   {self.file_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Legend: [.] OK   [!] LOW gap   [x] MEDIUM gap   [X] HIGH gap")
        print("============================================")

    def print_json(self):
        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations, self.total_lines, self.malformed_count, 
            self.max_gap_violations, alibi_failures, self.causality_count, self.forgery_count
        )
        
        output = {
            "metadata": {
                "file_start": self.file_start.isoformat() if self.file_start else None,
                "file_end": self.file_end.isoformat() if self.file_end else None,
                "total_lines_processed": self.total_lines,
                "threshold_seconds": self.threshold
            },
            "anomalies": {
                "total_gaps_found": len(self.gaps),
                "malformed_lines_skipped": self.malformed_count,
                "causality_violations_detected": self.causality_count,
                "shannon_entropy_collapses": self.forgery_count,
                "alibi_failures_detected": alibi_failures
            },
            "trust_metrics": {
                "system_status": status.value,
                "log_trust_confidence_percent": trust,
                "suspicion_reason": reason
            },
            "detailed_gaps": [
                {
                    "start_time": g.start_time.isoformat(),
                    "end_time": g.end_time.isoformat(),
                    "duration_seconds": int(g.duration_seconds),
                    "severity": g.severity.value,
                    "alibi_events_caught": g.alibi_evidence_count
                } for g in self.gaps
            ]
        }
        print(json.dumps(output, indent=2))

    def print_csv(self):
        writer = csv.writer(sys.stdout)
        
        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations, self.total_lines, self.malformed_count, 
            self.max_gap_violations, alibi_failures, self.causality_count, self.forgery_count
        )
        
        writer.writerow([
            "start_time", "end_time", "duration_seconds", "severity", 
            "alibi_events_caught", "total_causality_violations", 
            "shannon_entropy_collapses", "system_trust_confidence", "system_status"
        ])
        
        for g in self.gaps:
            writer.writerow([
                g.start_time.isoformat(),
                g.end_time.isoformat(),
                int(g.duration_seconds),
                g.severity.value,
                g.alibi_evidence_count,
                self.causality_count,
                self.forgery_count,
                f"{trust}%",
                status.value
            ])

def print_banner():
    banner = """\033[96m████████╗███████╗███╗   ███╗██████╗  ██████╗ ██████╗  █████╗ 
╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗
   ██║   █████╗  ██╔████╔██║██████╔╝██║   ██║██████╔╝███████║
   ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║   ██║██╔══██╗██╔══██║
   ██║   ███████╗██║ ╚═╝ ██║██║     ╚██████╔╝██║  ██║██║  ██║
   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\033[0m"""
    print(banner)
    print("\033[1m Tempora CLI — Forensic Log Integrity Analyzer \033[0m")
    print("=" * 63 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Tempora: Automated Log Integrity Monitor (integrity_check.py)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("logfile", nargs='?', default="logfile.log", help="Path to the log file to analyze")
    parser.add_argument("--alibi", type=str, default=None, help="Secondary log file to cross-reference (The Alibi Protocol)")
    parser.add_argument("--threshold", type=int, default=DEFAULT_CONFIG.min_gap_threshold, help="Minimum gap duration in seconds")
    parser.add_argument("--format", type=str, choices=["text", "json", "csv"], default="text", help="Output format (text, json, or csv)")
    parser.add_argument("--verbose", action="store_true", help="Print verbose warnings")
    parser.add_argument("--interactive", action="store_true", help="Launch the interactive wizard")
                        
    args = parser.parse_args()
    
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8')
    
    if args.format == "text":
        print_banner()

    if args.interactive:
        print("\033[1m[*] Welcome to the Tempora Interactive Setup Wizard\033[0m")
        log_in = input(f" [?] Path to the primary log file [{args.logfile}]: ").strip()
        if log_in: args.logfile = log_in
        
        thr_in = input(f" [?] Minimum gap threshold in seconds [{args.threshold}]: ").strip()
        if thr_in.isdigit(): args.threshold = int(thr_in)
        
        alibi_in = input(f" [?] (Optional) Path to a secondary log for the Alibi Protocol [None]: ").strip()
        if alibi_in: args.alibi = alibi_in
        
        print("\n[*] Initializing continuous forensic pipeline...\n")

    config = Config(min_gap_threshold=args.threshold)
    log_parser = LogParser(custom_formats=config.timestamp_formats)
    detector = GapDetector(min_threshold=config.min_gap_threshold, max_gap=config.max_reasonable_gap, safe_intervals=config.safe_intervals)
    
    gaps = []
    total_lines = 0
    malformed_count = 0
    max_gap_violations = 0
    file_start = None
    file_end = None

    try:
        for line_num, line in enumerate(generate_lines(args.logfile), 1):
            log_line = log_parser.parse_line(line, line_num)
            if log_line:
                if not file_start: file_start = log_line.timestamp
                file_end = log_line.timestamp
                
                if detector.last_log_line and (log_line.timestamp - detector.last_log_line.timestamp).total_seconds() > detector.max_gap:
                     max_gap_violations += 1

                for gap in detector.process_line(log_line):
                    gaps.append(gap)
            else:
                malformed_count += 1
                if args.verbose: print_warning(f"Line {line_num} malformed: {line.strip()[:50]}...")
            
            total_lines = line_num
            
    except FileNotFoundError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)

    if args.alibi and gaps:
        alibi_parser = LogParser(custom_formats=config.timestamp_formats)
        try:
            for alibi_line_num, line in enumerate(generate_lines(args.alibi), 1):
                alibi_log = alibi_parser.parse_line(line, alibi_line_num)
                if alibi_log:
                    for gap in gaps:
                        if gap.start_time < alibi_log.timestamp < gap.end_time:
                            gap.alibi_evidence_count += 1
        except FileNotFoundError as e:
            print_warning(f"[!] ALIBI PROTOCOL SKIPPED: Secondary log not found '{args.alibi}'")
        except PermissionError:
            print_warning(f"[!] ALIBI PROTOCOL SKIPPED: Insufficient permissions to read '{args.alibi}'")
        except Exception as e:
            print_warning(f"[!] ALIBI PROTOCOL FAILED: Unhandled exception during cross-reference: {e}")

    reporter = Reporter(gaps, total_lines, file_start, file_end, config.min_gap_threshold, malformed_count, max_gap_violations, len(detector.causality_violations), len(detector.forgeries))
    
    if args.format == "json":
        reporter.print_json()
    elif args.format == "csv":
        reporter.print_csv()
    else:
        reporter.print_core_report()
        reporter.print_advanced_summary()

if __name__ == "__main__":
    main()
