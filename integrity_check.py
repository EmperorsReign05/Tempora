import sys
import os
import argparse
import re
import math
import json
import csv
import hashlib
import statistics
from typing import Iterator, List, Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter
from enum import Enum

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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

    @classmethod
    def load_from_json(cls, path: str) -> "Config":
        if not os.path.exists(path):
            raise ConfigurationError(f"Config file not found: {path}")
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        cfg = cls()
        if "min_gap_threshold" in data: cfg.min_gap_threshold = int(data["min_gap_threshold"])
        if "max_reasonable_gap" in data: cfg.max_reasonable_gap = int(data["max_reasonable_gap"])
        if "timestamp_formats" in data: cfg.timestamp_formats = data["timestamp_formats"]
        return cfg

DEFAULT_CONFIG = Config()

@dataclass
class LogLine:
    timestamp: datetime
    raw_payload: str
    line_number: int

class PIISweeper:
    def __init__(self):
        self.rules = {
            "email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
            "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "api_key": re.compile(r'(?i)(?:key|token|secret)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9\-_]{16,})')
        }
        self.total_leaks = 0

    def scan(self, text: str):
        for pattern in self.rules.values():
            if pattern.search(text):
                self.total_leaks += 1

class LogParser:
    """
    Parses unformatted log lines using regex to extract timestamps.
    Automatically identifies common log time formats (ISO 8601, syslog, basic).
    """
    def __init__(self, custom_formats=None):
        self.formats = custom_formats or DEFAULT_CONFIG.timestamp_formats
        # Pre-compiled general regex designed to quickly catch standard time formats at the start of a line
        self._pattern = re.compile(
            r'^(?P<time_str>\d{2,4}[-/]?\d{2}[-/]?\d{2}[T\s]?\d{2}:\d{2}:\d{2}(?:\.\d+)?|' 
            r'\d{6}\s+\d{6}|' 
            r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        )

    def _parse_timestamp(self, time_str: str) -> Optional[datetime]:
        """Attempts to match extracted time string against available formats."""
        for fmt in self.formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                # If year isn't present in log (like in syslog `%b %d %H:%M:%S`), default to current year.
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return None

    def parse_line(self, line: str, line_num: int) -> Optional[LogLine]:
        """Parse raw log line, identify timestamp and reconstruct a LogLine metadata object."""
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
    """Represents a scenario where log timestamps travel back in time, indicating spoofing or clock sync failures."""
    timestamp_before: datetime
    timestamp_after: datetime
    line_num: int

@dataclass
class Forgery:
    """Represents an anomaly caught by the Shannon Entropy filter, usually indicating synthetic/scripted dummy logs injected as noise."""
    timestamp: datetime
    line_num: int
    entropy: float
    raw_text: str

def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy for a text string. 
    A lower score implies highly patterned/repetitive data (potential synthetic forgery).
    """
    if not text: return 0.0
    p, lns = Counter(text), float(len(text))
    # Standard formula: H(X) = -Σ(P(x) * log2(P(x)))
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
        """
        Processes a single log line against the previously cached line, calculating differences in time
        and looking for time jumps, anomalies, or entropy drops.
        Yields `Gap` objects whenever consecutive events cross the configured duration thresholds.
        """
        self.total_lines_processed += 1
        
        # Estimate log payload by clipping expected timestamp prefix out
        payload_text = log_line.raw_payload[20:]
        text_entropy = calculate_entropy(payload_text)
        is_forged = False
        
        # Only evaluate forgeries once baseline (first 50 lines) is established
        if self.entropy_count > 50 and len(payload_text) > 20:
             # If entropy collapses suddenly below 75% of rolling avg or below absolute threshold of 3.0
             if text_entropy < (self.rolling_entropy * 0.75) or text_entropy < 3.0: 
                 self.forgeries.append(Forgery(log_line.timestamp, log_line.line_number, text_entropy, log_line.raw_payload[:60]))
                 is_forged = True
                 
        # Maintain a rolling average of standard entropy characteristics
        if not is_forged:
            self.rolling_entropy = (self.rolling_entropy * self.entropy_count + text_entropy) / (self.entropy_count + 1)
        self.entropy_count += 1
        
        # Analyze temporal gaps between current line and last known line
        if self.last_log_line:
            delta = log_line.timestamp - self.last_log_line.timestamp
            duration = delta.total_seconds()
            
            # Causality Violation: log travels backward in time
            if duration < 0:
                self.causality_violations.append(CausalityViolation(self.last_log_line.timestamp, log_line.timestamp, log_line.line_number))
                self.last_log_line = log_line
                return
            
            # Catch catastrophic gaps (e.g. year skipping forward due to bad regex parse)
            if duration > self.max_gap:
                print_warning(f"⚠️ Detected unrealistic time jump ({duration}s). Possible validation error.")
            
            # If duration exceeds configured threshold, formalize it into a documented intervention GAP
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
    """
    Computes system trust metrics using fixed deduction rules based on the frequency 
    and severity of security-relevant log irregularities.
    Returns: Tuple of User-facing Heuristic Score, Overall SystemStatus, Adjusted Trust Percentage (0-100), and Text Explanations.
    """
    if total_lines == 0: return 0.0, SystemStatus.NORMAL, 100, "Log file implies normal contiguous structure"

    # Count gap triggers by logical severities
    high_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.HIGH)
    medium_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.MEDIUM)
    low_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.LOW)
    
    # Start at perfect trust, subtracting points based on anomaly weightings
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

    # Collect reasoning sentences based on detected events
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
    
    # Alternative raw score (e.g. arbitrary metric, not specifically 0-100 bound)
    score = (high_count * 3 + medium_count * 2 + low_count * 1) / total_lines
    
    # Classify overall status
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

class ExplainabilityEngine:
    @staticmethod
    def generate_narrative(gaps, causality_count, forgery_count, alibi_failures, status, pii_leaks=0) -> str:
        narrative = []
        if status == SystemStatus.COMPROMISED:
            narrative.append("The system sustained a highly sophisticated data-poisoning attack.")
        elif status == SystemStatus.SUSPICIOUS:
            narrative.append("The system exhibits suspicious temporal anomalies indicating potential probing or configuration failure.")
        else:
            narrative.append("No active hostility detected. System timeline is contiguous.")

        if causality_count > 0:
            narrative.append("The attacker likely spoofed NTP timestamps to mask activities, mapping to MITRE T1070.006 (Indicator Removal: Timestomp).")
        
        if forgery_count > 0:
            narrative.append("Synthetic log payloads injected to bypass volumetric detection, mapping to MITRE T1001 (Data Obfuscation).")

        if alibi_failures > 0:
            narrative.append(f"Secondary systems successfully achieved consensus ({alibi_failures} background activities confirmed during gaps), cryptographically proving intentional target log manipulation.")
            
        if pii_leaks > 0:
            narrative.append(f"Data exfiltration risk flagged: {pii_leaks} sensitive PII leakage events caught, mapping to MITRE T1005 (Data from Local System).")
            
        return " ".join(narrative)

class Reporter:
    def __init__(self, gaps: List[Gap], total_lines: int, file_start: datetime, file_end: datetime, threshold: int, malformed_count: int, max_gap_violations: int, causality_count: int, forgery_count: int, source_file: str = "unknown", file_hash: str = "N/A", pii_leaks: int = 0):
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
        self.gap_durations = [g.duration_seconds for g in self.gaps]

    def _build_enriched_payload(self) -> Dict[str, Any]:
        """Builds the enriched JSON payload used by all output formats."""
        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations, self.total_lines, self.malformed_count,
            self.max_gap_violations, alibi_failures, self.causality_count, self.forgery_count
        )
        
        total_span = 0
        if self.file_start and self.file_end:
            total_span = (self.file_end - self.file_start).total_seconds()
        
        high_c = sum(1 for d in self.gap_durations if calculate_severity(d) == Severity.HIGH)
        med_c = sum(1 for d in self.gap_durations if calculate_severity(d) == Severity.MEDIUM)
        low_c = sum(1 for d in self.gap_durations if calculate_severity(d) == Severity.LOW)
        
        # Build trust deduction breakdown
        deductions = []
        if low_c > 0: deductions.append(f"LOW gaps ({low_c}x): -{low_c * 2}")
        if med_c > 0: deductions.append(f"MEDIUM gaps ({med_c}x): -{med_c * 5}")
        if high_c > 0: deductions.append(f"HIGH gaps ({high_c}x): -{high_c * 15}")
        if self.max_gap_violations > 0: deductions.append(f"Max gap violations ({self.max_gap_violations}x): -{self.max_gap_violations * 20}")
        if self.causality_count > 0: deductions.append(f"Causality violations ({self.causality_count}x): -{self.causality_count * 30}")
        if self.forgery_count > 0: deductions.append(f"Entropy collapses ({self.forgery_count}x): -{self.forgery_count * 20}")
        if alibi_failures > 0: deductions.append(f"Alibi failures: -50")
        if self.malformed_count > 0: deductions.append(f"Malformed lines ({self.malformed_count}x): -{self.malformed_count * 0.1:.1f}")
        
        return {
            "metadata": {
                "analysis_timestamp": datetime.now().isoformat(),
                "source_file": self.source_file,
                "chain_of_custody_sha256": self.file_hash,
                "file_start": self.file_start.isoformat() if self.file_start else None,
                "file_end": self.file_end.isoformat() if self.file_end else None,
                "total_lines_processed": self.total_lines,
                "threshold_seconds": self.threshold,
                "total_timespan_seconds": int(total_span) if total_span else 0
            },
            "anomalies": {
                "total_gaps_found": len(self.gaps),
                "severity_breakdown": {"HIGH": high_c, "MEDIUM": med_c, "LOW": low_c},
                "malformed_lines_skipped": self.malformed_count,
                "causality_violations_detected": self.causality_count,
                "shannon_entropy_collapses": self.forgery_count,
                "alibi_failures_detected": alibi_failures,
                "pii_leakage_events": getattr(self, 'pii_leaks', 0)
            },
            "trust_metrics": {
                "system_status": status.value,
                "log_trust_confidence_percent": trust,
                "suspicion_reason": reason,
                "trust_deduction_breakdown": deductions
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
                    "position_percent": round(((g.start_time - self.file_start).total_seconds() / total_span) * 100, 1) if total_span > 0 else 0,
                    "width_percent": round((g.duration_seconds / total_span) * 100, 1) if total_span > 0 else 0,
                    "alibi_events_caught": g.alibi_evidence_count
                } for g in self.gaps
            ]
        }

    def print_core_report(self):
        """Prints the STRICT REQUIRED deliverable format."""
        print(f"{Colors.BOLD}Source:{Colors.ENDC}    {self.source_file}")
        print(f"{Colors.BOLD}SHA-256:{Colors.ENDC}   {self.file_hash}")
        print(f"{Colors.BOLD}Threshold:{Colors.ENDC} {self.threshold}s")
        print(f"{Colors.BOLD}Scanned:{Colors.ENDC}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        if not self.gaps:
            print(f"{Colors.OKGREEN}No Gaps Detected.{Colors.ENDC}")
            return
            
        for gap in self.gaps:
            color = Colors.OKCYAN
            if gap.severity == Severity.HIGH: color = Colors.FAIL
            elif gap.severity == Severity.MEDIUM: color = Colors.WARNING
            
            print(f"{color}Gap Detected [{gap.severity.value}]{Colors.ENDC}")
            print(f"  Start:    {gap.start_time.strftime('%H:%M:%S')} (line {gap.start_line_num})")
            print(f"  End:      {gap.end_time.strftime('%H:%M:%S')} (line {gap.end_line_num})")
            print(f"  Duration: {int(gap.duration_seconds)}s ({format_duration(gap.duration_seconds)})")
            if gap.alibi_evidence_count > 0:
                print(f"  {Colors.FAIL}[ALIBI FAILED: {gap.alibi_evidence_count} cross-log events in this window]{Colors.ENDC}")
            print()
            
        print(f"{Colors.BOLD}Total Gaps Found: {len(self.gaps)}{Colors.ENDC}")

    def print_advanced_summary(self):
        print("\n" + Colors.OKCYAN + "="*40 + Colors.ENDC)
        print(f"{Colors.BOLD}=== TEMPORA ADVANCED INTEGRITY MATRIX ==={Colors.ENDC}")
        print(Colors.OKCYAN + "="*40 + Colors.ENDC)
        print(f"[✓] Chain of Custody (SHA-256): {self.file_hash}")
        
        mad_median = statistics.median(self.gap_durations) if self.gap_durations else 0
        mad = statistics.median([abs(x - mad_median) for x in self.gap_durations]) if self.gap_durations else 0

        alibi_failures = sum(1 for g in self.gaps if g.alibi_evidence_count > 0)
        score, status, trust, reason = calculate_global_suspicion(
            self.gap_durations, self.total_lines, self.malformed_count, 
            self.max_gap_violations, alibi_failures, self.causality_count, self.forgery_count
        )
        
        status_color = Colors.OKGREEN
        if status == SystemStatus.COMPROMISED: status_color = Colors.FAIL
        elif status == SystemStatus.SUSPICIOUS: status_color = Colors.WARNING
        
        print(f"Total Lines Processed: {self.total_lines}")
        print(f"System Status:         {status_color}{status.value}{Colors.ENDC}")
        print(f"Log Trust Confidence:  {status_color}{trust}%{Colors.ENDC}")
        
        narrative = ExplainabilityEngine.generate_narrative(self.gaps, self.causality_count, self.forgery_count, alibi_failures, status, getattr(self, 'pii_leaks', 0))
        
        print(f"\n{Colors.WARNING}[!] INCIDENT NARRATIVE & MITRE MAPPING{Colors.ENDC}")
        print(narrative)
        
        if self.gaps or self.causality_count > 0 or self.forgery_count > 0:
            print(f"\n{Colors.BOLD}=== ANOMALY BREAKDOWN ==={Colors.ENDC}")
            for i, gap in enumerate(self.gaps, 1):
                print(f"ID: GAP-{i:02d} | {gap.start_time.strftime('%H:%M:%S')} -> {gap.end_time.strftime('%H:%M:%S')} ({int(gap.duration_seconds)}s)")
                
                if gap.duration_seconds > (mad * 3) and mad > 0:
                    print(f"[CAUSE]    Statistical threshold explicitly violated (Deviation exceeds MAD limit: {mad:.1f}s).")
                else:
                    print(f"[CAUSE]    Static threshold violated (Minimum enforced: {self.threshold}s).")
                
                if gap.alibi_evidence_count > 0:
                    print(f"[ALIBI]    {gap.alibi_evidence_count} Background events contradicted silence (Consensus Failure).")
            
            if self.forgery_count > 0:
                print(f"[EVIDENCE] Entropy collapse computed globally for {self.forgery_count} instances.")
            if self.causality_count > 0:
                print(f"[EVIDENCE] Causality violated globally {self.causality_count} times.")
            if getattr(self, 'pii_leaks', 0) > 0:
                print(f"[LEAKAGE]  PII Exfiltration filter triggered {self.pii_leaks} times.")
        
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
            if gap.severity == Severity.HIGH: timeline_buckets[bucket_idx] = f"{Colors.FAIL}X{Colors.ENDC}"
            elif gap.severity == Severity.MEDIUM: timeline_buckets[bucket_idx] = f"{Colors.WARNING}x{Colors.ENDC}"
            else: timeline_buckets[bucket_idx] = f"{Colors.OKCYAN}!{Colors.ENDC}"
            
        timeline_str = "".join(timeline_buckets)
        print(f"[{timeline_str}]")
        print(f"End:   {self.file_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Legend: [.] OK   {Colors.OKCYAN}[!] LOW gap{Colors.ENDC}   {Colors.WARNING}[x] MEDIUM gap{Colors.ENDC}   {Colors.FAIL}[X] HIGH gap{Colors.ENDC}")
        print(Colors.OKCYAN + "============================================" + Colors.ENDC)

    def print_json(self):
        print(json.dumps(self._build_enriched_payload(), indent=2))

    def print_csv(self):
        writer = csv.writer(sys.stdout, lineterminator='\n')
        
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

    def print_html(self):
        output = self._build_enriched_payload()
        json_data = json.dumps(output)
        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tempora Forensic Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0; --text-main: #0f172a;
            --text-muted: #64748b; --primary: #2563eb;
            --danger: #dc2626; --warning: #f59e0b; --success: #10b981;
            --font-mono: ui-monospace, SFMono-Regular, Consolas, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
        }}
        body {{ font-family: var(--font-sans); background-color: var(--bg); color: var(--text-main); margin: 0; padding: 2.5rem 4rem; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 1.5rem; }}
        
        .header {{ display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 0.5rem; }}
        .header-title h1 {{ margin: 0; font-size: 2rem; font-weight: 800; color: #1e293b; letter-spacing: -0.025em; }}
        .header-title p {{ margin: 0.25rem 0 0 0; color: var(--text-muted); font-size: 1rem; }}
        .export-group {{ display: flex; gap: 0.75rem; }}
        .btn {{ display: inline-flex; align-items: center; justify-content: center; padding: 0.6rem 1.25rem; font-size: 0.85rem; font-weight: 600; border-radius: 6px; cursor: pointer; border: none; color: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.05); transition: opacity 0.2s; }}
        .btn:hover {{ opacity: 0.9; }}
        .btn-primary {{ background-color: var(--primary); }}
        .btn-success {{ background-color: var(--success); }}

        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .card-title {{ margin: 0 0 1.25rem 0; font-size: 0.9rem; text-transform: none; font-weight: 700; color: #0f172a; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }}
        
        .status-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }}
        .status-box {{ padding-right: 1.5rem; border-right: 1px solid var(--border); }}
        .status-box:last-child {{ border-right: none; }}
        .status-box .label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-main); font-weight: 700; margin-bottom: 0.25rem; letter-spacing: 0.05em; }}
        .status-box .value {{ font-size: 2.5rem; font-weight: 800; display: flex; align-items: center; letter-spacing: -0.025em; line-height: 1.2; }}
        .status-box .value.danger {{ color: var(--danger); }}
        .status-box .value.warning {{ color: var(--warning); }}
        .status-box .value.success {{ color: var(--success); }}
        .status-box .value.neutral {{ color: var(--text-main); }}

        .chart-container {{ width: 100%; height: 300px; position: relative; }}

        .panels-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
        
        .diag-box {{ background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 1rem; font-size: 0.9rem; margin-bottom: 1rem; color: #1e3a8a; }}
        .diag-box strong {{ color: #1e40af; }}
        .trigger-list {{ margin: 0; padding-left: 1.25rem; font-size: 0.9rem; color: var(--text-main); }}
        
        .alibi-box {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 1rem; font-size: 0.95rem; font-weight: 600; color: #166534; margin-bottom: 0.75rem; }}
        .alibi-desc {{ font-size: 0.9rem; color: var(--text-main); line-height: 1.5; }}
        .alibi-box.danger {{ background: #fef2f2; border-color: #fecaca; color: #991b1b; }}
        
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th, td {{ text-align: left; padding: 0.75rem 1rem; }}
        th {{ color: var(--text-main); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; border-bottom: 1px solid var(--border); letter-spacing: 0.05em; }}
        td {{ border-bottom: 1px solid #f1f5f9; color: var(--text-main); }}
        tr:last-child td {{ border-bottom: none; }}
        
        .badge {{ display: inline-flex; align-items: center; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .badge-danger {{ background: #fef2f2; color: #b91c1c; }}
        .badge-warning {{ background: #fffbeb; color: #d97706; }}
        .badge-success {{ background: #f0fdf4; color: #15803d; }}

        .glossary-section {{ margin-top: 1rem; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 2rem; }}
        .glossary-item h4 {{ margin: 0 0 0.5rem 0; font-size: 0.85rem; font-weight: 700; color: var(--text-main); }}
        .glossary-item p {{ margin: 0; font-size: 0.8rem; color: var(--text-muted); line-height: 1.5; }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-title">
                <h1>Tempora Forensic Audit Report</h1>
                <p>Enterprise Integrity Matrix & Audit Report <br/><span style="font-size: 0.85rem; font-family: var(--font-mono); color: var(--success);" id="shaHash"></span></p>
            </div>
            <div class="export-group">
                <button class="btn btn-primary" onclick="exportJSON()">&#x2193; Export JSON</button>
                <button class="btn btn-success" onclick="exportCSV()">&#x2193; Export CSV</button>
            </div>
        </header>

        <div class="card">
            <h2 class="card-title">System Status Overview</h2>
            <div class="status-grid">
                <div class="status-box">
                    <div class="label">Primary Assessment</div>
                    <div class="value" id="statusValue">
                        <svg id="statusIcon" style="width:32px;height:32px;margin-right:8px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        <span id="statusText"></span>
                    </div>
                </div>
                <div class="status-box">
                    <div class="label">Trust Confidence</div>
                    <div class="value neutral" id="trustValue">0%</div>
                </div>
                <div class="status-box">
                    <div class="label">Total Logs Analyzed</div>
                    <div class="value neutral" id="linesValue">0</div>
                </div>
                <div class="status-box">
                    <div class="label">Total Interventions</div>
                    <div class="value neutral" id="gapsValue">0</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2 class="card-title">Chronological Anomaly Distribution</h2>
            <div class="chart-container">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>

        <div class="panels-row">
            <div class="card">
                <h2 class="card-title">Forensic Triggers (Investigation Details)</h2>
                <div class="diag-box">
                    <strong>Diagnostic:</strong> <span id="flaggedReason"></span>
                </div>
                <ul class="trigger-list" id="anomalyList"></ul>
            </div>
            <div class="card">
                <h2 class="card-title">The Alibi Protocol Status</h2>
                <div id="alibiBox" class="alibi-box"></div>
                <div id="alibiDesc" class="alibi-desc"></div>
            </div>
        </div>

        <div class="card">
            <h2 class="card-title" style="border-bottom:none; margin-bottom:0;">Detailed Anomaly Ledger</h2>
            <table style="margin: 0 -1.5rem; width: calc(100% + 3rem);">
                <thead>
                    <tr>
                        <th style="padding-left: 1.5rem;">Severity</th>
                        <th>Start Timestamp</th>
                        <th>End Timestamp</th>
                        <th>Duration (s)</th>
                        <th style="padding-right: 1.5rem;">Alibi Protocol</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>

        <div>
            <h2 class="card-title" style="border-bottom: none; margin-bottom: 0;">Forensic Terminology Reference</h2>
            <div class="glossary-section">
                <div class="glossary-item">
                    <h4>Causality Violation</h4>
                    <p>Triggered when a log entry's timestamp occurs <em>before</em> the preceding entry's timestamp. This strongly indicates deliberate tampering (e.g., NTP spoofing), clock desynchronization, or out-of-order writes used to mask true event timelines.</p>
                </div>
                <div class="glossary-item">
                    <h4>Shannon Entropy Collapse</h4>
                    <p>A mathematical measurement of text randomness. Abnormally low entropy in log payloads indicates synthetic or script-generated content (e.g., an automated attacker injecting repetitive dummy logs to bury their tracks in "noise").</p>
                </div>
                <div class="glossary-item">
                    <h4>The Alibi Protocol</h4>
                    <p>A cross-referencing technique that compares a missing timeframe (gap) in the primary log against activity in an immutable secondary log (like <code>auth.log</code>). Activity in the secondary log mathematically proves the primary log gap was intentional deletion.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const reportData = {json_data};
        const m = reportData.metadata;
        const a = reportData.anomalies;
        const t = reportData.trust_metrics;
        const gaps = reportData.detailed_gaps;

        // Status
        const stText = document.getElementById('statusText');
        const stValueBox = document.getElementById('statusValue');
        const trustVal = document.getElementById('trustValue');
        
        stText.textContent = t.system_status;
        if (t.system_status === 'COMPROMISED') {{
            stValueBox.className = 'value danger';
            document.getElementById('statusIcon').style.display = 'block';
        }} else if (t.system_status === 'SUSPICIOUS') {{
            stValueBox.className = 'value warning';
            document.getElementById('statusIcon').style.display = 'block';
        }} else {{
            stValueBox.className = 'value success';
            document.getElementById('statusIcon').style.display = 'none';
        }}

        trustVal.textContent = t.log_trust_confidence_percent + '%';
        document.getElementById('linesValue').textContent = m.total_lines_processed.toLocaleString();
        document.getElementById('gapsValue').textContent = a.total_gaps_found;
        
        if (m.chain_of_custody_sha256 && m.chain_of_custody_sha256 !== "N/A") {{
            document.getElementById('shaHash').innerHTML = '<strong>[✓] Chain of Custody (SHA-256):</strong> ' + m.chain_of_custody_sha256;
        }}

        // Triggers
        document.getElementById('flaggedReason').textContent = t.suspicion_reason;
        const anList = document.getElementById('anomalyList');
        let listHTML = '';
        if (a.causality_violations_detected > 0) listHTML += '<li>Causality Violations (Time Jumps): ' + a.causality_violations_detected + '</li>';
        if (a.shannon_entropy_collapses > 0) listHTML += '<li>Shannon Entropy Collapses: ' + a.shannon_entropy_collapses + '</li>';
        if (a.malformed_lines_skipped > 0) listHTML += '<li>Malformed Lines Skipped: ' + a.malformed_lines_skipped + '</li>';
        if (listHTML === '') listHTML = '<li style="color:var(--success)">No advanced anomalous behaviors detected. System appears stable.</li>';
        anList.innerHTML = listHTML;

        // Alibi
        const abBox = document.getElementById('alibiBox');
        const abDesc = document.getElementById('alibiDesc');
        if (a.alibi_failures_detected > 0) {{
            abBox.textContent = 'Evidence of Tampering Found';
            abBox.className = 'alibi-box danger';
            abDesc.innerHTML = 'Cross-referencing detected <strong>' + a.alibi_failures_detected + '</strong> instances where secondary logs confirm background activity during primary log gaps.';
        }} else {{
            abBox.textContent = 'Protocol Passed / Inactive';
            abBox.className = 'alibi-box';
            abDesc.textContent = 'No conflicting background activity was detected during missing timeframes, or the protocol was not utilized.';
        }}

        // Table
        const tb = document.getElementById('tableBody');
        if (gaps.length === 0) {{
            tb.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted)">No anomalies detected.</td></tr>';
        }} else {{
            gaps.forEach(g => {{
                const bClass = g.severity === 'HIGH' ? 'badge-danger' : (g.severity === 'MEDIUM' ? 'badge-warning' : 'badge-success');
                tb.innerHTML += '<tr>' +
                    '<td style="padding-left: 1.5rem;"><span class="badge ' + bClass + '">' + g.severity + '</span></td>' +
                    '<td>' + g.start_time.replace("T", " ").split(".")[0] + '</td>' +
                    '<td>' + g.end_time.replace("T", " ").split(".")[0] + '</td>' +
                    '<td>' + g.duration_seconds.toLocaleString() + 's</td>' +
                    '<td style="padding-right: 1.5rem;">' + (g.alibi_events_caught > 0 ? "<span style=\\"color:var(--danger); font-weight: bold\\">Failed</span>" : "—") + '</td>' +
                '</tr>';
            }});
        }}

        // Chart.js
        if (gaps.length > 0) {{
            const ctx = document.getElementById('timelineChart').getContext('2d');
            
            // To loosely scale the x-axis, let's inject filler 0 duration bars before/after gap 
            // for pure layout matching the image (which has an X axis representing real timeline with an isolated orange bar).
            // Image shows X-axis "Time (seconds)" with interval values like 0, 200, 400 ... 1800, 
            // and an orange bar somewhere in the middle. We'll plot X correctly if it's scatter or standard bar with labels.
            const labelsStr = [];
            const dVals = [];
            gaps.forEach((g) => {{
                // we'll just plot all gaps
                labelsStr.push(g.start_time.replace('T', ' ').split('.')[0]);
                dVals.push(g.duration_seconds);
            }});

            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labelsStr,
                    datasets: [{{
                        label: 'Duration',
                        data: dVals,
                        backgroundColor: '#f59e0b',
                        maxBarThickness: 40
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            title: {{ display: true, text: 'Time (Timestamp)', color: '#64748b' }},
                            grid: {{ display: false }}
                        }},
                        y: {{
                            title: {{ display: true, text: 'Duration (seconds)', color: '#64748b' }},
                            beginAtZero: true,
                            grid: {{ color: '#f1f5f9' }}
                        }}
                    }},
                    plugins: {{ legend: {{ display: false }} }}
                }}
            }});
        }} else {{
            document.querySelector('.chart-container').innerHTML = '<div style="color: var(--text-muted); padding: 4rem 0; text-align: center;">No anomaly data to plot.</div>';
        }}

        function exportJSON() {{
            const blob = new Blob([JSON.stringify(reportData, null, 2)], {{type: 'application/json'}});
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'tempora_report.json'; a.click();
        }}
        function exportCSV() {{
            let csv = "severity,start_time,end_time,duration_seconds,alibi_caught\\n";
            gaps.forEach(g => {{ csv += g.severity + ',' + g.start_time + ',' + g.end_time + ',' + g.duration_seconds + ',' + g.alibi_events_caught + '\\n'; }});
            const blob = new Blob([csv], {{type: 'text/csv'}});
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'tempora_report.csv'; a.click();
        }}
    </script>
</body>
</html>'''
        print(html_template)

def print_banner():
    if os.name == 'nt': os.system("") # Init VT100 colors on Windows CMD natively
    banner = """
\033[96m████████╗███████╗███╗   ███╗██████╗  ██████╗ ██████╗  █████╗ 
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
    parser.add_argument("--alibi", nargs='+', default=None, help="Secondary log files to cross-reference (The Alibi Protocol)")
    parser.add_argument("--threshold", type=int, default=None, help="Minimum gap duration in seconds")
    parser.add_argument("--config", type=str, default=None, help="Path to JSON configuration file for custom layouts")
    parser.add_argument("--scan-pii", action="store_true", help="Enable lightweight PII data leakage scanning")
    parser.add_argument("--format", type=str, choices=["text", "json", "csv", "html"], default="text", help="Output format (text, json, csv, or html)")
    parser.add_argument("--out", type=str, default=None, help="Path to save the output natively (bypasses Windows pipeline corruption)")
    parser.add_argument("--verbose", action="store_true", help="Print verbose warnings")
    parser.add_argument("--interactive", action="store_true", help="Launch the interactive wizard")
                        
    args = parser.parse_args()
    
    if args.out:
        sys.stdout = open(args.out, 'w', encoding='utf-8')
    elif hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8')
    
    if args.format == "text":
        print_banner()

    if args.interactive:
        print(f"{Colors.OKCYAN}{Colors.BOLD}[*] Welcome to the Tempora Interactive Setup Wizard{Colors.ENDC}")
        log_in = input(f" [?] Path to the primary log file [{args.logfile}]: ").strip()
        if log_in: args.logfile = log_in
        
        thr_in = input(f" [?] Minimum gap threshold in seconds [{args.threshold}]: ").strip()
        if thr_in.isdigit(): args.threshold = int(thr_in)
        
        alibi_in = input(f" [?] (Optional) Path to secondary logs for the Alibi Protocol (space-separated) [None]: ").strip()
        if alibi_in: args.alibi = alibi_in.split()
        
        print("\n[*] Initializing continuous forensic pipeline...\n")

    if args.config:
        try:
            config = Config.load_from_json(args.config)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)
    else:
        config = Config()
        
    if args.threshold is not None:
        config.min_gap_threshold = args.threshold
        
    pii_sweeper = PIISweeper() if args.scan_pii else None
    
    log_parser = LogParser(custom_formats=config.timestamp_formats)
    detector = GapDetector(min_threshold=config.min_gap_threshold, max_gap=config.max_reasonable_gap, safe_intervals=config.safe_intervals)
    
    gaps = []
    total_lines = 0
    malformed_count = 0
    max_gap_violations = 0
    file_start = None
    file_end = None
    
    file_hash = "N/A"
    try:
        h = hashlib.sha256()
        with open(args.logfile, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""): h.update(chunk)
        file_hash = h.hexdigest()
    except Exception:
        pass

    try:
        for line_num, line in enumerate(generate_lines(args.logfile), 1):
            log_line = log_parser.parse_line(line, line_num)
            if log_line:
                if pii_sweeper: pii_sweeper.scan(log_line.raw_payload)
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
    except PermissionError as e:
        print_error(f"Permission denied to read log file: {args.logfile}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)

    if args.alibi and gaps:
        alibi_parser = LogParser(custom_formats=config.timestamp_formats)
        for alibi_file in args.alibi:
            try:
                for alibi_line_num, line in enumerate(generate_lines(alibi_file), 1):
                    alibi_log = alibi_parser.parse_line(line, alibi_line_num)
                    if alibi_log:
                        for gap in gaps:
                            if gap.start_time < alibi_log.timestamp < gap.end_time:
                                gap.alibi_evidence_count += 1
            except FileNotFoundError:
                print_warning(f"[!] ALIBI PROTOCOL SKIPPED: Secondary log not found '{alibi_file}'")
            except PermissionError:
                print_warning(f"[!] ALIBI PROTOCOL SKIPPED: Insufficient permissions to read '{alibi_file}'")
            except Exception as e:
                print_warning(f"[!] ALIBI PROTOCOL FAILED: Unhandled exception during cross-reference on '{alibi_file}': {e}")

    pii_leaks = getattr(pii_sweeper, 'total_leaks', 0) if args.scan_pii else 0
    reporter = Reporter(gaps, total_lines, file_start, file_end, config.min_gap_threshold, malformed_count, max_gap_violations, len(detector.causality_violations), len(detector.forgeries), source_file=args.logfile, file_hash=file_hash, pii_leaks=pii_leaks)
    
    if args.format == "json":
        reporter.print_json()
    elif args.format == "csv":
        reporter.print_csv()
    elif args.format == "html":
        reporter.print_html()
    else:
        reporter.print_core_report()
        reporter.print_advanced_summary()

if __name__ == "__main__":
    main()
