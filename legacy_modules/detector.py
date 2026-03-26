"""
Engine for detecting suspicious gaps in sequential log lines.
"""
from dataclasses import dataclass
from typing import Iterator, List
from datetime import datetime
from collections import Counter
import math

from parser import LogLine
from severity import Severity, calculate_severity
from config import DEFAULT_CONFIG
from utils import print_warning

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
    """Represents a detected time gap in the log."""
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    severity: Severity
    start_line_num: int
    end_line_num: int
    alibi_evidence_count: int = 0

class GapDetector:
    """
    Stateful detector that processes lines as a stream and detects gaps.
    Maintains minimal memory footprint.
    """
    def __init__(self, min_threshold: int = DEFAULT_CONFIG.min_gap_threshold, max_gap: int = DEFAULT_CONFIG.max_reasonable_gap, safe_intervals=None):
        self.min_threshold = min_threshold
        self.max_gap = max_gap
        self.safe_intervals = safe_intervals or DEFAULT_CONFIG.safe_intervals
        self.last_log_line = None
        
        # Stats accumulation
        self.total_lines_processed = 0
        self.causality_violations: List[CausalityViolation] = []
        self.forgeries: List[Forgery] = []
        self.rolling_entropy = 0.0
        self.entropy_count = 0

    def _is_in_safe_interval(self, start: datetime, end: datetime) -> bool:
        """Check if a given gap falls entirely within a known safe interval."""
        for safe_start, safe_end in self.safe_intervals:
            if start >= safe_start and end <= safe_end:
                return True
        return False

    def process_line(self, log_line: LogLine) -> Iterator[Gap]:
        """
        Process a single successfully parsed log line.
        Yields a Gap object if a threshold-exceeding time jump is detected.
        """
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
                print_warning(f"Detected unrealistic time jump ({duration}s). Possible parsing error at line {log_line.line_number}. Skipping from severity scoring.")
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
