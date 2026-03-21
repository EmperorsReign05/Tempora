"""
Engine for detecting suspicious gaps in sequential log lines.
"""
from dataclasses import dataclass
from typing import Iterator, List
from datetime import datetime

from parser import LogLine
from severity import Severity, calculate_severity
from config import DEFAULT_CONFIG
from utils import print_warning

@dataclass
class Gap:
    """Represents a detected time gap in the log."""
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    severity: Severity
    start_line_num: int
    end_line_num: int

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
        
        if self.last_log_line:
            # Calculate time difference
            delta = log_line.timestamp - self.last_log_line.timestamp
            duration = delta.total_seconds()
            
            if duration > self.max_gap:
                print_warning(f"⚠️ Detected unrealistic time jump ({duration}s). Possible parsing error at line {log_line.line_number}. Skipping from severity scoring.")
            elif duration >= self.min_threshold:
                # We have a gap exceeding our minimum threshold
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
        
        # Progress state
        self.last_log_line = log_line
