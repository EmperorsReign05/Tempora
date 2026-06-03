from datetime import datetime
from typing import List, Iterator
from tempora.core.models import (
    Gap,
    NormalizedEvent,
    CausalityViolation,
    Forgery,
    Severity,
)
from tempora.config.settings import BusinessHours
from tempora.intelligence.entropy import calculate_entropy
import sys


def print_warning(msg: str):
    print(msg, file=sys.stderr)


def is_outside_business_hours(
    start: datetime, end: datetime, bh: BusinessHours
) -> bool:
    if bh.ignore_weekends and start.weekday() >= 5 and end.weekday() >= 5:
        return True
    bh_start_h, bh_start_m = map(int, bh.start_time.split(":"))
    bh_end_h, bh_end_m = map(int, bh.end_time.split(":"))
    from datetime import time

    bh_start = time(bh_start_h, bh_start_m)
    bh_end = time(bh_end_h, bh_end_m)
    if end.time() < bh_start:
        return True
    if start.time() > bh_end:
        return True
    return False


def calculate_severity(duration_seconds: float) -> Severity:
    if duration_seconds > 3600:
        return Severity.HIGH
    if duration_seconds > 300:
        return Severity.MEDIUM
    return Severity.LOW


class GapDetector:
    def __init__(
        self,
        min_threshold: int = 60,
        max_gap: int = 172800,
        safe_intervals=None,
        business_hours: BusinessHours = None,
    ):
        self.min_threshold = min_threshold
        self.max_gap = max_gap
        self.business_hours = business_hours
        self.safe_intervals = safe_intervals or []
        self.last_log_line = None

        self.total_lines_processed = 0
        self.causality_violations: List[CausalityViolation] = []
        self.forgeries: List[Forgery] = []
        self.rolling_entropy = 0.0
        self.entropy_count = 0

    def _is_in_safe_interval(self, start: datetime, end: datetime) -> bool:
        for safe_start, safe_end in self.safe_intervals:
            if start >= safe_start and end <= safe_end:
                return True
        return False

    def process_line(self, log_line: NormalizedEvent) -> Iterator[Gap]:
        self.total_lines_processed += 1

        # Estimate log payload by clipping expected timestamp prefix out
        payload_text = log_line.raw_payload[20:]
        text_entropy = calculate_entropy(payload_text)
        is_forged = False

        # Only evaluate forgeries once baseline (first 50 lines) is established
        if self.entropy_count > 50 and len(payload_text) > 20:
            if text_entropy < (self.rolling_entropy * 0.75) or text_entropy < 3.0:
                self.forgeries.append(
                    Forgery(
                        log_line.timestamp,
                        log_line.line_number,
                        text_entropy,
                        log_line.raw_payload[:60],
                    )
                )
                is_forged = True

        if not is_forged:
            self.rolling_entropy = (
                self.rolling_entropy * self.entropy_count + text_entropy
            ) / (self.entropy_count + 1)
        self.entropy_count += 1

        if self.last_log_line:
            delta = log_line.timestamp - self.last_log_line.timestamp
            duration = delta.total_seconds()

            if duration < 0:
                self.causality_violations.append(
                    CausalityViolation(
                        self.last_log_line.timestamp,
                        log_line.timestamp,
                        log_line.line_number,
                    )
                )
                self.last_log_line = log_line
                return

            if duration > self.max_gap:
                print_warning(
                    f"⚠️ Detected unrealistic time jump ({duration}s). Possible validation error."
                )

            elif duration >= self.min_threshold:
                if not self._is_in_safe_interval(
                    self.last_log_line.timestamp, log_line.timestamp
                ):
                    severity = calculate_severity(duration)
                    if self.business_hours and is_outside_business_hours(
                        self.last_log_line.timestamp,
                        log_line.timestamp,
                        self.business_hours,
                    ):
                        severity = Severity.LOW
                    yield Gap(
                        start_time=self.last_log_line.timestamp,
                        end_time=log_line.timestamp,
                        duration_seconds=duration,
                        severity=severity,
                        start_line_num=self.last_log_line.line_number,
                        end_line_num=log_line.line_number,
                    )
        self.last_log_line = log_line
