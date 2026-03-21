"""
Configuration settings and constants for Tempora.
"""
from dataclasses import dataclass, field
from typing import List, Tuple
from datetime import datetime

@dataclass
class SeverityThresholds:
    """Thresholds (in seconds) for defining severity of time gaps."""
    medium: int = 300  # 5 minutes
    high: int = 3600   # 1 hour

@dataclass
class Config:
    """Main configuration object."""
    # Minimum gap in seconds to report
    min_gap_threshold: int = 60
    
    # Maximum reasonable gap (48 hours). Exceeding this is treated as a parsing error.
    max_reasonable_gap: int = 172800
    
    # Severity boundaries
    severity: SeverityThresholds = field(default_factory=SeverityThresholds)
    
    # Common timestamp formats to try parsing
    # Order matters: more specific/common first
    timestamp_formats: List[str] = field(default_factory=lambda: [
        "%Y-%m-%d %H:%M:%S",
        "%y%m%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S"
    ])
    
    # Safe intervals: Lists of (start, end) tuples indicating known maintenance windows.
    # Gaps falling entirely within these intervals are ignored.
    safe_intervals: List[Tuple[datetime, datetime]] = field(default_factory=list)

# Default configuration instance
DEFAULT_CONFIG = Config()
