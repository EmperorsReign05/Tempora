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
    min_gap_threshold: int = 60
    max_reasonable_gap: int = 172800
    severity: SeverityThresholds = field(default_factory=SeverityThresholds)
    timestamp_formats: List[str] = field(default_factory=lambda: [
        "%Y-%m-%d %H:%M:%S",
        "%y%m%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S"
    ])
    
    safe_intervals: List[Tuple[datetime, datetime]] = field(default_factory=list)

DEFAULT_CONFIG = Config()
