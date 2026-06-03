from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime
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

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class SystemStatus(Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"

@dataclass
class NormalizedEvent:
    """
    The canonical data model for a single audit event in Tempora.
    Abstracts over Regex-based text logs and CloudTrail JSON objects.
    """
    timestamp: datetime
    raw_payload: str
    line_number: int
    actor: Optional[str] = None
    source_ip: Optional[str] = None
    region: Optional[str] = None
    event_name: Optional[str] = None
    event_source: Optional[str] = None

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

@dataclass
class Gap:
    """
    Represents an anomalous period of silence in the audit trail.
    """
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    severity: Severity
    start_line_num: int
    end_line_num: int
    alibi_evidence_count: int = 0
