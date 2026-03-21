"""
Severity scoring logic and log suspicion assessment.
"""
from enum import Enum
from typing import List, Tuple

from config import DEFAULT_CONFIG

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    
class SystemStatus(Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"

def calculate_severity(duration_seconds: float) -> Severity:
    """
    Calculate the severity classification for a given time gap.
    """
    if duration_seconds >= DEFAULT_CONFIG.severity.high:
        return Severity.HIGH
    elif duration_seconds >= DEFAULT_CONFIG.severity.medium:
        return Severity.MEDIUM
    return Severity.LOW

class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

def calculate_global_suspicion(gap_durations: List[float], total_lines: int) -> Tuple[float, SystemStatus, Confidence]:
    """
    Determine the overall risk level for the entire log file.
    
    Formula:
      score = (HIGH_gaps * 3 + MEDIUM_gaps * 2 + LOW_gaps * 1) / total_lines
      
    Returns a tuple of (suspicion_score, SystemStatus, Confidence)
    """
    if not gap_durations or total_lines == 0:
        return 0.0, SystemStatus.NORMAL, Confidence.HIGH

    # Tally severities
    high_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.HIGH)
    medium_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.MEDIUM)
    low_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.LOW)
    
    # Explicit suspicion score formula
    score = (high_count * 3 + medium_count * 2 + low_count * 1) / total_lines
    
    # Determine risk classification and confidence
    confidence = Confidence.LOW
    
    if high_count > 0 or score > 0.05:
        # e.g., if 5% of lines are equivalent to a LOW severity drop, it's compromised
        status = SystemStatus.COMPROMISED
        confidence = Confidence.HIGH if score > 0.1 else Confidence.MEDIUM
    elif medium_count > 0 or score > 0.01:
        # e.g., > 1% is suspicious
        status = SystemStatus.SUSPICIOUS
        confidence = Confidence.MEDIUM
    else:
        status = SystemStatus.NORMAL
        confidence = Confidence.HIGH
        
    return score, status, confidence
