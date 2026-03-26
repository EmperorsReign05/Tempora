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

def calculate_global_suspicion(gap_durations: List[float], total_lines: int, malformed_count: int = 0, max_gap_violations: int = 0, alibi_failures: int = 0, causality_count: int = 0, forgery_count: int = 0) -> Tuple[float, SystemStatus, int, str]:
    """
    Determine the overall risk level and trustworthiness for the entire log file.
    
    Formula for Trust Score: Starts at 100%.
      -2% per LOW gap
      -5% per MEDIUM gap
      -15% per HIGH gap
      -20% per MAX REASONABLE GAP violation
      -30% per CAUSALITY VIOLATION (Time Travel / NTP Spoofing)
      -20% per SHANNON ENTROPY FORGERY (Scripted synthetics)
      -1% per 10 malformed lines
      -50% if ANY Alibi Verification fails (Proof of tampering)

    Returns:
      (suspicion_score, SystemStatus, trust_percentage, reason)
    """
    if total_lines == 0:
        return 0.0, SystemStatus.NORMAL, 100, "Log file implies normal contiguous structure"

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
    
    if alibi_failures > 0:
        trust -= 50

    trust = max(0, min(100, int(trust)))

    reasons = []
    if alibi_failures > 0:
        reasons.append(f"CRITICAL: {alibi_failures} Alibi Failures detected (Proven tampering)")
    if causality_count > 0:
        reasons.append(f"CAUSALITY VIOLATION: {causality_count} reverse-time jumps detected (Evidence of NTP Spoofing/Timestamp Backdating)")
    if forgery_count > 0:
        reasons.append(f"SYNTHETIC FORGERY: {forgery_count} instances of Shannon Entropy collapse (Scripted log injection)")
    if high_count > 0:
        reasons.append("Major timeline disruptions (HIGH gaps)")
    if max_gap_violations > 0:
        reasons.append(f"{max_gap_violations} instances of catastrophic timestamp inconsistency")
    if malformed_count > (total_lines * 0.01):
        reasons.append("Unusually high volume of malformed/corrupted lines")
    
    if not reasons and trust < 100:
        reasons.append("Minor temporal inconsistencies degrading reliability")
    elif not reasons:
        reasons.append("Perfect contiguous structural integrity")

    reason_str = " | ".join(reasons)

    score = (high_count * 3 + medium_count * 2 + low_count * 1) / total_lines
    
    if alibi_failures > 0 or trust < 50:
        status = SystemStatus.COMPROMISED
    elif trust < 85:
        status = SystemStatus.SUSPICIOUS
    else:
        status = SystemStatus.NORMAL
        
    return score, status, trust, reason_str
