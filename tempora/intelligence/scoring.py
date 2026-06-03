from typing import List, Tuple
from tempora.core.models import SystemStatus, Severity
from tempora.intelligence.threshold import calculate_severity


def calculate_global_suspicion(
    gap_durations: List[float],
    total_lines: int,
    malformed_count: int = 0,
    max_gap_violations: int = 0,
    alibi_failures: int = 0,
    causality_count: int = 0,
    forgery_count: int = 0,
) -> Tuple[float, SystemStatus, int, str]:
    if total_lines == 0:
        return (
            0.0,
            SystemStatus.NORMAL,
            100,
            "Log file implies normal contiguous structure",
        )

    high_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.HIGH)
    medium_count = sum(
        1 for d in gap_durations if calculate_severity(d) == Severity.MEDIUM
    )
    low_count = sum(1 for d in gap_durations if calculate_severity(d) == Severity.LOW)

    trust = 100.0
    trust -= low_count * 2
    trust -= medium_count * 5
    trust -= high_count * 15
    trust -= max_gap_violations * 20
    trust -= causality_count * 30
    trust -= forgery_count * 20
    trust -= malformed_count * 0.1

    if alibi_failures > 0:
        trust -= 50
    trust = max(0, min(100, int(trust)))

    reasons = []
    if alibi_failures > 0:
        reasons.append(
            f"CRITICAL: {alibi_failures} Alibi Failures detected (Proven tampering)"
        )
    if causality_count > 0:
        reasons.append(
            f"CAUSALITY VIOLATION: {causality_count} reverse-time jumps detected"
        )
    if forgery_count > 0:
        reasons.append(
            f"SYNTHETIC FORGERY: {forgery_count} instances of Shannon Entropy collapse"
        )
    if high_count > 0:
        reasons.append("Major timeline disruptions (HIGH gaps)")
    if max_gap_violations > 0:
        reasons.append(
            f"{max_gap_violations} instances of catastrophic timestamp inconsistency"
        )
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


class ExplainabilityEngine:
    @staticmethod
    def generate_narrative(
        gaps, causality_count, forgery_count, alibi_failures, status, pii_leaks=0
    ) -> str:
        narrative = []
        if status == SystemStatus.COMPROMISED:
            narrative.append(
                "The system sustained a highly sophisticated data-poisoning attack."
            )
        elif status == SystemStatus.SUSPICIOUS:
            narrative.append(
                "The system exhibits suspicious temporal anomalies indicating potential probing or configuration failure."
            )
        else:
            narrative.append(
                "No active hostility detected. System timeline is contiguous."
            )

        if causality_count > 0:
            narrative.append(
                "The attacker likely spoofed NTP timestamps to mask activities, mapping to MITRE T1070.006 (Indicator Removal: Timestomp)."
            )

        if forgery_count > 0:
            narrative.append(
                "Synthetic log payloads injected to bypass volumetric detection, mapping to MITRE T1001 (Data Obfuscation)."
            )

        if alibi_failures > 0:
            narrative.append(
                f"Secondary systems successfully achieved consensus ({alibi_failures} background activities confirmed during gaps), cryptographically proving intentional target log manipulation."
            )

        if pii_leaks > 0:
            narrative.append(
                f"Data exfiltration risk flagged: {pii_leaks} sensitive PII leakage events caught, mapping to MITRE T1005 (Data from Local System)."
            )

        return " ".join(narrative)
