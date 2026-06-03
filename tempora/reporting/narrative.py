from typing import List
from tempora.core.models import Gap


class NarrativeEngine:
    def __init__(self):
        self.mitre_mappings = {
            "DeleteTrail": "T1562.008 (Disable or Modify Cloud Trail)",
            "StopLogging": "T1562.008 (Disable or Modify Cloud Trail)",
            "CreateAccessKey": "T1098 (Account Manipulation)",
            "ConsoleLogin": "T1078 (Valid Accounts)",
            "root_abuse": "T1078.001 (Default Accounts)",
            "time_gap": "T1070.006 (Timestomp / Indicator Removal)",
        }

    def generate_narrative(self, gaps: List[Gap], cloud_alerts: List[str]) -> str:
        narrative = []
        if gaps:
            narrative.append(
                f"Detected {len(gaps)} abnormal audit silence(s) indicating potential log tampering [{self.mitre_mappings['time_gap']}]."
            )

        for alert in cloud_alerts:
            if "ROOT ABUSE" in alert:
                narrative.append(
                    f"Root account usage detected, representing a severe risk [{self.mitre_mappings['root_abuse']}]."
                )
            elif "IAM ESCALATION" in alert:
                narrative.append(
                    f"Privilege escalation activity detected in the audit trail [{self.mitre_mappings['CreateAccessKey']}]."
                )
            elif "IMPOSSIBLE TRAVEL" in alert:
                narrative.append(
                    f"Impossible travel authentication anomaly detected [{self.mitre_mappings['ConsoleLogin']}]."
                )

        if not narrative:
            return "No significant structural or IAM anomalies detected in the audit sequence."

        return " ".join(narrative)
