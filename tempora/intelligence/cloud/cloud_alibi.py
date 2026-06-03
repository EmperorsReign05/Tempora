from typing import List
from tempora.core.models import Gap, NormalizedEvent


class CloudAlibiValidator:
    """
    Cross-validates CloudTrail silence against secondary cloud layers (VPC Flow Logs, S3 Access Logs).
    """

    def cross_validate(self, gaps: List[Gap], secondary_events: List[NormalizedEvent]):
        for gap in gaps:
            for event in secondary_events:
                if gap.start_time < event.timestamp < gap.end_time:
                    gap.alibi_evidence_count += 1
