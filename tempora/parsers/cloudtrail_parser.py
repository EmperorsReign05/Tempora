import json
from datetime import datetime
from typing import Optional
from tempora.core.models import NormalizedEvent
from tempora.parsers.base import BaseParser


class CloudTrailParser(BaseParser):
    def parse_line(self, line: str, line_num: int) -> Optional[NormalizedEvent]:
        line = line.strip()
        # Fast exit for non-JSON lines
        if not line or not line.startswith("{"):
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        event_time_str = data.get("eventTime")
        if not event_time_str:
            return None

        try:
            # CloudTrail uses ISO8601 e.g. 2024-10-14T10:00:00Z
            event_time_str = event_time_str.replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(event_time_str)
            # Remove timezone to match local RegexParser behavior for now
            timestamp = timestamp.replace(tzinfo=None)
        except ValueError:
            return None

        actor = None
        user_identity = data.get("userIdentity", {})
        if isinstance(user_identity, dict):
            actor = (
                user_identity.get("arn")
                or user_identity.get("userName")
                or user_identity.get("principalId")
            )

        return NormalizedEvent(
            timestamp=timestamp,
            raw_payload=line,
            line_number=line_num,
            actor=actor,
            source_ip=data.get("sourceIPAddress"),
            region=data.get("awsRegion"),
            event_name=data.get("eventName"),
            event_source=data.get("eventSource"),
        )
