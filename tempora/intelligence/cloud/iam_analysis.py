from typing import Optional
from tempora.core.models import NormalizedEvent

from tempora.config.settings import Config


class IAMAnalyzer:
    """
    Analyzes NormalizedEvent sequences to detect privilege escalation chains and root abuse.
    """

    def __init__(self, config: Config):
        self.suspicious_events = config.suspicious_events

    def process_event(self, event: NormalizedEvent) -> Optional[str]:
        if event.event_name in self.suspicious_events:
            return f"⚠️ IAM ESCALATION WARNING: {event.actor} performed {event.event_name} at {event.timestamp}"

        if event.actor and "root" in event.actor.lower():
            return f"⚠️ ROOT ABUSE WARNING: AWS Root account activity detected at {event.timestamp} ({event.event_name})"

        return None
