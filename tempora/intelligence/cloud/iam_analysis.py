from typing import List, Iterator, Optional
from tempora.core.models import NormalizedEvent

class IAMAnalyzer:
    """
    Analyzes NormalizedEvent sequences to detect privilege escalation chains and root abuse.
    """
    def __init__(self):
        self.suspicious_events = [
            "CreateAccessKey",
            "AttachUserPolicy",
            "AttachGroupPolicy",
            "AttachRolePolicy",
            "CreateLoginProfile",
            "UpdateAssumeRolePolicy",
            "PutUserPolicy"
        ]

    def process_event(self, event: NormalizedEvent) -> Optional[str]:
        if event.event_name in self.suspicious_events:
            return f"⚠️ IAM ESCALATION WARNING: {event.actor} performed {event.event_name} at {event.timestamp}"
        
        if event.actor and "root" in event.actor.lower():
            return f"⚠️ ROOT ABUSE WARNING: AWS Root account activity detected at {event.timestamp} ({event.event_name})"
        
        return None
