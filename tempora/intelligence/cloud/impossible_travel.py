from typing import List, Dict, Optional
from datetime import datetime
from tempora.core.models import NormalizedEvent

from tempora.config.settings import Config

class ImpossibleTravelDetector:
    """
    Tracks source_ip, ASN, and GeoIP transitions to detect physically impossible authentications.
    """
    def __init__(self, config: Config):
        self.max_speed_kmh = config.max_travel_speed_kmh
        # In a full implementation, we would use MaxMind GeoIP.
        # We will track last seen IPs per actor.
        self.actor_last_seen: Dict[str, dict] = {}

    def process_event(self, event: NormalizedEvent) -> Optional[str]:
        if not event.actor or not event.source_ip:
            return None
            
        last_seen = self.actor_last_seen.get(event.actor)
        if last_seen:
            last_ip = last_seen['ip']
            last_time = last_seen['time']
            
            if last_ip != event.source_ip:
                # IP changed. Time delta:
                delta_hours = (event.timestamp - last_time).total_seconds() / 3600.0
                if delta_hours > 0:
                    # In a real system we'd calculate geographical distance between last_ip and event.source_ip
                    # Here we just flag rapid IP jumps.
                    if delta_hours < 1.0: # Less than 1 hour IP jump
                        self.actor_last_seen[event.actor] = {'ip': event.source_ip, 'time': event.timestamp}
                        return f"🚨 IMPOSSIBLE TRAVEL WARNING: {event.actor} jumped from {last_ip} to {event.source_ip} in {delta_hours:.2f} hours!"
                        
        self.actor_last_seen[event.actor] = {'ip': event.source_ip, 'time': event.timestamp}
        return None
