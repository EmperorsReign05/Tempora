import os
import json
from typing import List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from tempora.core.exceptions import ConfigurationError

@dataclass
class Config:
    min_gap_threshold: int = 60
    max_reasonable_gap: int = 172800 
    timestamp_formats: List[str] = field(default_factory=lambda: [
        "%y%m%d %H%M%S",        
        "%Y-%m-%d %H:%M:%S,%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%b %d %H:%M:%S"
    ])
    safe_intervals: List[Tuple[datetime, datetime]] = field(default_factory=list)

    @classmethod
    def load_from_json(cls, path: str) -> "Config":
        if not os.path.exists(path):
            raise ConfigurationError(f"Config file not found: {path}")
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        cfg = cls()
        if "min_gap_threshold" in data: cfg.min_gap_threshold = int(data["min_gap_threshold"])
        if "max_reasonable_gap" in data: cfg.max_reasonable_gap = int(data["max_reasonable_gap"])
        if "timestamp_formats" in data: cfg.timestamp_formats = data["timestamp_formats"]
        return cfg

DEFAULT_CONFIG = Config()
