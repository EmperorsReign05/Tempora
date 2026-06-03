import os
import json
from typing import List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
from tempora.core.exceptions import ConfigurationError

import yaml

@dataclass
class BusinessHours:
    start_time: str = "00:00"
    end_time: str = "23:59"
    timezone: str = "UTC"
    ignore_weekends: bool = False

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
    business_hours: Optional[BusinessHours] = None
    suspicious_events: List[str] = field(default_factory=lambda: [
        "CreateAccessKey",
        "AttachUserPolicy",
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "CreateLoginProfile",
        "UpdateAssumeRolePolicy",
        "PutUserPolicy"
    ])
    max_travel_speed_kmh: int = 1000

    @classmethod
    def load_from_file(cls, path: str) -> "Config":
        if not os.path.exists(path):
            raise ConfigurationError(f"Config file not found: {path}")
        
        _, ext = os.path.splitext(path)
        with open(path, 'r', encoding='utf-8') as f:
            if ext.lower() in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
                if 'tempora' in data: data = data['tempora']
            elif ext.lower() == '.json':
                data = json.load(f)
            else:
                raise ConfigurationError(f"Unsupported config format: {ext}")
                
        cfg = cls()
        if "min_gap_threshold" in data: cfg.min_gap_threshold = int(data["min_gap_threshold"])
        elif "threshold" in data and "min_gap" in data["threshold"]:
            cfg.min_gap_threshold = int(data["threshold"]["min_gap"])
            
        if "max_reasonable_gap" in data: cfg.max_reasonable_gap = int(data["max_reasonable_gap"])
        elif "threshold" in data and "max_gap" in data["threshold"]:
            cfg.max_reasonable_gap = int(data["threshold"]["max_gap"])
            
        if "timestamp_formats" in data: cfg.timestamp_formats = data["timestamp_formats"]
        
        if "business_hours" in data:
            bh = data["business_hours"]
            cfg.business_hours = BusinessHours(
                start_time=bh.get("start", "09:00"),
                end_time=bh.get("end", "17:00"),
                timezone=bh.get("timezone", "UTC"),
                ignore_weekends=bh.get("ignore_weekends", False)
            )
            
        return cfg

DEFAULT_CONFIG = Config()
