"""
Timestamp extraction and log line parsing.
"""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from exceptions import MalformedLineWarning
from config import DEFAULT_CONFIG

@dataclass
class LogLine:
    """Represents a successfully parsed line of log data."""
    timestamp: datetime
    raw_payload: str
    line_number: int

class LogParser:
    """
    Handles robust extraction of timestamps from log entries.
    Designed to fall back across multiple formats.
    """
    def __init__(self, custom_formats=None):
        self.formats = custom_formats or DEFAULT_CONFIG.timestamp_formats
        
        # We look for something that resembles a date/time structure at the start or inside the line.
        # This generic pattern grabs a block of characters that look like a timestamp. 
        # For a truly extensible robust solution we try parsing prefix text using datetime.strptime
        self._pattern = re.compile(
            r'^(?P<time_str>\d{2,4}[-/]?\d{2}[-/]?\d{2}[T\s]?\d{2}:\d{2}:\d{2}(?:\.\d+)?|' # standard ISO or similar
            r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})' # syslog like `Oct 14 12:30:00`
        )

    def _parse_timestamp(self, time_str: str) -> Optional[datetime]:
        """Attempt to parse a datetime using configured formats."""
        for fmt in self.formats:
            try:
                # If year is missing like syslog format, default to current year.
                dt = datetime.strptime(time_str, fmt)
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return None

    def parse_line(self, line: str, line_num: int) -> Optional[LogLine]:
        """
        Extract the timestamp and payload from a log line.
        Returns a LogLine object or None if the line is unparseable or completely malformed.
        """
        line = line.strip()
        if not line:
            return None # Skip empty lines

        match = self._pattern.search(line)
        if match:
            time_str = match.group('time_str')
            timestamp = self._parse_timestamp(time_str)
            
            if timestamp:
                return LogLine(
                    timestamp=timestamp, 
                    raw_payload=line, 
                    line_number=line_num
                )
            
        # If no regex match or all parsing failed, we raise a warning for malformed line
        # but return None so the detector can safely skip it.
        return None
