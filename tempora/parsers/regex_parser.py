import re
from datetime import datetime
from typing import Optional, List
from tempora.core.models import NormalizedEvent
from tempora.parsers.base import BaseParser


class RegexParser(BaseParser):
    """
    Parses unstructured text logs by executing regex patterns
    against timestamp headers to extract chronological context.
    """

    def __init__(self, custom_formats: List[str] = None):
        self.formats = custom_formats or []
        self._pattern = re.compile(
            r"^(?P<time_str>\d{2,4}[-/]?\d{2}[-/]?\d{2}[T\s]?\d{2}:\d{2}:\d{2}(?:\.\d+)?|"
            r"\d{6}\s+\d{6}|"
            r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        )

    def _parse_timestamp(self, time_str: str) -> Optional[datetime]:
        for fmt in self.formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return None

    def parse_line(self, line: str, line_num: int) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        match = self._pattern.search(line)
        if match:
            time_str = match.group("time_str")
            timestamp = self._parse_timestamp(time_str)
            if timestamp:
                return NormalizedEvent(
                    timestamp=timestamp, raw_payload=line, line_number=line_num
                )
        return None
