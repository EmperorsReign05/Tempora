from abc import ABC, abstractmethod
from typing import Optional
from tempora.core.models import NormalizedEvent

class BaseParser(ABC):
    @abstractmethod
    def parse_line(self, line: str, line_num: int) -> Optional[NormalizedEvent]:
        pass
