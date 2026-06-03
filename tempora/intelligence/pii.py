import re


class PIISweeper:
    def __init__(self):
        self.rules = {
            "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
            "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "api_key": re.compile(
                r'(?i)(?:key|token|secret)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9\-_]{16,})'
            ),
        }
        self.total_leaks = 0

    def scan(self, text: str):
        for pattern in self.rules.values():
            if pattern.search(text):
                self.total_leaks += 1
