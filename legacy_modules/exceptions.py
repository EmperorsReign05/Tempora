"""
Custom exceptions for Tempora.
"""

class LogAnalyzerError(Exception):
    """Base exception for all log analyzer errors."""
    pass


class ConfigurationError(LogAnalyzerError):
    """Raised when there is an issue with the provided configuration."""
    pass


class LogParseError(LogAnalyzerError):
    """Raised when a severe error occurs during log parsing."""
    pass


class MalformedLineWarning(Warning):
    """Warning emitted when a single line is malformed but processing can continue."""
    pass
