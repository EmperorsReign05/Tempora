class LogAnalyzerError(Exception):
    pass

class ConfigurationError(LogAnalyzerError):
    pass

class LogParseError(LogAnalyzerError):
    pass

class MalformedLineWarning(Warning):
    pass
