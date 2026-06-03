from tempora.core.analyzer import TemporaAnalyzer
from tempora.parsers.regex_parser import RegexParser
from tempora.config.settings import Config
from tempora.reporting.reporter import Reporter

__version__ = "2.0.0"
__all__ = ["TemporaAnalyzer", "RegexParser", "Config", "analyze"]

def analyze(filepath: str, config_path: str = None, scan_pii: bool = False, **kwargs) -> Reporter:
    """
    Public Developer API for Tempora Framework.
    Analyzes a log file and returns the generated forensic Reporter object.
    """
    if config_path:
        config = Config.load_from_file(config_path)
    else:
        config = Config()
        
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
            
    parser = RegexParser(custom_formats=config.timestamp_formats)
    analyzer = TemporaAnalyzer(parser=parser, config=config, scan_pii=scan_pii)
    
    return analyzer.analyze_file(filepath)
