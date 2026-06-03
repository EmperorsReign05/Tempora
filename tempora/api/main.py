from typing import Optional, Any, Iterator, List
from tempora.core.analyzer import TemporaAnalyzer
from tempora.parsers.regex_parser import RegexParser
from tempora.parsers.cloudtrail_parser import CloudTrailParser
from tempora.config.settings import Config
from tempora.reporting.reporter import Reporter


def _build_analyzer(
    is_cloudtrail: bool = False,
    config_path: Optional[str] = None,
    scan_pii: bool = False,
    **kwargs: Any
) -> TemporaAnalyzer:
    if config_path:
        config = Config.load_from_file(config_path)
    else:
        config = Config()

    for key, value in kwargs.items():
        if value is not None and hasattr(config, key):
            setattr(config, key, value)

    if is_cloudtrail:
        parser = CloudTrailParser()
    else:
        parser = RegexParser(custom_formats=config.timestamp_formats)

    return TemporaAnalyzer(parser=parser, config=config, scan_pii=scan_pii)


def analyze(
    filepath: str,
    is_cloudtrail: bool = False,
    config_path: Optional[str] = None,
    scan_pii: bool = False,
    alibi_logs: Optional[List[str]] = None,
    **kwargs: Any
) -> Reporter:
    """
    Public Developer API to analyze a static log file.

    :param filepath: Path to the log file (text or JSON).
    :param is_cloudtrail: If True, uses the CloudTrail JSON parser instead of Regex.
    :param config_path: Optional path to a custom configuration JSON/YAML.
    :param scan_pii: If True, enables PII data leakage scanning.
    :param alibi_logs: List of background logs to cross-reference (The Alibi Protocol).
    :param kwargs: Override config values dynamically (e.g. min_gap_threshold=120)
    :return: Reporter object containing forensic metrics and gaps.
    """
    analyzer = _build_analyzer(is_cloudtrail, config_path, scan_pii, **kwargs)
    reporter = analyzer.analyze_file(filepath)
    if alibi_logs:
        analyzer.run_alibi_protocol(alibi_logs)
    return reporter


def analyze_stream(
    stream: Iterator[str],
    source_name: str = "stream",
    is_cloudtrail: bool = False,
    config_path: Optional[str] = None,
    scan_pii: bool = False,
    live_output: bool = True,
    **kwargs: Any
) -> Reporter:
    """
    Public Developer API to analyze a live stream.
    Automatically catches KeyboardInterrupt to return a partial Reporter.

    :param stream: Python generator or iterator yielding string events.
    :param source_name: Identifiable name for the stream.
    :param is_cloudtrail: If True, uses the CloudTrail JSON parser.
    :param config_path: Optional path to a custom configuration JSON/YAML.
    :param scan_pii: If True, enables PII data leakage scanning.
    :param live_output: Whether to print warnings natively to the console during stream.
    :param kwargs: Override config values dynamically.
    :return: Reporter object containing forensic metrics and gaps caught before interrupt.
    """
    analyzer = _build_analyzer(is_cloudtrail, config_path, scan_pii, **kwargs)
    try:
        return analyzer.analyze_stream(
            stream, source_name=source_name, live_output=live_output
        )
    except KeyboardInterrupt:
        return analyzer.generate_reporter(source_name=source_name)
