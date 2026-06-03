from tempora.core.analyzer import TemporaAnalyzer
from tempora.parsers.regex_parser import RegexParser
from tempora.config.settings import Config


def test_analyzer_stream():
    parser = RegexParser(custom_formats=["%Y-%m-%d %H:%M:%S"])
    config = Config(min_gap_threshold=60)
    analyzer = TemporaAnalyzer(parser=parser, config=config)

    lines = [
        "2024-10-15 08:00:00 Event 1",
        "2024-10-15 08:00:10 Event 2",
        "2024-10-15 08:02:00 Event 3",  # 110s gap
    ]

    reporter = analyzer.analyze_stream(iter(lines))
    assert reporter.total_lines == 3
    assert len(reporter.gaps) == 1
    assert reporter.gaps[0].duration_seconds == 110
