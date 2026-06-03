from tempora.parsers.regex_parser import RegexParser

def test_regex_parser():
    parser = RegexParser(custom_formats=["%Y-%m-%d %H:%M:%S"])
    log = parser.parse_line("2024-10-15 08:00:00 Started process", 1)
    assert log is not None
    assert log.timestamp.year == 2024
    assert log.timestamp.hour == 8
    assert log.line_number == 1

def test_invalid_line():
    parser = RegexParser()
    log = parser.parse_line("Just some random text without timestamp", 2)
    assert log is None
