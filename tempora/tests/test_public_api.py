from tempora import analyze
from tempora.reporting.reporter import Reporter


def test_public_analyze_api(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("2024-10-14 10:00:00 Started\n2024-10-14 10:00:10 Event\n")

    reporter = analyze(str(log_file))

    assert isinstance(reporter, Reporter)
    assert reporter.total_lines == 2
    assert len(reporter.gaps) == 0


def test_public_analyze_api_with_kwargs(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "2024-10-14 10:00:00 Started\n2024-10-14 10:02:00 Event\n"
    )  # 120s gap

    # Overriding min_gap_threshold via kwargs
    reporter = analyze(str(log_file), min_gap_threshold=300)

    assert reporter.total_lines == 2
    assert len(reporter.gaps) == 0  # 120s gap is below the 300s threshold override
