"""
Entry point for Tempora CLI.
"""
import argparse
import sys
from datetime import datetime

from config import Config, DEFAULT_CONFIG
from utils import generate_lines, print_error, print_warning
from parser import LogParser
from detector import GapDetector
from reporter import Reporter
from exceptions import MalformedLineWarning

def main():
    parser = argparse.ArgumentParser(
        description="Tempora: Automated Log Integrity Monitor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("logfile", nargs='?', default="app.log", help="Path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=DEFAULT_CONFIG.min_gap_threshold,
                        help="Minimum gap duration in seconds to flag")
    parser.add_argument("--format", choices=["cli", "json"], default="cli",
                        help="Output format")
    parser.add_argument("--summary", action="store_true",
                        help="Include summary metrics")
    parser.add_argument("--timeline", action="store_true",
                        help="Include ASCII timeline visualization")
    parser.add_argument("--interactive", action="store_true",
                        help="Launch interactive configuration mode")
    parser.add_argument("--verbose", action="store_true",
                        help="Print verbose warnings for malformed lines")
                        
    args = parser.parse_args()

    # Interactive mode logic
    if args.interactive:
        print("=== Tempora Interactive Setup ===")
        logfile = input(f"Enter path to log file [{args.logfile}]: ").strip()
        if logfile: args.logfile = logfile
        
        thresh_input = input(f"Enter threshold in seconds [{args.threshold}]: ").strip()
        if thresh_input.isdigit(): args.threshold = int(thresh_input)
        
        fmt_input = input(f"Output format (cli/json) [{args.format}]: ").strip()
        if fmt_input in ['cli', 'json']: args.format = fmt_input
        
        if args.format == 'cli':
            summ_in = input(f"Include summary metrics? (y/n) [{'y' if args.summary else 'n'}]: ").strip().lower()
            if summ_in == 'y': args.summary = True
            time_in = input(f"Include visual timeline? (y/n) [{'y' if args.timeline else 'n'}]: ").strip().lower()
            if time_in == 'y': args.timeline = True

    # Configuration override
    config = Config(min_gap_threshold=args.threshold)
    
    log_parser = LogParser(custom_formats=config.timestamp_formats)
    detector = GapDetector(min_threshold=config.min_gap_threshold, safe_intervals=config.safe_intervals)
    
    gaps = []
    total_lines = 0
    file_start = None
    file_end = None

    # Stream processing flow
    try:
        for line_num, line in enumerate(generate_lines(args.logfile), 1):
            log_line = log_parser.parse_line(line, line_num)
            
            if log_line:
                if not file_start:
                    file_start = log_line.timestamp
                file_end = log_line.timestamp
                
                # Feed to detector
                for gap in detector.process_line(log_line):
                    gaps.append(gap)
            else:
                if args.verbose:
                    print_warning(f"Line {line_num} malformed or skipped: {line.strip()[:50]}...")
            
            total_lines = line_num
            
    except FileNotFoundError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Fatal error during processing: {e}")
        sys.exit(1)

    # Output Reporting Phase
    reporter = Reporter(gaps, total_lines, file_start, file_end, config.min_gap_threshold, args.interactive)
    
    if args.format == "json":
        reporter.print_json()
    else:
        # CLI text formatting
        reporter.print_cli_report()
        if args.summary:
            reporter.print_summary()
        if args.timeline:
            reporter.print_ascii_timeline()

if __name__ == "__main__":
    main()
