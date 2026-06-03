import sys
import os
import argparse
from tempora.api.main import analyze, analyze_stream
from tempora.core.models import Colors


def print_error(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)


def print_banner():
    if os.name == "nt":
        os.system("")
    banner = """\033[96m████████╗███████╗███╗   ███╗██████╗  ██████╗ ██████╗  █████╗ 
╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗
   ██║   █████╗  ██╔████╔██║██████╔╝██║   ██║██████╔╝███████║
   ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║   ██║██╔══██╗██╔══██║
   ██║   ███████╗██║ ╚═╝ ██║██║     ╚██████╔╝██║  ██║██║  ██║
   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\033[0m"""
    print(banner)
    print("\033[1m Tempora CLI — Forensic Log Integrity Analyzer \033[0m")
    print("=" * 63 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Tempora: Automated Log Integrity Monitor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "logfile", nargs="?", default="logfile.log", help="Path to the log file"
    )
    parser.add_argument(
        "--alibi", nargs="+", default=None, help="Secondary log files to cross-reference"
    )
    parser.add_argument(
        "--threshold", type=int, default=None, help="Minimum gap duration in seconds"
    )
    parser.add_argument(
        "--config", type=str, default=None, help="Path to YAML/JSON configuration file"
    )
    parser.add_argument(
        "--stream", action="store_true", help="Enable streaming mode"
    )
    parser.add_argument(
        "--cloudtrail", action="store_true", help="Parse AWS CloudTrail JSON events"
    )
    parser.add_argument(
        "--aws-cloudwatch", type=str, default=None, help="Poll AWS CloudWatch directly"
    )
    parser.add_argument(
        "--scan-pii", action="store_true", help="Enable PII data leakage scanning"
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "csv", "html"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--out", type=str, default=None, help="Path to save the output natively"
    )
    parser.add_argument(
        "--interactive", action="store_true", help="Launch the interactive wizard"
    )

    args = parser.parse_args()

    if args.out:
        sys.stdout = open(args.out, "w", encoding="utf-8")
    elif hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if args.format == "text":
        print_banner()

    if args.interactive:
        print(f"{Colors.OKCYAN}{Colors.BOLD}[*] Welcome to the Tempora Interactive Setup Wizard{Colors.ENDC}")
        log_in = input(f" [?] Path to the primary log file [{args.logfile}]: ").strip()
        if log_in:
            args.logfile = log_in

        thr_in = input(f" [?] Minimum gap threshold in seconds [{args.threshold}]: ").strip()
        if thr_in.isdigit():
            args.threshold = int(thr_in)

        alibi_in = input(" [?] (Optional) Path to secondary logs for the Alibi Protocol (space-separated) [None]: ").strip()
        if alibi_in:
            args.alibi = alibi_in.split()
        print("\n[*] Initializing forensic pipeline...\n")

    try:
        if args.aws_cloudwatch:
            from tempora.streaming.aws_stream import CloudWatchStreamer
            streamer = CloudWatchStreamer(log_group=args.aws_cloudwatch)
            print(f"[*] Starting live AWS CloudWatch stream on {args.aws_cloudwatch}... (Press Ctrl+C to stop)")
            reporter = analyze_stream(
                streamer.stream_events(),
                source_name=f"cloudwatch:{args.aws_cloudwatch}",
                is_cloudtrail=args.cloudtrail,
                config_path=args.config,
                scan_pii=args.scan_pii,
                live_output=True,
                min_gap_threshold=args.threshold,
            )
            print("\n[*] CloudWatch stream terminated by user. Generating final report...")

        elif args.stream:
            print(f"[*] Starting continuous stream analysis on {args.logfile}... (Press Ctrl+C to stop)")
            def follow_file(path):
                import time
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue
                        yield line

            streamer = follow_file(args.logfile)
            reporter = analyze_stream(
                streamer,
                source_name=args.logfile,
                is_cloudtrail=args.cloudtrail,
                config_path=args.config,
                scan_pii=args.scan_pii,
                live_output=True,
                min_gap_threshold=args.threshold,
            )
            print("\n[*] Stream terminated by user. Generating final report...")
        else:
            reporter = analyze(
                args.logfile,
                is_cloudtrail=args.cloudtrail,
                config_path=args.config,
                scan_pii=args.scan_pii,
                alibi_logs=args.alibi,
                min_gap_threshold=args.threshold,
            )

    except FileNotFoundError:
        print_error(f"File not found: {args.logfile}")
        sys.exit(1)
    except ImportError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Fatal error during analysis: {e}")
        sys.exit(1)

    if args.format == "json":
        reporter.print_json()
    elif args.format == "csv":
        reporter.print_csv()
    elif args.format == "html":
        reporter.print_html()
    else:
        reporter.print_core_report()
        reporter.print_advanced_summary()


if __name__ == "__main__":
    main()
