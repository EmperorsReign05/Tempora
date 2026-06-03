import sys
import os
import argparse
from tempora.core.analyzer import TemporaAnalyzer
from tempora.parsers.regex_parser import RegexParser
from tempora.config.settings import Config
from tempora.core.exceptions import ConfigurationError
from tempora.core.models import Colors

def print_error(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)

def print_banner():
    if os.name == 'nt': os.system("")
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
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("logfile", nargs='?', default="logfile.log", help="Path to the log file to analyze")
    parser.add_argument("--alibi", nargs='+', default=None, help="Secondary log files to cross-reference (The Alibi Protocol)")
    parser.add_argument("--threshold", type=int, default=None, help="Minimum gap duration in seconds")
    parser.add_argument("--config", type=str, default=None, help="Path to JSON configuration file for custom layouts")
    parser.add_argument("--scan-pii", action="store_true", help="Enable lightweight PII data leakage scanning")
    parser.add_argument("--format", type=str, choices=["text", "json", "csv", "html"], default="text", help="Output format (text, json, csv, or html)")
    parser.add_argument("--out", type=str, default=None, help="Path to save the output natively")
    parser.add_argument("--verbose", action="store_true", help="Print verbose warnings")
    parser.add_argument("--interactive", action="store_true", help="Launch the interactive wizard")
                        
    args = parser.parse_args()
    
    if args.out:
        sys.stdout = open(args.out, 'w', encoding='utf-8')
    elif hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8')
    
    if args.format == "text":
        print_banner()

    if args.interactive:
        print(f"{Colors.OKCYAN}{Colors.BOLD}[*] Welcome to the Tempora Interactive Setup Wizard{Colors.ENDC}")
        log_in = input(f" [?] Path to the primary log file [{args.logfile}]: ").strip()
        if log_in: args.logfile = log_in
        
        thr_in = input(f" [?] Minimum gap threshold in seconds [{args.threshold}]: ").strip()
        if thr_in.isdigit(): args.threshold = int(thr_in)
        
        alibi_in = input(f" [?] (Optional) Path to secondary logs for the Alibi Protocol (space-separated) [None]: ").strip()
        if alibi_in: args.alibi = alibi_in.split()
        
        print("\n[*] Initializing continuous forensic pipeline...\n")

    if args.config:
        try:
            config = Config.load_from_json(args.config)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)
    else:
        config = Config()
        
    if args.threshold is not None:
        config.min_gap_threshold = args.threshold
        
    log_parser = RegexParser(custom_formats=config.timestamp_formats)
    analyzer = TemporaAnalyzer(parser=log_parser, config=config, scan_pii=args.scan_pii)
    
    try:
        reporter = analyzer.analyze_file(args.logfile)
    except FileNotFoundError as e:
        print_error(f"File not found: {args.logfile}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Fatal error during analysis: {e}")
        sys.exit(1)

    if args.alibi:
        analyzer.run_alibi_protocol(args.alibi)

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
