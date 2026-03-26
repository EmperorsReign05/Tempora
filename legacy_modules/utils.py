"""
Utility functions for file handling and formatting.
"""
import os
import sys
from typing import Iterator

def generate_lines(filepath: str) -> Iterator[str]:
    """
    Generator that lazily reads a file line-by-line.
    Memory efficient for GB-scale log files.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")
        
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield line

def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds into a human-readable string.
    """
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    
    minutes, remaining_seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {int(remaining_seconds)}s"
        
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {int(remaining_seconds)}s"

def print_error(msg: str):
    """Print an error message to stderr."""
    print(f"ERROR: {msg}", file=sys.stderr)

def print_warning(msg: str):
    """Print a warning message to stderr."""
    print(f"WARNING: {msg}", file=sys.stderr)
