"""
Streaming file tailer and batch loader for continuous NDR ingestion.
"""
import time
import os
from pathlib import Path
from typing import Generator, Union


def follow_file(filepath: Union[str, Path], poll_interval: float = 0.5) -> Generator[str, None, None]:
    """
    Tails a growing file (like live conn.log or eve.json) yielding new lines.
    """
    p = Path(filepath)
    if not p.exists():
        raise FileNotFoundError(f"Cannot tail non-existent file: {filepath}")

    with open(p, "r", encoding="utf-8", errors="replace") as f:
        # Seek to end for live capture, or start from 0 if desired
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line
