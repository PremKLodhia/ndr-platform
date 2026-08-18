"""
High-performance parser for Zeek TSV log files (with #fields header) and JSON logs.
"""
import json
import logging
from pathlib import Path
from typing import Generator, List, Optional, Union, Any
from .models import ZeekConnRecord

logger = logging.getLogger(__name__)


class ZeekParser:
    """Parses Zeek connection and protocol logs."""

    @staticmethod
    def _safe_float(val: Any, default: float = 0.0) -> float:
        if val in (None, "-", "", "(empty)"):
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        if val in (None, "-", "", "(empty)"):
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def parse_conn_line_tsv(line: str, fields: List[str]) -> Optional[ZeekConnRecord]:
        """Parse a single TSV line from conn.log given the fields header."""
        if line.startswith("#") or not line.strip():
            return None
        parts = line.strip().split("\t")
        if len(parts) < len(fields):
            return None
        
        data = dict(zip(fields, parts))
        try:
            return ZeekConnRecord(
                timestamp=ZeekParser._safe_float(data.get("ts", 0.0)),
                uid=data.get("uid", ""),
                src_ip=data.get("id.orig_h", ""),
                src_port=ZeekParser._safe_int(data.get("id.orig_p", 0)),
                dst_ip=data.get("id.resp_h", ""),
                dst_port=ZeekParser._safe_int(data.get("id.resp_p", 0)),
                proto=data.get("proto", "tcp").lower(),
                service=None if data.get("service") == "-" else data.get("service"),
                duration=ZeekParser._safe_float(data.get("duration", 0.0)),
                orig_bytes=ZeekParser._safe_int(data.get("orig_bytes", 0)),
                resp_bytes=ZeekParser._safe_int(data.get("resp_bytes", 0)),
                conn_state=data.get("conn_state", ""),
                history=data.get("history", ""),
                orig_pkts=ZeekParser._safe_int(data.get("orig_pkts", 0)),
                orig_ip_bytes=ZeekParser._safe_int(data.get("orig_ip_bytes", 0)),
                resp_pkts=ZeekParser._safe_int(data.get("resp_pkts", 0)),
                resp_ip_bytes=ZeekParser._safe_int(data.get("resp_ip_bytes", 0)),
            )
        except Exception as e:
            logger.warning(f"Failed to parse Zeek conn line: {e}")
            return None

    @staticmethod
    def parse_conn_json_line(line: str) -> Optional[ZeekConnRecord]:
        """Parse a single JSON line from streaming Zeek conn.log."""
        if not line.strip():
            return None
        try:
            data = json.loads(line)
            # Handle nested id vs flat fields
            orig_h = data.get("id.orig_h") or data.get("id", {}).get("orig_h", "")
            orig_p = data.get("id.orig_p") or data.get("id", {}).get("orig_p", 0)
            resp_h = data.get("id.resp_h") or data.get("id", {}).get("resp_h", "")
            resp_p = data.get("id.resp_p") or data.get("id", {}).get("resp_p", 0)

            return ZeekConnRecord(
                timestamp=ZeekParser._safe_float(data.get("ts", 0.0)),
                uid=data.get("uid", ""),
                src_ip=orig_h,
                src_port=ZeekParser._safe_int(orig_p),
                dst_ip=resp_h,
                dst_port=ZeekParser._safe_int(resp_p),
                proto=str(data.get("proto", "tcp")).lower(),
                service=data.get("service"),
                duration=ZeekParser._safe_float(data.get("duration", 0.0)),
                orig_bytes=ZeekParser._safe_int(data.get("orig_bytes", 0)),
                resp_bytes=ZeekParser._safe_int(data.get("resp_bytes", 0)),
                conn_state=data.get("conn_state", ""),
                history=data.get("history", ""),
                orig_pkts=ZeekParser._safe_int(data.get("orig_pkts", 0)),
                orig_ip_bytes=ZeekParser._safe_int(data.get("orig_ip_bytes", 0)),
                resp_pkts=ZeekParser._safe_int(data.get("resp_pkts", 0)),
                resp_ip_bytes=ZeekParser._safe_int(data.get("resp_ip_bytes", 0)),
            )
        except Exception as e:
            logger.warning(f"Error parsing JSON Zeek line: {e}")
            return None

    @classmethod
    def stream_tsv_file(cls, filepath: Union[str, Path]) -> Generator[ZeekConnRecord, None, None]:
        """Stream and yield parsed records from a Zeek TSV file."""
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Zeek log file not found: {filepath}")

        fields: List[str] = []
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if fields:
                    rec = cls.parse_conn_line_tsv(line, fields)
                    if rec:
                        yield rec
