"""
High-performance, dataset-agnostic parser for Zeek logs (conn.log, dns.log, http.log, ssl.log).
Produces the SAME unified NormalizedFlow schema used across the entire NDR pipeline.
"""
import json
import logging
from pathlib import Path
from typing import Generator, List, Optional, Union, Dict, Any
from .common_schema import NormalizedFlow
from .models import ZeekConnRecord
from ..features.entropy import calculate_shannon_entropy

logger = logging.getLogger(__name__)


class ZeekParser:
    """Parses Zeek connection and protocol logs into the NormalizedFlow common schema."""

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

    @classmethod
    def conn_record_to_normalized_flow(
        cls,
        rec: ZeekConnRecord,
        dns_info: Optional[Dict[str, Any]] = None,
        ssl_info: Optional[Dict[str, Any]] = None,
        http_info: Optional[Dict[str, Any]] = None
    ) -> NormalizedFlow:
        """Convert a ZeekConnRecord and correlated metadata into a NormalizedFlow."""
        dns_query = dns_info.get("query") if dns_info else None
        dns_entropy = calculate_shannon_entropy(dns_query) if dns_query else 0.0

        ssl_ja3 = ssl_info.get("ja3") if ssl_info else None
        ssl_ja3s = ssl_info.get("ja3s") if ssl_info else None
        ssl_subj = ssl_info.get("subject") if ssl_info else None

        http_m = http_info.get("method") if http_info else None
        http_u = http_info.get("uri") if http_info else None
        http_ua = http_info.get("user_agent") if http_info else None

        return NormalizedFlow(
            flow_id=f"ZEEK_{rec.uid}",
            timestamp=rec.timestamp,
            src_ip=rec.src_ip,
            src_port=rec.src_port,
            dst_ip=rec.dst_ip,
            dst_port=rec.dst_port,
            proto=rec.proto.lower(),
            duration=max(rec.duration, 0.000001),
            src_bytes=rec.orig_bytes or rec.orig_ip_bytes,
            dst_bytes=rec.resp_bytes or rec.resp_ip_bytes,
            src_pkts=rec.orig_pkts,
            dst_pkts=rec.resp_pkts,
            label="BENIGN",  # Default unlabelled network flow until detection pipeline
            attack_category="UNKNOWN",
            dns_query=dns_query,
            dns_entropy=round(dns_entropy, 4),
            ssl_ja3=ssl_ja3,
            ssl_ja3s=ssl_ja3s,
            ssl_subject=ssl_subj,
            http_method=http_m,
            http_uri=http_u,
            http_user_agent=http_ua,
            raw_source="Zeek"
        )

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
    def parse_ssl_log(cls, filepath: Union[str, Path]) -> Dict[str, Dict[str, Any]]:
        """Extract JA3/JA3S fingerprints keyed by flow uid."""
        p = Path(filepath)
        if not p.exists():
            return {}
        ssl_map = {}
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            fields = []
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#") or not fields:
                    continue
                parts = line.strip().split("\t")
                if len(parts) >= len(fields):
                    d = dict(zip(fields, parts))
                    uid = d.get("uid")
                    if uid:
                        ssl_map[uid] = {
                            "ja3": d.get("ja3") if d.get("ja3") != "-" else None,
                            "ja3s": d.get("ja3s") if d.get("ja3s") != "-" else None,
                            "subject": d.get("subject") if d.get("subject") != "-" else None,
                        }
        return ssl_map

    @classmethod
    def parse_dns_log(cls, filepath: Union[str, Path]) -> Dict[str, Dict[str, Any]]:
        """Extract DNS query and answers keyed by flow uid."""
        p = Path(filepath)
        if not p.exists():
            return {}
        dns_map = {}
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            fields = []
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#") or not fields:
                    continue
                parts = line.strip().split("\t")
                if len(parts) >= len(fields):
                    d = dict(zip(fields, parts))
                    uid = d.get("uid")
                    if uid:
                        dns_map[uid] = {
                            "query": d.get("query") if d.get("query") != "-" else None,
                            "qtype_name": d.get("qtype_name") if d.get("qtype_name") != "-" else None,
                            "rcode_name": d.get("rcode_name") if d.get("rcode_name") != "-" else None
                        }
        return dns_map

    @classmethod
    def stream_tsv_file(cls, filepath: Union[str, Path]) -> Generator[NormalizedFlow, None, None]:
        """Stream and yield NormalizedFlows from a Zeek TSV file."""
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Zeek log file not found: {filepath}")

        # Check for adjacent protocol logs in the same directory
        log_dir = p.parent
        ssl_map = cls.parse_ssl_log(log_dir / "ssl.log") if (log_dir / "ssl.log").exists() else {}
        dns_map = cls.parse_dns_log(log_dir / "dns.log") if (log_dir / "dns.log").exists() else {}

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
                        yield cls.conn_record_to_normalized_flow(
                            rec,
                            dns_info=dns_map.get(rec.uid),
                            ssl_info=ssl_map.get(rec.uid)
                        )
