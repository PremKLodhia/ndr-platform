"""
Parser for Suricata EVE JSON event logs.
"""
import json
import logging
from pathlib import Path
from typing import Generator, Optional, Union, Dict, Any
from .models import SuricataAlert

logger = logging.getLogger(__name__)


class SuricataParser:
    """Parses Suricata eve.json stream and alert entries."""

    @staticmethod
    def parse_eve_line(line: str) -> Optional[SuricataAlert]:
        """Parse a single line from eve.json into a SuricataAlert if event_type is alert."""
        if not line.strip():
            return None
        try:
            event: Dict[str, Any] = json.loads(line)
            if event.get("event_type") != "alert":
                return None
            
            alert_info = event.get("alert", {})
            return SuricataAlert(
                timestamp=event.get("timestamp", ""),
                src_ip=event.get("src_ip", ""),
                src_port=int(event.get("src_port", 0)),
                dst_ip=event.get("dest_ip", event.get("dst_ip", "")),
                dst_port=int(event.get("dest_port", event.get("dst_port", 0))),
                proto=event.get("proto", "tcp").lower(),
                signature_id=int(alert_info.get("signature_id", 0)),
                signature=alert_info.get("signature", "Unknown Signature"),
                category=alert_info.get("category", "Generic"),
                severity=int(alert_info.get("severity", 3)),
                raw_event=event
            )
        except Exception as e:
            logger.warning(f"Error parsing Suricata eve line: {e}")
            return None

    @classmethod
    def stream_eve_file(cls, filepath: Union[str, Path]) -> Generator[SuricataAlert, None, None]:
        """Stream and yield alerts from a Suricata eve.json file."""
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Suricata EVE file not found: {filepath}")

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                alert = cls.parse_eve_line(line)
                if alert:
                    yield alert
