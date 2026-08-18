"""
Normalized data models for network traffic ingestion (Zeek, Suricata, and unified flows).
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


@dataclass
class ZeekConnRecord:
    """Represents a parsed Zeek conn.log entry."""
    timestamp: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: Optional[str] = None
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = ""
    local_orig: Optional[bool] = None
    local_resp: Optional[bool] = None
    missed_bytes: int = 0
    history: str = ""
    orig_pkts: int = 0
    orig_ip_bytes: int = 0
    resp_pkts: int = 0
    resp_ip_bytes: int = 0
    tunnel_parents: Optional[List[str]] = None


@dataclass
class SuricataAlert:
    """Represents a parsed Suricata EVE alert event."""
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    signature_id: int
    signature: str
    category: str
    severity: int
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    raw_event: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedFlow:
    """
    Unified representation of a network flow fusing connection metrics and signature alerts.
    """
    flow_id: str
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    duration: float
    src_bytes: int
    dst_bytes: int
    src_pkts: int
    dst_pkts: int
    conn_state: str = ""
    service: Optional[str] = None
    alerts: List[SuricataAlert] = field(default_factory=list)
    raw_payload_bytes: Optional[bytes] = None
