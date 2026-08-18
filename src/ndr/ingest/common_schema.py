"""
Common normalized schema across all raw dataset sources (CICIDS2017, UNSW-NB15, CTU-13, and Zeek logs).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


@dataclass
class NormalizedFlow:
    """
    Standardized flow schema shared across all dataset loaders and Zeek logs.
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
    label: str = "BENIGN"
    attack_category: str = "BENIGN"
    mitre_technique: Optional[str] = None
    
    # Extended protocol and temporal attributes (when available)
    fwd_iat_mean: float = 0.0
    bwd_iat_mean: float = 0.0
    fwd_iat_std: float = 0.0
    bwd_iat_std: float = 0.0
    dns_query: Optional[str] = None
    dns_entropy: float = 0.0
    ssl_ja3: Optional[str] = None
    ssl_ja3s: Optional[str] = None
    ssl_subject: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    raw_source: str = "unknown"
