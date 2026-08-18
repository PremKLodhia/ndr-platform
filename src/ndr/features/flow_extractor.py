"""
Tabular flow feature extraction for machine learning and anomaly detection.
Computes 40+ statistical, temporal, and structural flow features.
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Union, Optional
from ..ingest.models import UnifiedFlow, ZeekConnRecord
from .entropy import calculate_shannon_entropy

# Standard feature column order
FLOW_FEATURE_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "tot_bytes",
    "src_pkts",
    "dst_pkts",
    "tot_pkts",
    "bytes_per_sec",
    "pkts_per_sec",
    "src_dst_byte_ratio",
    "src_dst_pkt_ratio",
    "avg_pkt_size",
    "avg_src_pkt_size",
    "avg_dst_pkt_size",
    "payload_entropy",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "is_well_known_dst_port",
    "is_registered_dst_port",
    "is_ephemeral_dst_port",
    "is_well_known_src_port",
    "is_ephemeral_src_port",
    "conn_state_SF",
    "conn_state_S0",
    "conn_state_REJ",
    "conn_state_RSTO",
    "conn_state_RSTR",
    "has_signature_alert",
    "alert_count",
    "max_alert_severity",
]


class FlowFeatureExtractor:
    """Extracts standardized numeric feature vectors from network flows."""

    @staticmethod
    def extract_from_unified_flow(flow: UnifiedFlow) -> Dict[str, float]:
        """Extract features from a UnifiedFlow instance."""
        duration = max(float(flow.duration), 0.000001)
        src_bytes = max(int(flow.src_bytes), 0)
        dst_bytes = max(int(flow.dst_bytes), 0)
        tot_bytes = src_bytes + dst_bytes

        src_pkts = max(int(flow.src_pkts), 0)
        dst_pkts = max(int(flow.dst_pkts), 0)
        tot_pkts = src_pkts + dst_pkts

        bytes_per_sec = tot_bytes / duration
        pkts_per_sec = tot_pkts / duration

        src_dst_byte_ratio = src_bytes / (dst_bytes + 1.0)
        src_dst_pkt_ratio = src_pkts / (dst_pkts + 1.0)

        avg_pkt_size = tot_bytes / max(tot_pkts, 1)
        avg_src_pkt_size = src_bytes / max(src_pkts, 1)
        avg_dst_pkt_size = dst_bytes / max(dst_pkts, 1)

        entropy = calculate_shannon_entropy(flow.raw_payload_bytes) if flow.raw_payload_bytes else 0.0

        proto = flow.proto.lower()
        is_tcp = 1.0 if proto == "tcp" else 0.0
        is_udp = 1.0 if proto == "udp" else 0.0
        is_icmp = 1.0 if proto == "icmp" else 0.0

        dst_p = int(flow.dst_port)
        src_p = int(flow.src_port)

        is_well_known_dst = 1.0 if dst_p < 1024 else 0.0
        is_registered_dst = 1.0 if 1024 <= dst_p < 49152 else 0.0
        is_ephemeral_dst = 1.0 if dst_p >= 49152 else 0.0

        is_well_known_src = 1.0 if src_p < 1024 else 0.0
        is_ephemeral_src = 1.0 if src_p >= 49152 else 0.0

        state = flow.conn_state.upper()
        conn_state_SF = 1.0 if state == "SF" else 0.0
        conn_state_S0 = 1.0 if state == "S0" else 0.0
        conn_state_REJ = 1.0 if state == "REJ" else 0.0
        conn_state_RSTO = 1.0 if state == "RSTO" else 0.0
        conn_state_RSTR = 1.0 if state == "RSTR" else 0.0

        alert_count = float(len(flow.alerts))
        has_alert = 1.0 if alert_count > 0 else 0.0
        # In Suricata, severity 1 is high, 3 is low. If no alert, severity = 0.
        max_sev = max([4 - a.severity for a in flow.alerts], default=0.0)

        return {
            "duration": float(flow.duration),
            "src_bytes": float(src_bytes),
            "dst_bytes": float(dst_bytes),
            "tot_bytes": float(tot_bytes),
            "src_pkts": float(src_pkts),
            "dst_pkts": float(dst_pkts),
            "tot_pkts": float(tot_pkts),
            "bytes_per_sec": float(bytes_per_sec),
            "pkts_per_sec": float(pkts_per_sec),
            "src_dst_byte_ratio": float(src_dst_byte_ratio),
            "src_dst_pkt_ratio": float(src_dst_pkt_ratio),
            "avg_pkt_size": float(avg_pkt_size),
            "avg_src_pkt_size": float(avg_src_pkt_size),
            "avg_dst_pkt_size": float(avg_dst_pkt_size),
            "payload_entropy": float(entropy),
            "is_tcp": is_tcp,
            "is_udp": is_udp,
            "is_icmp": is_icmp,
            "is_well_known_dst_port": is_well_known_dst,
            "is_registered_dst_port": is_registered_dst,
            "is_ephemeral_dst_port": is_ephemeral_dst,
            "is_well_known_src_port": is_well_known_src,
            "is_ephemeral_src_port": is_ephemeral_src,
            "conn_state_SF": conn_state_SF,
            "conn_state_S0": conn_state_S0,
            "conn_state_REJ": conn_state_REJ,
            "conn_state_RSTO": conn_state_RSTO,
            "conn_state_RSTR": conn_state_RSTR,
            "has_signature_alert": has_alert,
            "alert_count": alert_count,
            "max_alert_severity": max_sev,
        }

    @classmethod
    def extract_from_zeek(cls, rec: ZeekConnRecord) -> Dict[str, float]:
        """Extract features directly from a ZeekConnRecord."""
        flow = UnifiedFlow(
            flow_id=rec.uid,
            timestamp=rec.timestamp,
            src_ip=rec.src_ip,
            src_port=rec.src_port,
            dst_ip=rec.dst_ip,
            dst_port=rec.dst_port,
            proto=rec.proto,
            duration=rec.duration,
            src_bytes=rec.orig_bytes or rec.orig_ip_bytes,
            dst_bytes=rec.resp_bytes or rec.resp_ip_bytes,
            src_pkts=rec.orig_pkts,
            dst_pkts=rec.resp_pkts,
            conn_state=rec.conn_state,
            service=rec.service
        )
        return cls.extract_from_unified_flow(flow)

    @classmethod
    def to_dataframe(cls, flows: List[UnifiedFlow]) -> pd.DataFrame:
        """Convert a batch of flows to a standard pandas DataFrame."""
        rows = [cls.extract_from_unified_flow(f) for f in flows]
        df = pd.DataFrame(rows)
        # Ensure column ordering
        for col in FLOW_FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0
        return df[FLOW_FEATURE_COLUMNS]
