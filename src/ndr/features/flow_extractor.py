"""
Extended tabular flow feature extractor supporting NormalizedFlow from all data sources.
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Union, Optional
from ..ingest.common_schema import NormalizedFlow
from ..ingest.models import UnifiedFlow, ZeekConnRecord
from .entropy import calculate_shannon_entropy
from .dns_features import extract_dns_features

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
    "fwd_iat_mean",
    "bwd_iat_mean",
    "payload_entropy",
    "dns_query_len",
    "dns_subdomain_entropy",
    "dns_digit_ratio",
    "has_ssl_ja3",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "is_well_known_dst_port",
    "is_registered_dst_port",
    "is_ephemeral_dst_port",
    "is_well_known_src_port",
    "is_ephemeral_src_port",
]


class FlowFeatureExtractor:
    """Extracts standardized numeric feature vectors from NormalizedFlows."""

    @classmethod
    def extract_from_normalized_flow(cls, flow: NormalizedFlow) -> Dict[str, float]:
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

        dns_feats = extract_dns_features(flow.dns_query)

        proto = str(flow.proto).lower()
        is_tcp = 1.0 if "tcp" in proto or proto == "6" else 0.0
        is_udp = 1.0 if "udp" in proto or proto == "17" else 0.0
        is_icmp = 1.0 if "icmp" in proto or proto == "1" else 0.0

        dst_p = int(flow.dst_port)
        src_p = int(flow.src_port)

        is_well_known_dst = 1.0 if dst_p < 1024 else 0.0
        is_registered_dst = 1.0 if 1024 <= dst_p < 49152 else 0.0
        is_ephemeral_dst = 1.0 if dst_p >= 49152 else 0.0

        is_well_known_src = 1.0 if src_p < 1024 else 0.0
        is_ephemeral_src = 1.0 if src_p >= 49152 else 0.0

        has_ja3 = 1.0 if flow.ssl_ja3 and flow.ssl_ja3 != "-" else 0.0

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
            "fwd_iat_mean": float(flow.fwd_iat_mean),
            "bwd_iat_mean": float(flow.bwd_iat_mean),
            "payload_entropy": float(flow.dns_entropy),
            "dns_query_len": dns_feats["dns_query_len"],
            "dns_subdomain_entropy": dns_feats["dns_subdomain_entropy"],
            "dns_digit_ratio": dns_feats["dns_digit_ratio"],
            "has_ssl_ja3": has_ja3,
            "is_tcp": is_tcp,
            "is_udp": is_udp,
            "is_icmp": is_icmp,
            "is_well_known_dst_port": is_well_known_dst,
            "is_registered_dst_port": is_registered_dst,
            "is_ephemeral_dst_port": is_ephemeral_dst,
            "is_well_known_src_port": is_well_known_src,
            "is_ephemeral_src_port": is_ephemeral_src,
        }

    @classmethod
    def extract_from_unified_flow(cls, flow: UnifiedFlow) -> Dict[str, float]:
        norm = NormalizedFlow(
            flow_id=flow.flow_id,
            timestamp=flow.timestamp,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
            duration=flow.duration,
            src_bytes=flow.src_bytes,
            dst_bytes=flow.dst_bytes,
            src_pkts=flow.src_pkts,
            dst_pkts=flow.dst_pkts,
            raw_source="UnifiedFlow"
        )
        return cls.extract_from_normalized_flow(norm)

    @classmethod
    def to_dataframe(cls, flows: Union[List[NormalizedFlow], List[UnifiedFlow]]) -> pd.DataFrame:
        if not flows:
            return pd.DataFrame(columns=FLOW_FEATURE_COLUMNS)
        if isinstance(flows[0], NormalizedFlow):
            rows = [cls.extract_from_normalized_flow(f) for f in flows]
        else:
            rows = [cls.extract_from_unified_flow(f) for f in flows]
        df = pd.DataFrame(rows)
        for col in FLOW_FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0
        return df[FLOW_FEATURE_COLUMNS]
