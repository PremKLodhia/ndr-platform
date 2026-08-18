"""
Unit tests for flow feature extraction and Shannon entropy computation.
"""
import pytest
from ndr.features.entropy import calculate_shannon_entropy
from ndr.features.flow_extractor import FlowFeatureExtractor, FLOW_FEATURE_COLUMNS
from ndr.ingest.models import UnifiedFlow


def test_shannon_entropy():
    # Low entropy: repetitive bytes
    low_entropy = calculate_shannon_entropy(b"AAAAAAAABBBBBBBB")
    assert 0.5 <= low_entropy <= 1.5

    # High entropy: pseudo-random byte distribution
    high_entropy = calculate_shannon_entropy(bytes(range(256)))
    assert high_entropy > 7.9


def test_flow_feature_extraction():
    flow = UnifiedFlow(
        flow_id="FLOW-001",
        timestamp=1700000000.0,
        src_ip="192.168.1.15",
        src_port=52341,
        dst_ip="8.8.8.8",
        dst_port=53,
        proto="udp",
        duration=0.5,
        src_bytes=128,
        dst_bytes=512,
        src_pkts=2,
        dst_pkts=2,
        conn_state="SF"
    )

    feats = FlowFeatureExtractor.extract_from_unified_flow(flow)
    for col in FLOW_FEATURE_COLUMNS:
        assert col in feats, f"Missing feature column: {col}"

    assert feats["duration"] == 0.5
    assert feats["tot_bytes"] == 640.0
    assert feats["is_udp"] == 1.0
    assert feats["is_tcp"] == 0.0
    assert feats["is_well_known_dst_port"] == 1.0  # DNS port 53 < 1024
