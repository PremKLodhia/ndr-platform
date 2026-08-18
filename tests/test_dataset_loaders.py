"""
Unit tests for CICIDS2017 and UNSW-NB15 dataset loaders, port entropy, and DNS feature extraction.
"""
import pytest
from ndr.ingest.cicids_loader import CICIDS2017Loader
from ndr.ingest.unsw_loader import UNSWNB15Loader
from ndr.features.port_entropy import calculate_port_entropy
from ndr.features.dns_features import extract_dns_features
from ndr.features.timing_stats import calculate_timing_stats


def test_cicids_loader_normalization():
    raw_row = {
        "Flow ID": "192.168.10.50-10.0.0.1-443-50000-6",
        "Source IP": "192.168.10.50",
        "Source Port": "50000",
        "Destination IP": "10.0.0.1",
        "Destination Port": "443",
        "Protocol": "6",
        "Flow Duration": "1000000",  # 1 second in microseconds
        "Total Fwd Packets": "10",
        "Total Backward Packets": "12",
        "Total Length of Fwd Packets": "1500",
        "Total Length of Bwd Packets": "4500",
        "Fwd IAT Mean": "100000",
        "Bwd IAT Mean": "80000",
        "Label": "PortScan"
    }

    norm = CICIDS2017Loader.normalize_row(raw_row)
    assert norm.src_ip == "192.168.10.50"
    assert norm.dst_port == 443
    assert norm.duration == 1.0
    assert norm.src_bytes == 1500
    assert norm.dst_bytes == 4500
    assert norm.label == "MALICIOUS"
    assert norm.attack_category == "PORT_SCAN"
    assert norm.mitre_technique == "T1046"


def test_unsw_loader_normalization():
    raw_row = {
        "srcip": "172.16.0.10",
        "sport": "3389",
        "dstip": "192.168.1.5",
        "dsport": "54321",
        "proto": "tcp",
        "dur": "0.5",
        "sbytes": "800",
        "dbytes": "1200",
        "Spkts": "8",
        "Dpkts": "10",
        "attack_cat": "Backdoor",
        "label": "1"
    }

    norm = UNSWNB15Loader.normalize_row(raw_row)
    assert norm.src_ip == "172.16.0.10"
    assert norm.dst_ip == "192.168.1.5"
    assert norm.duration == 0.5
    assert norm.attack_category == "C2_BEACONING"
    assert norm.mitre_technique == "T1071.001"
    assert norm.label == "MALICIOUS"


def test_port_entropy():
    # Single port repeated -> 0 entropy
    assert calculate_port_entropy([80, 80, 80, 80]) == 0.0

    # Diverse ports -> high entropy
    diverse_ports = list(range(100, 200))
    entropy = calculate_port_entropy(diverse_ports)
    assert entropy > 6.0


def test_dns_features_dga_vs_normal():
    # Normal query
    normal = extract_dns_features("google.com")
    assert normal["dns_query_len"] == 10.0
    assert normal["dns_subdomain_entropy"] < 3.5

    # DGA / Tunneling query with high randomness
    dga = extract_dns_features("a8f9c1e7b23d90x89q3m1.c2.attacker.com")
    assert dga["dns_query_len"] > 25.0
    assert dga["dns_subdomain_entropy"] > 3.8
    assert dga["dns_digit_ratio"] > 0.3


def test_timing_stats():
    iats = [0.01, 0.02, 0.01, 0.03, 0.015]
    stats = calculate_timing_stats(iats)
    assert stats["iat_mean"] > 0.0
    assert stats["iat_max"] == 0.03
    assert stats["iat_cv"] >= 0.0
