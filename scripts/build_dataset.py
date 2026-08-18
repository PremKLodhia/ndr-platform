"""
Dataset Processing and Feature Engineering Pipeline.
Ingests raw dataset files from data/raw/ (CICIDS2017, UNSW-NB15, and Zeek logs),
extracts normalized flow features, validates data quality, and writes processed feature tables
and manifest.json into data/processed/.
"""
import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
import pandas as pd

from ndr.ingest.common_schema import NormalizedFlow
from ndr.ingest.cicids_loader import CICIDS2017Loader
from ndr.ingest.unsw_loader import UNSWNB15Loader
from ndr.ingest.zeek_parser import ZeekParser
from ndr.features.flow_extractor import FlowFeatureExtractor, FLOW_FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DatasetBuilder")


def scan_and_process_raw_data(
    raw_dir: str = "data/raw",
    output_dir: str = "data/processed",
    sample_limit: int = 100000
) -> Dict[str, Any]:
    raw_path = Path(raw_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    sources_found = []
    all_flows: List[NormalizedFlow] = []
    data_quality_issues = {
        "missing_ip_or_ports": 0,
        "negative_or_zero_packets": 0,
        "invalid_numeric_values": 0
    }

    # 1. Search for CICIDS2017 CSV files
    cicids_files = list(raw_path.glob("**/*ISCX*.csv")) + list(raw_path.glob("**/cicids2017/**/*.csv"))
    if cicids_files:
        logger.info(f"Found {len(cicids_files)} CICIDS2017 raw file(s).")
        for f in cicids_files:
            sources_found.append(str(f))
            try:
                for chunk in CICIDS2017Loader.load_csv(f, chunksize=10000):
                    for flow in chunk:
                        if not flow.src_ip or not flow.dst_ip:
                            data_quality_issues["missing_ip_or_ports"] += 1
                            continue
                        if flow.src_pkts + flow.dst_pkts <= 0:
                            data_quality_issues["negative_or_zero_packets"] += 1
                            continue
                        all_flows.append(flow)
                        if len(all_flows) >= sample_limit:
                            break
                    if len(all_flows) >= sample_limit:
                        break
            except Exception as e:
                logger.error(f"Error loading {f}: {e}")

    # 2. Search for UNSW-NB15 CSV files
    unsw_files = list(raw_path.glob("**/*UNSW*.csv")) + list(raw_path.glob("**/unsw-nb15/**/*.csv"))
    if unsw_files:
        logger.info(f"Found {len(unsw_files)} UNSW-NB15 raw file(s).")
        for f in unsw_files:
            sources_found.append(str(f))
            try:
                for chunk in UNSWNB15Loader.load_csv(f, chunksize=10000):
                    for flow in chunk:
                        if not flow.src_ip or not flow.dst_ip:
                            data_quality_issues["missing_ip_or_ports"] += 1
                            continue
                        if flow.src_pkts + flow.dst_pkts <= 0:
                            data_quality_issues["negative_or_zero_packets"] += 1
                            continue
                        all_flows.append(flow)
                        if len(all_flows) >= sample_limit:
                            break
                    if len(all_flows) >= sample_limit:
                        break
            except Exception as e:
                logger.error(f"Error loading {f}: {e}")

    # 3. Search for Zeek conn.log files
    zeek_files = list(raw_path.glob("**/conn.log"))
    if zeek_files:
        logger.info(f"Found {len(zeek_files)} Zeek log file(s).")
        for f in zeek_files:
            sources_found.append(str(f))
            try:
                for flow in ZeekParser.stream_tsv_file(f):
                    all_flows.append(flow)
                    if len(all_flows) >= sample_limit:
                        break
            except Exception as e:
                logger.error(f"Error loading {f}: {e}")

    # If no raw datasets downloaded yet, generate standard baseline distribution for pipeline validation
    if not all_flows:
        logger.warning(
            "[!] No raw dataset CSVs detected in data/raw/.\n"
            "    Generating synthetic benchmark partition (1000 flows) for verification.\n"
            "    Please download CICIDS2017 / UNSW-NB15 to data/raw/ to build full production datasets."
        )
        sources_found.append("synthetic_baseline_generator")
        np.random.seed(42)
        # 700 Benign
        for i in range(700):
            all_flows.append(NormalizedFlow(
                flow_id=f"SYNTH_BENIGN_{i}",
                timestamp=1700000000.0 + i,
                src_ip=f"192.168.1.{(i % 50) + 10}",
                src_port=40000 + (i % 20000),
                dst_ip="1.1.1.1" if i % 2 == 0 else "8.8.8.8",
                dst_port=443 if i % 2 == 0 else 53,
                proto="tcp" if i % 2 == 0 else "udp",
                duration=np.random.uniform(0.05, 5.0),
                src_bytes=int(np.random.uniform(100, 3000)),
                dst_bytes=int(np.random.uniform(200, 15000)),
                src_pkts=int(np.random.uniform(3, 30)),
                dst_pkts=int(np.random.uniform(3, 40)),
                label="BENIGN",
                attack_category="BENIGN",
                raw_source="SyntheticBaseline"
            ))
        # 150 Port scans
        for i in range(150):
            all_flows.append(NormalizedFlow(
                flow_id=f"SYNTH_SCAN_{i}",
                timestamp=1700005000.0 + i,
                src_ip="10.10.10.99",
                src_port=50000 + i,
                dst_ip="192.168.1.1",
                dst_port=20 + (i % 100),
                proto="tcp",
                duration=0.005,
                src_bytes=40,
                dst_bytes=0,
                src_pkts=1,
                dst_pkts=0,
                label="MALICIOUS",
                attack_category="PORT_SCAN",
                mitre_technique="T1046",
                raw_source="SyntheticBaseline"
            ))
        # 150 DDoS
        for i in range(150):
            all_flows.append(NormalizedFlow(
                flow_id=f"SYNTH_DDOS_{i}",
                timestamp=1700010000.0 + i,
                src_ip=f"172.16.0.{(i % 200) + 1}",
                src_port=1024 + i,
                dst_ip="192.168.1.1",
                dst_port=80,
                proto="tcp",
                duration=0.01,
                src_bytes=1500,
                dst_bytes=0,
                src_pkts=100,
                dst_pkts=0,
                label="MALICIOUS",
                attack_category="DDOS_FLOOD",
                mitre_technique="T1498.001",
                raw_source="SyntheticBaseline"
            ))

    # Extract tabular features
    logger.info(f"Extracting features from {len(all_flows)} flows...")
    features_df = FlowFeatureExtractor.to_dataframe(all_flows)
    
    # Append labels and metadata
    features_df["label"] = [f.label for f in all_flows]
    features_df["attack_category"] = [f.attack_category for f in all_flows]
    features_df["mitre_technique"] = [f.mitre_technique or "N/A" for f in all_flows]
    features_df["raw_source"] = [f.raw_source for f in all_flows]

    # Save processed dataset
    output_csv = out_path / "processed_flows.csv"
    features_df.to_csv(output_csv, index=False)
    logger.info(f"Saved processed dataset to {output_csv}")

    # Compute class balance
    class_balance = features_df["attack_category"].value_counts().to_dict()
    label_balance = features_df["label"].value_counts().to_dict()

    manifest = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "total_rows_processed": len(features_df),
        "feature_count": len(FLOW_FEATURE_COLUMNS),
        "sources_detected": sources_found,
        "data_quality_issues": data_quality_issues,
        "binary_label_balance": label_balance,
        "class_balance": class_balance,
        "output_file": str(output_csv)
    }

    manifest_path = out_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(f"Manifest written to {manifest_path}")

    return manifest


if __name__ == "__main__":
    manifest = scan_and_process_raw_data()
    print("\n==================================================")
    print("DATASET PROCESSING MANIFEST SUMMARY")
    print("==================================================")
    print(f"Total Rows Processed: {manifest['total_rows_processed']}")
    print(f"Sources:              {manifest['sources_detected']}")
    print(f"Binary Label Balance: {manifest['binary_label_balance']}")
    print(f"Class Balance:        {manifest['class_balance']}")
    print(f"Quality Flags:        {manifest['data_quality_issues']}")
    print("==================================================")
