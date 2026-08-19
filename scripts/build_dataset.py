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
from ndr.features.flow_extractor import FlowFeatureExtractor, FLOW_FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DatasetBuilder")


def build_multiclass_dataset(
    raw_dir: str = "data/raw/MachineLearningCSV/MachineLearningCVE",
    output_dir: str = "data/processed",
    max_benign_per_file: int = 15000,
    max_ddos_per_file: int = 15000,
    max_portscan: int = 35000
):
    raw_path = Path(raw_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_files = list(raw_path.glob("*.csv"))
    if not csv_files:
        logger.error(f"No CSV files found in {raw_dir}")
        return

    logger.info(f"Processing all {len(csv_files)} CICIDS2017 files for balanced multi-class coverage...")
    all_flows: List[NormalizedFlow] = []
    class_counts = {}

    for file_idx, csv_file in enumerate(csv_files):
        logger.info(f"Loading {csv_file.name}...")
        file_benign = 0
        file_ddos = 0
        file_portscan = 0
        
        try:
            for chunk in pd.read_csv(csv_file, chunksize=25000, encoding="utf-8", encoding_errors="ignore", low_memory=False):
                chunk.columns = [c.strip() for c in chunk.columns]
                label_col = [c for c in chunk.columns if "label" in c.lower()][0]

                for row in chunk.to_dict(orient="records"):
                    norm_flow = CICIDS2017Loader.normalize_row(row, file_idx=file_idx)
                    
                    if not norm_flow.src_ip or not norm_flow.dst_ip:
                        continue
                    if norm_flow.src_pkts + norm_flow.dst_pkts <= 0:
                        continue

                    cat = norm_flow.attack_category
                    if cat == "BENIGN":
                        if file_benign >= max_benign_per_file:
                            continue
                        file_benign += 1
                    elif cat == "DDOS_FLOOD":
                        if file_ddos >= max_ddos_per_file:
                            continue
                        file_ddos += 1
                    elif cat == "PORT_SCAN":
                        if file_portscan >= max_portscan:
                            continue
                        file_portscan += 1

                    all_flows.append(norm_flow)
                    class_counts[cat] = class_counts.get(cat, 0) + 1
        except Exception as e:
            logger.error(f"Error reading {csv_file.name}: {e}")

    logger.info(f"Total flows collected across all 8 files: {len(all_flows):,}")
    logger.info(f"Class breakdown: {json.dumps(class_counts, indent=2)}")

    # Extract 31+ tabular features
    logger.info("Extracting tabular flow feature vectors...")
    records = []
    for flow in all_flows:
        feat_dict = FlowFeatureExtractor.extract_from_normalized_flow(flow)
        feat_dict["label"] = flow.label
        feat_dict["attack_category"] = flow.attack_category
        feat_dict["mitre_technique"] = flow.mitre_technique or "N/A"
        records.append(feat_dict)

    df_out = pd.DataFrame(records)
    out_csv = out_path / "processed_flows.csv"
    df_out.to_csv(out_csv, index=False)
    logger.info(f"Saved processed dataset to {out_csv} ({df_out.shape})")

    manifest = {
        "dataset_name": "CICIDS2017_MultiClass_Balanced",
        "total_flows": len(df_out),
        "class_breakdown": class_counts,
        "feature_count": len(FLOW_FEATURE_COLUMNS),
        "source_files": [f.name for f in csv_files]
    }
    (out_path / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(f"Saved manifest to {out_path / 'manifest.json'}")


if __name__ == "__main__":
    build_multiclass_dataset()
