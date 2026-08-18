"""
Raw CSV dataset loader for CICIDS2017.
Normalizes heterogeneous column naming and whitespace quirks.
"""
import os
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Generator, List, Dict, Any, Union
from .common_schema import NormalizedFlow

logger = logging.getLogger(__name__)

# Standard label mapping for CICIDS2017 -> Unified Classes & MITRE IDs
CICIDS_LABEL_MAP = {
    "BENIGN": ("BENIGN", "N/A"),
    "PORT SCAN": ("PORT_SCAN", "T1046"),
    "PORTSCAN": ("PORT_SCAN", "T1046"),
    "DOS HULK": ("DDOS_FLOOD", "T1498.001"),
    "DOS GOLDENEYE": ("DDOS_FLOOD", "T1498.001"),
    "DOS SLOWLORIS": ("DDOS_FLOOD", "T1498"),
    "DOS SLOWHTTPTEST": ("DDOS_FLOOD", "T1498"),
    "DDOS": ("DDOS_FLOOD", "T1498.001"),
    "BOT": ("C2_BEACONING", "T1071.001"),
    "FTP-PATATOR": ("BRUTE_FORCE", "T1110.001"),
    "SSH-PATATOR": ("BRUTE_FORCE", "T1110.001"),
    "INFILTRATION": ("EXPLOIT_RCE", "T1190"),
    "WEB ATTACK – BRUTE FORCE": ("BRUTE_FORCE", "T1110"),
    "WEB ATTACK – XSS": ("EXPLOIT_RCE", "T1190"),
    "WEB ATTACK – SQL INJECTION": ("EXPLOIT_RCE", "T1190"),
    "HEARTBLEED": ("EXPLOIT_RCE", "T1190")
}


class CICIDS2017Loader:
    """Loads and normalizes CICIDS2017 raw CSV data files."""

    @classmethod
    def normalize_row(cls, row: Dict[str, Any], file_idx: int = 0) -> NormalizedFlow:
        # Strip whitespace from keys
        clean_row = {str(k).strip(): v for k, v in row.items()}
        
        raw_label = str(clean_row.get("Label", "BENIGN")).strip().upper()
        norm_class, mitre_id = "BENIGN", None
        for k, (c, m) in CICIDS_LABEL_MAP.items():
            if k in raw_label:
                norm_class, mitre_id = c, m
                break

        # Safe numeric parsing
        def _get_float(key, default=0.0):
            val = clean_row.get(key, default)
            try:
                f = float(val)
                return 0.0 if np.isnan(f) or np.isinf(f) else f
            except:
                return default

        def _get_int(key, default=0):
            val = clean_row.get(key, default)
            try:
                f = float(val)
                return 0 if np.isnan(f) or np.isinf(f) else int(f)
            except:
                return default

        # CICIDS2017 flow duration is in microseconds
        duration_sec = _get_float("Flow Duration", 0.0) / 1_000_000.0

        return NormalizedFlow(
            flow_id=f"CICIDS_{file_idx}_{clean_row.get('Flow ID', clean_row.get('Source IP', '0'))}",
            timestamp=_get_float("Timestamp", 0.0),
            src_ip=str(clean_row.get("Source IP", clean_row.get("Src IP", "0.0.0.0"))),
            src_port=_get_int("Source Port", _get_int("Src Port", 0)),
            dst_ip=str(clean_row.get("Destination IP", clean_row.get("Dst IP", "0.0.0.0"))),
            dst_port=_get_int("Destination Port", _get_int("Dst Port", 0)),
            proto="tcp" if _get_int("Protocol", 6) == 6 else ("udp" if _get_int("Protocol", 6) == 17 else "other"),
            duration=max(duration_sec, 0.000001),
            src_bytes=_get_int("Total Length of Fwd Packets", _get_int("TotLen Fwd Pkts", 0)),
            dst_bytes=_get_int("Total Length of Bwd Packets", _get_int("TotLen Bwd Pkts", 0)),
            src_pkts=_get_int("Total Fwd Packets", _get_int("Tot Fwd Pkts", 0)),
            dst_pkts=_get_int("Total Backward Packets", _get_int("Tot Bwd Pkts", 0)),
            label="MALICIOUS" if norm_class != "BENIGN" else "BENIGN",
            attack_category=norm_class,
            mitre_technique=mitre_id,
            fwd_iat_mean=_get_float("Fwd IAT Mean", 0.0) / 1_000_000.0,
            bwd_iat_mean=_get_float("Bwd IAT Mean", 0.0) / 1_000_000.0,
            fwd_iat_std=_get_float("Fwd IAT Std", 0.0) / 1_000_000.0,
            bwd_iat_std=_get_float("Bwd IAT Std", 0.0) / 1_000_000.0,
            raw_source="CICIDS2017"
        )

    @classmethod
    def load_csv(cls, filepath: Union[str, Path], chunksize: int = 10000) -> Generator[List[NormalizedFlow], None, None]:
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"CICIDS2017 file not found: {filepath}")

        for chunk_idx, df in enumerate(pd.read_csv(p, chunksize=chunksize, low_memory=False, encoding="utf-8", on_bad_lines="skip")):
            # Standardize column headers
            df.columns = [c.strip() for c in df.columns]
            flows = [cls.normalize_row(row, file_idx=chunk_idx) for row in df.to_dict(orient="records")]
            yield flows
