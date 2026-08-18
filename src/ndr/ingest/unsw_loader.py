"""
Raw CSV dataset loader for UNSW-NB15.
Maps feature columns and attack categories to common normalized schema.
"""
import os
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Generator, List, Dict, Any, Union
from .common_schema import NormalizedFlow

logger = logging.getLogger(__name__)

UNSW_CATEGORY_MAP = {
    "NORMAL": ("BENIGN", "N/A"),
    "RECONNAISSANCE": ("PORT_SCAN", "T1046"),
    "DOS": ("DDOS_FLOOD", "T1498.001"),
    "BACKDOOR": ("C2_BEACONING", "T1071.001"),
    "EXPLOITS": ("EXPLOIT_RCE", "T1190"),
    "GENERIC": ("EXPLOIT_RCE", "T1190"),
    "FUZZERS": ("RECON_FUZZ", "T1046"),
    "WORMS": ("LATERAL_MOVEMENT", "T1021"),
    "SHELLCODE": ("EXECUTION", "T1059"),
    "ANALYSIS": ("RECON_SCAN", "T1046")
}


class UNSWNB15Loader:
    """Loads and normalizes UNSW-NB15 raw CSV dataset files."""

    @classmethod
    def normalize_row(cls, row: Dict[str, Any], idx: int = 0) -> NormalizedFlow:
        clean_row = {str(k).strip(): v for k, v in row.items()}
        
        raw_cat = str(clean_row.get("attack_cat", clean_row.get("Attack_Cat", "Normal"))).strip().upper()
        norm_class, mitre_id = "BENIGN", None
        for k, (c, m) in UNSW_CATEGORY_MAP.items():
            if k in raw_cat:
                norm_class, mitre_id = c, m
                break

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

        proto_str = str(clean_row.get("proto", "tcp")).lower()

        return NormalizedFlow(
            flow_id=f"UNSW_{idx}_{clean_row.get('srcip', '0')}_{clean_row.get('sport', '0')}",
            timestamp=_get_float("stime", 0.0),
            src_ip=str(clean_row.get("srcip", clean_row.get("src_ip", "0.0.0.0"))),
            src_port=_get_int("sport", _get_int("src_port", 0)),
            dst_ip=str(clean_row.get("dstip", clean_row.get("dst_ip", "0.0.0.0"))),
            dst_port=_get_int("dsport", _get_int("dst_port", 0)),
            proto=proto_str,
            duration=max(_get_float("dur", 0.0), 0.000001),
            src_bytes=_get_int("sbytes", 0),
            dst_bytes=_get_int("dbytes", 0),
            src_pkts=_get_int("Spkts", _get_int("spkts", 0)),
            dst_pkts=_get_int("Dpkts", _get_int("dpkts", 0)),
            label="MALICIOUS" if norm_class != "BENIGN" or _get_int("label", 0) == 1 else "BENIGN",
            attack_category=norm_class,
            mitre_technique=mitre_id,
            fwd_iat_mean=_get_float("sinpkt", 0.0) / 1000.0,
            bwd_iat_mean=_get_float("dinpkt", 0.0) / 1000.0,
            raw_source="UNSW-NB15"
        )

    @classmethod
    def load_csv(cls, filepath: Union[str, Path], chunksize: int = 10000) -> Generator[List[NormalizedFlow], None, None]:
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"UNSW-NB15 file not found: {filepath}")

        for chunk_idx, df in enumerate(pd.read_csv(p, chunksize=chunksize, low_memory=False, encoding="utf-8", on_bad_lines="skip")):
            df.columns = [c.strip() for c in df.columns]
            flows = [cls.normalize_row(row, idx=chunk_idx*chunksize + i) for i, row in enumerate(df.to_dict(orient="records"))]
            yield flows
