"""
Packet and burst inter-arrival timing statistics.
"""
import numpy as np
from typing import Sequence, Dict


def calculate_timing_stats(iats: Sequence[float]) -> Dict[str, float]:
    """Calculate mean, std, max, and coefficient of variation for inter-arrival times."""
    if not iats or len(iats) == 0:
        return {"iat_mean": 0.0, "iat_std": 0.0, "iat_max": 0.0, "iat_cv": 0.0}

    arr = np.array(iats, dtype=float)
    mean = float(np.mean(arr))
    std = float(np.std(arr))
    max_val = float(np.max(arr))
    cv = (std / mean) if mean > 0 else 0.0

    return {
        "iat_mean": round(mean, 6),
        "iat_std": round(std, 6),
        "iat_max": round(max_val, 6),
        "iat_cv": round(cv, 4)
    }
