"""
Destination and source port distribution entropy calculation for detecting port scanning (T1046) and sweeping.
"""
import math
from typing import Sequence, Dict, List


def calculate_port_entropy(ports: Sequence[int]) -> float:
    """
    Compute Shannon entropy over a sequence of observed destination or source ports.
    High entropy (~3.5+) indicates wide scanning or ephemeral cycling.
    """
    if not ports:
        return 0.0

    length = len(ports)
    frequencies: Dict[int, int] = {}
    for p in ports:
        frequencies[p] = frequencies.get(p, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)
