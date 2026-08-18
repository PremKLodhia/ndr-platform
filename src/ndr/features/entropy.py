"""
Payload entropy calculation utilities for detecting encrypted C2, DNS tunneling, and packed payloads.
"""
import math
from typing import Union, Sequence


def calculate_shannon_entropy(data: Union[bytes, bytearray, Sequence[int], str]) -> float:
    """
    Compute Shannon entropy (in bits per symbol, 0.0 to 8.0 for byte streams).
    Higher values (~7.5+) indicate high randomness / encryption / compression.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    length = len(data)
    if length == 0:
        return 0.0

    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)
