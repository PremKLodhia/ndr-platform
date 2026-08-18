"""
DNS query linguistic and structural feature extraction for detecting DNS Tunneling (T1071.004) and DGAs.
"""
import re
from typing import Dict, Any, Optional
from .entropy import calculate_shannon_entropy


def extract_dns_features(query: Optional[str]) -> Dict[str, float]:
    """
    Extract domain length, subdomain entropy, digit ratio, and vowel ratio from DNS queries.
    """
    if not query or query in ("-", "(empty)", "none"):
        return {
            "dns_query_len": 0.0,
            "dns_subdomain_entropy": 0.0,
            "dns_digit_ratio": 0.0,
            "dns_vowel_ratio": 0.0,
            "dns_label_count": 0.0,
        }

    clean_query = query.strip().rstrip(".").lower()
    length = len(clean_query)
    if length == 0:
        return {
            "dns_query_len": 0.0,
            "dns_subdomain_entropy": 0.0,
            "dns_digit_ratio": 0.0,
            "dns_vowel_ratio": 0.0,
            "dns_label_count": 0.0,
        }

    labels = clean_query.split(".")
    subdomain = labels[0] if len(labels) > 2 else clean_query

    entropy = calculate_shannon_entropy(subdomain)
    digits = sum(1 for c in clean_query if c.isdigit())
    vowels = sum(1 for c in clean_query if c in "aeiou")

    return {
        "dns_query_len": float(length),
        "dns_subdomain_entropy": float(entropy),
        "dns_digit_ratio": round(digits / length, 4),
        "dns_vowel_ratio": round(vowels / max(length - digits, 1), 4),
        "dns_label_count": float(len(labels)),
    }
