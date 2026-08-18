"""
Suricata Signature Alert Engine with MITRE ATT&CK technique mapping.
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from ...ingest.models import SuricataAlert

# Curated Mapping of Signature Categories/SIDs to MITRE ATT&CK
MITRE_SIGNATURE_MAP = {
    # Reconnaissance / Discovery
    "SCAN": ("T1046", "Network Service Discovery"),
    "PORT SCAN": ("T1046", "Network Service Discovery"),
    "NMAP": ("T1046", "Network Service Discovery"),
    
    # Initial Access / Exploitation
    "EXPLOIT": ("T1190", "Exploit Public-Facing Application"),
    "WEB_SERVER": ("T1190", "Exploit Public-Facing Application"),
    "SQL INJECTION": ("T1190", "Exploit Public-Facing Application"),
    
    # Credential Access / Brute Force
    "BRUTEFORCE": ("T1110", "Brute Force"),
    "LOGIN": ("T1110", "Brute Force"),
    "AUTH": ("T1110", "Brute Force"),
    "SSH": ("T1110.001", "Password Guessing"),
    
    # Command and Control
    "C2": ("T1071", "Application Layer Protocol"),
    "BEACON": ("T1071.001", "Web Protocols"),
    "BOTNET": ("T1584", "Compromise Infrastructure"),
    "TROJAN": ("T1071", "Application Layer Protocol"),
    "DNS TUNNEL": ("T1071.004", "DNS"),
    "IODINE": ("T1071.004", "DNS"),
    "DNSCAT": ("T1071.004", "DNS"),
    
    # Exfiltration
    "EXFILTRATION": ("T1048", "Exfiltration Over Alternative Protocol"),
    "DATA LOSS": ("T1048", "Exfiltration Over Alternative Protocol"),
    
    # Impact / DoS
    "DOS": ("T1498", "Network Denial of Service"),
    "DDOS": ("T1498", "Network Denial of Service"),
    "FLOOD": ("T1498.001", "Direct Network Flood"),
}


@dataclass
class SignatureDetection:
    alert: SuricataAlert
    mitre_id: str
    mitre_tactic: str
    severity_weight: float  # 1.0 = Critical, 0.6 = Medium, 0.3 = Low
    is_high_fidelity: bool


class SuricataEngine:
    """Enriches and evaluates Suricata alerts against MITRE ATT&CK framework."""

    @classmethod
    def map_to_mitre(cls, alert: SuricataAlert) -> tuple[str, str]:
        """Map signature name / category to MITRE ATT&CK technique ID and name."""
        target_text = f"{alert.signature} {alert.category}".upper()
        
        for key, (tech_id, tech_name) in MITRE_SIGNATURE_MAP.items():
            if key in target_text:
                return tech_id, tech_name
        
        return "T1071", "Standard Application Layer Protocol (Uncategorized Alert)"

    @classmethod
    def evaluate_alert(cls, alert: SuricataAlert) -> SignatureDetection:
        """Convert raw alert into enriched SignatureDetection with weighted severity."""
        tech_id, tech_name = cls.map_to_mitre(alert)
        alert.mitre_technique_id = tech_id
        alert.mitre_tactic = tech_name

        # Severity in Suricata: 1 is highest, 3/4 is lowest
        if alert.severity == 1:
            weight = 1.0
            high_fidelity = True
        elif alert.severity == 2:
            weight = 0.65
            high_fidelity = False
        else:
            weight = 0.30
            high_fidelity = False

        return SignatureDetection(
            alert=alert,
            mitre_id=tech_id,
            mitre_tactic=tech_name,
            severity_weight=weight,
            is_high_fidelity=high_fidelity
        )
