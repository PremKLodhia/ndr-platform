"""
Signature Evaluation Harness:
Simulates/evaluates Suricata signature rules against labelled test PCAPs/flows,
measuring what signatures catch alone vs what is missed and caught by the ML/Anomaly layer.
"""
import os
import json
import logging
import joblib
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any

from ndr.ingest.models import UnifiedFlow, SuricataAlert
from ndr.detection.signatures.suricata_engine import SuricataEngine, SignatureDetection
from ndr.detection.classifier.xgb_classifier import FlowClassifier
from ndr.detection.anomaly.autoencoder import BenignFlowAutoencoder
from ndr.decision.arbiter import DecisionArbiter, ActionVerdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SignatureTester")


def evaluate_dual_path_synergy():
    logger.info("Evaluating Suricata Signature Coverage vs ML/Anomaly Dual-Path Layer...")

    # Load ML models
    classifier = FlowClassifier()
    autoencoder = BenignFlowAutoencoder()
    if Path("models/flow_classifier.joblib").exists():
        classifier = joblib.load("models/flow_classifier.joblib")
    if Path("models/benign_autoencoder.joblib").exists():
        autoencoder = BenignFlowAutoencoder.load("models/benign_autoencoder.joblib")

    arbiter = DecisionArbiter(classifier=classifier, autoencoder=autoencoder)

    # Define multi-vector evaluation scenarios
    scenarios = [
        # Scenario A: Known Signature Attack (Port Scan matching ET rule)
        {
            "name": "Known Aggressive SYN Portscan",
            "mitre": "T1046",
            "flow": UnifiedFlow(
                flow_id="SCENARIO-A",
                timestamp=1700000000.0,
                src_ip="10.10.10.99",
                src_port=52341,
                dst_ip="192.168.1.1",
                dst_port=22,
                proto="tcp",
                duration=0.01,
                src_bytes=40,
                dst_bytes=0,
                src_pkts=1,
                dst_pkts=0,
                conn_state="S0",
                alerts=[
                    SuricataAlert(
                        timestamp="2026-08-18T12:00:00Z",
                        src_ip="10.10.10.99",
                        src_port=52341,
                        dst_ip="192.168.1.1",
                        dst_port=22,
                        proto="tcp",
                        signature_id=3000001,
                        signature="NDR T1046 - Rapid TCP SYN Portscan Detected",
                        category="attempted-recon",
                        severity=1
                    )
                ]
            )
        },
        # Scenario B: Evasive / Slow C2 Beaconing (NO Signature match, caught by ML/Anomaly)
        {
            "name": "Evasive Low-Frequency C2 Beacon (Signature Bypass)",
            "mitre": "T1071.001",
            "flow": UnifiedFlow(
                flow_id="SCENARIO-B",
                timestamp=1700000100.0,
                src_ip="192.168.1.130",
                src_port=49888,
                dst_ip="203.0.113.88",
                dst_port=443,
                proto="tcp",
                duration=120.0,
                src_bytes=3500,
                dst_bytes=4200,
                src_pkts=25,
                dst_pkts=30,
                conn_state="SF",
                alerts=[]  # No signature alert triggered!
            )
        },
        # Scenario C: Known DNS Exfiltration
        {
            "name": "DNS Tunneling Exfiltration",
            "mitre": "T1071.004",
            "flow": UnifiedFlow(
                flow_id="SCENARIO-C",
                timestamp=1700000200.0,
                src_ip="192.168.1.120",
                src_port=45000,
                dst_ip="10.0.0.53",
                dst_port=53,
                proto="udp",
                duration=0.5,
                src_bytes=800,
                dst_bytes=200,
                src_pkts=5,
                dst_pkts=2,
                alerts=[
                    SuricataAlert(
                        timestamp="2026-08-18T12:00:00Z",
                        src_ip="192.168.1.120",
                        src_port=45000,
                        dst_ip="10.0.0.53",
                        dst_port=53,
                        proto="udp",
                        signature_id=3000004,
                        signature="NDR T1071.004 - Suspected DNS Tunneling Exfiltration Query",
                        category="bad-unknown",
                        severity=1
                    )
                ]
            )
        },
        # Scenario D: Zero-Day / Novel Protocol Anomaly (NO Signature, caught by Autoencoder)
        {
            "name": "Novel Zero-Day Tunneling Channel (Unseen Pattern)",
            "mitre": "T1572",
            "flow": UnifiedFlow(
                flow_id="SCENARIO-D",
                timestamp=1700000300.0,
                src_ip="192.168.1.250",
                src_port=60000,
                dst_ip="198.51.100.4",
                dst_port=8080,
                proto="tcp",
                duration=0.001,
                src_bytes=50000,
                dst_bytes=10,
                src_pkts=50,
                dst_pkts=1,
                conn_state="RSTR",
                alerts=[]  # No signature alert!
            )
        }
    ]

    results = []
    print("\n==================================================================")
    print("DUAL-PATH EVALUATION: SIGNATURE IDS vs ML/ANOMALY LAYER")
    print("==================================================================")
    print(f"{'Attack Scenario':<45} | {'Sig Alert?':<10} | {'ML/AE Verdict':<18} | {'Final Containment'}")
    print("-" * 105)

    for sc in scenarios:
        flow = sc["flow"]
        has_sig = len(flow.alerts) > 0
        verdict = arbiter.evaluate_flow(flow)

        sig_status = "CAUGHT" if has_sig else "MISSED"
        ml_status = verdict.verdict.value
        contained = "YES (" + verdict.verdict.value + ")" if verdict.verdict != ActionVerdict.PASS else "NO (PASS)"

        print(f"{sc['name']:<45} | {sig_status:<10} | {ml_status:<18} | {contained}")
        results.append({
            "scenario": sc["name"],
            "mitre": sc["mitre"],
            "signature_caught": has_sig,
            "final_verdict": verdict.verdict.value,
            "reasons": verdict.reasons
        })

    print("==================================================================\n")
    return results


if __name__ == "__main__":
    evaluate_dual_path_synergy()
