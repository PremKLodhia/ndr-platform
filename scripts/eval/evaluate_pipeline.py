"""
Evaluation harness running the NDR pipeline against network flow batches.
Computes non-fabricated Confusion Matrix, Precision, Recall, F1-Score, and FPR.
"""
import numpy as np
import pandas as pd
from ndr.ingest.models import UnifiedFlow, SuricataAlert
from ndr.features.flow_extractor import FlowFeatureExtractor, FLOW_FEATURE_COLUMNS
from ndr.detection.classifier.xgb_classifier import FlowClassifier
from ndr.detection.anomaly.autoencoder import BenignFlowAutoencoder
from ndr.decision.arbiter import DecisionArbiter, ActionVerdict
from ndr.viz.dashboard import MetricsReporter


def run_pipeline_evaluation():
    """Run complete evaluation against synthetic test distribution."""
    print("==================================================================")
    print("NDR PLATFORM: EMPIRICAL EVALUATION HARNESS")
    print("==================================================================")

    np.random.seed(42)
    classifier = FlowClassifier()
    autoencoder = BenignFlowAutoencoder()

    # Step 1: Create synthetic training baseline using UnifiedFlows
    print("[*] Generating training distribution (Benign + Multi-class Attacks)...")
    train_flows: list[UnifiedFlow] = []
    train_labels: list[str] = []

    # 300 Benign training flows (Web, DNS, internal traffic)
    for i in range(300):
        flow = UnifiedFlow(
            flow_id=f"TRAIN-BENIGN-{i}",
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
            conn_state="SF"
        )
        train_flows.append(flow)
        train_labels.append("BENIGN")

    # 80 Port scan flows
    for i in range(80):
        flow = UnifiedFlow(
            flow_id=f"TRAIN-SCAN-{i}",
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
            conn_state="S0"
        )
        train_flows.append(flow)
        train_labels.append("PORT_SCAN")

    # 80 DDoS flood flows
    for i in range(80):
        flow = UnifiedFlow(
            flow_id=f"TRAIN-DDOS-{i}",
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
            conn_state="S0"
        )
        train_flows.append(flow)
        train_labels.append("DDOS_FLOOD")

    train_df = FlowFeatureExtractor.to_dataframe(train_flows)
    classifier.fit(train_df, np.array(train_labels))
    
    # Train autoencoder strictly on benign samples
    benign_df = train_df[np.array(train_labels) == "BENIGN"]
    autoencoder.fit(benign_df.values.astype(np.float32), epochs=15)

    arbiter = DecisionArbiter(classifier=classifier, autoencoder=autoencoder)

    # Step 2: Test against unseen evaluation split
    print("[*] Evaluating pipeline against 100 test samples...")
    y_true = []  # 0 = Benign, 1 = Malicious
    y_pred = []  # 0 = Pass, 1 = Contain (Block/Quarantine)

    # 70 Benign test flows
    for i in range(70):
        f = UnifiedFlow(
            flow_id=f"TEST-BENIGN-{i}",
            timestamp=1700000000.0 + i,
            src_ip="192.168.1.50",
            src_port=49000 + i,
            dst_ip="1.1.1.1",
            dst_port=443,
            proto="tcp",
            duration=np.random.uniform(0.1, 5.0),
            src_bytes=int(np.random.uniform(200, 2000)),
            dst_bytes=int(np.random.uniform(500, 8000)),
            src_pkts=int(np.random.uniform(5, 20)),
            dst_pkts=int(np.random.uniform(5, 30)),
            conn_state="SF"
        )
        verdict = arbiter.evaluate_flow(f)
        is_blocked = 1 if verdict.verdict in [ActionVerdict.BLOCK_AND_ISOLATE, ActionVerdict.QUARANTINE_VLAN] else 0
        y_true.append(0)
        y_pred.append(is_blocked)

    # 30 Malicious test flows (Port scans with Suricata alerts)
    for i in range(30):
        alert = SuricataAlert(
            timestamp="2026-08-18T12:00:00Z",
            src_ip="10.10.10.99",
            src_port=50000 + i,
            dst_ip="192.168.1.1",
            dst_port=22,
            proto="tcp",
            signature_id=2001001,
            signature="ET SCAN Fast Portscan Detected",
            category="Reconnaissance",
            severity=1
        )
        f = UnifiedFlow(
            flow_id=f"TEST-ATTACK-{i}",
            timestamp=1700001000.0 + i,
            src_ip="10.10.10.99",
            src_port=50000 + i,
            dst_ip="192.168.1.1",
            dst_port=22,
            proto="tcp",
            duration=0.01,
            src_bytes=40,
            dst_bytes=0,
            src_pkts=1,
            dst_pkts=0,
            conn_state="S0",
            alerts=[alert]
        )
        verdict = arbiter.evaluate_flow(f)
        is_blocked = 1 if verdict.verdict in [ActionVerdict.BLOCK_AND_ISOLATE, ActionVerdict.QUARANTINE_VLAN] else 0
        y_true.append(1)
        y_pred.append(is_blocked)

    # Step 3: Compute Real Metrics
    metrics = MetricsReporter.calculate_metrics(y_true, y_pred)
    print("\n--- EVALUATION RESULTS ---")
    for k, v in metrics.items():
        print(f"  {k:22s}: {v}")
    print("==================================================================")


if __name__ == "__main__":
    run_pipeline_evaluation()
