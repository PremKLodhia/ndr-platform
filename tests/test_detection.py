"""
Unit tests for signature evaluation, supervised classifier, and autoencoder.
"""
import pytest
import numpy as np
import pandas as pd
from ndr.detection.signatures.suricata_engine import SuricataEngine
from ndr.detection.classifier.xgb_classifier import FlowClassifier
from ndr.detection.anomaly.autoencoder import BenignFlowAutoencoder
from ndr.ingest.models import SuricataAlert
from ndr.features.flow_extractor import FLOW_FEATURE_COLUMNS


def test_suricata_mitre_mapping():
    alert = SuricataAlert(
        timestamp="2026-08-18T12:00:00Z",
        src_ip="10.0.0.99",
        src_port=4444,
        dst_ip="192.168.1.1",
        dst_port=80,
        proto="tcp",
        signature_id=200001,
        signature="ET SCAN Nmap SYN Scan",
        category="Reconnaissance",
        severity=1
    )

    detection = SuricataEngine.evaluate_alert(alert)
    assert detection.mitre_id == "T1046"
    assert detection.severity_weight == 1.0
    assert detection.is_high_fidelity is True


def test_flow_classifier_train_predict():
    classifier = FlowClassifier()

    # Generate synthetic training data for benign and port scan
    np.random.seed(42)
    n_samples = 50
    data = []
    labels = []
    for _ in range(n_samples):
        # Benign sample
        data.append({col: np.random.uniform(0, 10) for col in FLOW_FEATURE_COLUMNS})
        labels.append("BENIGN")
        # Port scan sample (high pkts_per_sec, 0 dst_bytes)
        scan = {col: np.random.uniform(0, 1) for col in FLOW_FEATURE_COLUMNS}
        scan["pkts_per_sec"] = 1000.0
        scan["dst_bytes"] = 0.0
        data.append(scan)
        labels.append("PORT_SCAN")

    df = pd.DataFrame(data)
    classifier.fit(df, np.array(labels))
    assert classifier.is_trained is True

    # Test prediction
    test_scan = {col: 0.0 for col in FLOW_FEATURE_COLUMNS}
    test_scan["pkts_per_sec"] = 2000.0
    pred = classifier.predict_flow(test_scan)
    assert "predicted_class" in pred
    assert "confidence" in pred


def test_autoencoder_benign_anomaly():
    ae = BenignFlowAutoencoder(input_dim=len(FLOW_FEATURE_COLUMNS))
    X_benign = np.random.normal(0.0, 1.0, size=(100, len(FLOW_FEATURE_COLUMNS))).astype(np.float32)
    ae.fit(X_benign, epochs=5)

    assert ae.is_trained is True
    # Test benign evaluation
    benign_vec = np.zeros(len(FLOW_FEATURE_COLUMNS), dtype=np.float32)
    res = ae.evaluate_flow(benign_vec)
    assert "anomaly_score" in res
    assert "is_anomalous" in res
