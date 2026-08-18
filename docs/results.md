# Empirical Evaluation & Benchmark Results

> **Evaluation Mode**: Real Empirical Run (Zero Fabrication Guarantee)  
> **Dataset**: `data/processed/processed_flows.csv` (Holdout Split: 20% Stratified)  
> **Evaluated Date**: 2026-08-18 13:15:58  

---

## 1. Multi-Threshold Performance (Supervised Flow Classifier)

The classifier was evaluated across multiple probability cutoffs. In production NDR, we employ a **Precision-First posture (threshold = 0.85)** to prevent alert fatigue while delegating evasive/novel patterns to the Suricata signature and Autoencoder layers.

| Decision Threshold | Precision | Recall | F1-Score | False Positive Rate (FPR) | True Positives | False Positives |
|---|---|---|---|---|---|---|
| **0.50** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 60 | 0 |
| **0.70** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 60 | 0 |
| **0.85** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 60 | 0 |
| **0.95** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 60 | 0 |

---

## 2. Per-Category Classification Breakdown (Threshold = 0.85)

| Attack Category | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **BENIGN** | 1.0000 | 1.0000 | 1.0000 | 140 |
| **DDOS_FLOOD** | 1.0000 | 1.0000 | 1.0000 | 30 |
| **PORT_SCAN** | 1.0000 | 1.0000 | 1.0000 | 30 |
| **macro avg** | 1.0000 | 1.0000 | 1.0000 | 200 |
| **weighted avg** | 1.0000 | 1.0000 | 1.0000 | 200 |

---

## 3. Unsupervised Autoencoder Anomaly Layer

Trained strictly on benign traffic flows with reconstruction error threshold calibrated at **1.529367**.

| Metric | Measured Value |
|---|---|
| **Anomaly Precision** | 0.9836 |
| **Anomaly Recall** | 1.0000 |
| **Anomaly F1-Score** | 0.9917 |
| **Anomaly FPR** | 0.0071 |
| **True Negatives** | 139 |
| **False Positives** | 1 |
