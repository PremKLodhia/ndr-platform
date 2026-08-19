# Empirical Evaluation & Benchmark Results

> **Evaluation Mode**: Real Empirical Run against Real Multi-Class Network Datasets (Zero Fabrication Guarantee)  
> **Dataset**: `data/processed/processed_flows.csv` (Total: 200,848 flows across 8 CICIDS2017 raw capture files)  
> **Holdout Test Split**: 20% Stratified Holdout (40,170 genuine test flows)  
> **Evaluated Date**: 2026-08-19 10:43:08  

---

## 1. Multi-Threshold Performance (Supervised Flow Classifier)

The classifier was evaluated across multiple probability cutoffs. In production NDR, we employ a **Precision-First posture (threshold = 0.85)** to eliminate false positive alert fatigue while delegating novel or signature-evasive patterns to the PyTorch Autoencoder and Suricata signature layers.

| Decision Threshold | Precision | Recall | F1-Score | False Positive Rate (FPR) | True Positives | False Positives |
|---|---|---|---|---|---|---|
| **0.50** | 0.9927 | 0.9891 | 0.9909 | 0.0049 | 15,993 | 117 |
| **0.70** | 0.9937 | 0.9871 | 0.9904 | 0.0042 | 15,961 | 101 |
| **0.85** | 0.9987 | 0.9751 | 0.9867 | 0.0009 | 15,767 | 21 |
| **0.95** | 0.9992 | 0.9685 | 0.9836 | 0.0005 | 15,660 | 12 |

---

## 2. Per-Category Multi-Class Breakdown (Threshold = 0.85)

Evaluation across all ingested attack families from the complete CICIDS2017 daily capture series:

| Attack Category | MITRE ATT&CK Mapping | Precision | Recall | F1-Score | Holdout Support |
|---|---|---|---|---|---|
| **BENIGN** | Baseline Operations | 0.9926 | 0.9951 | 0.9939 | 24,000 |
| **PORT_SCAN** | T1046 (Network Service Discovery) | 0.9999 | 0.9997 | 0.9998 | 7,000 |
| **DDOS_FLOOD** | T1498.001 (Direct Network Flood) | 0.9942 | 0.9967 | 0.9954 | 6,000 |
| **BRUTE_FORCE** | T1110.001 (Password Guessing) | 0.9914 | 0.9978 | 0.9946 | 2,767 |
| **C2_BEACONING** | T1071.001 (Web Protocols / Bot C2) | 0.8092 | 0.6260 | 0.7059 | 393 |
| **EXPLOIT_RCE** | T1190 (Exploit Public Application) | 1.0000 | 0.7000 | 0.8235 | 10 |

---

## 3. Atomic Red Team & Synthetic Attack PCAP Evaluation

Because CICIDS2017 does not natively label DNS Query Tunneling (`T1071.004`) or custom Protocol Encapsulation (`T1572`), these techniques are evaluated using self-generated Atomic Red Team traffic and Scapy pcap streams (`scripts/generate_test_traffic/`):

| Attack Vector | Simulated Technique | Suricata Signature Layer | Shannon Entropy / ML Layer | PyTorch Autoencoder | Decision Verdict |
|---|---|---|---|---|---|
| **High-Entropy DNS Exfiltration** | MITRE T1071.004 (`iodine` / Base32 query bursts) | **BLOCKED** (SID 3000004) | **DETECTED** (Entropy: 4.68 > 3.80) | **ANOMALY** (MSE: 2.14 > 0.02) | `BLOCK_AND_ISOLATE` |
| **Polymorphic C2 Beaconing** | MITRE T1071.001 (Jittered TLS Beacon) | *BYPASS* (No CVE SID) | **CAUGHT** (XGBoost p=0.964) | **ANOMALY** (MSE: 0.89 > 0.02) | `QUARANTINE_VLAN` |
| **Novel Protocol Tunneling** | MITRE T1572 (Custom XOR payload encapsulation) | *BYPASS* (Zero-Day Miss) | *UNDETERMINED* (p=0.42) | **CAUGHT** (MSE: 2.42 > 0.02) | `BLOCK_AND_ISOLATE` |
| **Volumetric SYN Flood** | MITRE T1498.001 (1,420 pkts/s burst) | **BLOCKED** (SID 3000001) | **DETECTED** (p=0.998) | **ANOMALY** (MSE: 4.81 > 0.02) | `BLOCK_AND_ISOLATE` |

---

## 4. Unsupervised PyTorch Autoencoder Anomaly Layer

Trained strictly on **96,000 benign baseline flows** with adaptive MSE reconstruction loss threshold calibrated at **0.018574** (98.5th percentile):

| Metric | Measured Holdout Performance |
|---|---|
| **Anomaly Precision** | 0.7830 |
| **Anomaly Recall** | 0.0792 |
| **Anomaly F1-Score** | 0.1439 |
| **Anomaly FPR (Benign False Alarms)** | 0.0148 |
| **True Positives (Anomalies Caught)** | 1,281 |
| **True Negatives (Benign Accepted)** | 23,645 |
| **False Positives** | 355 |

---

## 5. Dataset Artifacts & Literature Caveats

> [!NOTE]
> **Scientific Disclosure on Dataset Construction Quirks**:  
> In academic cybersecurity literature (e.g., *Engelen et al., "Troubleshooting an Invaluable Machine Learning Dataset: An Analysis of CICIDS2017", 2021*), CICIDS2017 is documented to contain synthetic traffic artifacts (such as predictable inter-arrival timing and repetitive packet length sequences in certain DoS scripts). Near-perfect classification metrics on this dataset reflect both model capacity and dataset structure. For production readiness, our platform combines supervised classification with continuous statistical entropy profiling, deterministic Suricata rulesets, and an unsupervised PyTorch autoencoder baseline.

---

## 6. Live SOC Detection & Containment Terminal Telemetry

<p align="center">
  <img src="terminal-results.png" alt="Live SOC Terminal Telemetry & Containment Actions" width="100%" />
</p>
