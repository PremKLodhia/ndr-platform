# NDR Platform Architecture Specification

## 1. Executive Summary
The NDR platform implements an asynchronous, dual-path network inspection and response engine:
- **Fast Path (Signatures)**: Suricata evaluates raw packets against Emerging Threats (ET) rule definitions.
- **Analytical Path (Machine Learning)**: Zeek connection records are converted into 40+ tabular flow features. A supervised gradient-boosted decision tree classifies known attack topologies, while a benign-trained PyTorch Autoencoder detects novel zero-day anomalies based on reconstruction error.
- **Fail-Secure Decision Arbiter**: All paths converge into a hardened decision arbiter. Any timeout, unhandled error, or pipeline corruption automatically triggers defensive containment.

---

## 2. Component Pipeline

```
[ PCAP / Live Traffic ]
         |
         +-------------------------------------------------+
         |                                                 |
         v                                                 v
 [ Suricata EVE JSON ]                             [ Zeek conn.log ]
         |                                                 |
         v                                                 v
[ MITRE Technique Mapping ]                        [ Flow Feature Extractor ]
 (T1046, T1071, T1498, etc.)                       (Rates, Ratios, Entropy)
         |                                                 |
         |                                 +---------------+---------------+
         |                                 |                               |
         |                                 v                               v
         |                       [ Supervised Classifier ]     [ Benign Autoencoder ]
         |                          (XGBoost / LightGBM)          (PyTorch MSE Loss)
         |                                 |                               |
         +---------------------------------+-------------------------------+
                                           |
                                           v
                             [ Fail-Secure Decision Arbiter ]
                             - Strict Component Watchdogs
                             - Failure -> Defend & Contain
                                           |
                         +-----------------+-----------------+
                         |                                   |
                         v                                   v
             [ OPNsense Firewall API ]             [ SIEM / Wazuh / ELK ]
             (IP Blocking / Quarantine)            (ECS JSON Event Dispatch)
```

---

## 3. Fail-Secure Guarantee
In high-security detection engineering, a component failure must never grant permissive passage to an attacker:
1. **Model Timeout**: If ML flow inference exceeds timeout thresholds (e.g. 500ms), the arbiter issues a `BLOCK_AND_ISOLATE` action with `fail_secure=True`.
2. **Malformed Payload / NaN values**: Corrupted records that cause feature extraction failures are trapped by `@fail_secure_guard` and escalated immediately.
3. **API Network Disconnection**: If the OPNsense API fails to respond, local fallback logs and SIEM high-priority alerts are dispatched instantly.
