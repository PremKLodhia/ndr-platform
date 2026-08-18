# MITRE ATT&CK Threat Mapping Matrix

Every detection rule, classifier category, and attack generator in the NDR platform maps explicitly to verified MITRE ATT&CK Technique IDs.

| Threat Category | MITRE ATT&CK Technique ID | Technique Name | Detection Layer | Containment Action |
|---|---|---|---|---|
| **Port Scanning / Recon** | `T1046` | Network Service Discovery | Suricata + XGBoost | `QUARANTINE_VLAN` |
| **SYN / UDP Floods** | `T1498.001` | Direct Network Flood | Suricata + XGBoost | `BLOCK_AND_ISOLATE` |
| **Web C2 Beaconing** | `T1071.001` | Web Protocols (C2) | Suricata + Autoencoder | `BLOCK_AND_ISOLATE` |
| **DNS Tunneling** | `T1071.004` | DNS Exfiltration & C2 | Entropy + XGBoost | `BLOCK_AND_ISOLATE` |
| **SSH / Auth Brute Force** | `T1110.001` | Password Guessing | Suricata + XGBoost | `BLOCK_AND_ISOLATE` |
| **Public Exploits (RCE)** | `T1190` | Exploit Public-Facing App | Suricata (Sev 1) | `BLOCK_AND_ISOLATE` |
| **Novel / Unseen Channel**| `T1071` | Application Layer Protocol | Autoencoder (Loss > Thresh)| `QUARANTINE_VLAN` |
| **Component Failure** | `T1071` | Fail-Secure Defensive Trigger | Decision Guard | `BLOCK_AND_ISOLATE` |
