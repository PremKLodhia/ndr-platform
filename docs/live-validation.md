# Live Lab Validation Guide & Runbook

This runbook guides you through triggering live attacks from within your virtual lab network and verifying end-to-end NDR ingestion, dual-path detection, and automated containment.

---

## 1. Network Topology Checklist
- [ ] **OPNsense Firewall VM**: Running with `em0` (WAN), `em1` (LAN 192.168.10.1/24), `em2` (Quarantine 192.168.99.1/24).
- [ ] **Monitor VM (Ubuntu 22.04 LTS)**: Running with `eth0` (Mgmt: 192.168.10.20) and `eth1` (SPAN / Promiscuous Tap).
- [ ] **Attacker / Target Workstations**: Running on VLAN 10 (192.168.10.0/24).

---

## 2. Triggering Lab Attacks

### A. Network Reconnaissance & Port Scanning (MITRE ATT&CK T1046)
From your Attacker VM:
```bash
# Run aggressive Nmap SYN scan against internal target
sudo nmap -sS -p 1-1000 -T4 192.168.10.50
```
- **Expected Suricata Alert**: `SID 3000001 (NDR T1046 - Rapid TCP SYN Portscan Detected)`
- **Expected Classifier**: `PORT_SCAN (Confidence > 90%)`
- **Expected Action**: Source IP added to `ndr_blocked_ips` table on OPNsense.

---

### B. High-Volume TCP SYN Flood (MITRE ATT&CK T1498.001)
From your Attacker VM:
```bash
# Generate high-rate SYN flood using hping3
sudo hping3 -S -p 80 --flood --rand-source 192.168.10.50
```
- **Expected Suricata Alert**: `SID 3000002 (NDR T1498.001 - High-Rate TCP SYN Flood Target Overload)`
- **Expected Classifier**: `DDOS_FLOOD`
- **Expected Action**: `BLOCK_AND_ISOLATE`

---

### C. DNS Tunneling / Data Exfiltration (MITRE ATT&CK T1071.004)
From your Attacker VM:
```bash
# Simulate DNS exfiltration queries using iodine or script
python scripts/generate_test_traffic/generate_attacks.py
```
- **Expected Entropy**: `dns_subdomain_entropy > 3.8`
- **Expected Decision**: `BLOCK_AND_ISOLATE`

---

### D. Atomic Red Team C2 Simulation (MITRE ATT&CK T1071.001)
From your Workstation:
```bash
# Execute Atomic Red Team HTTP C2 test
python scripts/generate_test_traffic/atomic_runner.py --technique T1071.001 --target 203.0.113.88
```
- **Expected Classifier / Autoencoder**: `C2_BEACONING` / `Loss > Threshold`
- **Expected Action**: `QUARANTINE_VLAN` (VLAN 99)

---

## 3. Verifying Results in Live Lab
1. Check OPNsense live firewall aliases:
   `https://192.168.1.1/ui/firewall/alias` -> inspect `ndr_blocked_ips`.
2. Inspect SIEM alerts dispatched to Wazuh Manager:
   `http://localhost:5601` or `/var/ossec/logs/alerts/alerts.json`.
