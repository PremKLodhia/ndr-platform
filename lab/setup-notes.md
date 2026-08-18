# Lab Setup Guide & Step-by-Step Instructions

## 1. Virtual Machine Provisioning

### OPNsense VM
- **RAM**: 2 GB
- **CPU**: 2 Cores
- **Network Adapters**:
  1. Adapter 1: Bridged / NAT (WAN uplink)
  2. Adapter 2: Internal Network `intnet_lan` (Trusted LAN)
  3. Adapter 3: Internal Network `intnet_quarantine` (Quarantine VLAN)
- **API Setup**:
  1. Navigate to **System > Access > Users** in the web GUI.
  2. Create an API User and generate API Key & Secret.
  3. Create a Firewall Alias table named `ndr_blocked_ips` (Type: *Hosts*).
  4. Create a top-priority Firewall Rule blocking all traffic matching `ndr_blocked_ips`.

### Monitor VM (Ubuntu Server 22.04 LTS)
- **RAM**: 4 GB
- **CPU**: 2 - 4 Cores
- **Network Adapters**:
  1. Adapter 1: `intnet_lan` (Management IP: `192.168.10.20`)
  2. Adapter 2: `intnet_lan` (Promiscuous Mode: *Allow All*)
- **Provisioning**:
  Run `bash lab/install-monitor-vm.sh` to install Zeek and Suricata.

---

## 2. Benchmark Datasets Download Guide

### 1. CICIDS2017
- URL: [UNB Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
- Accept research agreement and place CSV flow files into `data/raw/cicids2017/`.

### 2. UNSW-NB15
- URL: [UNSW Sydney Project Portal](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- Download CSV/PCAP sets and place into `data/raw/unsw-nb15/`.

### 3. CTU-13
- URL: [Stratosphere IPS CTU-13 Dataset](https://www.stratosphereips.org/datasets-ctu13)
- Download botnet scenarios and place into `data/raw/ctu13/`.
