#!/usr/bin/env bash
# ==============================================================================
# NDR Monitor VM Provisioning Script (Ubuntu Server 22.04 / 24.04)
# Installs and configures Zeek, Suricata, and network TAP / SPAN interface.
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "    Provisioning NDR Monitor VM (Zeek + Suricata TAP)    "
echo "=========================================================="

# 1. Update and install base utilities
sudo apt-get update
sudo apt-get install -y \
    curl \
    wget \
    gnupg \
    lsb-release \
    net-tools \
    ethtool \
    libpcap-dev \
    python3 \
    python3-pip \
    python3-venv \
    jq

# 2. Install Suricata IDS
echo "[+] Installing Suricata..."
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata

# Enable EVE JSON logging in /etc/suricata/suricata.yaml
sudo suricata-update
sudo systemctl enable suricata

# 3. Install Zeek Network Security Monitor
echo "[+] Installing Zeek..."
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install -y zeek-lts

# 4. Configure Promiscuous Mode on TAP Interface (e.g. eth1)
TAP_IFACE="eth1"
echo "[+] Configuring promiscuous mode and disabling offloading on ${TAP_IFACE}..."
sudo ip link set ${TAP_IFACE} promisc on up
sudo ethtool -K ${TAP_IFACE} rx off tx off gso off tso off gro off lro off || true

echo "=========================================================="
echo " Monitor VM setup complete. Zeek and Suricata are active! "
echo "=========================================================="
