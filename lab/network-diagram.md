# Virtual Lab Network Topology & Hardware Layout

```mermaid
graph TD
    WAN((Internet / WAN)) <-->|em0| OPNSENSE[OPNsense Firewall VM
192.168.1.1]

    subgraph InternalNetworks ["Enterprise Security Segments"]
        OPNSENSE <-->|em1: Trusted LAN 192.168.10.0/24| VSWITCH[Virtual Switch / SPAN Port Mirror]
        OPNSENSE <-->|em2: Quarantine VLAN 99 192.168.99.0/24| QUARANTINE_NET[Isolated Quarantine Subnet]
        
        VSWITCH <-->|eth0: Mgmt IP 192.168.10.20| MONITOR_VM[Ubuntu NDR Monitor Host
Zeek + Suricata + NDR Engine]
        VSWITCH -.->|eth1: Promiscuous TAP Mirror| MONITOR_VM
        
        VSWITCH <--> TARGET_VM[Internal Workstations & Servers
192.168.10.50]
        VSWITCH <--> ATTACKER_VM[Attacker Workstation
192.168.10.99]
    end

    MONITOR_VM -->|OPNsense REST API Containment| OPNSENSE
    MONITOR_VM -->|ECS JSON Logs| WAZUH[Wazuh / ELK SOC SIEM]
```

## IP Subnet Plan
- **Trusted LAN (VLAN 10)**: `192.168.10.0/24` (Gateway: `192.168.10.1`)
- **Quarantine Subnet (VLAN 99)**: `192.168.99.0/24` (Gateway: `192.168.99.1` - No WAN Routing)
- **Monitor Management**: `192.168.10.20`
- **Monitor SPAN / Promiscuous Tap**: `eth1` (No IP assigned, promiscuous mode active)
