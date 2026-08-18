# Virtual Lab Network Topology

The detection engineering lab is structured into isolated Virtual LANs (VLANs) routed through an **OPNsense Firewall VM**, with an **Ubuntu Monitor VM** capturing mirrored traffic via a virtual SPAN/TAP interface.

```
                    +--------------------------------+
                    |        Internet / WAN          |
                    |         (NAT / Bridge)         |
                    +---------------+----------------+
                                    |
                    +---------------+----------------+
                    |       OPNsense Firewall VM     |
                    |  (Routing, NAT, API Filtering) |
                    |      IP: 192.168.1.1           |
                    +---+------------------------+---+
                        |                        |
                        | VLAN 10 (Trusted LAN)  | VLAN 99 (Quarantine)
                        | 192.168.10.0/24        | 192.168.99.0/24
                        |                        |
            +-----------+-----------+            +-----------------------+
            |  Target / Workstation |            | Isolated Quarantined  |
            |     192.168.10.50     |            |       Endpoints       |
            +-----------+-----------+            +-----------------------+
                        |
                        | [Port Mirror / SPAN / Promiscuous Tap]
                        v
            +-------------------------------+
            |       Monitor VM (Ubuntu)     |
            | - Promiscuous Tap Interface   |
            | - Suricata (Signature IDS)    |
            | - Zeek (Connection Logger)    |
            | - NDR Decision Arbiter        |
            | - Automated OPNsense API Push |
            +-------------------------------+
```

## Interface Allocation

| Node | Interface Name | Purpose | IP / Subnet |
|---|---|---|---|
| **OPNsense VM** | `em0` / WAN | Uplink to Host / WAN | DHCP |
| **OPNsense VM** | `em1` / LAN | Trusted Internal Network | `192.168.10.1/24` |
| **OPNsense VM** | `em2` / Quarantine | Isolated Quarantine VLAN 99 | `192.168.99.1/24` |
| **Monitor VM** | `eth0` / Mgmt | Management & API orchestration | `192.168.10.20/24` |
| **Monitor VM** | `eth1` / SPAN | Promiscuous Mirror (Zeek + Suricata) | No IP (Promisc) |
