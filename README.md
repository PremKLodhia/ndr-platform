# Network Detection & Response (NDR) Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange.svg)](docs/threat-mapping.md)
[![Fail-Secure](https://img.shields.io/badge/Architecture-Fail--Secure-red.svg)](docs/architecture.md)

An end-to-end, portfolio-grade Network Detection and Response platform that ingests live/replayed network traffic, performs dual-path classification (Suricata signature rules + XGBoost/LightGBM flow classifiers + PyTorch benign autoencoders), and executes automated firewall containment actions (OPNsense API) under a strict fail-secure guarantee.

---

## Key Design Principles

1. **Fail-Secure Decision Engine**: Component timeouts, malformed logs, or classifier crashes default to defensive containment and escalation—never a silent bypass.
2. **Dual-Path Detection**:
   - **Fast Path**: Suricata signature rules for known exploits and indicators.
   - **Analytical Path**: Supervised tabular flow classification (XGBoost/LightGBM) + unsupervised anomaly detection (benign-trained PyTorch Autoencoder).
3. **Strict MITRE ATT&CK Mapping**: Every signature, flow classification, and containment trigger explicitly traces to an ATT&CK technique ID.
4. **Research Honesty**: Zero fabricated metrics. All performance benchmarks represent real executions against public benchmark datasets (CICIDS2017, UNSW-NB15, CTU-13) and self-generated isolated lab pcaps.

---

## Architecture Overview

```
                          +-------------------------+
                          |   Network Traffic /     |
                          |      PCAP Ingest        |
                          +------------+------------+
                                       |
                 +---------------------+---------------------+
                 |                                           |
                 v                                           v
     +-----------------------+                   +-----------------------+
     |  Suricata Signatures  |                   |   Zeek Connection     |
     |   (Fast / Known)      |                   |    & Flow Logs        |
     +-----------+-----------+                   +-----------+-----------+
                 |                                           |
                 | MITRE Alerts                              v
                 |                               +-----------------------+
                 |                               |  Feature Extraction   |
                 |                               +-----------+-----------+
                 |                                           |
                 |                       +-------------------+-------------------+
                 |                       |                                       |
                 |                       v                                       v
                 |           +-----------------------+               +-----------------------+
                 |           |  Supervised Classifier|               |   Benign Autoencoder  |
                 |           |   (XGBoost / LightGBM)|               |   (Anomaly / 0-Day)   |
                 |           +-----------+-----------+               +-----------+-----------+
                 |                       |                                       |
                 +-----------------------+-------------------+-------------------+
                                                             |
                                                             v
                                             +-------------------------------+
                                             |      Fail-Secure Arbiter      |
                                             |  (Timeout -> Escalate/Block)  |
                                             +---------------+---------------+
                                                             |
                                             +---------------+---------------+
                                             |                               |
                                             v                               v
                                 +-----------------------+       +-----------------------+
                                 |  OPNsense Firewall    |       |   SIEM / Wazuh / ELK  |
                                 |  Automated Containment|       |    Event Logging      |
                                 +-----------------------+       +-----------------------+
```

---

## Project Status

| Phase | Milestone | Status | Notes |
|---|---|---|---|
| **Phase 0** | Repo Scaffold & Environment Baseline | **Completed** | Full directory tree, configurations, and stubs created |
| **Phase 1** | Lab Topology & Ingest Pipeline | In Progress | Lab setup docs, Zeek/Suricata log ingestion engines |
| **Phase 2** | Feature Engineering & Dataset Prep | Pending | CICIDS2017, UNSW-NB15, CTU-13 extraction & ATT&CK mapping |
| **Phase 3** | Dual-Path Detection Engine | Pending | Suricata parser, XGBoost classifier, PyTorch Autoencoder |
| **Phase 4** | Fail-Secure Decision & Response | Pending | Decision arbiter, OPNsense API integration, SIEM logging |
| **Phase 5** | Verification & Portfolio Report | Pending | Replayed attacks, end-to-end evaluation, docs/results.md |

---

## Directory Structure

```
ndr-platform/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── threat-mapping.md
│   └── results.md
├── lab/
│   ├── network-diagram.md
│   └── setup-notes.md
├── data/
│   ├── raw/
│   ├── processed/
│   └── pcaps/
├── src/ndr/
│   ├── ingest/
│   ├── features/
│   ├── detection/
│   │   ├── signatures/
│   │   ├── classifier/
│   │   └── anomaly/
│   ├── decision/
│   ├── response/
│   └── viz/
├── tests/
├── scripts/
│   ├── generate_test_traffic/
│   └── eval/
├── docker-compose.yml
├── pyproject.toml
└── .env.example
```

---

## Getting Started

### Prerequisites
- Python 3.11+
- Git
- Docker & Docker Compose (optional for Suricata/Wazuh containers)

### Installation
```bash
# Clone the repository
git clone https://github.com/username/ndr-platform.git
cd ndr-platform

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .[dev]

# Set up environment variables
cp .env.example .env
```

---

## Documentation Links
- [Detailed System Architecture](docs/architecture.md)
- [MITRE ATT&CK Threat Mapping](docs/threat-mapping.md)
- [Empirical Evaluation & Results](docs/results.md)
- [Virtual Lab Setup & Topology](lab/setup-notes.md)
