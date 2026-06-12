# 🛡️ Hypervisor-Level VM Introspection Security System

An **industry-grade, agentless behavioral monitoring and intrusion detection system** for Windows Virtual Machines. Monitors network traffic, file system activity, memory/CPU usage, and infers process behavior — all **externally from the host**, with zero software installed inside the VM. Powered by a MITRE ATT&CK-mapped rule engine, a FastAPI backend, and a Streamlit real-time dashboard.

---

## 📋 Table of Contents

- [About](#about)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [API Reference](#api-reference)
- [Attack Simulation](#attack-simulation-pen-testing)
- [Detection Rules & MITRE ATT&CK](#detection-rules--mitre-attck)
- [Dashboard Features](#dashboard-features)
- [Threat Intelligence](#threat-intelligence)
- [Important Notes](#important-notes)

---

## About

**VM Introspection Security System** monitors a Windows VM running on VirtualBox (or any hypervisor) entirely from the host machine — no agent, no software, no modifications to the guest OS. It captures live network packets via Scapy, watches the VM-shared folder with Watchdog, tracks memory/CPU/disk/process metrics via psutil, and correlates all signals through a behavioral rule engine that maps detections to **MITRE ATT&CK techniques**.

Flagged events, composite alerts, and a full attack timeline are served through a FastAPI REST API and visualized on a live Streamlit dashboard with geo-IP mapping, protocol charts, and forensic export.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   HOST MACHINE                       │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │   Network     │  │    File      │  │  Memory /  │ │
│  │   Monitor     │  │   Monitor    │  │  CPU / IO  │ │
│  │   (Scapy)     │  │  (Watchdog)  │  │  (psutil)  │ │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘ │
│         └──────────┬───────┴────────────────┘        │
│                    │                                  │
│         ┌──────────▼──────────┐                      │
│         │  Behavioral Analyzer │                      │
│         │  (MITRE Rule Engine) │                      │
│         └──────────┬──────────┘                      │
│                    │                                  │
│         ┌──────────▼──────────┐                      │
│         │  DataStore (SQLite)  │                      │
│         └──────────┬──────────┘                      │
│                    │                                  │
│  ┌─────────────────┼───────────────┐                 │
│  │                 │               │                 │
│  ▼                 ▼               ▼                 │
│ FastAPI         Streamlit       Attack               │
│ Backend         Dashboard       Simulator            │
│ (:8000)         (:8501)         (CLI)                │
└──────────────────────┬──────────────────────────────┘
                       │  Bridged Adapter / Shared Folder
              ┌────────▼────────┐
              │  Windows VM     │
              │  (VirtualBox)   │
              │  ← NO AGENT →   │
              └─────────────────┘
```

---

## Features

### 🔍 Agentless Monitoring
- 📡 **Live promiscuous packet capture** — captures ALL traffic on the active interface, like Wireshark
- 📂 **Shared folder file watching** — SHA-256 hashing + Shannon entropy analysis on every file event
- 🖥️ **Host resource monitoring** — real-time memory, CPU, disk I/O, network I/O, and top-N processes via psutil
- 🔄 **Auto-detects** active network interface on startup

### 🚨 Behavioral Analysis Engine
- 🧠 **Composite rule correlation** — cross-correlates network + file + resource signals simultaneously
- 🎯 **MITRE ATT&CK mapping** — every alert tagged with technique ID and tactic
- 📈 **Dynamic threat score** (0–100) with decay when system returns to healthy state
- ⏱️ **Alert cooldown** — prevents duplicate alerts per rule within a configurable window
- 🔍 **Process behavior inference** — infers data exfiltration, crypto-mining/C2, malware drops from indirect signals (agentless)

### 🗺️ Threat Intelligence
- 🌍 **Geo-IP mapping** — maps external IPs to cities/countries on a world map
- 🗄️ **Local threat database** — 10+ pre-loaded malicious IPs with risk scores, malware families, and MITRE tags
- 🔗 **AbuseIPDB integration** (optional) — live IP reputation lookup with SQLite caching
- 🧬 **VirusTotal integration** (optional) — file hash lookup for SHA-256 hashes of suspicious files

### 📊 Dashboard & API
- ⚡ **FastAPI REST backend** — 18 endpoints including export, pentest triggers, analyst notes
- 📺 **Streamlit real-time dashboard** — auto-refreshes every 2 seconds
- 📤 **JSON export** for logs and alerts
- 🔐 **Optional API key authentication**

### 🔬 Penetration Testing
- 4 built-in attack scenarios: **Data Exfiltration**, **Malware Drop**, **C2 Beaconing**, **Full Attack Chain**
- Triggerable via CLI (`simulate_attack.py`) or REST API (`POST /pentest/{scenario}`)
- Generates realistic threat data to validate detection rules and dashboard

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend API | Python 3.10+, FastAPI, Uvicorn |
| Dashboard | Streamlit, Plotly |
| Packet Capture | Scapy |
| File Monitoring | Watchdog |
| Resource Monitoring | psutil |
| Data Storage | SQLite (via DataStore), JSON export |
| Threat Intel APIs | AbuseIPDB, VirusTotal (optional) |
| Config Management | python-dotenv |
| Type Checking | Pyright (standard mode) |

---

## Project Structure

```
vm-security/
│
├── api.py                  # FastAPI backend — 18 REST endpoints, all monitors
├── dashboard.py            # Streamlit dashboard — Plotly charts, geo map, alerts
├── behavioral_analyzer.py  # MITRE-mapped rule engine — composite threat scoring
├── network_monitor.py      # Scapy packet sniffer — promiscuous capture + detection
├── file_monitor.py         # Watchdog file watcher — SHA-256 + entropy analysis
├── memory_monitor.py       # psutil resource monitor — memory, CPU, disk, processes
├── threat_intel.py         # Threat intelligence — geo-IP, MITRE map, AbuseIPDB, VT
├── data_store.py           # Thread-safe SQLite singleton — metrics, logs, alerts
├── config.py               # Central config — env vars + psutil interface auto-detect
├── simulate_attack.py      # CLI attack simulator — 4 pen-test scenarios
├── test_geo.py             # Debug utility — inspect captured external IPs
│
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── pyrightconfig.json      # Pyright type checker config
│
├── data/                   # Auto-created — SQLite DB + JSON exports
│   ├── security.db
│   ├── logs.json
│   ├── alerts.json
│   └── timeline.json
│
└── shared_folder/          # Monitored folder shared with the VM (auto-created)
```

---

## Prerequisites

- **Python 3.10+** — [Download](https://python.org)
- **VirtualBox** with a Windows VM — optional (simulation mode works without)
- ⚠️ **Administrator / root privileges** required for packet capture

### Packet Capture Driver
| OS | Driver | Install |
|---|---|---|
| Linux | libpcap | `sudo apt install libpcap-dev` |
| Windows | Npcap | [nmap.org/npcap](https://nmap.org/npcap/) — check **WinPcap API-compatible Mode** |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/vm-introspection-security.git
cd vm-introspection-security
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

```env
# Your organization details
ORG_NAME="My Organisation"
ANALYST_NAME="Security Analyst"
DEPLOYMENT_ID="VM-SEC-001"

# VM's IP address on the network
VM_IP="192.168.1.100"

# Network interface (leave empty for auto-detect)
# VM_MONITOR_IFACE="Wi-Fi"

# Shared folder path (host-side)
# VM_SHARED_FOLDER="C:/Users/Public/VMSecurityShared"

# Optional: Promiscuous capture (capture ALL traffic, not just VM_IP)
PROMISCUOUS_CAPTURE="true"

# Optional: Threat Intelligence API Keys
# ABUSEIPDB_API_KEY="your_key_here"
# VIRUSTOTAL_API_KEY="your_key_here"

# Optional: Secure the API
# API_SECRET_KEY="change_me_in_production"
```

---

## Running the System

> ⚠️ You need **two terminals** — one for the API backend, one for the dashboard.

### Terminal 1 — Start the Backend API

**Linux (requires sudo for packet capture):**
```bash
sudo python api.py
```

**Windows (run Command Prompt as Administrator):**
```bash
python api.py
```

Expected output:
```
VM INTROSPECTION SECURITY SYSTEM — STARTING
Org: My Organisation  |  Deployment: VM-SEC-001
All modules started. API ready at http://0.0.0.0:8000
```

API docs available at: **http://localhost:8000/docs**

---

### Terminal 2 — Start the Dashboard

```bash
streamlit run dashboard.py
```

Dashboard opens at: **http://localhost:8501**

---

### Terminal 3 — Run Attack Simulation (Optional)

```bash
# Individual scenarios
python simulate_attack.py data_exfiltration
python simulate_attack.py malware_drop
python simulate_attack.py beacon_c2

# Full attack chain (all scenarios in sequence)
python simulate_attack.py full_attack
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/status` | GET | Current threat score, status, and key metrics |
| `/events` | GET | Recent log events (filterable, paginated) |
| `/alerts` | GET | Security alerts (filter by severity/type) |
| `/timeline` | GET | Chronological attack timeline |
| `/metrics` | GET | Detailed metrics with memory/CPU history |
| `/dashboard-data` | GET | Aggregated single-call endpoint for Streamlit |
| `/geo/connections` | GET | Geo-located external IP connections |
| `/threat-intel` | GET | Full local threat intelligence database |
| `/threat-intel/{ip}` | GET | Single IP lookup (live AbuseIPDB if configured) |
| `/threat-intel/hash/{sha256}` | GET | File hash lookup via VirusTotal |
| `/system/info` | GET | Host OS, interfaces, uptime, analyst info |
| `/export/logs` | GET | Download all logs as JSON |
| `/export/alerts` | GET | Download all alerts as JSON |
| `/report` | GET | Full VM security report |
| `/pentest/{scenario}` | POST | Trigger a pen-test scenario (background thread) |
| `/system/reset` | POST | Reset all in-memory metrics |
| `/analyst/note` | POST | Add an analyst investigation note |
| `/analyst/notes` | GET | Retrieve all analyst notes |

---

## Attack Simulation / Pen-Testing

### Via CLI
```bash
python simulate_attack.py [scenario]
```

### Via API
```bash
curl -X POST http://localhost:8000/pentest/full_attack
```

### Scenarios

| Scenario | MITRE Technique | What It Simulates |
|---|---|---|
| `data_exfiltration` | T1041 — Exfiltration Over C2 | File creation + external TCP traffic + memory spike |
| `malware_drop` | T1105 — Ingress Tool Transfer | `.exe`, `.dll`, `.bat`, `.ps1` files in shared folder |
| `beacon_c2` | T1071 — Application Layer Protocol | Repeated TCP connections to port 4444 (Metasploit) |
| `full_attack` | T1486 — Multi-vector | All three scenarios run in sequence |

---

## Detection Rules & MITRE ATT&CK

### Network Rules
| Trigger | Score Delta | MITRE |
|---|---|---|
| Unknown external source IP | +variable | T1071 |
| Suspicious port (4444, 1337, etc.) | +variable | T1071 |
| Beaconing (≥5 connections in 60s) | +variable | T1071 |

### File Rules
| Trigger | Severity | MITRE |
|---|---|---|
| `.exe`, `.dll`, `.bat`, `.ps1`, `.hta` | CRITICAL | T1105 |
| Other suspicious extensions | WARNING | T1105 |
| File entropy > 7.0 (packed/encrypted) | WARNING | — |
| File size > 10MB | WARNING | — |

### Resource Rules
| Trigger | Score Delta | MITRE |
|---|---|---|
| Memory > 75% + external IPs | +30 | T1041 |
| Memory spike > 20% in one reading | +25 | — |
| CPU > 80% + suspicious events | +25 | T1496 |
| Disk write > 50 MB/s | +15 | — |

### Composite Behavioral Rules
| Trigger | Score Delta | MITRE |
|---|---|---|
| Network + File activity together | +40 | T1105 |
| Memory spike + Network activity | +30 | T1041 |
| High CPU + Beaconing | +25 | T1496 |
| Network + File + Resource (all 3) | +50 | T1486 — Multi-Vector |

### Threat Status Thresholds
| Score | Status |
|---|---|
| 0 – 49 | ✅ SAFE |
| 50 – 74 | ⚠️ WARNING |
| 75 – 100 | 🔴 UNDER ATTACK |

---

## Dashboard Features

1. **Live status banner** — SAFE / WARNING / UNDER ATTACK with threat score
2. **Metric cards** — Total Packets, Suspicious Events, Unique IPs, Memory %, CPU %
3. **Protocol pie chart** — TCP / UDP / ICMP distribution
4. **Suspicious activity bar chart** — events over time
5. **Memory & CPU line graph** — with warning/critical threshold lines
6. **Live packet table** — real-time network packet details
7. **Color-coded alert panel** — 🔴 CRITICAL, 🟡 WARNING, 🔵 INFO
8. **Attack timeline** — chronological event display
9. **Geo-IP world map** — external connection source locations (Plotly)
10. **Threat intelligence table** — risk scores, malware families, MITRE tags
11. **Security report** — full ASCII summary
12. **JSON export** — download logs and alerts

---

## Threat Intelligence

The system includes a local threat database with pre-loaded entries for known malicious IPs including C2 servers (Cobalt Strike, Meterpreter, NjRAT), ransomware handlers (LockBit 3.0), botnet nodes (Mirai), and credential harvesters (AsyncRAT).

Optional external enrichment:
- **AbuseIPDB** — live IP reputation with confidence scores (set `ABUSEIPDB_API_KEY` in `.env`)
- **VirusTotal** — file hash analysis for suspicious files detected in the shared folder (set `VIRUSTOTAL_API_KEY` in `.env`)
- All external results are **cached in SQLite** to avoid rate limits

---

## Important Notes

- Run as **Administrator / sudo** — required for promiscuous packet capture
- On Windows, **Npcap must be installed** with WinPcap compatibility mode
- The system is **fully agentless** — nothing is installed inside the VM
- Without admin privileges, the system automatically falls back to **benign simulation mode** (no synthetic attacks — just background traffic)
- The `shared_folder/` and `data/` directories are **auto-created** on first run
- All data persists to `data/security.db` (SQLite) and is retained for 30 days by default (configurable)
- This tool is intended for **authorized security research and monitoring only**

---

## Credits

- Packet capture — [Scapy](https://scapy.net/)
- File monitoring — [Watchdog](https://github.com/gorakhargosh/watchdog)
- System metrics — [psutil](https://github.com/giampaolo/psutil)
- REST API — [FastAPI](https://fastapi.tiangolo.com/)
- Dashboard — [Streamlit](https://streamlit.io/) + [Plotly](https://plotly.com/)
- Threat framework — [MITRE ATT&CK](https://attack.mitre.org/)
