<div align="center">

# 🛡️ ForensIQ

### Digital Forensics & Incident Response Analyzer for Linux

**v3.0** · A modern, all-in-one DFIR triage tool with AI-powered analysis

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-green)]()

[Features](#-features) · [Install](#-installation) · [Usage](#-usage) · [Architecture](#-architecture) · [Roadmap](#-roadmap)

</div>

---

## 📖 Overview

**ForensIQ** is a desktop DFIR (Digital Forensics & Incident Response) analyzer that performs comprehensive triage of a Linux system in under a minute. It collects data from 19 distinct sources, correlates events into attack chains, visualizes findings in an interactive dashboard, and optionally explains them in plain language using an AI analyst.

Built for **SME security teams, IT administrators, and incident responders** who need fast answers without deploying a full SIEM.

### Why ForensIQ?

| Feature | ForensIQ | Velociraptor | Autopsy | Splunk |
|---------|:--------:|:------------:|:-------:|:------:|
| Single-binary install | ✅ | ❌ | ❌ | ❌ |
| Works on live system | ✅ | ✅ | ❌ | ✅ |
| AI explanation | ✅ | ❌ | ❌ | ❌ |
| Event graph correlation | ✅ | ❌ | ❌ | ✅ |
| PDF report export | ✅ | ❌ | ✅ | ✅ |
| Free & open-source | ✅ | ✅ | ✅ | ❌ |

---

## ✨ Features

### 🔍 Comprehensive Scanning (19 scanners)
- **Processes** — running processes, CPU/memory anomalies, suspicious command lines
- **Network** — open ports, active connections, malicious destinations, geo-located IPs
- **Persistence** — autostart entries, cron jobs, systemd services
- **Users** — login events, failed authentication attempts, active sessions
- **Files** — SUID/SGID binaries, recently modified files, deleted artifacts
- **Devices** — USB history, browser activity
- **Logs** — auth.log, syslog, journalctl, kernel log, dpkg history

### 📊 Interactive Dashboard
- Real-time risk score (0–100) with severity breakdown
- Activity timeline with click-to-filter (1H / 1D / 1W / 1MO / All)
- Category distribution donut chart
- Top findings with one-click navigation
- Search across all findings by description, source, severity

### 🕸️ Event Graph (Correlation Engine)
- D3.js force-directed graph linking processes, ports, connections, files, users
- Smart filtering — auto-prioritizes by severity and connectivity
- Attack chains — automatically detects connected subgraphs with HIGH/CRITICAL nodes
- Interactive: drag, zoom, pan, click for details

### 🤖 AI Analyst (Optional)
- Local AI via **Ollama** (free, runs on your hardware) or cloud via **Anthropic Claude API**
- Automatic post-scan assessment with verdict, top threats, immediate actions
- Interactive chat with full scan context
- 100-message history per session
- Disabled by default — enable in `forensiq_app.py`

### 🚨 Real-Time Monitoring
- Background thread monitors new ports and suspicious processes every 60s
- System tray notifications + in-app toast alerts
- Severity-based color coding (CRITICAL / HIGH / MEDIUM)

### 📑 Export & Reporting
- **PDF report** — professional multi-page document with cover, executive summary, findings tables
- **CSV export** — for spreadsheet analysis
- **JSON export** — full raw data dump
- **Session comparison** — diff between any two scans (risk delta, new/resolved findings, process/port changes)

### 🎨 Modern UI
- Dark / Light theme (persisted)
- Virtual scrolling for large datasets
- Detail overlay with copy-to-clipboard
- IP geolocation with country flags

---

## 🚀 Installation

### Quick Install (Linux)

```bash
git clone https://github.com/YOUR_USERNAME/forensiq.git
cd forensiq
chmod +x install.sh
./install.sh
```

After installation, launch from your application menu (search "ForensIQ") or run `forensiq` in a terminal.

### Manual Install

```bash
# 1. Install Python dependencies
pip install --user PyQt6 PyQt6-WebEngine reportlab

# 2. Clone the repo
git clone https://github.com/YOUR_USERNAME/forensiq.git
cd forensiq

# 3. Run directly
sudo python3 forensiq_app.py
```

### Uninstall

```bash
./uninstall.sh
```

User data at `~/.forensiq/` is preserved by default.

---

## 📚 Usage

### First Launch

When you start ForensIQ, a session dialog appears with three options:

1. **Open Previous Session** — load a saved scan from the list
2. **Load Log File (.json)** — open a scan from any path
3. **New Scan** — runs a fresh scan automatically (default action)

### Running a Scan

- Click **▶ RUN SCAN** in the top-right corner
- Progress is shown in the bottom-left
- A live timer appears in the top bar
- Scan typically completes in 10–60 seconds depending on system size

### Reviewing Results

- **Dashboard** — high-level overview, risk score, stat cards
- **Findings** — full event list with severity filters
- **Event Graph** — visual correlation of related events
- **Compare** — diff between two sessions
- Click any event to see the full detail overlay with raw data

### Exporting

- **PDF report** — click the `📄 PDF` button in the top bar (saved to `~/Downloads/`)
- **CSV / JSON** — buttons next to the export controls

### Data Location

All user data is stored in `~/.forensiq/`:

```
~/.forensiq/
├── sessions/                    # Saved scan history
│   ├── 2026-04-27_14-32_host.json
│   └── 2026-04-26_09-15_host.json
└── forensiq_report.json         # Most recent scan
```

This means **moving the program between computers doesn't carry over data** — each machine has its own session history.

---

## 🤖 Enabling AI Analyst

The AI Analyst tab is **disabled by default**. To enable:

### Option 1: Local AI via Ollama (recommended, free)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model (~4.7 GB)
ollama pull llama3.1:8b

# 3. Enable systemd service
sudo systemctl enable --now ollama
```

Then edit `~/.local/share/forensiq/forensiq_app.py`:

```python
AI_ENABLED     = True
OLLAMA_ENABLED = True
OLLAMA_MODEL   = "llama3.1:8b"
```

### Option 2: Anthropic Claude API

```python
AI_ENABLED        = True
OLLAMA_ENABLED    = False
ANTHROPIC_API_KEY = "sk-ant-api03-..."  # from console.anthropic.com
```

Restart ForensIQ — the AI Analyst tab will appear in the sidebar.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    forensiq_app.py                       │
│         (PyQt6 desktop wrapper + HTTP proxy)             │
│                                                          │
│  ┌────────────────┐   ┌──────────────────────────────┐  │
│  │  QWebEngine    │←──│  Local HTTP Server (:18765)  │  │
│  │   (loads HTML) │   │                              │  │
│  └────────────────┘   │  /api/report                 │  │
│         ↑              │  /api/correlations           │  │
│         │              │  /api/sessions               │  │
│         │              │  /api/ai     (proxy)         │  │
│         │              │  /api/pdf                    │  │
│         │              └──────────────────────────────┘  │
│         │                          ↓                     │
│         │              ┌──────────────────────────────┐  │
│         │              │   forensiq_engine.py         │  │
│         │              │  • 19 scanners               │  │
│         │              │  • Correlation engine        │  │
│         │              │  • PDF generator             │  │
│         │              │  • Windows/Linux dispatch    │  │
│         │              └──────────────────────────────┘  │
│         │                                                │
│  ┌──────┴───────────────────────────────────────────┐   │
│  │              ForensIQ.html                        │   │
│  │   Vanilla JS + D3.js + Chart.js dashboard        │   │
│  └───────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
                              ↓
                  ┌───────────────────────┐
                  │    ~/.forensiq/       │
                  │    sessions/*.json    │
                  └───────────────────────┘
```

### File Structure

```
forensiq/
├── forensiq_app.py        # Main entry — PyQt6 window + HTTP server
├── forensiq_engine.py     # Scanner engine + correlation + PDF generator
├── ForensIQ.html          # Dashboard UI (HTML + JS + CSS)
├── install.sh             # One-click installer for Linux
├── uninstall.sh           # Uninstaller
├── requirements.txt       # Python dependencies
├── README.md              # This file
└── LICENSE                # MIT license
```

---

## 🗺️ Roadmap

### v3.0 (Planned)
- **MITRE ATT&CK mapping** — auto-tag findings with technique IDs (T1059, T1078, etc.)
- **Score explanation** — "Risk 87 because: 2 critical processes + 3 suspicious autostart entries"
- **RAM analysis** — Volatility3 integration for hidden process detection
- **Rootkit detection** — `/proc` vs filesystem comparison
- **File recovery** — `extundelete` / `testdisk` integration
- **Deep network analysis** — pcap capture and analysis (via `scapy`)
- **VirusTotal integration** — hash lookup for suspicious binaries
- **Fine-tuned AI** — train on DFIR data for domain-specific responses
- **RAG knowledge base** — MITRE ATT&CK + CVE database

### v4.0 (Future)
- Distributed agents for remote machine monitoring
- Centralized PostgreSQL event storage
- Multi-host correlation
- Web-based admin console

---

## 🤝 Contributing

Pull requests welcome. For major changes, please open an issue first.

```bash
# Setup development environment
git clone https://github.com/YOUR_USERNAME/forensiq.git
cd forensiq
pip install -r requirements.txt

# Run from source
sudo python3 forensiq_app.py
```

---

## 📄 License

MIT © 2026 Egor Gubarev

---

## 🙏 Acknowledgments

- **Chart.js** — dashboard visualizations
- **D3.js** — event graph rendering
- **PyQt6** — desktop framework
- **ReportLab** — PDF generation
- **Ollama** — local AI inference

---

<div align="center">

**Built by Egor Gubarev** · [Report a bug](https://github.com/YOUR_USERNAME/forensiq/issues) · [Request a feature](https://github.com/YOUR_USERNAME/forensiq/issues)

</div>
