# DTAC-IR: Dynamic Trust Assessment & Control — Incident Response Platform

> Real-time network intrusion detection with ML-powered threat classification, dynamic trust scoring, and automated incident response.

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          DTAC-IR Platform                        │
├──────────────┬──────────────────┬──────────────────┬────────────┤
│  Network     │  Detection       │  Trust Scoring   │  Automated │
│  Capture     │  Engine          │  Engine          │  Response  │
│  (Scapy)     │  Rules + ML      │  (Per-Device)    │  (Actions) │
├──────────────┴──────────────────┴──────────────────┴────────────┤
│                    FastAPI Backend + WebSocket                    │
├──────────────────────────────┬──────────────────────────────────┤
│       React Dashboard        │      PostgreSQL + Redis           │
└──────────────────────────────┴──────────────────────────────────┘
```

## Features

**Phase 1 — Core Detection Engine**
- Real-time packet capture via Scapy with simulation mode (no root required for dev)
- Rule-based detection: Port Scan, SYN Flood, DNS Exfiltration, Brute Force, ARP Spoofing
- Per-IP stateful tracking with rolling time windows
- Feature extraction pipeline compatible with ML input format

**Phase 2 — ML + Trust Scoring**
- Random Forest classifier trained on CICIDS2017 dataset
- Dynamic Trust Score (0–100) per device with exponential temporal decay
- Score deductions weighted by severity × attack type × ML confidence
- Analyst override support with audit trail

**Phase 3 — Dashboard + Automation**
- React dashboard with real-time WebSocket updates
- Alert management with acknowledge/resolve/false-positive workflow
- Automated IP blocking and quarantine via iptables (opt-in)
- Slack/email alerting integration

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet Capture | Scapy 2.5 |
| ML | scikit-learn (Random Forest) |
| Backend | FastAPI + SQLAlchemy (async) |
| Database | PostgreSQL 16 |
| Cache/Queue | Redis 7 |
| Frontend | React 18 + TypeScript |
| Deployment | Docker + Docker Compose |

## Quick Start

### Prerequisites
- WSL2 (Ubuntu 22.04+) or native Linux
- Python 3.11+, Node.js 20+, Docker
- Git

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/dtac-ir.git
cd dtac-ir
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Run (Development)

```bash
# Terminal 1: Start database
make db-up

# Terminal 2: Start backend (simulation mode — no root needed)
make dev-backend

# Terminal 3: Start frontend
make dev-frontend
```

Open http://localhost:3000 for the dashboard, http://localhost:8000/api/docs for the API.

### Run (Docker — full stack)

```bash
make docker-up
```

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Port Scan | >20 unique dst ports in 60s | MEDIUM |
| SYN Flood | >100 SYN packets, >85% SYN ratio | CRITICAL |
| DNS Exfiltration | >200 byte DNS payload or >50 queries/min | HIGH |
| Brute Force | >10 connections to auth ports (22,23,3389) in 60s | HIGH |
| ARP Spoofing | IP-MAC binding change detected | HIGH |

## Trust Scoring

Trust scores range 0–100 per device:

| Score Range | Status | Action |
|-------------|--------|--------|
| 70–100 | Trusted | Monitor |
| 30–69 | Suspicious | Alert analyst |
| 10–29 | Quarantined | Restrict traffic |
| 0–9 | Blocked | Auto-block |

Scores recover over time via exponential decay — a port scan doesn't permanently blacklist a device.

## Project Structure

```
dtac-ir/
├── backend/          # FastAPI + detection engine
│   └── app/
│       ├── detection/    # Scapy capture + rules
│       ├── ml/           # Model inference
│       ├── trust/        # Trust scoring engine
│       ├── response/     # Automated actions
│       └── api/          # REST + WebSocket endpoints
├── frontend/         # React dashboard
├── ml/               # Notebooks + trained models
├── docker/           # Compose files
├── docs/             # Architecture + threat model
└── scripts/          # Setup + utilities
```

## Dataset

ML model trained on [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — the industry-standard IDS benchmark dataset from the Canadian Institute for Cybersecurity.

## License

MIT — see [LICENSE](LICENSE)

---

*Built as part of a cybersecurity engineering portfolio. Not intended for production deployment without security review.*
