# SENTINEL■AI // GOTHAM INTELLIGENCE TERMINAL
**End-to-End Automated Financial Crime Adjudication & Compliance Automation Pipeline**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-00FF8C?style=for-the-badge&logo=fastapi&logoColor=black)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3B82F6?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Groq LPU](https://img.shields.io/badge/Groq%20LPU-Llama--3.3--70B-FF8C42?style=for-the-badge&logo=ai&logoColor=white)](https://groq.com/)
[![Pandas](https://img.shields.io/badge/Pandas-2.0+-FF4444?style=for-the-badge&logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![Docker](https://img.shields.io/badge/Docker-Production%20Ready-0066FF?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-4A5568?style=for-the-badge)](LICENSE)

---

## 🌐 Executive Overview

**SentinelAI** is an enterprise-grade fintech compliance and anti-money laundering (AML) platform designed to bridge the gap between deterministic statistical feature engineering and ultra-low-latency Generative AI reasoning. 

Inspired by the dark, high-density aesthetics of **Palantir Gotham** and **Bloomberg Terminal**, SentinelAI inspects high-volume transactional streams, surfaces multi-hop financial crime patterns, renders legally grounded adjudication verdicts via Groq LPU (`llama-3.3-70b-versatile`), and automates down-stream compliance workflows (SLA ticket dispatching, Jira payloads, and customer regulatory notifications).

---

## 🏛️ Architecture & Data Pipeline

```
 [ Payment Gateway / Core Banking Stream ]
                   │
                   ▼ (Raw Transaction Stream / JSONL / CSV)
       ┌───────────────────────┐
       │   Ingestion & Normal  │  <-- Pydantic Schema Validation & UUID Assigning
       └───────────┬───────────┘
                   │
                   ▼ (Sliding Window Buffer)
       ┌───────────────────────┐
       │   Pandas Engine       │  <-- Vectorized Feature Engine (10m, 60s, 24h windows):
       └───────────┬───────────┘      Calculates Z-Score, Haversine Geo-Velocity, & IQR
                   │
        [ Anomaly Detected? ]
           ├── NO  ──► [ Save to WORM Cold Storage & SHA-256 Audit Trail ] (OK)
           └── YES ──┐
                     ▼
          ┌───────────────────────┐
          │   Groq LPU AI Engine  │  <-- Stage 1: Forensic Chain-of-Thought (CoT)
          └───────────┬───────────┘      Stage 2: Chief Compliance Officer JSON Verdict
                      │
                      ▼
         [ Adjudicated Risk Level ]
           ├── LOW ──► [ Passive Monitoring / Auto-Close ]
           └── MEDIUM / HIGH / CRITICAL
                      │
                      ▼
          ┌───────────────────────┐
          │ Automation Dispatcher │  <-- Dynamic SLA Routing (2h, 8h, 24h queues)
          └───────────┬───────────┘      Generates Atlassian Jira Payloads & Customer Emails
                      │
                      ▼
          ┌───────────────────────┐
          │   FastAPI & Gotham UI │  <-- Real-time SSE Stream & Interactive Dark Terminal
          └───────────────────────┘
```

---

## ✨ Core Platform Capabilities

### 📊 1. Hybrid Statistical Engine (Pandas Vectorized Rules)
Instead of overwhelming generative models with raw unflagged traffic, SentinelAI acts as a deterministic filter processing thousands of logs per second:
* **Cross-Device Fraud:** Detects single attacker IPs accessing **>5 distinct user accounts** within a 10-minute window.
* **Velocity Spikes:** Flags card-testing and bot attacks triggering **>20 transactions** in under 60 seconds.
* **Dormant Reactivation:** Identifies accounts inactive for **>180 days** executing sudden high-value transfer bursts (>10 txs in 5m).
* **Geo-Jurisdiction Mismatch:** Evaluates IP origin country codes against registered KYC domicile jurisdictions.
* **Impossible Travel:** Vectorized Haversine distance tracking catching consecutive physical card/device uses across distant nations separated by impossible travel times (<60 minutes).

### ⚡ 2. Cognitive Adjudication Engine (Groq LPU)
Utilizing Groq's ultra-fast Language Processing Units (~280–560 tokens/second):
* **Two-Stage Inspection:** 
  1. *Investigator Role*: Unconstrained Chain-of-Thought forensic analysis decomposing transaction sequences.
  2. *Judge Role*: Chief Compliance Officer synthesis enforcing strict **Pydantic v2 structured JSON** verdicts.
* **Self-Healing Output:** Automatic re-prompting if LLM syntax deviates from required schemas.
* **Automatic Fallback:** Seamless failover from `llama-3.3-70b-versatile` to `llama-3.1-8b-instant` under extreme API load.

### 🛡️ 3. Cryptographic WORM Audit Trail
Every system action, Pandas rule trigger, and LLM reasoning step is permanently chained in an immutable append-only audit log (`SentinelAI/logs/audit.log`). Each entry calculates a SHA-256 cryptographic hash of the preceding record (`prev_hash`), ensuring complete regulatory compliance with **PSD2, AMLD5, GDPR, and SOX**.

### 🎨 4. Gotham Intelligence Terminal UI
A single-file dark cyberpunk Single Page Application featuring:
* **Chart.js Risk Matrix:** Live Doughnut adjudication chart.
* **Interactive Kanban Board:** Real-time L2/L3 queue management (`OPEN`, `IN_PROGRESS`, `RESOLVED`).
* **Slide-In Forensic Drawer:** Deep-dive case inspection displaying raw statistical indicators alongside Groq reasoning.
* **Server-Sent Events (SSE):** Live visual overlay tracking execution phases step-by-step.

---

## 🚀 Quickstart Guide (Local Development)

### Prerequisites
* Python 3.11 or 3.12
* Node.js / NPM (optional, UI runs standalone via CDN)
* Groq API Key ([Get one free here](https://console.groq.com/))

### 1. Clone & Setup Virtual Environment
```bash
git clone https://github.com/your-org/SentinelAI.git
cd SentinelAI

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy the template configuration file:
```bash
cp .env.example .env
```
Edit `.env` and insert your API key:
```env
GROQ_API_KEY="gsk_your_actual_api_key_here"
```
*(Note: If omitted or left as default placeholder, SentinelAI automatically activates high-speed **Simulated LPU Mode** for zero-cost offline evaluation).*

### 3. Launch the Terminal
Start the API server and interactive UI:
```bash
python3 main.py --serve
```
Open your browser and navigate to:
👉 **`http://localhost:8000/`**

---

## 💻 Command-Line Interface (CLI) Reference

SentinelAI can be executed headless in CI/CD pipelines or batch processing crons:

```bash
# Execute batch inspection over custom dataset
python3 main.py --input SentinelAI/logs/transactions.jsonl --mode batch --risk-threshold 50.0

# Run evaluation without persisting files to disk (Dry Run)
python3 main.py --mode batch --dry-run --language EN

# Force export daily executive board dossier and CSV summaries
python3 main.py --mode batch --export-report
```

---

## ☁️ Cloud & Serverless Deployment Guide

SentinelAI can be deployed via containers (Docker Compose) or serverless platforms like **Vercel**.

### Option A: Serverless Deployment to Vercel (FastAPI + SPA)
SentinelAI comes pre-configured with `vercel.json` and `api/index.py` for immediate deployment to Vercel's Python runtime.

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```
2. Deploy to Vercel:
   ```bash
   vercel --prod
   ```
3. Add Environment Variable in Vercel Dashboard:
   * Key: `GROQ_API_KEY`
   * Value: `gsk_your_actual_api_key_here`

*(Note: When running on Vercel (`VERCEL=1`), all persistence paths automatically route to serverless ephemeral `/tmp/SentinelAI` memory).*

### Option B: Deployment via Docker Compose
```bash
# Build and launch container stack in detached mode
docker-compose up -d --build

# Inspect real-time server logs
docker-compose logs -f sentinelai

# Stop stack
docker-compose down
```

### Option B: Standalone Docker Build
```bash
# Build production container image
docker build -t sentinelai-engine:latest .

# Run container exposing port 8000
docker run -d -p 8000:8000 --name sentinelai \
  -e GROQ_API_KEY="gsk_your_api_key" \
  -v $(pwd)/SentinelAI/cases:/app/SentinelAI/cases \
  -v $(pwd)/SentinelAI/verdicts:/app/SentinelAI/verdicts \
  sentinelai-engine:latest
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the interactive Gotham Intelligence Terminal UI |
| `GET` | `/api/health` | Returns system operational readiness and engine statuses |
| `GET` | `/api/stats` | Macro KPI metrics, risk distributions, and USD token costs |
| `POST` | `/api/pipeline/run` | Asynchronously triggers full compliance pipeline job |
| `POST` | `/api/pipeline/stream` | Live Server-Sent Events (SSE) streaming pipeline execution |
| `GET` | `/api/cases` | Retrieves all flagged statistical fraud cases (`List[FraudCase]`) |
| `POST` | `/api/cases` | Opens a manual investigation case from compliance analysts |
| `GET` | `/api/verdicts` | Retrieves all cognitive LLM adjudications (`List[LLMVerdict]`) |
| `GET` | `/api/tickets` | Retrieves operational workflow tickets (`List[ComplianceTicket]`) |
| `GET` | `/api/emails` | Retrieves generated customer legal notices (`List[ClientEmail]`) |
| `GET` | `/api/reports/latest` | Retrieves the latest executive board session dossier |

*Full interactive Swagger/OpenAPI documentation is available at:* **`http://localhost:8000/docs`**

---

## 📁 Repository Structure

```text
SentinelAI/
├── ai/                      # Generative AI LPU layer (Groq SDK, CoT Inspector, Prompts)
├── analytics/               # Deterministic Pandas statistical engines & heuristics
├── api/                     # FastAPI REST server & Server-Sent Events (SSE) router
├── automation/              # Workflow dispatchers (Tickets, Jira formatting, Emails)
├── config/                  # Central YAML settings, AML limits, and SLA rules
├── frontend/                # Single-file Gotham Intelligence Terminal (HTML/JS/Tailwind)
├── ingestion/               # Synthetic transaction generators & normalization filters
├── models/                  # Unified Pydantic v2 domain schemas
├── cases/                   # Persistent JSON storage for flagged statistical cases
├── verdicts/                # Persistent JSON storage for adjudicated LLM decisions
├── tickets/                 # Persistent JSON storage for L2/L3 compliance tickets
├── emails/                  # Persistent JSON storage for generated customer notices
├── reports/                 # Multi-format executive session deliverables (.json & .txt)
└── logs/                    # Immutable WORM SHA-256 cryptographic audit logs
```

---

## 📜 License
Distributed under the MIT License. See `LICENSE` for details.
