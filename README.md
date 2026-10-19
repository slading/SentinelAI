# SENTINEL■AI // AML INVESTIGATION WORKBENCH
**Deterministic transaction detection with optional LLM adjudication — synthetic data only.**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-00FF8C?style=for-the-badge&logo=fastapi&logoColor=black)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3B82F6?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Pandas](https://img.shields.io/badge/Pandas-2.0+-FF4444?style=for-the-badge&logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![Groq](https://img.shields.io/badge/Groq-optional%20live%20mode-FF8C42?style=for-the-badge&logo=ai&logoColor=white)](https://groq.com/)
[![Docker](https://img.shields.io/badge/Docker-container-0066FF?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
![License](https://img.shields.io/badge/License-not%20specified-4A5568?style=for-the-badge)

> ### ▶ Live public demo: [**https://sentinel-ai-ten-nu.vercel.app**](https://sentinel-ai-ten-nu.vercel.app)
>
> Read-only, synthetic, precomputed fixtures — no sign-in, no live AI calls, no writes.
> The full local pipeline and its optional live Groq mode are described below.

---

## ⚠️ Read this first: two very different surfaces

This repository contains **one codebase** that runs in **two modes**. They do not have the same capabilities.

| Aspect | **Public Vercel demo** | **Local / private run** |
| :--- | :--- | :--- |
| **What it is** | A read-only dashboard over precomputed fixtures | The full pipeline, executed by you on your machine |
| **Data** | 4 synthetic cases + 4 verdicts + 4 tickets + 4 notices + 1 report (17 JSON fixtures in `SentinelAI/demo_data/`) | Bundled synthetic stream (`SentinelAI/logs/test_stream.jsonl`) or your own JSONL/CSV |
| **Detection** | None at request time — fixtures are precomputed | Deterministic Pandas rules run for real |
| **LLM** | No LLM call is reachable: the pipeline routes are blocked and the stored verdicts are fixtures labelled `model_used: "demo-precomputed"`. `SENTINELAI_LLM_MODE` defaults to `mock` | Mock by default; live Groq is an explicit opt-in |
| **Writes** | Impossible. `POST /api/cases`, `/api/pipeline/run`, `/api/pipeline/stream` return **404** | Available only with an explicit non-production key setup |
| **Storage** | Bundled fixtures via `SENTINELAI_DATA_DIR`; `/tmp` write paths are per-instance and non-durable | Local JSON files under `SentinelAI/` (or `SENTINELAI_DATA_DIR`) |

> **SentinelAI is a demonstration and engineering workbench, not a compliance system of record.** It is not production-ready, has not been validated against any regulator, is not designed for real customer data, and does not deliver emails or open Jira issues. See the **Not production-ready** section below.

---

## 🌐 What SentinelAI is

SentinelAI is a small AML/fraud investigation workbench built around two layers:

1. **A deterministic filter** — vectorised Pandas rules that turn a transaction stream into explainable `FraudCase` records with a fixed risk score per typology.
2. **An optional LLM adjudication layer** — a two-stage Groq prompt (investigator → judge) that converts each case into a schema-validated `LLMVerdict` and a recommended action.

Around those sit ticket/notice/report generators and a read-only web console. The console takes visual cues from Palantir Gotham and Bloomberg Terminal (no affiliation); all data shipped in this repository is synthetic.

---

## 🏛️ Architecture

```
 [ JSONL / CSV transaction stream  — synthetic fixture or your own file ]
                   │
                   ▼
       ┌───────────────────────┐
       │  Ingestion / load     │  <-- pandas.read_json(lines=True) / read_csv
       └───────────┬───────────┘
                   │
                   ▼
       ┌───────────────────────┐
       │  FraudDetector        │  <-- 5 deterministic rules, fixed risk scores
       │  (Pandas)             │      embedded in analytics/fraud_detector.py
       └───────────┬───────────┘
                   │
          [ cases flagged? ]
             ├── no  ──► pipeline finishes with zero cases
             └── yes ─┐
                      ▼
       ┌───────────────────────┐
       │  LLMInspector         │  <-- Stage 1: investigator narrative
       │  (Groq, optional)     │      Stage 2: judge → strict JSON verdict
       └───────────┬───────────┘      mock mode simulates both stages locally
                   │
                   ▼
       ┌───────────────────────┐
       │  Generators           │  <-- compliance ticket JSON, client notice JSON,
       │  (local JSON files)   │      session report JSON
       └───────────┬───────────┘
                   │
                   ▼
       ┌───────────────────────┐
       │  FastAPI + SPA        │  <-- GET-only public API; dashboard at /
       └───────────────────────┘
```

**What is *not* in that path:** a database, a message queue, a live transaction ingest socket, outbound email/Jira transport, or an audit writer. Each of those is discussed below.

### Implemented vs. not wired

| Component | Code exists | Wired into the shipped API? |
| :--- | :--- | :--- |
| Pandas rule engine (`SentinelAI/analytics/fraud_detector.py`) | Yes | Yes (CLI + `POST /api/pipeline/*`) |
| Groq two-stage inspector | Yes | Yes, mock by default |
| Ticket / notice / report generators | Yes | Yes (write local JSON) |
| Jira payload formatting (`export_jira_format`) | Yes | **No** — helper only, never dispatched |
| SMTP / email delivery | **No** | — |
| SHA-256 chained audit log | Yes | **No** — only the unmounted `/api/v1` router uses it |
| `/api/v1/*` router, WebSocket, streaming simulator | Yes | **No** — deliberately unmounted; returns 404 |
| Durable database storage | **No** | — |

---

## ✨ Core capabilities (verified against the code)

### 📊 1. Deterministic rule engine

`SentinelAI/analytics/fraud_detector.py` runs five sliding-window rules. Thresholds and scores are **hard-coded in that module**:

| Rule (`rule_triggered`) | Condition | Risk score |
| :--- | :--- | ---: |
| `CROSS_DEVICE_IP_SPIKE` | one IP touches **> 5** distinct accounts within **10 min** | 75.0 |
| `VELOCITY_60S_SPIKE` | one account makes **> 20** transactions within **60 s** | 80.0 |
| `DORMANT_REACTIVATION_BURST` | **> 180 days** of inactivity, then **> 10** transactions within **5 min** | 85.0 |
| `GEO_JURISDICTION_MISMATCH` | transaction country ≠ account home country | 60.0 |
| `IMPOSSIBLE_GEO_TRAVEL` | two consecutive transactions in different countries **< 60 min** apart | 90.0 |

Cases are deduplicated by `(rule, sorted transaction ids)` and sorted by risk score. Detection is reproducible for a fixed input file; case IDs embed `uuid4` and therefore differ per run.

> ⚠️ **Label-assisted paths.** Two detectors also read the optional `fraud_scenario` column: dormant reactivation treats a `Dormant Reactivation` tag as an assumed 205-day gap, and geo mismatch can fall back to rows tagged `Geo Mismatch`. That column is populated in the bundled synthetic stream, so those two findings are partly label-assisted there. On unlabelled data they rely only on observed timestamps and country codes — which is also why they are stricter and quieter.

> ⚠️ **Two rule sets exist.** `SentinelAI/analytics/fraud_rules.py` (with `config/thresholds.yaml`) belongs to the legacy `/api/v1` path and is **not** used by the mounted API or the CLI. The `aml_thresholds` block in `SentinelAI/config/config.yaml` is likewise read by neither detector. Edit the constants in `fraud_detector.py` to change live behaviour.

### ⚡ 2. LLM adjudication (optional)

* **Two stages** — an investigator prompt producing free-text analysis, then a judge prompt producing JSON that is validated into the `LLMVerdict` Pydantic model.
* **Schema repair** — malformed JSON is re-prompted up to `max_retries` (3) times; out-of-enum risk levels/actions are coerced to a safe default derived from the case risk score.
* **Model fallback** — `llama-3.3-70b-versatile` → `llama-3.1-8b-instant` after retry exhaustion (`SentinelAI/config/config.yaml`).
* **Mock by default** — `SENTINELAI_LLM_MODE=mock` never constructs the Groq SDK client, even if `GROQ_API_KEY` is set. Mock verdicts are synthetic placeholders, not analysis.
* **Live is opt-in** — `SENTINELAI_LLM_MODE=live` requires a real, non-placeholder `GROQ_API_KEY`; it fails closed otherwise.

Throughput figures such as *"280–560 tokens/second"* are vendor-published model specs copied into `MODEL_METADATA`, not measurements taken in this repository.

### 🎫 3. Deliverable generation (local files, no delivery)

For every verdict the local pipeline writes:

* a **compliance ticket** (`SentinelAI/tickets/TKT-*.json`) with priority, queue assignee and `sla_hours` derived from the risk level (CRITICAL 2 h, HIGH 8 h, MEDIUM 24 h, LOW 72 h);
* a **client notice draft** (`SentinelAI/emails/<case_id>.json`) unless the action is `MONITOR`;
* a **session report** (`SentinelAI/reports/<date>.json`).

`export_jira_format()` can render a ticket as a Jira-shaped payload and `export_all_csv()` can export tickets, but **nothing calls them**, and no email is ever sent. These are artifacts for inspection, not completed workflow actions.

### 🎨 4. Web console

A single-file dashboard (`SentinelAI/frontend/index.html`, no build step, no CDN dependency) with hash routing:

* **Overview** — counts and a hand-drawn SVG risk bar chart, recommended-action mix, latest stored report.
* **Investigations** — searchable case table, detail view, slide-in preview drawer.
* **Deliverables** — read-only ticket / notice / report browser.
* **Pipeline, Rules, Settings** — explicit "unavailable in this demo" panels; there is no rule editor or settings API.

The console is honest about being read-only: creation, pipeline and deliverable-download controls are disabled and labelled.

### 🛡️ 5. Audit trail (present but not wired)

`SentinelAI/logs/audit_logger.py` appends JSON lines to a local file and links each entry to the previous one with SHA-256 (`prev_hash` → `event_hash`). Important qualifications:

* The **mounted** API (`SentinelAI/api/server.py`) never writes audit events. Only the unmounted `/api/v1` orchestrator path calls the logger, so `/api/v1/audit` returns 404.
* It is an **ordinary append-only text file on the local filesystem** — not WORM storage, not tamper-evident against a filesystem-level edit, and not replicated.
* No conformance with PSD2, AMLD5, GDPR, SOX or any other regime has been assessed. Regulatory strings in prompts and fixtures are illustrative.

---

## 🚫 Not production-ready

Explicit non-goals and known gaps:

* **No real customer data path.** Ingestion is file-based; there is no streaming socket, queue consumer, or PII handling policy.
* **No durable persistence.** Records are JSON files re-read at start-up. Vercel uses per-instance `/tmp` (non-durable, no cross-instance sharing).
* **No multi-tenancy, RBAC, SSO, or user accounts.** A single optional API key exists for local testing only.
* **No outbound side effects.** No email delivery, no Jira/ServiceNow integration, no account freezing.
* **No audit trail on the public API**, despite the chained logger existing in the tree.
* **No validated model performance.** There is no labelled corpus, precision/recall measurement, drift monitoring or backtesting.
* **No regulatory certification.** Nothing here has been reviewed by a compliance function or regulator.
* **Health checks are static.** `/api/health` returns constant `READY` strings; it does not probe Groq, storage, or disk.
* **Threshold configuration is scattered** across the detector constants, `config/config.yaml` and `config/thresholds.yaml`; only the first currently drives the mounted pipeline, so the YAML files can silently disagree with behaviour.

---

## 🚀 Quickstart (local)

### Prerequisites

* Python **3.11** or **3.12**
* No Node.js required for the UI (it is served by FastAPI as a static file)
* A Groq API key **only** if you want live AI calls ([console.groq.com](https://console.groq.com/))

### 1. Clone and install

```bash
git clone https://github.com/slading/SentinelAI.git
cd SentinelAI

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

`pytest` is intentionally **not** in `requirements.txt`; install it separately if you want to run tests.

### 2. Configure the environment

```bash
cp .env.example .env
```

The template is safe by default:

```env
SENTINELAI_PRIVILEGED_MODE=disabled
SENTINELAI_LLM_MODE=mock
```

Mock mode never constructs a Groq client and makes no network calls. The public API is read-only.

### 3. Start the server

```bash
python3 main.py --serve
```

Open **`http://localhost:8000/`** for the console, or **`http://localhost:8000/docs`** for the OpenAPI schema.

> **Start-up storage note:** locally, records are rehydrated from `SentinelAI/{cases,verdicts,tickets,emails,reports}` by default. Because the repository ships example artifacts, a fresh clone will show existing records — and a few legacy ticket files that no longer match the current schema are skipped with a warning. To start from a clean store:
>
> ```bash
> SENTINELAI_DATA_DIR=/tmp/sentinelai-scratch SENTINELAI_REHYDRATE=0 python3 main.py --serve
> ```

### 4. Enabling privileged writes (local testing only)

The three mutating routes are disabled unless **all** of the following hold: `SENTINELAI_PRIVILEGED_MODE=api_key`, a key of ≥ 32 ASCII characters in `SENTINELAI_PRIVILEGED_API_KEY`, and an `ENVIRONMENT` value in `development`, `dev`, `local`, `private`, `test`, or `testing`.

```env
ENVIRONMENT=development
SENTINELAI_PRIVILEGED_MODE=api_key
SENTINELAI_PRIVILEGED_API_KEY=<random 32+ character local-only secret>
```

Send it as an `X-API-Key` header from a trusted local client:

```bash
curl -X POST http://localhost:8000/api/pipeline/run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SENTINELAI_PRIVILEGED_API_KEY" \
  -d '{"input_file": "SentinelAI/logs/test_stream.jsonl"}'
```

`input_file` must name one of the bundled fixtures (`SentinelAI/logs/test_stream.jsonl` or `.csv`); arbitrary paths are rejected with 422. Never put this key in frontend code or browser storage.

### 5. Enabling live Groq

```env
SENTINELAI_LLM_MODE=live
GROQ_API_KEY=<real server-side key>
```

Live mode is never exercised by the test suite. A missing or placeholder key raises at start-up rather than silently falling back.

---

## 💻 CLI reference

The CLI runs the same detection + adjudication stack headlessly. Commands below were executed against the checked-in 500-row synthetic stream.

```bash
# Full batch run over the bundled synthetic dataset
python3 main.py --input SentinelAI/logs/test_stream.jsonl --risk-threshold 50.0

# Evaluate without writing tickets/notices/report to disk
python3 main.py --input SentinelAI/logs/test_stream.jsonl --mode batch --dry-run --language EN

# Evaluation plus a persisted report (even under --dry-run)
python3 main.py --input SentinelAI/logs/test_stream.jsonl --dry-run --export-report
```

Notes on actual behaviour:

* Default `--input` is `SentinelAI/logs/transactions.jsonl`. **That file does not exist in this repository**; when it is missing the tool logs a warning and generates a fresh synthetic stream (100 accounts, 1,000 transactions, `seed=42`).
* `--mode {batch,stream}` is accepted but currently cosmetic — both values execute the same batch path.
* `--risk-threshold` filters detected cases *before* LLM adjudication (default `50.0`).
* Non-dry runs write tickets, notices and a report into `SentinelAI/{tickets,emails,reports}`. Detected cases and verdicts are **not** persisted by the CLI path.
* `--language` accepts `EN`, `RU`, `PL`, `DE` and affects generated notice text.
* `--fraud-rate` is a *target*, not a hard cap: scenario injection can overshoot it (a 5 % target on a small stream can produce far more fraud rows than requested).
* **A non-dry run writes into your working tree** (`SentinelAI/tickets`, `SentinelAI/emails`, `SentinelAI/reports`). The CLI generators use those fixed relative paths and ignore `SENTINELAI_DATA_DIR`, so `--dry-run` is the reliable way to inspect results without creating files.

Generate a fresh dataset explicitly:

```bash
python3 -m SentinelAI.ingestion.data_generator \
  --accounts 100 --transactions 1000 --fraud-rate 0.05 --seed 42 \
  --output SentinelAI/logs/transactions.jsonl
```

---

## 📡 REST API reference

The public surface is **GET-only**. Same-origin browser access needs no CORS; cross-origin access is opt-in via `SENTINELAI_CORS_ORIGINS` (exact origins, wildcards discarded, credentials disabled).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the web console (`index.html`) |
| `GET` | `/docs`, `/openapi.json` | Interactive schema (POST entries will 404 unless locally enabled) |
| `GET` | `/api/health` | Static status object (not a live probe) |
| `GET` | `/api/stats` | Case/verdict counts, risk + action distributions, token total, illustrative cost |
| `GET` | `/api/cases` | All case records |
| `GET` | `/api/cases/{case_id}` | One case; legacy `#`-prefixed IDs also resolve via aliases |
| `GET` | `/api/verdicts` | All verdicts |
| `GET` | `/api/verdicts/{case_id}` | Verdict for one case |
| `GET` | `/api/tickets` | All compliance tickets |
| `GET` | `/api/tickets/{ticket_id}` | One ticket |
| `GET` | `/api/emails` | All client notices |
| `GET` | `/api/emails/{case_id}` | Notice for one case |
| `GET` | `/api/reports` | All session reports |
| `GET` | `/api/reports/latest` | Most recent report (404 if none) |
| `POST` | `/api/cases` | **Privileged.** Manual case; 404 by default, 201 when locally enabled |
| `POST` | `/api/pipeline/run` | **Privileged.** Queue a background run; 404 by default, 202 when locally enabled |
| `POST` | `/api/pipeline/stream` | **Privileged.** SSE progress stream; 404 by default, 200 when locally enabled |

Error semantics worth knowing:

* Disabled privileged routes return **404**, not 401/403 — they are indistinguishable from absent routes by design.
* Enabled-but-misconfigured private mode returns **503**; a wrong or missing key returns **401**.
* Request bodies are capped at 64 KiB (**413**), and case IDs are validated before any filesystem write (**422**).
* On the public demo, every GET endpoint serves the 17 bundled fixtures and nothing else.

---

## ☁️ Deployment

### Option A — Vercel (public read-only demo)

Deployed instance: <https://sentinel-ai-ten-nu.vercel.app>

`vercel.json` routes every request to `api/index.py`, which:

1. sets `VERCEL=1`;
2. forces `SENTINELAI_DATA_DIR` to `SentinelAI/demo_data` and `SENTINELAI_REHYDRATE=1`;
3. mounts the FastAPI app.

```bash
npm i -g vercel
vercel --prod
```

The result is exactly the public demo surface described above: 4 cases, 4 verdicts, 4 tickets, 4 notices, 1 report. All three privileged POST routes return 404 regardless of environment variables, because `is_production_runtime()` treats any `VERCEL`/`VERCEL_ENV`/`production` marker as non-privileged. Write paths under `/tmp/SentinelAI` are per-instance and must not be treated as storage.

### Option B — Docker Compose

```bash
docker compose up -d --build
docker compose logs -f sentinelai
docker compose down
```

### Option C — Standalone Docker image

```bash
docker build -t sentinelai-engine:latest .

docker run -d -p 8000:8000 --name sentinelai \
  -e SENTINELAI_PRIVILEGED_MODE=disabled \
  -e SENTINELAI_LLM_MODE=mock \
  -v "$(pwd)/SentinelAI/cases:/app/SentinelAI/cases" \
  -v "$(pwd)/SentinelAI/verdicts:/app/SentinelAI/verdicts" \
  sentinelai-engine:latest
```

Both Docker paths set `ENVIRONMENT=production`, `SENTINELAI_PRIVILEGED_MODE=disabled` and `SENTINELAI_LLM_MODE=mock`. **The container therefore serves the read-only console, not an interactive pipeline.** To exercise writes inside a container you must override those variables (`ENVIRONMENT=development` plus the api_key settings above) and accept that this is a local experiment. Mount the directories you want to keep; nothing else survives a container rebuild.

---

## 📁 Repository structure

```text
SentinelAI/                        # repository root
├── main.py                        # thin wrapper → SentinelAI.main:main
├── api/index.py                   # Vercel entrypoint (forces demo_data)
├── vercel.json
├── Dockerfile · docker-compose.yml
├── .env.example
├── requirements.txt
├── README.md
├── uploads/screen.png             # stale concept mockup (not used by the app)
├── tests/
│   ├── test_api_security.py       # auth, limits, CORS, mock-mode guarantees
│   ├── test_d7a_demo_fixtures.py  # public demo fixture integrity
│   ├── test_d6b_local_e2e.py      # local rehydration + case-ID behaviour
│   └── d6b_child.py               # subprocess worker for the E2E tests
└── SentinelAI/
    ├── ai/                        # Groq client, two-stage inspector, prompts, reports
    ├── analytics/                 # fraud_detector.py (live rules); fraud_rules.py (legacy)
    ├── api/                       # server.py (mounted); router.py + websocket.py (unmounted)
    ├── automation/                # ticket/notice/report generators, legacy dispatchers
    ├── config/                    # config.yaml, thresholds.yaml, settings.py
    ├── frontend/                  # index.html (single-file console)
    ├── ingestion/                 # synthetic generator, normalizer, buffer
    ├── models/                    # Pydantic v2 schemas
    ├── demo_data/                 # 17 read-only fixtures served on Vercel
    ├── cases/ verdicts/ tickets/ emails/ reports/   # local artifact output
    └── logs/                      # test_stream.{jsonl,csv}, audit_logger.py, audit.log
```

`uploads/screen.png` is an **outdated concept mockup** (it shows non-existent live metrics such as 1.28 M transactions and an active "Run pipeline" control) and does not reflect the shipped read-only console.

---

## 🧪 Tests

```bash
python -m pytest tests/test_api_security.py tests/test_d7a_demo_fixtures.py -v
python -m pytest tests/test_d6b_local_e2e.py -v          # spawns subprocesses; ~1 min
```

* `test_api_security.py` — default-deny for all three POST routes, 404 in production/Vercel, 401 vs 503 semantics, body limits, case-ID sanitisation, CORS, mock mode never instantiating Groq.
* `test_d7a_demo_fixtures.py` — Vercel simulation: exactly 4 cases, 4 tickets, 17 fixtures total.
* `test_d6b_local_e2e.py` — cross-process restart/rehydration, `#`-prefixed ID resolution, collision and path-traversal handling.

All tests run in mock LLM mode and require no network access; `pytest` must be installed separately.

---

## 📜 License

**No license file is currently present in this repository.** The MIT badge that previously appeared here pointed at a `LICENSE` file that does not exist, so no license can be inferred from it. Add an explicit `LICENSE` before redistributing or reusing this code.
