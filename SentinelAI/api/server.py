"""
SentinelAI Core REST & SSE API Server Module (FastAPI).

Provides full HTTP CRUD access to suspicious cases, LLM verdicts, operational tickets,
customer emails, session reports, and real-time Server-Sent Events (SSE) pipeline execution.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

import pandas as pd
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from pydantic import BaseModel, Field

from SentinelAI.ai.llm_inspector import LLMInspector
from SentinelAI.ai.report_generator import ReportGenerator
from SentinelAI.analytics.fraud_detector import FraudDetector
from SentinelAI.automation.email_generator import EmailGenerator
from SentinelAI.automation.ticket_generator import TicketGenerator
from SentinelAI.ingestion.data_generator import FintechDataGenerator
from SentinelAI.models.schemas import (
    ClientEmail,
    ComplianceTicket,
    FraudCase,
    InvestigationReport,
    LLMVerdict,
    SessionReport,
)

# Configure structured request logger
logger = logging.getLogger("SentinelAI.APIServer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [APIServer] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# Request Models
class PipelineRunRequest(BaseModel):
    input_file: str = Field(
        default="SentinelAI/logs/test_stream.jsonl",
        description="Path to input CSV or JSONL transaction log file",
    )


class PipelineRunResponse(BaseModel):
    session_id: str
    status: str
    message: str


# Thread-safe in-memory storage repository backed by local disk directories
class DataRepository:
    def __init__(self, base_dir: Optional[str] = None):
        import os
        if base_dir is None:
            base_dir = "/tmp/SentinelAI" if os.getenv("VERCEL") == "1" else "SentinelAI"
        self.base_dir = Path(base_dir)
        self.cases_dir = self.base_dir / "cases"
        self.verdicts_dir = self.base_dir / "verdicts"
        self.tickets_dir = self.base_dir / "tickets"
        self.emails_dir = self.base_dir / "emails"
        self.reports_dir = self.base_dir / "reports"

        for p in [self.cases_dir, self.verdicts_dir, self.tickets_dir, self.emails_dir, self.reports_dir]:
            p.mkdir(parents=True, exist_ok=True)

        self.cases: Dict[str, FraudCase] = {}
        self.verdicts: Dict[str, LLMVerdict] = {}
        self.tickets: Dict[str, ComplianceTicket] = {}
        self.emails: Dict[str, ClientEmail] = {}
        self.reports: Dict[str, SessionReport] = {}
        self.last_updated: datetime = datetime.now(timezone.utc)

    def save_case(self, item: FraudCase) -> None:
        self.cases[item.case_id] = item
        with open(self.cases_dir / f"{item.case_id}.json", "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_verdict(self, item: LLMVerdict) -> None:
        self.verdicts[item.case_id] = item
        with open(self.verdicts_dir / f"{item.case_id}.json", "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_ticket(self, item: ComplianceTicket) -> None:
        self.tickets[item.ticket_id] = item
        with open(self.tickets_dir / f"{item.ticket_id}.json", "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_email(self, item: ClientEmail) -> None:
        self.emails[item.case_id] = item
        with open(self.emails_dir / f"{item.case_id}.json", "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_report(self, item: SessionReport) -> None:
        self.reports[item.report_id] = item
        with open(self.reports_dir / f"{item.date}.json", "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)


repo = DataRepository()

# Initialize FastAPI Application
app = FastAPI(
    title="SentinelAI Compliance Command API",
    version="2.0.0",
    description="End-to-End AML & Fraud Automation Engine powered by Pandas and Groq LPU.",
)

# Enable CORS for frontend UI interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Frontend Dashboard UI
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


@app.get("/", summary="SentinelAI Gotham Dashboard UI")
async def serve_dashboard():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard index.html not found.")
    return FileResponse(str(index_file))



# HTTP Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start_time) * 1000.0
    logger.info(
        f"{request.method} {request.url.path} | Status: {response.status_code} | Latency: {duration_ms:.2f}ms"
    )
    return response


# Structured Global Error Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled system exception at {request.url.path}: {type(exc).__name__} - {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal Server Error", "detail": str(exc)},
    )


# Pipeline Worker Execution Method
def execute_pipeline_task(session_id: str, input_file: str) -> None:
    logger.info(f"[Session {session_id}] Starting End-to-End Compliance Pipeline execution on '{input_file}'...")
    file_path = Path(input_file)

    # 1. Load or synthesize input dataframe
    if not file_path.exists():
        logger.warning(f"[Session {session_id}] File '{input_file}' not found. Auto-generating synthetic stream...")
        gen = FintechDataGenerator(num_accounts=50, num_transactions=400, fraud_rate=0.08, seed=42)
        records = gen.generate_stream()
        df = pd.DataFrame([r.to_dict() for r in records])
    elif file_path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path)
    else:
        df = pd.read_json(file_path, lines=True)

    # 2. Run Pandas Fraud Detection
    detector = FraudDetector(log_detailed=False)
    cases = detector.detect_all(df)
    for c in cases:
        repo.save_case(c)

    # 3. Run Groq LLM Inspection
    inspector = LLMInspector()
    verdicts = inspector.batch_inspect(cases, max_workers=2)
    for v in verdicts:
        repo.save_verdict(v)

    # 4. Generate Tickets & Emails
    ticket_gen = TicketGenerator()
    email_gen = EmailGenerator()
    tickets_created = []
    emails_created = []

    for v in verdicts:
        case = repo.cases.get(v.case_id)
        if case:
            t = ticket_gen.generate(v, case)
            repo.save_ticket(t)
            tickets_created.append(t)

            e = email_gen.generate(v, {"client_name": f"Client_{v.case_id[:6]}", "account_id": case.related_accounts[0] if case.related_accounts else "ACC_00"})
            if e:
                repo.save_email(e)
                emails_created.append(e)

    # 5. Generate Session Report
    report_gen = ReportGenerator()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report = report_gen.generate_daily_report(
        date=today_str,
        verdicts=verdicts,
        tickets=tickets_created,
        emails=emails_created,
        total_transactions=len(df),
    )
    repo.save_report(report)
    logger.info(f"[Session {session_id}] Pipeline completed successfully. Processed {len(cases)} cases.")


# =====================================================================
# ENDPOINTS
# =====================================================================


@app.get("/api/health", summary="Check system operational status")
async def health_check():
    return {
        "status": "ONLINE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "engines": {
            "pandas_detector": "READY",
            "groq_llm_inspector": "READY",
            "automation_dispatchers": "READY",
        },
    }


@app.post("/api/pipeline/run", response_model=PipelineRunResponse, status_code=202, summary="Trigger automated compliance pipeline")
async def run_pipeline(payload: PipelineRunRequest, background_tasks: BackgroundTasks):
    session_id = f"SESS_{uuid.uuid4().hex[:8].upper()}"
    background_tasks.add_task(execute_pipeline_task, session_id, payload.input_file)
    return PipelineRunResponse(
        session_id=session_id,
        status="QUEUED",
        message=f"Pipeline job initiated in background for input file '{payload.input_file}'.",
    )


@app.post("/api/pipeline/stream", summary="Live Server-Sent Events (SSE) pipeline execution stream")
async def stream_pipeline(payload: PipelineRunRequest):
    """
    Executes the compliance pipeline and streams real-time step progress to the UI via SSE.
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        session_id = f"SESS_{uuid.uuid4().hex[:8].upper()}"
        yield f"event: init\ndata: {json.dumps({'session_id': session_id, 'step': 'INITIALIZING', 'progress': 5})}\n\n"
        await asyncio.sleep(0.3)

        # Step 1: Ingestion
        yield f"event: progress\ndata: {json.dumps({'session_id': session_id, 'step': 'INGESTING_TRANSACTIONS', 'progress': 20})}\n\n"
        await asyncio.sleep(0.4)
        gen = FintechDataGenerator(num_accounts=30, num_transactions=200, fraud_rate=0.08, seed=42)
        records = gen.generate_stream()
        df = pd.DataFrame([r.to_dict() for r in records])

        # Step 2: Pandas Statistical Filter
        yield f"event: progress\ndata: {json.dumps({'session_id': session_id, 'step': 'PANDAS_STATISTICAL_DETECTION', 'progress': 45})}\n\n"
        await asyncio.sleep(0.4)
        detector = FraudDetector(log_detailed=False)
        cases = detector.detect_all(df)
        for c in cases:
            repo.save_case(c)

        # Step 3: Groq LLM Adjudication
        yield f"event: progress\ndata: {json.dumps({'session_id': session_id, 'step': 'GROQ_LLM_ADJUDICATION', 'progress': 75, 'flagged_cases': len(cases)})}\n\n"
        await asyncio.sleep(0.5)
        inspector = LLMInspector()
        verdicts = inspector.batch_inspect(cases[:4], max_workers=2)
        for v in verdicts:
            repo.save_verdict(v)

        # Step 4: Automation (Tickets & Emails)
        yield f"event: progress\ndata: {json.dumps({'session_id': session_id, 'step': 'GENERATING_TICKETS_AND_EMAILS', 'progress': 90})}\n\n"
        await asyncio.sleep(0.3)

        # Step 5: Complete
        yield f"event: complete\ndata: {json.dumps({'session_id': session_id, 'step': 'COMPLETED', 'progress': 100, 'total_cases': len(cases), 'verdicts_rendered': len(verdicts)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/cases", response_model=FraudCase, status_code=201, summary="Create a manual investigation case")
async def create_case(payload: Dict[str, Any]):
    case_id = payload.get("case_id") or f"#{uuid.uuid4().hex[:4].upper()}-X"
    if not case_id.startswith("#"):
        case_id = f"#{case_id}"
    new_case = FraudCase(
        case_id=case_id,
        rule_triggered=str(payload.get("rule_triggered", "Manual-Escalation")),
        risk_score=float(payload.get("risk_score", 85.0)),
        related_accounts=payload.get("related_accounts", ["ACC_MANUAL"]),
        related_transactions=payload.get("related_transactions", []),
        timestamps=[datetime.now(timezone.utc)],
        evidence_summary=str(payload.get("description", "Manual investigation opened by compliance analyst.")),
    )
    repo.save_case(new_case)
    return new_case


@app.get("/api/cases", response_model=List[FraudCase], summary="List all flagged fraud cases")
async def get_cases():
    return list(repo.cases.values())


@app.get("/api/cases/{case_id}", response_model=FraudCase, summary="Get details of a specific fraud case")
async def get_case(case_id: str):
    if case_id not in repo.cases:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
    return repo.cases[case_id]


@app.get("/api/verdicts", response_model=List[LLMVerdict], summary="List all LLM compliance verdicts")
async def get_verdicts():
    return list(repo.verdicts.values())


@app.get("/api/verdicts/{case_id}", response_model=LLMVerdict, summary="Get LLM verdict for a specific case")
async def get_verdict(case_id: str):
    if case_id not in repo.verdicts:
        raise HTTPException(status_code=404, detail=f"Verdict for Case ID '{case_id}' not found.")
    return repo.verdicts[case_id]


@app.get("/api/tickets", response_model=List[ComplianceTicket], summary="List all operational compliance tickets")
async def get_tickets():
    return list(repo.tickets.values())


@app.get("/api/tickets/{ticket_id}", response_model=ComplianceTicket, summary="Get details of a specific ticket")
async def get_ticket(ticket_id: str):
    if ticket_id not in repo.tickets:
        raise HTTPException(status_code=404, detail=f"Ticket ID '{ticket_id}' not found.")
    return repo.tickets[ticket_id]


@app.get("/api/emails", response_model=List[ClientEmail], summary="List all dispatched client notifications")
async def get_emails():
    return list(repo.emails.values())


@app.get("/api/emails/{case_id}", response_model=ClientEmail, summary="Get client email for a specific case")
async def get_email(case_id: str):
    if case_id not in repo.emails:
        raise HTTPException(status_code=404, detail=f"Client email for Case ID '{case_id}' not found.")
    return repo.emails[case_id]


@app.get("/api/reports", response_model=List[SessionReport], summary="List all executive session reports")
async def get_reports():
    return list(repo.reports.values())


@app.get("/api/reports/latest", response_model=SessionReport, summary="Get the latest executive session report")
async def get_latest_report():
    if not repo.reports:
        raise HTTPException(status_code=404, detail="No session reports generated yet.")
    sorted_reports = sorted(repo.reports.values(), key=lambda r: r.generated_at, reverse=True)
    return sorted_reports[0]


@app.get("/api/stats", summary="Get macro system statistics and cost breakdown")
async def get_stats():
    total_cases = len(repo.cases)
    verdict_list = list(repo.verdicts.values())

    risk_dist: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    actions_breakdown: Dict[str, int] = {"MONITOR": 0, "REQUEST_KYC": 0, "FREEZE": 0, "ESCALATE": 0}
    total_tokens = 0

    for v in verdict_list:
        risk_dist[v.risk_level] = risk_dist.get(v.risk_level, 0) + 1
        actions_breakdown[v.action] = actions_breakdown.get(v.action, 0) + 1
        total_tokens += v.tokens_used

    # Calculate approximate cost based on Llama-3.3-70B pricing (~$0.69 / 1M tokens)
    cost_usd = round((total_tokens / 1_000_000.0) * 0.69, 6)

    return {
        "total_cases": total_cases,
        "risk_distribution": risk_dist,
        "actions_breakdown": actions_breakdown,
        "tokens_used": total_tokens,
        "cost_usd": cost_usd,
        "last_updated": repo.last_updated.isoformat(),
    }
