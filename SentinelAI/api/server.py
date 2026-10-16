"""
SentinelAI Core REST & SSE API Server Module (FastAPI).

Provides full HTTP CRUD access to suspicious cases, LLM verdicts, operational tickets,
customer emails, session reports, and real-time Server-Sent Events (SSE) pipeline execution.
"""

import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Type
from urllib.parse import unquote

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


# ---------------------------------------------------------------------------
# D6-B: storage configuration helpers
#
# LOCAL-ONLY MITIGATION — NOT PRODUCTION PERSISTENCE.
#
# `DataRepository` keeps every record in process memory. Historically that memory
# was never populated from disk, so a freshly-started process always answered
# `GET /api/cases -> []` even while valid JSON sat in the storage directory.
#
# `load_from_disk()` below re-reads that directory at start-up. It is enabled by
# default ONLY for non-serverless (non-Vercel) runs, because on Vercel the
# storage directory is `/tmp/SentinelAI`, which is per-instance and non-durable:
# silently rehydrating there would create a false impression of persistence
# across instances/recycles without actually providing it.
#
# Durable multi-instance persistence requires an external datastore (see the
# D6-B report); this change deliberately does not attempt to provide it.
# ---------------------------------------------------------------------------

def _truthy(value: Optional[str]) -> bool:
    """Interprets an environment variable as a boolean flag."""
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _resolve_base_dir() -> str:
    """
    Resolves the repository storage root.

    Precedence: SENTINELAI_DATA_DIR > Vercel ephemeral /tmp > relative 'SentinelAI'.
    SENTINELAI_DATA_DIR exists so local runs and tests can target an isolated
    directory instead of writing into the working tree.
    """
    override = os.getenv("SENTINELAI_DATA_DIR")
    if override:
        return override
    return "/tmp/SentinelAI" if os.getenv("VERCEL") == "1" else "SentinelAI"


# Attempts to draw a collision-free auto-generated case ID before giving up.
MAX_CASE_ID_ATTEMPTS = 8

# ---------------------------------------------------------------------------
# D6-B / SEC-1: validation of caller-supplied case IDs
#
# `DataRepository.save_case` builds a filesystem path straight from the case ID
# ('<cases_dir>/<case_id>.json'), so an unvalidated ID is an arbitrary file-write
# primitive. Concretely:
#   * 'a/../../x'   - path traversal; resolved by open();
#   * '/tmp/x'      - pathlib JOIN REPLACES the base directory entirely, so the
#                     record is written wherever the attacker points;
#   * 'C:\...'      - the same class of problem on Windows;
#   * control chars - log injection and unrepresentable filenames.
#
# New submissions are therefore checked against a strict allow-list below.
#
# Reads are deliberately NOT re-validated. Historical records must stay readable
# and resolvable through the RC-1 alias policy even when they predate these rules
# (for example a record literally named '%23GHOST'), so validation applies only
# at the POST /api/cases boundary - never in load_from_disk() or resolve_*().
# ---------------------------------------------------------------------------

# Optional single leading '#' for legacy IDs, then an alphanumeric start and a
# conservative run of URL- and filesystem-safe characters.
#   * no '.'  - rules out '.', '..' and extension tricks outright;
#   * no '/' or '\' - no path separators, traversal or absolute paths;
#   * no '%'  - percent-decoding ambiguity (see the RC-1 resolution policy);
#   * no whitespace and no control characters.
SAFE_NEW_CASE_ID = re.compile(r"^#?[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

# Checked explicitly (before the regex) so the rejection message names the cause.
_FORBIDDEN_CASE_ID_MARKERS = ("..", "/", "\\", "%", "\x00")


def validate_new_case_id(case_id: Any) -> str:
    """
    Validates a caller-supplied case ID for POST /api/cases.

    Returns the ID unchanged when it is safe to use as a single filename
    component and as a URL path segment, otherwise raises ValueError carrying a
    human-readable reason (surfaced by the endpoint as HTTP 422).
    """
    if not isinstance(case_id, str):
        raise ValueError("case_id must be a string.")
    if case_id.strip() != case_id:
        raise ValueError("case_id must not contain leading or trailing whitespace.")
    if not case_id:
        raise ValueError("case_id must not be empty.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in case_id):
        raise ValueError("case_id must not contain control characters.")
    for marker in _FORBIDDEN_CASE_ID_MARKERS:
        if marker in case_id:
            raise ValueError(f"case_id must not contain {marker!r}.")
    if not SAFE_NEW_CASE_ID.match(case_id):
        raise ValueError(
            "case_id must match ^#?[A-Za-z0-9][A-Za-z0-9_-]{0,127}$ "
            "(letters, digits, '_' and '-'; an optional leading '#' for legacy IDs)."
        )
    return case_id


def _rehydration_enabled() -> bool:
    """
    Rehydration is ON by default for local/container runs and OFF by default in
    serverless (Vercel) runs. Set SENTINELAI_REHYDRATE=1/0 to force either way.
    """
    flag = os.getenv("SENTINELAI_REHYDRATE")
    if flag is not None:
        return _truthy(flag)
    return os.getenv("VERCEL") != "1"


# Thread-safe in-memory storage repository backed by local disk directories
class DataRepository:
    def __init__(self, base_dir: Optional[str] = None, rehydrate: Optional[bool] = None):
        if base_dir is None:
            base_dir = _resolve_base_dir()
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

        # D6-B: rehydration telemetry (see LOCAL-ONLY MITIGATION note above)
        self.rehydrate_enabled: bool = _rehydration_enabled() if rehydrate is None else bool(rehydrate)
        self.rehydrated: bool = False
        self.rehydrated_counts: Dict[str, int] = {}
        if self.rehydrate_enabled:
            self.load_from_disk()

    # ------------------------------------------------------------------
    # D6-B: local filesystem rehydration (LOCAL-ONLY MITIGATION)
    # ------------------------------------------------------------------

    def _load_directory(
        self,
        directory: Path,
        model_cls: Type[BaseModel],
        key_attr: str,
        mapping: Dict[str, Any],
    ) -> int:
        """
        Validates and loads every `*.json` file in `directory` into `mapping`.

        Unreadable or schema-invalid files are logged and skipped so that one
        corrupt artifact can never take the whole API down at start-up.
        Records already present in memory are never overwritten.
        """
        loaded = 0
        if not directory.exists():
            return 0
        for path in sorted(directory.glob("*.json")):
            try:
                item = model_cls.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001 - defensive: never fail start-up
                logger.warning(
                    f"[D6-B rehydrate] Skipping unreadable record '{path.name}': "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            key = getattr(item, key_attr)
            if key in mapping:
                continue
            mapping[key] = item
            loaded += 1
        return loaded

    def load_from_disk(self) -> Dict[str, int]:
        """
        Re-populates the in-memory indexes from the storage directory.

        LOCAL-ONLY MITIGATION: this makes a single long-lived process (local
        `uvicorn`, Docker) survive a restart. It does NOT make state durable
        across serverless instances and must not be presented as such.
        """
        counts = {
            "cases": self._load_directory(self.cases_dir, FraudCase, "case_id", self.cases),
            "verdicts": self._load_directory(self.verdicts_dir, LLMVerdict, "case_id", self.verdicts),
            "tickets": self._load_directory(self.tickets_dir, ComplianceTicket, "ticket_id", self.tickets),
            "emails": self._load_directory(self.emails_dir, ClientEmail, "case_id", self.emails),
            "reports": self._load_directory(self.reports_dir, SessionReport, "report_id", self.reports),
        }
        self.rehydrated = True
        self.rehydrated_counts = counts
        total = sum(counts.values())
        if total:
            logger.info(
                f"[D6-B rehydrate] Loaded {total} record(s) from '{self.base_dir}' "
                f"(cases={counts['cases']}, verdicts={counts['verdicts']}, "
                f"tickets={counts['tickets']}, emails={counts['emails']}, "
                f"reports={counts['reports']}). LOCAL-ONLY MITIGATION - not durable storage."
            )
        return counts

    # ------------------------------------------------------------------
    # D6-B / RC-1: case-ID resolution
    #
    # Background. Legacy manual case IDs are '#' prefixed (e.g. '#308B-X'). '#'
    # is the URL fragment delimiter, so '/api/cases/#308B-X' never reaches the
    # server: the fragment is dropped client-side and FastAPI's redirect_slashes
    # turns the remainder into 'GET /api/cases/' (200 + the whole list). That is
    # unfixable server-side, hence URL-safe IDs for new records (see create_case)
    # plus the resolver below so legacy IDs stay reachable.
    #
    # RESOLUTION POLICY (two tiers, deliberately conservative):
    #
    #   Tier 1 - ENCODING NORMALIZATION, exact match.
    #     The raw path segment and its progressively percent-DECODED forms are
    #     the SAME identifier ('#ABC' and '%23ABC' differ only in transport
    #     encoding). The first spelling that exists verbatim as a key wins, so
    #     an exact ID ALWAYS takes precedence over any alias.
    #     The percent-ENCODED form is deliberately NOT a candidate: encoding
    #     server-side would let a request for '#ABC' match a record literally
    #     named '%23ABC', i.e. silently return an unrelated record. Decode on
    #     the way in; never re-encode.
    #
    #   Tier 2 - '#' ALIAS, unambiguous only.
    #     Only reached when Tier 1 missed. The leading '#' is toggled so that
    #     clients which strip or add it still find legacy records. It resolves
    #     ONLY when it yields exactly one candidate. If several alias candidates
    #     exist the request is ambiguous and is REFUSED (None -> HTTP 404) with
    #     a warning, never silently resolved to an arbitrary record.
    #
    #   Backward compatibility: a legacy '#' ID resolves from every spelling
    #   ('#ABC', 'ABC', '%23ABC') for as long as that is unambiguous. If both
    #   'ABC' and '#ABC' exist, each is reachable by its own exact spelling and
    #   no lookup ever crosses between them.
    # ------------------------------------------------------------------

    MAX_DECODE_PASSES = 3

    @classmethod
    def _normalizations(cls, identifier: str) -> List[str]:
        """Ordered, de-duplicated percent-decodings of `identifier` (Tier 1)."""
        ordered: List[str] = []
        seen = set()
        current = (identifier or "").strip()
        for _ in range(cls.MAX_DECODE_PASSES):
            if current and current not in seen:
                seen.add(current)
                ordered.append(current)
            decoded = unquote(current)
            if decoded == current:
                break
            current = decoded
        return ordered

    @classmethod
    def _alias_candidates(cls, identifier: str) -> List[str]:
        """'#'-toggled aliases of every normalization of `identifier` (Tier 2)."""
        ordered: List[str] = []
        seen = set()
        for base in cls._normalizations(identifier):
            toggled = base[1:] if base.startswith("#") else f"#{base}"
            if toggled and toggled not in seen:
                seen.add(toggled)
                ordered.append(toggled)
        return ordered

    def _resolve(self, mapping: Dict[str, Any], identifier: str) -> Optional[str]:
        # Tier 1: exact match over transport-encoding variants. Exact wins.
        for candidate in self._normalizations(identifier):
            if candidate in mapping:
                return candidate

        # Tier 2: legacy '#' alias - only when unambiguous, never a guess.
        matches = [a for a in self._alias_candidates(identifier) if a in mapping]
        if len(matches) == 1:
            logger.info(
                f"[D6-B resolve] '{identifier}' matched no exact key; "
                f"resolved via '#' alias to '{matches[0]}'."
            )
            return matches[0]
        if len(matches) > 1:
            logger.warning(
                f"[D6-B resolve] Ambiguous '#' alias for '{identifier}': "
                f"candidates {matches}. Refusing to guess; returning 404."
            )
        return None

    def resolve_case_id(self, case_id: str) -> Optional[str]:
        return self._resolve(self.cases, case_id)

    def resolve_verdict_id(self, case_id: str) -> Optional[str]:
        return self._resolve(self.verdicts, case_id)

    def resolve_ticket_id(self, ticket_id: str) -> Optional[str]:
        return self._resolve(self.tickets, ticket_id)

    def resolve_email_id(self, case_id: str) -> Optional[str]:
        return self._resolve(self.emails, case_id)

    @staticmethod
    def _contained_path(directory: Path, filename: str) -> Path:
        """
        SEC-1: resolves `directory / filename` and refuses to return a path that
        escapes `directory`.

        This guards the write sink itself, so an unsafe identifier reaching
        save_* from any present or future caller cannot become an arbitrary
        file write - independently of the submission-boundary validation.
        """
        root = directory.resolve()
        target = (directory / filename).resolve()
        if target.parent != root:
            raise ValueError(
                f"Refusing to write outside '{root}': '{filename}' resolves to '{target}'."
            )
        return target

    # NOTE (SEC-1): every save_* method resolves its target path FIRST and only
    # then mutates the in-memory index, so a rejected identifier can neither
    # create a file nor alter an existing record.

    def save_case(self, item: FraudCase) -> None:
        path = self._contained_path(self.cases_dir, f"{item.case_id}.json")
        self.cases[item.case_id] = item
        with open(path, "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_verdict(self, item: LLMVerdict) -> None:
        path = self._contained_path(self.verdicts_dir, f"{item.case_id}.json")
        self.verdicts[item.case_id] = item
        with open(path, "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_ticket(self, item: ComplianceTicket) -> None:
        path = self._contained_path(self.tickets_dir, f"{item.ticket_id}.json")
        self.tickets[item.ticket_id] = item
        with open(path, "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_email(self, item: ClientEmail) -> None:
        path = self._contained_path(self.emails_dir, f"{item.case_id}.json")
        self.emails[item.case_id] = item
        with open(path, "w", encoding="utf-8") as f:
            f.write(item.model_dump_json(indent=2))
        self.last_updated = datetime.now(timezone.utc)

    def save_report(self, item: SessionReport) -> None:
        path = self._contained_path(self.reports_dir, f"{item.date}.json")
        self.reports[item.report_id] = item
        with open(path, "w", encoding="utf-8") as f:
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
    # D6-B: the generators otherwise resolve their own storage path from os.getenv
    # ("VERCEL"), which silently diverges from DataRepository.base_dir whenever
    # SENTINELAI_DATA_DIR is set - rehydration would then never find the tickets,
    # emails or reports this run produced. Route them through the repository root.
    ticket_gen = TicketGenerator(base_dir=str(repo.tickets_dir))
    email_gen = EmailGenerator(base_dir=str(repo.emails_dir))
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

    # 5. Generate Session Report (same storage-root routing as step 4)
    report_gen = ReportGenerator(base_dir=str(repo.reports_dir))
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
    """
    Opens a manual investigation case.

    Case-ID policy (D6-B / RC-1 + RC-2):

    * '#' is the URL fragment delimiter, so '/api/cases/#XXXX-X' never reaches
      the server. Auto-generated IDs are therefore URL-safe (see also
      `DataRepository._resolve` for how legacy '#' IDs stay reachable).
    * Auto-generated IDs embed a **full uuid4** (122 random bits). The previous
      24-bit fragment reached a 50% collision probability at ~4.8k cases, and a
      collision silently overwrote the existing record. Full-width UUIDs make
      that infeasible at any realistic volume.
    * Defence in depth: a drawn ID that already exists is **re-drawn** rather
      than overwriting; exhausting the attempts returns 503, never a silent
      replace.
    * A caller-supplied ID that already exists is rejected with **409 Conflict**
      instead of replacing the record.
    * Both checks are alias-aware (`resolve_case_id`), so the API refuses to
      create 'ABC' when '#ABC' exists - that pair would make every later lookup
      ambiguous.
    * SEC-1: a caller-supplied ID is validated against `validate_new_case_id`
      before use. It becomes a filesystem path, so traversal, absolute paths,
      separators, control characters and percent-encoding are rejected with
      **422 Unprocessable Content**. Legacy '#' IDs such as '#D6B-LEGACY'
      remain valid. Reads are never re-validated, so historical records stay
      readable.
    """
    requested_id = payload.get("case_id")

    if requested_id is not None:
        try:
            case_id = validate_new_case_id(requested_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid case_id: {exc}",
            )
        if repo.resolve_case_id(case_id) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Case ID '{case_id}' already exists. Supply a different case_id.",
            )
    else:
        for _ in range(MAX_CASE_ID_ATTEMPTS):
            candidate = f"CASE_MANUAL_{uuid.uuid4().hex.upper()}"
            if repo.resolve_case_id(candidate) is None:
                case_id = candidate
                break
        else:
            logger.error(
                f"[D6-B] Exhausted {MAX_CASE_ID_ATTEMPTS} attempts allocating a unique case ID."
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not allocate a unique case ID. Retry the request.",
            )
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
    # D6-B: resolve '#'-prefixed / percent-encoded legacy IDs (see DataRepository.resolve_case_id)
    resolved = repo.resolve_case_id(case_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
    return repo.cases[resolved]


@app.get("/api/verdicts", response_model=List[LLMVerdict], summary="List all LLM compliance verdicts")
async def get_verdicts():
    return list(repo.verdicts.values())


@app.get("/api/verdicts/{case_id}", response_model=LLMVerdict, summary="Get LLM verdict for a specific case")
async def get_verdict(case_id: str):
    resolved = repo.resolve_verdict_id(case_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail=f"Verdict for Case ID '{case_id}' not found.")
    return repo.verdicts[resolved]


@app.get("/api/tickets", response_model=List[ComplianceTicket], summary="List all operational compliance tickets")
async def get_tickets():
    return list(repo.tickets.values())


@app.get("/api/tickets/{ticket_id}", response_model=ComplianceTicket, summary="Get details of a specific ticket")
async def get_ticket(ticket_id: str):
    resolved = repo.resolve_ticket_id(ticket_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail=f"Ticket ID '{ticket_id}' not found.")
    return repo.tickets[resolved]


@app.get("/api/emails", response_model=List[ClientEmail], summary="List all dispatched client notifications")
async def get_emails():
    return list(repo.emails.values())


@app.get("/api/emails/{case_id}", response_model=ClientEmail, summary="Get client email for a specific case")
async def get_email(case_id: str):
    resolved = repo.resolve_email_id(case_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail=f"Client email for Case ID '{case_id}' not found.")
    return repo.emails[resolved]


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
