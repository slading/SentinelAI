"""
SentinelAI End-to-End Compliance Pipeline Launcher & CLI.

Orchestrates the complete data flow from ingestion through statistical detection,
generative LLM inspection, automated ticketing, customer notification, and executive
reporting. Supports CLI batch execution, dry runs, and launching the REST/SSE API server.
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

# Ensure workspace path resolution
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR.parent) not in sys.path:
    sys.path.insert(0, str(BASE_DIR.parent))

from SentinelAI.ai.llm_inspector import LLMInspector
from SentinelAI.ai.report_generator import ReportGenerator
from SentinelAI.analytics.fraud_detector import FraudDetector
from SentinelAI.automation.email_generator import EmailGenerator
from SentinelAI.automation.ticket_generator import TicketGenerator
from SentinelAI.ingestion.data_generator import FintechDataGenerator
from SentinelAI.models.schemas import ClientEmail, ComplianceTicket, FraudCase, LLMVerdict

# Configure structured CLI logger
logger = logging.getLogger("SentinelAI.Main")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [SentinelAI] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def render_summary_box(
    tx_count: int,
    cases_count: int,
    risk_dist: Dict[str, int],
    actions_dist: Dict[str, int],
    tickets_count: int,
    emails_count: int,
    tokens_used: int,
    cost_usd: float,
) -> None:
    """Renders the executive report summary in a formatted ASCII box."""
    tx_str = f"{tx_count:,}"
    cases_str = f"{cases_count:,}"
    crit_str = f"{risk_dist.get('CRITICAL', 0):,}"
    high_str = f"{risk_dist.get('HIGH', 0):,}"
    med_str = f"{risk_dist.get('MEDIUM', 0):,}"
    low_str = f"{risk_dist.get('LOW', 0):,}"

    freeze_str = f"{actions_dist.get('FREEZE', 0):,}"
    escalate_str = f"{actions_dist.get('ESCALATE', 0):,}"
    kyc_str = f"{actions_dist.get('REQUEST_KYC', 0):,}"
    mon_str = f"{actions_dist.get('MONITOR', 0):,}"

    tkt_str = f"{tickets_count:,}"
    eml_str = f"{emails_count:,}"
    tok_str = f"{tokens_used:,}"
    cost_str = f"~${cost_usd:,.2f}" if cost_usd >= 0.01 else f"~${cost_usd:,.4f}"

    print("\n" + "╔" + "═" * 38 + "╗")
    print("║" + "SENTINELAI REPORT".center(38) + "║")
    print("╠" + "═" * 38 + "╣")
    print(f"║ {'Transactions:':<18} {tx_str:<19}║")
    print(f"║ {'Fraud Cases:':<18} {cases_str:<19}║")
    print("╠" + "═" * 38 + "╣")
    print(f"║ {'CRITICAL:':<18} {crit_str:<19}║")
    print(f"║ {'HIGH:':<18} {high_str:<19}║")
    print(f"║ {'MEDIUM:':<18} {med_str:<19}║")
    print(f"║ {'LOW:':<18} {low_str:<19}║")
    print("╠" + "═" * 38 + "╣")
    print(f"║ {'FREEZE:':<18} {freeze_str:<19}║")
    print(f"║ {'ESCALATE:':<18} {escalate_str:<19}║")
    print(f"║ {'REQUEST_KYC:':<18} {kyc_str:<19}║")
    print(f"║ {'MONITOR:':<18} {mon_str:<19}║")
    print("╠" + "═" * 38 + "╣")
    print(f"║ {'Tickets:':<18} {tkt_str:<19}║")
    print(f"║ {'Emails:':<18} {eml_str:<19}║")
    print(f"║ {'Tokens used:':<18} {tok_str:<19}║")
    print(f"║ {'Cost:':<18} {cost_str:<19}║")
    print("╚" + "═" * 38 + "╝\n")


def run_pipeline(
    input_path: str,
    mode: str,
    risk_threshold: float,
    dry_run: bool,
    language: str,
    export_report: bool,
) -> None:
    """Executes the complete SentinelAI compliance pipeline."""
    logger.info(f"=== Initializing SentinelAI Pipeline | Mode: {mode.upper()} | Dry-Run: {dry_run} ===")

    # Step 1: Load or generate data
    file_path = Path(input_path)
    if not file_path.exists():
        logger.warning(f"Input file '{input_path}' not found. Generating realistic synthetic stream...")
        generator = FintechDataGenerator(num_accounts=100, num_transactions=1000, fraud_rate=0.08, seed=42)
        records = generator.generate_stream()
        df = pd.DataFrame([r.to_dict() for r in records])
    elif file_path.suffix.lower() == ".csv":
        logger.info(f"Loading transaction stream from CSV '{input_path}'...")
        df = pd.read_csv(file_path)
    else:
        logger.info(f"Loading transaction stream from JSONL '{input_path}'...")
        df = pd.read_json(file_path, lines=True)

    tx_count = len(df)
    logger.info(f"Ingested {tx_count:,} transaction records successfully.")

    # Step 2: Run Statistical Fraud Detection
    detector = FraudDetector(log_detailed=False)
    all_cases = detector.detect_all(df)

    # Filter cases by risk threshold
    filtered_cases = [c for c in all_cases if c.risk_score >= risk_threshold]
    logger.info(f"Statistical detector identified {len(all_cases)} total cases ({len(filtered_cases)} meet risk threshold >= {risk_threshold}).")

    # Step 3: Run LLM Inspector Adjudication
    inspector = LLMInspector()
    verdicts: List[LLMVerdict] = []
    if filtered_cases:
        verdicts = inspector.batch_inspect(filtered_cases, max_workers=3)

    # Step 4: Automation — Tickets & Emails
    ticket_gen = TicketGenerator()
    email_gen = EmailGenerator()
    tickets_created: List[ComplianceTicket] = []
    emails_created: List[ClientEmail] = []

    case_map = {c.case_id: c for c in filtered_cases}

    for verdict in verdicts:
        case = case_map.get(verdict.case_id)
        if not case:
            continue

        # Create ticket
        if not dry_run:
            tkt = ticket_gen.generate(verdict, case)
            tickets_created.append(tkt)
        else:
            tkt = ComplianceTicket(
                ticket_id=f"DRY_TKT_{verdict.case_id[:6]}",
                case_id=verdict.case_id,
                title=f"[{verdict.risk_level}] Dry-Run Alert",
                priority=verdict.risk_level,
                description=verdict.reasoning,
                evidence_summary=case.evidence_summary,
                action_required=verdict.action,
                sla_hours=24,
                assignee="dry-run-queue",
            )
            tickets_created.append(tkt)

        # Create email
        client_info = {
            "client_name": f"Account_Holder_{case.related_accounts[0] if case.related_accounts else 'UNKNOWN'}",
            "account_id": case.related_accounts[0] if case.related_accounts else "ACC_UNKNOWN",
        }

        if not dry_run:
            eml = email_gen.generate(verdict, client_info, language=language)
            if eml:
                emails_created.append(eml)
        elif verdict.action != "MONITOR":
            eml = ClientEmail(
                email_id=f"DRY_EML_{verdict.case_id[:6]}",
                case_id=verdict.case_id,
                client_name=client_info["client_name"],
                account_id=client_info["account_id"],
                subject=f"Notice regarding {client_info['account_id']}",
                body="Dry run simulated body.",
                language=language,
            )
            emails_created.append(eml)

    # Step 5: Report Generation
    report_gen = ReportGenerator()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if not dry_run or export_report:
        report = report_gen.generate_daily_report(
            date=today_str,
            verdicts=verdicts,
            tickets=tickets_created,
            emails=emails_created,
            total_transactions=tx_count,
        )
        tokens_consumed = report.tokens_used
        cost_usd = report.estimated_cost_usd
    else:
        tokens_consumed = sum(v.tokens_used for v in verdicts)
        cost_usd = report_gen.get_cost_estimate(tokens_consumed)

    # Aggregate distribution statistics for report
    risk_dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    actions_dist: Dict[str, int] = {"FREEZE": 0, "ESCALATE": 0, "REQUEST_KYC": 0, "MONITOR": 0}

    for v in verdicts:
        if v.risk_level in risk_dist:
            risk_dist[v.risk_level] += 1
        if v.action in actions_dist:
            actions_dist[v.action] += 1

    # Step 6: Render ASCII Summary Box
    render_summary_box(
        tx_count=tx_count,
        cases_count=len(filtered_cases),
        risk_dist=risk_dist,
        actions_dist=actions_dist,
        tickets_count=len(tickets_created),
        emails_count=len(emails_created),
        tokens_used=tokens_consumed,
        cost_usd=cost_usd,
    )


def main() -> None:
    """Entrypoint CLI parser and execution handler."""
    parser = argparse.ArgumentParser(description="SentinelAI Compliance Command & Pipeline Engine")
    parser.add_argument(
        "--input",
        type=str,
        default="SentinelAI/logs/transactions.jsonl",
        help="Path to input transaction log file (.csv or .jsonl)",
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="batch",
        choices=["batch", "stream"],
        help="Execution mode: batch processing or stream",
    )
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=50.0,
        help="Minimum Pandas risk score required to escalate to LLM inspection",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute pipeline evaluation without writing files to local disk",
    )
    parser.add_argument(
        "--language",
        type=str,
        default="EN",
        choices=["EN", "RU", "PL", "DE"],
        help="Language code for customer notifications",
    )
    parser.add_argument(
        "--export-report",
        action="store_true",
        help="Force generation and save of daily executive report even on dry run",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch the FastAPI REST & SSE server via uvicorn",
    )

    args = parser.parse_args()

    if args.serve:
        import uvicorn
        logger.info("Starting SentinelAI FastAPI server on http://0.0.0.0:8000...")
        uvicorn.run("SentinelAI.api.server:app", host="0.0.0.0", port=8000, reload=True)
    else:
        run_pipeline(
            input_path=args.input,
            mode=args.mode,
            risk_threshold=args.risk_threshold,
            dry_run=args.dry_run,
            language=args.language,
            export_report=args.export_report,
        )


if __name__ == "__main__":
    main()
