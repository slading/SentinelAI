"""
SentinelAI Executive & Daily Reporting Module.

Synthesizes batch adjudication verdicts, workflow tickets, and customer notifications
into macro-level executive reports for leadership and regulatory oversight.
Calculates token compute economics and persists multi-format report deliverables.
"""

import json
import logging
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from SentinelAI.ai.groq_client import GroqClient, PRICING_PER_1M_TOKENS
from SentinelAI.ai.prompt_templates import format_prompt, get_system_prompt
from SentinelAI.models.schemas import ClientEmail, ComplianceTicket, LLMVerdict, SessionReport

# Configure module-level structured logging
logger = logging.getLogger("SentinelAI.ReportGenerator")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [ReportGenerator] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class ReportGenerator:
    """
    Executive reporting engine for SentinelAI.
    Generates macroeconomic compliance summaries, single-case abstracts,
    and USD compute cost estimators using generative AI.
    """

    def __init__(self, groq_client: Optional[GroqClient] = None, base_dir: Optional[str] = None) -> None:
        """Initialize ReportGenerator with underlying GroqClient and output directory."""
        import os
        self.groq_client = groq_client or GroqClient()
        if base_dir is None:
            base_dir = "/tmp/SentinelAI/reports" if os.getenv("VERCEL") == "1" else "SentinelAI/reports"
        self.reports_dir = Path(base_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def get_cost_estimate(self, tokens: int, model: Optional[str] = None) -> float:
        """
        Calculates estimated API compute cost in USD for a given token volume.
        Uses blended prompt/completion pricing for the configured Groq LPU model.

        Args:
            tokens: Total tokens consumed.
            model: Model identifier (defaults to primary_model).

        Returns:
            Estimated dollar cost rounded to 6 decimal places.
        """
        model_name = model or self.groq_client.primary_model
        rates = PRICING_PER_1M_TOKENS.get(model_name, PRICING_PER_1M_TOKENS["default"])
        # Blended average of prompt and completion rates (~50/50 split assumption)
        blended_rate = (rates["prompt"] + rates["completion"]) / 2.0
        cost = (tokens / 1_000_000.0) * blended_rate
        return round(cost, 6)

    def generate_case_summary(self, verdict: LLMVerdict) -> str:
        """
        Generates a concise, high-level narrative summary for a single adjudicated case.

        Args:
            verdict: The LLMVerdict object to summarize.

        Returns:
            Crisp narrative paragraph suitable for executive briefing.
        """
        logger.info(f"Generating executive summary for Case '{verdict.case_id}'...")
        prompt = (
            f"Summarize the following financial crime adjudication in 2 concise, professional sentences:\n"
            f"Case: {verdict.case_id} | Risk Level: {verdict.risk_level} | Action: {verdict.action} | "
            f"Regulation: {verdict.regulatory_basis} | Rationale: {verdict.reasoning}"
        )
        system_prompt = get_system_prompt("REPORT_SYSTEM")

        summary = self.groq_client.complete(
            system_prompt=system_prompt,
            user_prompt=prompt,
            temperature=0.2,
            max_tokens=250,
        )
        return summary.strip()

    def generate_daily_report(
        self,
        date: str,
        verdicts: List[LLMVerdict],
        tickets: List[ComplianceTicket],
        emails: List[ClientEmail],
        total_transactions: Optional[int] = None,
    ) -> SessionReport:
        """
        Synthesizes macro statistical metrics across verdicts, tickets, and emails,
        invokes Groq to draft an executive board summary, and saves JSON and TXT deliverables.

        Args:
            date: Reporting window string (e.g. '2026-07-01').
            verdicts: List of adjudicated LLMVerdicts.
            tickets: List of generated ComplianceTickets.
            emails: List of dispatched ClientEmails.
            total_transactions: Optional count of underlying transactions scanned.

        Returns:
            Fully populated SessionReport Pydantic model.
        """
        logger.info(f"Synthesizing daily session report for window '{date}' across {len(verdicts)} verdicts...")

        # Step 1: Assemble macro statistics
        total_cases = len(verdicts)
        tx_count = total_transactions if total_transactions is not None else max(total_cases * 25, 100)

        risk_counter = Counter(v.risk_level for v in verdicts)
        action_counter = Counter(v.action for v in verdicts)
        reg_counter = Counter(v.regulatory_basis for v in verdicts)

        risk_distribution: Dict[str, int] = {
            "LOW": risk_counter.get("LOW", 0),
            "MEDIUM": risk_counter.get("MEDIUM", 0),
            "HIGH": risk_counter.get("HIGH", 0),
            "CRITICAL": risk_counter.get("CRITICAL", 0),
        }
        actions_breakdown: Dict[str, int] = {
            "MONITOR": action_counter.get("MONITOR", 0),
            "REQUEST_KYC": action_counter.get("REQUEST_KYC", 0),
            "FREEZE": action_counter.get("FREEZE", 0),
            "ESCALATE": action_counter.get("ESCALATE", 0),
        }

        top_patterns = [f"{reg} ({cnt} cases)" for reg, cnt in reg_counter.most_common(5)]
        if not top_patterns:
            top_patterns = ["Standard AML Velocity & Geo Anomalies"]

        tokens_consumed = sum(v.tokens_used for v in verdicts) + self.groq_client.tokens_used
        estimated_cost = self.get_cost_estimate(tokens_consumed)

        stats_summary = {
            "Total Scanned Transactions": tx_count,
            "Flagged Cases": total_cases,
            "Critical Alerts": risk_distribution["CRITICAL"],
            "Account Freezes": actions_breakdown["FREEZE"],
            "Tickets Created": len(tickets),
            "Client Notices Dispatched": len(emails),
        }

        # Step 2: Groq writes executive summary
        logger.info("Invoking Groq LPU to compose executive board summary...")
        user_prompt = format_prompt(
            "DAILY_REPORT",
            date=date,
            stats=stats_summary,
            top_patterns=top_patterns,
            actions_taken=actions_breakdown,
        )
        system_prompt = get_system_prompt("REPORT_SYSTEM")

        executive_summary = self.groq_client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.15,
            max_tokens=800,
        )

        report_id = f"REP_{uuid.uuid4().hex[:8].upper()}"
        session_report = SessionReport(
            report_id=report_id,
            date=date,
            total_transactions=tx_count,
            total_cases=total_cases,
            risk_distribution=risk_distribution,
            actions_breakdown=actions_breakdown,
            tickets_generated=len(tickets),
            emails_generated=len(emails),
            tokens_used=tokens_consumed,
            estimated_cost_usd=estimated_cost,
            executive_summary=executive_summary.strip(),
        )

        # Step 3: Save multi-format deliverables (JSON and TXT)
        json_path = self.reports_dir / f"{date}.json"
        txt_path = self.reports_dir / f"{date}.txt"

        with open(json_path, "w", encoding="utf-8") as f_json:
            f_json.write(session_report.model_dump_json(indent=2))

        txt_content = (
            f"========================================================================\n"
            f"SENTINEL AI — EXECUTIVE BOARD COMPLIANCE REPORT\n"
            f"Reporting Window: {date} | Report Ref: {report_id}\n"
            f"========================================================================\n\n"
            f"EXECUTIVE SUMMARY:\n"
            f"------------------------------------------------------------------------\n"
            f"{session_report.executive_summary}\n\n"
            f"KEY PERFORMANCE INDICATORS & METRICS:\n"
            f"------------------------------------------------------------------------\n"
            f"  * Total Transactions Scanned : {session_report.total_transactions:,}\n"
            f"  * Total Flagged Fraud Cases  : {session_report.total_cases:,}\n"
            f"  * Operational Tickets Created: {session_report.tickets_generated:,}\n"
            f"  * Customer Notices Dispatched: {session_report.emails_generated:,}\n"
            f"  * Total LLM Tokens Consumed  : {session_report.tokens_used:,}\n"
            f"  * Estimated Compute Cost USD : ${session_report.estimated_cost_usd:,.4f}\n\n"
            f"RISK TIER DISTRIBUTION:\n"
            f"------------------------------------------------------------------------\n"
            f"  * CRITICAL : {risk_distribution['CRITICAL']} case(s)\n"
            f"  * HIGH     : {risk_distribution['HIGH']} case(s)\n"
            f"  * MEDIUM   : {risk_distribution['MEDIUM']} case(s)\n"
            f"  * LOW      : {risk_distribution['LOW']} case(s)\n\n"
            f"ENFORCEMENT ACTIONS TAKEN:\n"
            f"------------------------------------------------------------------------\n"
            f"  * FREEZE ACCOUNT : {actions_breakdown['FREEZE']}\n"
            f"  * ESCALATE CASE  : {actions_breakdown['ESCALATE']}\n"
            f"  * REQUEST KYC    : {actions_breakdown['REQUEST_KYC']}\n"
            f"  * MONITOR ONLY   : {actions_breakdown['MONITOR']}\n\n"
            f"TOP REGULATORY TYPOLOGIES OBSERVED:\n"
            f"------------------------------------------------------------------------\n"
            + "\n".join(f"  - {pat}" for pat in top_patterns)
            + "\n\n========================================================================\n"
        )

        with open(txt_path, "w", encoding="utf-8") as f_txt:
            f_txt.write(txt_content)

        logger.info(f"Successfully saved session report to '{json_path}' and '{txt_path}'.")
        return session_report
