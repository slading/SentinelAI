"""
SentinelAI Compliance Ticket Generator Module.

Orchestrates the automated creation of operational tracking tickets for L2/L3
compliance analysts. Maps AI risk verdicts to strict resolution SLAs and queue assignees,
persists records to JSON, and formats payloads for Atlassian Jira and CSV bulk exports.
"""

import csv
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from SentinelAI.ai.groq_client import GroqClient
from SentinelAI.ai.prompt_templates import format_prompt, get_system_prompt
from SentinelAI.models.schemas import ComplianceTicket, FraudCase, LLMVerdict

# Configure module-level structured logging
logger = logging.getLogger("SentinelAI.TicketGenerator")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [TicketGenerator] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# SLA & Assignee routing rules mapped by adjudicated risk level
QUEUE_ROUTING_RULES: Dict[str, Tuple[int, str]] = {
    "LOW": (72, "monitoring-team"),
    "MEDIUM": (24, "kyc-team"),
    "HIGH": (8, "ops-team"),
    "CRITICAL": (2, "compliance-director"),
}

# Mapping between internal risk levels and standard Jira Priority names
JIRA_PRIORITY_MAP: Dict[str, str] = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Highest",
}


class TicketGenerator:
    """
    Automated workflow tracking ticket generator.
    Translates LLM verdicts and statistical evidence into structured operational tickets.
    """

    def __init__(self, groq_client: Optional[GroqClient] = None, base_dir: Optional[str] = None) -> None:
        """Initialize TicketGenerator with underlying GroqClient and output directory."""
        import os
        self.groq_client = groq_client or GroqClient()
        if base_dir is None:
            base_dir = "/tmp/SentinelAI/tickets" if os.getenv("VERCEL") == "1" else "SentinelAI/tickets"
        self.tickets_dir = Path(base_dir)
        self.tickets_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, verdict: LLMVerdict, fraud_case: FraudCase) -> ComplianceTicket:
        """
        Generates an operational compliance tracking ticket based on the adjudicated verdict.

        Args:
            verdict: The adjudicated LLMVerdict object.
            fraud_case: The underlying FraudCase containing statistical indicators.

        Returns:
            Fully formatted ComplianceTicket Pydantic model saved to local JSON storage.
        """
        risk_level = verdict.risk_level
        sla_hours, assignee = QUEUE_ROUTING_RULES.get(risk_level, (24, "kyc-team"))
        logger.info(f"Generating workflow ticket for Case '{verdict.case_id}' | Risk: {risk_level} -> Queue: {assignee} ({sla_hours}h SLA)")

        # Step 1: Format prompt
        user_prompt = format_prompt(
            "GENERATE_TICKET",
            case_id=verdict.case_id,
            verdict=verdict.model_dump(),
            evidence_summary=fraud_case.evidence_summary,
        )
        system_prompt = get_system_prompt("TICKET_SYSTEM")

        # Step 2 & 3: Send to Groq and parse strict JSON
        raw_json = self.groq_client.complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        ticket_id = f"TKT-{uuid.uuid4().hex[:8].upper()}"
        title = str(raw_json.get("title", f"[{risk_level}] AML Investigation: {fraud_case.rule_triggered} ({verdict.case_id})"))
        description = str(
            raw_json.get(
                "description",
                f"Automated compliance alert triggered under rule {fraud_case.rule_triggered}. AI confidence: {verdict.confidence*100:.1f}%. Rationale: {verdict.reasoning}",
            )
        )
        evidence_summary = str(raw_json.get("evidence_summary", fraud_case.evidence_summary))
        action_required = str(raw_json.get("action_required", f"Execute {verdict.action} per {verdict.regulatory_basis}"))
        tags = raw_json.get("tags", [fraud_case.rule_triggered, risk_level, verdict.action])
        if not isinstance(tags, list):
            tags = [str(tags)]

        # Step 4: Enforce exact SLA and assignee rules mapped from risk level
        ticket = ComplianceTicket(
            ticket_id=ticket_id,
            case_id=verdict.case_id,
            title=title,
            priority=risk_level,
            description=description,
            evidence_summary=evidence_summary,
            action_required=action_required,
            sla_hours=sla_hours,
            tags=[str(t) for t in tags],
            assignee=assignee,
            status="OPEN",
        )

        # Step 5: Save to tickets/{ticket_id}.json
        save_path = self.tickets_dir / f"{ticket_id}.json"
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(ticket.model_dump_json(indent=2))
        logger.info(f"Successfully generated and persisted ticket record to '{save_path}'.")

        return ticket

    def export_jira_format(self, ticket: ComplianceTicket, project_key: str = "COMP") -> Dict[str, Any]:
        """
        Converts a ComplianceTicket into an Atlassian Jira REST API payload format.

        Args:
            ticket: The ComplianceTicket to convert.
            project_key: Atlassian Jira project code (default 'COMP').

        Returns:
            Dictionary matching Jira Issue Creation REST payload specification.
        """
        jira_priority = JIRA_PRIORITY_MAP.get(ticket.priority, "Medium")
        formatted_description = (
            f"h3. Compliance Case Overview\n"
            f"*Linked Case ID:* {ticket.case_id}\n"
            f"*Resolution SLA:* {ticket.sla_hours} hours\n"
            f"*Assigned Queue:* {ticket.assignee}\n\n"
            f"h3. Description\n{ticket.description}\n\n"
            f"h3. Forensic Evidence Summary\n{{quote}}\n{ticket.evidence_summary}\n{{quote}}\n\n"
            f"h3. Action Required\n* {ticket.action_required}\n"
        )

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[{ticket.ticket_id}] {ticket.title}",
                "description": formatted_description,
                "issuetype": {"name": "Task"},
                "priority": {"name": jira_priority},
                "labels": [re_tag.replace(" ", "_") for re_tag in ticket.tags] + [f"SLA_{ticket.sla_hours}h"],
                "customfield_10010": ticket.case_id,  # Example Jira custom field mapping
            }
        }
        return payload

    def export_all_csv(self, tickets: List[ComplianceTicket], path: str) -> None:
        """
        Exports a batch of ComplianceTicket objects to a flat CSV file.

        Args:
            tickets: List of ComplianceTicket records.
            path: Target output filepath (must end in .csv).
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Exporting {len(tickets)} compliance tickets to CSV at '{target}'...")

        fieldnames = [
            "ticket_id",
            "case_id",
            "title",
            "priority",
            "sla_hours",
            "assignee",
            "status",
            "action_required",
            "tags",
            "created_at",
        ]

        with open(target, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for t in tickets:
                writer.writerow(
                    {
                        "ticket_id": t.ticket_id,
                        "case_id": t.case_id,
                        "title": t.title,
                        "priority": t.priority,
                        "sla_hours": t.sla_hours,
                        "assignee": t.assignee,
                        "status": t.status,
                        "action_required": t.action_required,
                        "tags": ", ".join(t.tags),
                        "created_at": t.created_at.isoformat() if hasattr(t.created_at, "isoformat") else str(t.created_at),
                    }
                )
        logger.info(f"CSV export complete. File written to '{target}'.")
