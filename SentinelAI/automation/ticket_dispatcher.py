import json
from pathlib import Path
from SentinelAI.models.transaction import Transaction
from SentinelAI.models.verdict import Verdict
from SentinelAI.models.audit import ComplianceTicket
from SentinelAI.logs.audit_logger import audit_logger

class TicketDispatcher:
    TICKETS_DIR = Path("SentinelAI/tickets")

    @classmethod
    async def create_ticket(cls, tx: Transaction, verdict: Verdict) -> ComplianceTicket:
        cls.TICKETS_DIR.mkdir(parents=True, exist_ok=True)
        
        ticket = ComplianceTicket(
            trace_id=tx.trace_id,
            user_id=tx.user_id,
            amount=tx.amount,
            risk_level=verdict.risk_level.value,
            fraud_typology=verdict.fraud_typology.value,
            ai_reasoning=verdict.reasoning,
            recommended_action=verdict.recommended_action.value,
            priority="CRITICAL" if verdict.risk_level.value == "CRITICAL" else "HIGH"
        )

        file_path = cls.TICKETS_DIR / f"{ticket.ticket_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(ticket.model_dump(), f, indent=2)

        await audit_logger.log_event(
            trace_id=tx.trace_id,
            action="GENERATED_COMPLIANCE_TICKET",
            actor="Automation_TicketDispatcher",
            payload={"ticket_id": ticket.ticket_id, "file_path": str(file_path)}
        )
        return ticket
