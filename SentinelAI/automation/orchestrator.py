import asyncio
from typing import Dict, Any, Callable, List
from SentinelAI.models.transaction import Transaction
from SentinelAI.models.verdict import Verdict, RiskLevel
from SentinelAI.ingestion.normalizer import TransactionNormalizer
from SentinelAI.ingestion.buffer_manager import transaction_buffer
from SentinelAI.analytics.fraud_rules import DeterministicFraudEngine
from SentinelAI.ai.groq_client import groq_client
from SentinelAI.automation.ticket_dispatcher import TicketDispatcher
from SentinelAI.automation.email_dispatcher import EmailDispatcher
from SentinelAI.automation.report_generator import ReportGenerator
from SentinelAI.logs.audit_logger import audit_logger

class ComplianceOrchestrator:
    """
    Central state machine orchestrating incoming transactions through:
    Ingestion -> Pandas Analytics -> Groq AI -> Action Automation -> Audit Trail -> Live WS Broadcast
    """
    def __init__(self):
        self._ws_callback: Callable[[Dict[str, Any]], None] = None

    def register_ws_broadcaster(self, callback: Callable[[Dict[str, Any]], None]):
        self._ws_callback = callback

    async def process_transaction(self, raw_tx: Any) -> Dict[str, Any]:
        # Step 1: Normalize & Validate (Ingestion)
        tx = TransactionNormalizer.normalize(raw_tx)
        
        await audit_logger.log_event(
            trace_id=tx.trace_id,
            action="INGESTED_TRANSACTION",
            actor="Ingestion_Normalizer",
            payload={"amount": tx.amount, "user_id": tx.user_id, "merchant": tx.merchant}
        )

        # Step 2: Fetch user history and add to sliding window buffer
        history = await transaction_buffer.get_user_history(tx.user_id)
        await transaction_buffer.add_transaction(tx)

        # Step 3: Run Pandas Deterministic Analytics Engine
        pandas_res = DeterministicFraudEngine.evaluate(tx, history)
        
        await audit_logger.log_event(
            trace_id=tx.trace_id,
            action="COMPLETED_PANDAS_ANALYTICS",
            actor="Analytics_DeterministicEngine",
            payload={
                "is_suspicious": pandas_res.is_suspicious,
                "z_score": pandas_res.z_score,
                "triggered_rules": pandas_res.triggered_rules
            }
        )

        # Step 4: Run Groq AI Cognitive Evaluation
        verdict = await groq_client.analyze_case(tx, pandas_res)
        
        await audit_logger.log_event(
            trace_id=tx.trace_id,
            action="COMPLETED_GROQ_AI_EVALUATION",
            actor=f"AI_{verdict.model_used}",
            payload={
                "risk_level": verdict.risk_level.value,
                "confidence": verdict.confidence_score,
                "typology": verdict.fraud_typology.value,
                "recommended_action": verdict.recommended_action.value
            }
        )

        # Step 5: Conditional Automated Workflow (If risk >= MEDIUM)
        ticket_id = None
        email_path = None
        report_path = None

        if verdict.risk_level != RiskLevel.LOW or pandas_res.is_suspicious:
            ticket = await TicketDispatcher.create_ticket(tx, verdict)
            ticket_id = ticket.ticket_id
            
            report_path = await ReportGenerator.generate_investigation_report(tx, pandas_res, verdict)
            email_path = await EmailDispatcher.dispatch_client_notice(tx, verdict)

        # Complete response payload
        result_payload = {
            "trace_id": tx.trace_id,
            "transaction": tx.model_dump(),
            "pandas_analysis": pandas_res.model_dump(),
            "verdict": verdict.model_dump(),
            "automation": {
                "ticket_id": ticket_id,
                "email_dispatched": email_path,
                "report_generated": report_path
            }
        }

        # Broadcast live to WebSocket frontends
        if self._ws_callback:
            try:
                if asyncio.iscoroutinefunction(self._ws_callback):
                    await self._ws_callback(result_payload)
                else:
                    self._ws_callback(result_payload)
            except Exception as e:
                print(f"[WS Broadcast Error]: {e}")

        return result_payload

orchestrator = ComplianceOrchestrator()
