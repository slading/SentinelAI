import asyncio
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from SentinelAI.models.transaction import Transaction
from SentinelAI.automation.orchestrator import orchestrator
from SentinelAI.ingestion.stream_consumer import StreamConsumerSimulator
from SentinelAI.ingestion.buffer_manager import transaction_buffer
from SentinelAI.logs.audit_logger import audit_logger
from SentinelAI.api.websocket import ws_manager

router = APIRouter(prefix="/api/v1", tags=["SentinelAI Compliance API"])

# Register WebSocket broadcaster with Orchestrator
orchestrator.register_ws_broadcaster(ws_manager.broadcast_incident)

@router.post("/transactions", status_code=202, summary="Ingest real-time transaction log")
async def ingest_transaction(tx: Dict[str, Any], background_tasks: BackgroundTasks):
    """
    Ingests a raw transaction log stream. Immediately acknowledges receipt (HTTP 202)
    and processes the End-to-End Pandas + Groq pipeline asynchronously.
    """
    background_tasks.add_task(orchestrator.process_transaction, tx)
    return {"status": "ACCEPTED", "message": "Transaction queued for deterministic & probabilistic AML evaluation."}

@router.post("/simulate", summary="Trigger synthetic fraud or benign transaction")
async def simulate_transaction(scenario: Optional[str] = None):
    """
    Triggers synthetic transaction generation (e.g. FRAUD_HIGH_VALUE_NIGHT, FRAUD_IMPOSSIBLE_TRAVEL).
    Executes synchronously so UI receives the immediate verdict and generated artifacts.
    """
    tx = StreamConsumerSimulator.generate_synthetic_transaction(forced_scenario=scenario)
    result = await orchestrator.process_transaction(tx)
    return result

@router.get("/history", summary="Get recent buffered transactions")
async def get_history(limit: int = 50):
    txs = await transaction_buffer.get_all_transactions()
    return {"count": len(txs), "transactions": [t.model_dump() for t in txs[:limit]]}

@router.get("/audit", summary="Get cryptographic SHA-256 audit trail")
async def get_audit(trace_id: Optional[str] = None, limit: int = 50):
    records = await audit_logger.get_audit_trail(trace_id=trace_id, limit=limit)
    return {"count": len(records), "audit_trail": records}

@router.get("/stats", summary="Get system health and KPI metrics")
async def get_stats():
    txs = await transaction_buffer.get_all_transactions()
    audits = await audit_logger.get_audit_trail(limit=200)
    
    flagged = [a for a in audits if a.get("action") == "GENERATED_COMPLIANCE_TICKET"]
    criticals = [a for a in audits if a.get("payload", {}).get("risk_level") == "CRITICAL"]
    
    return {
        "total_buffered_transactions": len(txs),
        "total_audit_events": len(audits),
        "incidents_escalated": len(flagged),
        "critical_alerts": len(criticals),
        "active_ws_connections": len(ws_manager.active_connections),
        "status": "OPERATIONAL",
        "engines": {
            "pandas_statistical": "ONLINE (Vectorized Rolling Features)",
            "groq_llm": "ONLINE (LPU Real-time Inference)"
        }
    }
