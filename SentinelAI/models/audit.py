from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid

class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str
    actor: str = "System_Orchestrator"
    action: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = "0" * 64
    event_hash: Optional[str] = None

class ComplianceTicket(BaseModel):
    ticket_id: str = Field(default_factory=lambda: f"TKT-{uuid.uuid4().hex[:8].upper()}")
    trace_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "OPEN"
    assigned_to: str = "Compliance_Queue_L2"
    priority: str = "HIGH"
    user_id: str
    amount: float
    risk_level: str
    fraud_typology: str
    ai_reasoning: str
    recommended_action: str
