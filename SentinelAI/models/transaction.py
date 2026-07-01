from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import uuid

class DeviceFingerprint(BaseModel):
    device_id: str = "dev_unknown"
    ip_address: str = "127.0.0.1"
    country_code: str = "PL"
    city: str = "Warsaw"
    user_agent: Optional[str] = "Mozilla/5.0 Fintech Client"

class Transaction(BaseModel):
    trace_id: str = Field(default_factory=lambda: f"tx_{uuid.uuid4().hex[:8]}")
    transaction_id: str = Field(default_factory=lambda: f"txn_{uuid.uuid4().hex[:12]}")
    user_id: str = Field(..., description="Unique user or account ID")
    amount: float = Field(..., gt=0.0, description="Transaction amount")
    currency: str = Field(default="USD", max_length=3)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    merchant: str = Field(default="Generic Merchant")
    merchant_category: str = Field(default="general_retail")
    card_pan_masked: str = Field(default="400012******3456")
    device: DeviceFingerprint = Field(default_factory=DeviceFingerprint)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("currency")
    @classmethod
    def uppercase_currency(cls, v: str) -> str:
        return v.upper()

class TransactionBatch(BaseModel):
    batch_id: str = Field(default_factory=lambda: f"batch_{uuid.uuid4().hex[:8]}")
    transactions: list[Transaction]
