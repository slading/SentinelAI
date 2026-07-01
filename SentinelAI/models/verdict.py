from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FraudTypology(str, Enum):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SMURFING = "SMURFING"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    MONEY_LAUNDERING = "MONEY_LAUNDERING"
    GEO_VELOCITY_ANOMALY = "GEO_VELOCITY_ANOMALY"
    HIGH_VALUE_ABNORMAL = "HIGH_VALUE_ABNORMAL"

class RecommendedAction(str, Enum):
    PASS = "PASS"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"

class PandasAnalysisResult(BaseModel):
    trace_id: str
    user_id: str
    amount: float
    is_suspicious: bool
    triggered_rules: List[str] = Field(default_factory=list)
    z_score: float = 0.0
    velocity_1h_count: int = 1
    velocity_24h_spend: float = 0.0
    geo_distance_km: float = 0.0
    summary: str = ""

class Verdict(BaseModel):
    trace_id: str
    risk_level: RiskLevel
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    fraud_typology: FraudTypology
    reasoning: str = Field(..., description="Legal and analytical rationale for the verdict")
    recommended_action: RecommendedAction
    model_used: str = "llama3-70b-8192"
