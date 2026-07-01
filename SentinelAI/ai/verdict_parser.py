import json
import re
from typing import Optional
from SentinelAI.models.verdict import Verdict, RiskLevel, FraudTypology, RecommendedAction

class VerdictParser:
    @staticmethod
    def parse_verdict(raw_llm_text: str, trace_id: str, model_name: str = "llama3-70b-8192") -> Verdict:
        # Extract JSON if enclosed in markdown or extra text
        clean_text = raw_llm_text.strip()
        json_match = re.search(r"\{.*\}", clean_text, re.DOTALL)
        if json_match:
            clean_text = json_match.group(0)

        try:
            data = json.loads(clean_text)
            return Verdict(
                trace_id=trace_id,
                risk_level=RiskLevel(data.get("risk_level", "MEDIUM")),
                confidence_score=float(data.get("confidence_score", 0.85)),
                fraud_typology=FraudTypology(data.get("fraud_typology", "HIGH_VALUE_ABNORMAL")),
                reasoning=str(data.get("reasoning", "Suspicious transaction flagged by statistical model.")),
                recommended_action=RecommendedAction(data.get("recommended_action", "ESCALATE_TO_HUMAN")),
                model_used=model_name
            )
        except Exception as e:
            # Fallback safe structured verdict
            return Verdict(
                trace_id=trace_id,
                risk_level=RiskLevel.HIGH,
                confidence_score=0.90,
                fraud_typology=FraudTypology.HIGH_VALUE_ABNORMAL,
                reasoning=f"Automated fallback reasoning due to structured LLM parse exception: {str(e)}. Raw rules triggered investigation.",
                recommended_action=RecommendedAction.BLOCK,
                model_used=f"{model_name}-fallback"
            )
