"""
SentinelAI Generative LLM Compliance Inspector Module.

Orchestrates multi-role AI investigations and adjudications over suspicious
financial crime cases. Combines Chain-of-Thought (CoT) forensic investigation
with strict JSON compliance adjudication, rate-limited thread pooling, and
comprehensive usage/latency telemetry.
"""

import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from tqdm import tqdm

from SentinelAI.ai.groq_client import GroqClient
from SentinelAI.ai.prompt_templates import format_prompt, get_system_prompt
from SentinelAI.models.schemas import FraudCase, InvestigationReport, LLMVerdict

# Configure module-level structured logging
logger = logging.getLogger("SentinelAI.LLMInspector")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [LLMInspector] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class LLMInspector:
    """
    Two-stage cognitive investigation and adjudication engine for SentinelAI.
    Stage 1: Forensic Investigation (Investigator role via Chain-of-Thought).
    Stage 2: Compliance Adjudication (Judge role via structured JSON output).
    """

    def __init__(self, groq_client: Optional[GroqClient] = None) -> None:
        """Initialize the LLMInspector with an underlying GroqClient and thread-safe throttling."""
        self.groq_client = groq_client or GroqClient()
        self._rate_limit_lock = threading.Lock()
        self._last_request_time: float = 0.0

    def _throttle(self, delay_sec: float = 1.0) -> None:
        """Enforces thread-safe rate limiting between concurrent API calls."""
        with self._rate_limit_lock:
            now = time.perf_counter()
            elapsed = now - self._last_request_time
            if elapsed < delay_sec:
                time.sleep(delay_sec - elapsed)
            self._last_request_time = time.perf_counter()

    def investigate(self, fraud_case: FraudCase) -> InvestigationReport:
        """
        Stage 1: Invokes Groq in the 'Investigator' role using Chain-of-Thought reasoning.
        Parses unconstrained forensic analysis into a structured InvestigationReport.
        """
        logger.info(f"[Stage 1: Investigate] Starting CoT analysis for case '{fraud_case.case_id}'...")
        start_t = time.perf_counter()
        initial_tokens = self.groq_client.tokens_used

        # Prepare context data matching INVESTIGATE_CASE template
        account_data = {
            "flagged_accounts": fraud_case.related_accounts,
            "rule_violation": fraud_case.rule_triggered,
        }
        tx_history = [
            {"tx_id": tx_id, "timestamp": str(fraud_case.timestamps[i]) if i < len(fraud_case.timestamps) else "UTC"}
            for i, tx_id in enumerate(fraud_case.related_transactions)
        ]

        # Format prompt
        user_prompt = format_prompt(
            "INVESTIGATE_CASE",
            case_id=fraud_case.case_id,
            rule_triggered=fraud_case.rule_triggered,
            account_data=account_data,
            transaction_history=tx_history,
            evidence_summary=fraud_case.evidence_summary,
            risk_score=fraud_case.risk_score,
        )
        system_prompt = get_system_prompt("INVESTIGATOR_SYSTEM")

        # Enforce rate limit & execute completion
        self._throttle(delay_sec=1.0)
        raw_text = self.groq_client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.1,
            max_tokens=1500,
        )

        latency_ms = int((time.perf_counter() - start_t) * 1000.0)
        tokens_consumed = self.groq_client.tokens_used - initial_tokens
        logger.info(
            f"[Stage 1: Investigate] Completed in {latency_ms}ms | Tokens consumed: {tokens_consumed}"
        )

        # Parse unstructured CoT narrative into structured InvestigationReport
        findings: List[str] = []
        indicators: List[str] = []
        cross_refs: List[str] = []

        for line in raw_text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("STEP ", "- ", "* ", "1.", "2.", "3.", "4.", "5.")):
                clean_line = re.sub(r"^(?:STEP \d+:?|-|\*|\d+\.)\s*", "", stripped).strip()
                if clean_line:
                    if "indicator" in stripped.lower() or "anomaly" in stripped.lower() or "suspicious" in stripped.lower():
                        indicators.append(clean_line)
                    elif "account" in stripped.lower() or "ip" in stripped.lower() or "device" in stripped.lower():
                        cross_refs.append(clean_line)
                    else:
                        findings.append(clean_line)

        # Fallback values if parsing yielded short lists
        if not findings:
            findings = [f"Automated CoT evaluation confirmed pattern: {fraud_case.rule_triggered}"]
        if not indicators:
            indicators = [f"Risk score threshold exceeded ({fraud_case.risk_score}/100)"]
        if not cross_refs:
            cross_refs = [f"Linked accounts: {', '.join(fraud_case.related_accounts)}"]

        return InvestigationReport(
            case_id=fraud_case.case_id,
            findings=findings,
            suspicious_indicators=indicators,
            cross_references=cross_refs,
            summary=raw_text.strip(),
            processing_time_ms=latency_ms,
        )

    def judge(self, report: InvestigationReport, fraud_case: FraudCase) -> LLMVerdict:
        """
        Stage 2: Invokes Groq in the 'Judge' (Chief Compliance Officer) role.
        Evaluates the InvestigationReport and returns a strictly validated Pydantic LLMVerdict.
        """
        logger.info(f"[Stage 2: Judge] Adjudicating verdict for case '{fraud_case.case_id}'...")
        start_t = time.perf_counter()
        initial_tokens = self.groq_client.tokens_used

        user_prompt = format_prompt(
            "JUDGE_VERDICT",
            case_id=fraud_case.case_id,
            investigation_report=report.model_dump(),
            risk_score=fraud_case.risk_score,
        )
        system_prompt = get_system_prompt("JUDGE_SYSTEM")

        # Enforce rate limit & request strict JSON
        self._throttle(delay_sec=1.0)
        raw_json = self.groq_client.complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        latency_ms = int((time.perf_counter() - start_t) * 1000.0)
        tokens_consumed = self.groq_client.tokens_used - initial_tokens

        # Ensure metadata fields required by LLMVerdict schema are present
        raw_json["case_id"] = fraud_case.case_id
        raw_json["processing_time_ms"] = latency_ms
        raw_json["model_used"] = self.groq_client.primary_model
        raw_json["tokens_used"] = tokens_consumed

        # Handle potential enum deviations gracefully before Pydantic validation
        valid_risks = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if raw_json.get("risk_level") not in valid_risks:
            raw_json["risk_level"] = "CRITICAL" if fraud_case.risk_score >= 85 else "HIGH"

        valid_actions = {"MONITOR", "REQUEST_KYC", "FREEZE", "ESCALATE"}
        if raw_json.get("action") not in valid_actions:
            raw_json["action"] = "FREEZE" if raw_json["risk_level"] == "CRITICAL" else "ESCALATE"

        verdict = LLMVerdict(**raw_json)
        logger.info(
            f"[Stage 2: Judge] Rendered Verdict: {verdict.risk_level} -> {verdict.action} "
            f"({verdict.confidence*100:.0f}% conf) in {latency_ms}ms"
        )
        return verdict

    def full_inspection(self, fraud_case: FraudCase) -> LLMVerdict:
        """
        Executes end-to-end two-stage inspection (investigate -> judge), measures
        cumulative execution duration, logs detailed stage telemetry, and returns final verdict.
        """
        logger.info(f"=== Starting Full Inspection on Case '{fraud_case.case_id}' ===")
        start_total = time.perf_counter()
        initial_tokens = self.groq_client.tokens_used

        # Stage 1: Investigate
        report = self.investigate(fraud_case)

        # Stage 2: Judge
        verdict = self.judge(report, fraud_case)

        total_latency_ms = int((time.perf_counter() - start_total) * 1000.0)
        total_tokens = self.groq_client.tokens_used - initial_tokens

        # Update verdict latency and tokens with total pipeline consumption
        verdict.processing_time_ms = total_latency_ms
        verdict.tokens_used = total_tokens

        logger.info(f"=== Full Inspection Complete for Case '{fraud_case.case_id}' ===")
        logger.info(f"  * Final Risk Level : {verdict.risk_level}")
        logger.info(f"  * Enforced Action  : {verdict.action}")
        logger.info(f"  * AI Confidence    : {verdict.confidence * 100:.1f}%")
        logger.info(f"  * Total Latency    : {total_latency_ms}ms")
        logger.info(f"  * Total Tokens Used: {total_tokens}")
        logger.info("====================================================================")
        return verdict

    def batch_inspect(self, cases: List[FraudCase], max_workers: int = 3) -> List[LLMVerdict]:
        """
        Processes multiple flagged fraud cases concurrently using a ThreadPoolExecutor.
        Enforces 1-second rate limiting between requests, displays a tqdm progress bar,
        and logs/skips any individual case failures without crashing the batch.
        """
        logger.info(f"=== Starting Batch Inspection on {len(cases)} cases (max_workers={max_workers}) ===")
        verdicts: List[LLMVerdict] = []

        if not cases:
            return verdicts

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_case = {
                executor.submit(self.full_inspection, case): case for case in cases
            }

            with tqdm(total=len(cases), desc="Inspecting Cases", unit="case") as pbar:
                for future in as_completed(future_to_case):
                    case = future_to_case[future]
                    pbar.set_postfix(case_id=case.case_id)
                    try:
                        verdict = future.result()
                        verdicts.append(verdict)
                    except Exception as err:
                        logger.error(
                            f"[Batch Inspection Error] Failed processing case '{case.case_id}': "
                            f"{type(err).__name__} - {err}. Skipping case."
                        )
                    finally:
                        pbar.update(1)

        # Sort final verdicts by risk hierarchy or confidence
        verdicts.sort(key=lambda v: v.confidence, reverse=True)
        logger.info(f"=== Batch Inspection Complete: Successfully adjudicated {len(verdicts)}/{len(cases)} cases ===")
        return verdicts
