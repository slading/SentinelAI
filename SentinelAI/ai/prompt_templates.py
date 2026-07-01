"""
SentinelAI Prompt Templates & Management Module.

Central repository for all system prompts and structured user prompt templates
utilized by the Groq LPU generative AI engine. Includes strict variable validation,
automatic serialization of complex data structures, and Chain-of-Thought (CoT) scaffolding.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Union
from pydantic import BaseModel


@dataclass(frozen=True)
class TemplateSpec:
    """Specification object for a prompt template including required variable validation keys."""

    name: str
    required_keys: Set[str]
    template_text: str


# =====================================================================
# SYSTEM PROMPTS
# =====================================================================

SYSTEM_PROMPTS: Dict[str, str] = {
    "INVESTIGATOR_SYSTEM": (
        "You are a Senior Financial Crime Investigator at SentinelAI. Analyze transaction data step-by-step "
        "using structured Chain-of-Thought (CoT) reasoning. Be precise, factual, and strictly objective when "
        "identifying suspicious patterns, structuring, or financial anomalies."
    ),
    "JUDGE_SYSTEM": (
        "You are the Chief Compliance Officer at SentinelAI. Render an authoritative, legally binding compliance "
        "verdict based strictly on the provided investigative evidence. You MUST output ONLY valid JSON matching "
        "the exact schema requested. Do not output any prose, markdown fences, or explanations outside the JSON block."
    ),
    "EMAIL_SYSTEM": (
        "You are a Senior Compliance Communications Specialist at SentinelAI. Draft formal, legally sound customer "
        "notification emails. Maintain a strictly neutral, protective tone and never directly accuse the client of "
        "illegal behavior or fraud. Reference standard banking Terms & Conditions regarding regulatory monitoring "
        "and account security holds."
    ),
    "TICKET_SYSTEM": (
        "You are the Compliance Operations Manager at SentinelAI. Create structured, actionable operational workflow "
        "tickets for L2/L3 compliance analysts. You MUST output ONLY valid JSON matching the required ticket schema "
        "without any narrative introduction or markdown code fences."
    ),
    "REPORT_SYSTEM": (
        "You are the Chief Compliance Officer at SentinelAI. Write concise, executive-level summaries for the Board "
        "of Directors and Regulatory Auditors in polished, professional English. Synthesize macro statistical indicators, "
        "risk distributions, and enforcement actions."
    ),
}


# =====================================================================
# USER TEMPLATES
# =====================================================================

USER_TEMPLATES: Dict[str, TemplateSpec] = {
    "INVESTIGATE_CASE": TemplateSpec(
        name="INVESTIGATE_CASE",
        required_keys={"case_id", "rule_triggered", "account_data", "transaction_history", "evidence_summary", "risk_score"},
        template_text="""CASE INVESTIGATION REQUEST
==========================
Case ID: {case_id}
Triggered AML Rule: {rule_triggered}
Statistical Risk Score: {risk_score} / 100.0

SUBJECT ACCOUNT PROFILE:
{account_data}

CHRONOLOGICAL TRANSACTION HISTORY:
{transaction_history}

DETERMINISTIC STATISTICAL EVIDENCE SUMMARY:
{evidence_summary}

INSTRUCTIONS:
Perform a step-by-step forensic investigation using the following Chain-of-Thought (CoT) framework:
STEP 1: Review flagged pattern and statistical risk metrics.
STEP 2: Analyze transaction data for structuring, velocity anomalies, or unusual amounts.
STEP 3: Identify specific suspicious indicators (e.g., geographic mismatch, device shifts).
STEP 4: Cross-reference linked accounts, IP addresses, and hardware signatures.
STEP 5: Formulate a synthesized, factual investigative summary.""",
    ),
    "JUDGE_VERDICT": TemplateSpec(
        name="JUDGE_VERDICT",
        required_keys={"case_id", "investigation_report", "risk_score"},
        template_text="""COMPLIANCE VERDICT ADJUDICATION
===============================
Case ID: {case_id}
Initial Statistical Risk Score: {risk_score} / 100.0

FORENSIC INVESTIGATION REPORT:
{investigation_report}

INSTRUCTIONS:
Evaluate the evidence and render a definitive compliance decision.
Output ONLY valid JSON matching exactly the structure below:
{{
  "case_id": "{case_id}",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "action": "MONITOR|REQUEST_KYC|FREEZE|ESCALATE",
  "confidence": 0.95,
  "reasoning": "Detailed legal and analytical rationale justifying the decision",
  "regulatory_basis": "Applicable regulation (e.g. PSD2 Article 97, AMLD5, FATF Rec 16)",
  "recommended_deadline_days": 1
}}""",
    ),
    "GENERATE_EMAIL": TemplateSpec(
        name="GENERATE_EMAIL",
        required_keys={"client_name", "account_id", "action_type", "language", "documents_required"},
        template_text="""CUSTOMER COMPLIANCE NOTIFICATION REQUEST
========================================
Client Addressee: {client_name}
Account ID: {account_id}
Enforcement Action Taken: {action_type}
Target Language Code: {language}
Required Verification Documents: {documents_required}

INSTRUCTIONS:
Draft a formal customer notification email in target language '{language}'.
Output ONLY valid JSON matching exactly the structure below:
{{
  "subject": "Formal email subject line referencing account security",
  "body": "Full HTML or clean plaintext email body referring to Terms & Conditions",
  "tone": "neutral_and_protective",
  "documents_requested": {documents_required}
}}""",
    ),
    "GENERATE_TICKET": TemplateSpec(
        name="GENERATE_TICKET",
        required_keys={"case_id", "verdict", "evidence_summary"},
        template_text="""OPERATIONAL WORKFLOW TICKET REQUEST
===================================
Case ID: {case_id}
Adjudicated Verdict: {verdict}
Attached Evidence Summary: {evidence_summary}

INSTRUCTIONS:
Generate an operational tracking ticket for the compliance investigation queue.
Output ONLY valid JSON matching exactly the structure below:
{{
  "title": "Concise issue headline",
  "priority": "LOW|MEDIUM|HIGH|CRITICAL",
  "description": "Full technical and compliance problem description",
  "evidence_summary": "Summary of key statistical and LLM findings",
  "action_required": "Concrete next steps required from L2/L3 compliance analyst",
  "sla_hours": 24,
  "tags": ["AML", "Velocity", "HighRisk"],
  "assignee": "Compliance_Queue_L2"
}}""",
    ),
    "DAILY_REPORT": TemplateSpec(
        name="DAILY_REPORT",
        required_keys={"date", "stats", "top_patterns", "actions_taken"},
        template_text="""EXECUTIVE BOARD SESSION REPORT REQUEST
======================================
Reporting Window / Date: {date}
Key System Metrics & KPI Stats: {stats}
Top Identified Crime Typologies: {top_patterns}
Summary of Enforcement Actions Taken: {actions_taken}

INSTRUCTIONS:
Write a comprehensive, professional executive summary for the Board of Directors.
Highlight key operational metrics, risk distributions, financial crime trends, and regulatory posture.""",
    ),
}


class PromptFormatter:
    """Helper engine providing strict variable validation and serialization for prompt templates."""

    @staticmethod
    def _serialize_value(val: Any) -> str:
        """Safely serializes complex Python objects (Pydantic models, dicts, lists) to formatted strings."""
        if isinstance(val, str):
            return val
        if isinstance(val, BaseModel):
            return json.dumps(val.model_dump(), indent=2, default=str)
        if isinstance(val, (dict, list)):
            return json.dumps(val, indent=2, default=str)
        return str(val)

    @classmethod
    def format_prompt(cls, template_name: str, **kwargs: Any) -> str:
        """
        Formats a registered user prompt template after performing strict variable validation.

        Args:
            template_name: Registered identifier in USER_TEMPLATES.
            **kwargs: Keyword arguments matching the template's required keys.

        Returns:
            Formatted prompt string ready for LLM submission.

        Raises:
            KeyError: If template_name is not registered.
            ValueError: If required keyword arguments are missing.
        """
        if template_name not in USER_TEMPLATES:
            raise KeyError(f"Prompt template '{template_name}' is not registered in USER_TEMPLATES.")

        spec = USER_TEMPLATES[template_name]
        provided_keys = set(kwargs.keys())
        missing_keys = spec.required_keys - provided_keys

        if missing_keys:
            raise ValueError(
                f"Validation failed for template '{template_name}'. Missing required keyword argument(s): "
                f"{sorted(missing_keys)}"
            )

        # Serialize complex arguments cleanly
        serialized_kwargs = {k: cls._serialize_value(v) for k, v in kwargs.items()}

        try:
            return spec.template_text.format(**serialized_kwargs)
        except KeyError as err:
            raise ValueError(f"Formatting failed for template '{template_name}': unmatched key {err}") from err

    @staticmethod
    def get_system_prompt(system_name: str) -> str:
        """Retrieves a registered system prompt string by identifier."""
        if system_name not in SYSTEM_PROMPTS:
            raise KeyError(f"System prompt '{system_name}' not found in SYSTEM_PROMPTS.")
        return SYSTEM_PROMPTS[system_name]


# Module-level convenience wrapper functions
def format_prompt(template_name: str, **kwargs: Any) -> str:
    """Module-level wrapper for PromptFormatter.format_prompt."""
    return PromptFormatter.format_prompt(template_name, **kwargs)


def get_system_prompt(system_name: str) -> str:
    """Module-level wrapper for PromptFormatter.get_system_prompt."""
    return PromptFormatter.get_system_prompt(system_name)
