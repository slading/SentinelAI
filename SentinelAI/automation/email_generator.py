"""
SentinelAI Compliance Customer Notification Generator Module.

Orchestrates the creation of formal, legally sound customer compliance notifications
and KYC document requests using generative AI. Automatically maps adjudication actions
to required document checklists, generates multilingual text, and persists JSON records.
"""

import json
import logging
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from SentinelAI.ai.groq_client import GroqClient
from SentinelAI.ai.prompt_templates import format_prompt, get_system_prompt
from SentinelAI.models.schemas import ClientEmail, LLMVerdict

# Configure module-level structured logging
logger = logging.getLogger("SentinelAI.EmailGenerator")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [EmailGenerator] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Document requirements by enforcement action
DOCUMENTS_BY_ACTION: Dict[str, List[str]] = {
    "REQUEST_KYC": [
        "Bank statements (last 3 months)",
        "Source of funds declaration form",
        "Proof of income / Employer verification",
        "Valid Government-issued ID / Passport",
    ],
    "FREEZE": [
        "Identity verification selfie with photo ID",
        "Detailed explanation of flagged transactions",
        "Supporting source of funds documentation",
    ],
    "ESCALATE": [
        "Bank statements (last 3 months)",
        "Source of funds declaration form",
        "Proof of income / Employer verification",
        "Valid Government-issued ID / Passport",
        "Detailed explanation of flagged transactions",
        "Legal representation details / Compliance affidavit",
    ],
}


class EmailGenerator:
    """
    AI-driven customer compliance email generator.
    Translates LLM verdicts into formal, polite, regulatory-compliant notification emails.
    """

    def __init__(self, groq_client: Optional[GroqClient] = None, base_dir: Optional[str] = None) -> None:
        """Initialize EmailGenerator with underlying GroqClient and storage paths."""
        import os
        self.groq_client = groq_client or GroqClient()
        if base_dir is None:
            base_dir = "/tmp/SentinelAI/emails" if os.getenv("VERCEL") == "1" else "SentinelAI/emails"
        self.emails_dir = Path(base_dir)
        self.emails_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        verdict: LLMVerdict,
        client_data: Dict[str, Any],
        language: str = "EN",
    ) -> Optional[ClientEmail]:
        """
        Generates a formal customer compliance email based on the adjudicated verdict action.

        Args:
            verdict: The adjudicated LLMVerdict object.
            client_data: Dictionary containing client details (e.g. client_name, account_id).
            language: Target ISO language code (e.g. 'EN', 'PL', 'DE').

        Returns:
            ClientEmail Pydantic model if notification is required, or None if action is MONITOR.
        """
        action = verdict.action
        logger.info(f"Evaluating email requirement for Case '{verdict.case_id}' | Action: {action}")

        # Step 1: Determine email type & necessity
        if action == "MONITOR":
            logger.info(f"Action is MONITOR for Case '{verdict.case_id}'. No customer notification required.")
            return None

        action_label_map = {
            "REQUEST_KYC": "Request Source of Funds & Verification",
            "FREEZE": "Account Restriction Notice",
            "ESCALATE": "Urgent Regulatory Compliance Inquiry",
        }
        action_type_label = action_label_map.get(action, "Compliance Verification Request")
        docs_required = DOCUMENTS_BY_ACTION.get(action, ["Government ID", "Source of Funds"])

        client_name = str(client_data.get("client_name", "Valued Client"))
        account_id = str(client_data.get("account_id", f"ACC_{verdict.case_id[:6]}"))

        # Step 2: Format prompt
        logger.info(f"Generating formal email for client '{client_name}' ({account_id}) in language '{language}'...")
        user_prompt = format_prompt(
            "GENERATE_EMAIL",
            client_name=client_name,
            account_id=account_id,
            action_type=action_type_label,
            language=language.upper(),
            documents_required=docs_required,
        )
        system_prompt = get_system_prompt("EMAIL_SYSTEM")

        # Step 3 & 4: Send to Groq and parse strict JSON
        raw_json = self.groq_client.complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        email_id = f"EMAIL_{uuid.uuid4().hex[:8].upper()}"
        subject = str(raw_json.get("subject", f"IMPORTANT: SentinelAI Account Verification Required ({account_id})"))
        body = str(
            raw_json.get(
                "body",
                f"Dear {client_name},\n\nWe are conducting a standard compliance review on account {account_id}. "
                f"Please submit the following documentation: {', '.join(docs_required)}.\n\nSincerely,\nSentinelAI Compliance Team",
            )
        )
        tone = str(raw_json.get("tone", "formal_and_protective"))

        email_record = ClientEmail(
            email_id=email_id,
            case_id=verdict.case_id,
            client_name=client_name,
            account_id=account_id,
            subject=subject,
            body=body,
            tone=tone,
            language=language.upper(),
            documents_requested=docs_required,
        )

        # Step 5: Save automatically to emails/{case_id}.json
        auto_save_path = self.emails_dir / f"{verdict.case_id}.json"
        self.save(email_record, str(auto_save_path))
        logger.info(f"Successfully generated and persisted email record to '{auto_save_path}'.")

        return email_record

    def preview(self, email: ClientEmail) -> None:
        """
        Aesthetically outputs the generated client email to the console.
        """
        print("\n" + "=" * 70)
        print(f"📧 CLIENT COMPLIANCE NOTIFICATION PREVIEW [{email.email_id}]")
        print("=" * 70)
        print(f"To          : {email.client_name} (Account ID: {email.account_id})")
        print(f"Case Ref    : {email.case_id}")
        print(f"Language    : {email.language} | Tone: {email.tone}")
        print(f"Subject     : {email.subject}")
        print("-" * 70)
        print("Requested Documents Checklist:")
        for doc in email.documents_requested:
            print(f"  [ ] {doc}")
        print("-" * 70)
        print("Message Body:\n")
        print(email.body)
        print("=" * 70 + "\n")

    def save(self, email: ClientEmail, path: str) -> None:
        """
        Persists the ClientEmail record as a formatted JSON file.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(email.model_dump_json(indent=2))
