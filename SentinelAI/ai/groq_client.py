"""
SentinelAI Generative AI Client Module (Groq LPU Engine).

Provides high-reliability, low-latency LLM inference via the Groq API.
Implements exponential backoff retries, automatic model fallback, JSON structure
validation with self-healing re-prompting, and granular usage/cost telemetry.
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from dotenv import load_dotenv
from groq import Groq, APIConnectionError, APIStatusError, RateLimitError

# Load environment variables from .env file
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Configure structured logging
logger = logging.getLogger("SentinelAI.GroqClient")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [GroqClient] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Accurate pricing per 1M tokens (USD) based on official Groq LPU developer rates
PRICING_PER_1M_TOKENS: Dict[str, Dict[str, float]] = {
    "llama-3.3-70b-versatile": {"prompt": 0.59, "completion": 0.79},
    "llama-3.1-8b-instant": {"prompt": 0.05, "completion": 0.08},
    "openai/gpt-oss-120b": {"prompt": 0.15, "completion": 0.60},
    "openai/gpt-oss-20b": {"prompt": 0.075, "completion": 0.30},
    "default": {"prompt": 0.59, "completion": 0.79},
}

# Model performance metadata (Speed in Tokens/sec, Context window size)
MODEL_METADATA: Dict[str, Dict[str, Any]] = {
    "llama-3.3-70b-versatile": {"speed_tps": 280, "context_window": 131072, "max_completion": 32768},
    "llama-3.1-8b-instant": {"speed_tps": 560, "context_window": 131072, "max_completion": 131072},
    "openai/gpt-oss-120b": {"speed_tps": 500, "context_window": 131072, "max_completion": 65536},
    "openai/gpt-oss-20b": {"speed_tps": 1000, "context_window": 131072, "max_completion": 65536},
}


class GroqClient:
    """
    Production-grade AI client wrapper for Groq LPU API.
    Features strict typing, exponential backoff, automatic fallback models,
    strict JSON output parsing, and real-time usage telemetry.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize the GroqClient. Reads API keys from .env and model parameters from YAML config.
        """
        cfg_file = Path(config_path) if config_path else BASE_DIR / "config" / "config.yaml"
        config_data: Dict[str, Any] = {}
        if cfg_file.exists():
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f) or {}
            except Exception as e:
                logger.warning(f"Failed to read YAML config at {cfg_file}: {e}")

        groq_cfg = config_data.get("groq", {})
        self.primary_model: str = str(groq_cfg.get("primary_model", "llama-3.3-70b-versatile"))
        self.fallback_model: str = str(groq_cfg.get("fallback_model", "llama-3.1-8b-instant"))
        self.default_temperature: float = float(groq_cfg.get("temperature", 0.1))
        self.default_max_tokens: int = int(groq_cfg.get("max_tokens", 2048))
        self.timeout: int = int(groq_cfg.get("timeout", 30))
        self.max_retries: int = int(groq_cfg.get("max_retries", 3))

        # API Key management
        self.api_key: str = os.getenv("GROQ_API_KEY", "")
        self._is_mock_key: bool = not self.api_key or self.api_key.startswith("gsk_xxxx") or self.api_key == "gsk_mock"

        if not self._is_mock_key:
            self.client: Optional[Groq] = Groq(api_key=self.api_key, timeout=self.timeout)
            logger.info(f"Initialized Groq SDK with primary model '{self.primary_model}' and fallback '{self.fallback_model}'.")
        else:
            self.client = None
            logger.warning("No live GROQ_API_KEY detected (found mock placeholder). Running in simulated LPU mode.")

        # Telemetry & Monitoring metrics
        self.tokens_used: int = 0
        self.requests_count: int = 0
        self.total_cost_usd: float = 0.0
        self._latencies_ms: List[float] = []

    def _calculate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculates dynamic execution cost in USD based on official model token rates."""
        rates = PRICING_PER_1M_TOKENS.get(model, PRICING_PER_1M_TOKENS["default"])
        cost = (prompt_tokens / 1_000_000.0) * rates["prompt"] + (completion_tokens / 1_000_000.0) * rates["completion"]
        return round(cost, 6)

    def _record_telemetry(self, model: str, prompt_tokens: int, completion_tokens: int, latency_ms: float) -> None:
        """Records latency, tokens consumed, requests count, and accumulated dollar cost."""
        self.requests_count += 1
        total_tok = prompt_tokens + completion_tokens
        self.tokens_used += total_tok
        self._latencies_ms.append(latency_ms)
        self.total_cost_usd += self._calculate_cost(model, prompt_tokens, completion_tokens)

    def _simulate_completion(self, system_prompt: str, user_prompt: str, is_json: bool = False) -> str:
        """Generates intelligent mock responses when testing without live API credentials."""
        start_t = time.perf_counter()
        time.sleep(0.12)  # Simulate real Groq LPU ultra-fast response latency (~120ms)
        latency_ms = (time.perf_counter() - start_t) * 1000.0

        approx_prompt_tok = int(len(system_prompt + user_prompt) / 4) + 20
        approx_comp_tok = 140
        self._record_telemetry(self.primary_model, approx_prompt_tok, approx_comp_tok, latency_ms)

        if is_json or "json" in system_prompt.lower():
            risk = "CRITICAL" if "18,500" in user_prompt or "KP" in user_prompt or "Impossible" in user_prompt else "MEDIUM"
            action = "FREEZE" if risk == "CRITICAL" else "ESCALATE"
            mock_payload = {
                "risk_level": risk,
                "action": action,
                "confidence": 0.94,
                "reasoning": "Simulated LPU analysis detected abnormal multi-factor transaction signatures consistent with reported AML typologies.",
                "regulatory_basis": "FATF Rec 16 & AMLD5 Article 14",
                "recommended_deadline_days": 1 if risk == "CRITICAL" else 3,
            }
            return json.dumps(mock_payload, indent=2)

        return "Simulated Groq AI completion: Transaction pattern evaluated against historical parameters."

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Executes text completion via Groq API.
        Implements exponential backoff (1s, 2s, 4s) and automatic model fallback on failure.
        """
        temp = temperature if temperature is not None else self.default_temperature
        max_tok = max_tokens if max_tokens is not None else self.default_max_tokens

        if self._is_mock_key or self.client is None:
            return self._simulate_completion(system_prompt, user_prompt, is_json=False)

        models_to_attempt = [self.primary_model, self.fallback_model]
        backoff_delays = [1.0, 2.0, 4.0]

        for model_idx, model_name in enumerate(models_to_attempt):
            for attempt in range(1, self.max_retries + 1):
                start_t = time.perf_counter()
                try:
                    logger.info(f"Invoking API completion | Model: {model_name} | Attempt: {attempt}/{self.max_retries}")
                    completion = self.client.chat.completions.create(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=temp,
                        max_tokens=max_tok,
                        timeout=self.timeout,
                    )
                    latency_ms = (time.perf_counter() - start_t) * 1000.0

                    response_text = completion.choices[0].message.content or ""
                    usage = completion.usage
                    prompt_tok = usage.prompt_tokens if usage else int(len(system_prompt + user_prompt) / 4)
                    comp_tok = usage.completion_tokens if usage else int(len(response_text) / 4)

                    self._record_telemetry(model_name, prompt_tok, comp_tok, latency_ms)
                    logger.info(f"Completion successful ({latency_ms:.1f}ms) | Tokens: {prompt_tok + comp_tok}")
                    return response_text

                except (APIConnectionError, APIStatusError, RateLimitError, Exception) as err:
                    latency_ms = (time.perf_counter() - start_t) * 1000.0
                    logger.error(f"Error on model '{model_name}' (attempt {attempt}): {type(err).__name__} - {err}")

                    if attempt < self.max_retries:
                        sleep_time = backoff_delays[attempt - 1]
                        logger.warning(f"Exponential backoff triggered. Sleeping for {sleep_time}s...")
                        time.sleep(sleep_time)
                    else:
                        logger.error(f"Exhausted {self.max_retries} attempts on model '{model_name}'.")

            if model_idx == 0 and model_name != self.fallback_model:
                logger.warning(f"Primary model '{self.primary_model}' unavailable. Switching to fallback '{self.fallback_model}'...")

        logger.critical("All Groq models failed. Reverting to safe automated exception handler.")
        raise RuntimeError("Groq API inference failed across primary and fallback models after all retry attempts.")

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        Executes completion requesting strict JSON output format.
        Retries up to 3 times specifically if returned text fails JSON validation/parsing.
        Logs every attempt and applies self-healing prompt guidance on syntax failures.
        """
        json_system_prompt = system_prompt
        if "json" not in json_system_prompt.lower():
            json_system_prompt += "\n\nIMPORTANT: Respond ONLY with valid JSON. Do not include markdown fences or narrative prose."

        if self._is_mock_key or self.client is None:
            raw_text = self._simulate_completion(json_system_prompt, user_prompt, is_json=True)
            return json.loads(raw_text)

        current_user_prompt = user_prompt

        for attempt in range(1, self.max_retries + 1):
            logger.info(f"Executing complete_json | Parse Attempt: {attempt}/{self.max_retries}")
            try:
                raw_response = self.complete(
                    system_prompt=json_system_prompt,
                    user_prompt=current_user_prompt,
                    temperature=0.05,
                )

                clean_text = raw_response.strip()
                code_fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", clean_text, re.DOTALL)
                if code_fence_match:
                    clean_text = code_fence_match.group(1)
                else:
                    brace_match = re.search(r"(\{.*\})", clean_text, re.DOTALL)
                    if brace_match:
                        clean_text = brace_match.group(1)

                parsed_json: Dict[str, Any] = json.loads(clean_text)
                if not isinstance(parsed_json, dict):
                    raise ValueError(f"Expected JSON dictionary object, got {type(parsed_json).__name__}")

                logger.info("JSON successfully parsed and validated.")
                return parsed_json

            except (json.JSONDecodeError, ValueError) as json_err:
                logger.error(f"JSON parsing failed on attempt {attempt}: {json_err}")
                if attempt < self.max_retries:
                    current_user_prompt = (
                        f"{user_prompt}\n\n[SYSTEM NOTICE]: Your previous attempt returned malformed JSON: {str(json_err)}. "
                        "Please regenerate your answer ensuring strict, valid JSON without any leading or trailing text."
                    )
                    time.sleep(1.0)
                else:
                    logger.critical("Exhausted all JSON parse attempts. Returning structured fallback dict.")
                    raise RuntimeError(f"Failed to generate valid JSON output from Groq API after {self.max_retries} attempts.") from json_err

        return {}

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns real-time usage and monitoring telemetry metrics.
        """
        avg_latency = sum(self._latencies_ms) / len(self._latencies_ms) if self._latencies_ms else 0.0
        return {
            "requests_count": self.requests_count,
            "tokens_used": self.tokens_used,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "average_latency_ms": round(avg_latency, 2),
            "primary_model": self.primary_model,
            "fallback_model": self.fallback_model,
            "mode": "SIMULATION" if self._is_mock_key else "LIVE_LPU",
        }
