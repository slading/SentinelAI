import os
import yaml
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    app_name: str = Field(default="SentinelAI Compliance Pipeline", alias="APP_NAME")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=True, alias="DEBUG")
    
    groq_api_key: str = Field(default="gsk_mock", alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama3-70b-8192", alias="GROQ_MODEL")
    mock_groq: bool = Field(default=True, alias="MOCK_GROQ")
    
    audit_log_path: str = Field(default="SentinelAI/logs/audit.log", alias="AUDIT_LOG_PATH")

    model_config = SettingsConfigDict(env_file=str(BASE_DIR / ".env"), extra="ignore")

    def load_thresholds(self) -> dict:
        thresholds_file = BASE_DIR / "config" / "thresholds.yaml"
        if not thresholds_file.exists():
            return {}
        with open(thresholds_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

settings = Settings()
thresholds = settings.load_thresholds()
