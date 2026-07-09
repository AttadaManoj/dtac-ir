"""
DTAC-IR Core Configuration
Loads all settings from environment variables with validation.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Application
    app_name: str = "DTAC-IR"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # API
    api_v1_prefix: str = "/api/v1"
    secret_key: str = Field(..., min_length=32)
    access_token_expire_minutes: int = 30

    # Database
    database_url: str
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "dtac_ir"
    postgres_user: str = "dtac_user"
    postgres_password: str = "dtac_password"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Network Capture
    capture_interface: str = "eth0"
    capture_filter: str = "tcp or udp"
    packet_buffer_size: int = 1000

    # ML
    model_path: str = "./ml/models/ids_model.pkl"
    scaler_path: str = "./ml/models/scaler.pkl"
    ml_confidence_threshold: float = 0.75

    # Trust Scoring
    trust_score_decay_rate: float = 0.05
    trust_score_min: int = 0
    trust_score_max: int = 100
    trust_alert_threshold: int = 30

    # Automated Response
    auto_block_enabled: bool = False
    auto_block_threshold: int = 10
    quarantine_duration_minutes: int = 60

    # Alerting
    slack_webhook_url: str = ""
    alert_email: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance — call this everywhere instead of instantiating directly."""
    return Settings()
