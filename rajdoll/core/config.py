"""Application settings loaded from environment variables (and an optional .env file)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RAJDOLL_", env_file=".env", extra="ignore")

    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://rajdoll_app@db:5432/rajdoll"
    secrets_dir: str = "/secrets"
    tools_url: str = "http://tools:9000"
    proxy_url: str = "http://tools:8081"
    tools_token: str = ""
    tools_db_password: str = ""
    llm_base_url: str = "http://host.docker.internal:1234/v1"
    llm_model: str = "qwen3-4b"
    worker_heartbeat_seconds: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
