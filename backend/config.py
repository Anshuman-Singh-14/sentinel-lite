"""Settings read from environment variables or the .env file."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    app_env: Literal["dev", "prod"] = "dev"
    secret_key: str = Field(min_length=32)
    domain: str = "localhost"
    database_path: Path = Path("sentinel.db")
    # Every activity event (logins, scans, admin changes) is also appended to this file.
    activity_log_path: Path = Path("logs/activity.log")
    # Comma-separated sites that may call the API from another origin (the frontend on
    # sentinellite.com calling api.sentinellite.com). Empty means same-origin only.
    allowed_origins: str = ""

    @field_validator("secret_key")
    @classmethod
    def not_placeholder(cls, value: str) -> str:
        if value.startswith("CHANGE_ME"):
            raise ValueError("set a real SECRET_KEY in .env")
        return value

    @field_validator("allowed_origins")
    @classmethod
    def no_wildcard(cls, value: str) -> str:
        # The session cookie is sent with credentials, and "*" would let any site use it.
        if "*" in value:
            raise ValueError("ALLOWED_ORIGINS must list exact origins, not *")
        return value

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"

    @property
    def db_file(self) -> Path:
        """A relative DATABASE_PATH is relative to the project folder, not the current directory."""
        return self.database_path if self.database_path.is_absolute() else ROOT / self.database_path

    @property
    def activity_log_file(self) -> Path:
        """Like db_file: a relative ACTIVITY_LOG_PATH is relative to the project folder."""
        path = self.activity_log_path
        return path if path.is_absolute() else ROOT / path


settings = Settings()
