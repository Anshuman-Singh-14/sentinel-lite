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

    @field_validator("secret_key")
    @classmethod
    def not_placeholder(cls, value: str) -> str:
        if value.startswith("CHANGE_ME"):
            raise ValueError("set a real SECRET_KEY in .env")
        return value

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"

    @property
    def db_file(self) -> Path:
        """A relative DATABASE_PATH is relative to the project folder, not the current directory."""
        return self.database_path if self.database_path.is_absolute() else ROOT / self.database_path


settings = Settings()
