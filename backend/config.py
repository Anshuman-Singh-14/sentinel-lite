"""Settings read from environment variables or the .env file."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

# Cloudflare's published Turnstile test keys: the widget and the server check always pass.
TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA"
TURNSTILE_TEST_SECRET_KEY = "1x0000000000000000000000000000000AA"


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

    # Email (account requests, approvals, password emails). Any SMTP server works; production
    # uses Resend (smtp.resend.com, username "resend", password = API key). Empty SMTP_HOST in
    # dev prints every email to the console instead of sending it.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = "Sentinel Lite <no-reply@sentinellite.com>"
    # The address people open the site at, used to build links in emails.
    public_url: str = ""
    # Cloudflare Turnstile (the "are you human" check on the account request form).
    turnstile_site_key: str = ""
    turnstile_secret_key: str = ""

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
    def public_base_url(self) -> str:
        return (self.public_url or "http://localhost:8000").rstrip("/")

    @property
    def turnstile_keys(self) -> tuple[str, str]:
        """(site key, secret key). In dev, empty keys fall back to Cloudflare's always-pass test keys."""
        if not self.is_prod and not (self.turnstile_site_key and self.turnstile_secret_key):
            return TURNSTILE_TEST_SITE_KEY, TURNSTILE_TEST_SECRET_KEY
        return self.turnstile_site_key, self.turnstile_secret_key

    @property
    def mail_enabled(self) -> bool:
        """In dev, emails without an SMTP server are printed, so mail always "works"."""
        return bool(self.smtp_host) or not self.is_prod

    @property
    def access_requests_enabled(self) -> bool:
        """In production the request form needs real email, Turnstile and a public URL for links."""
        if not self.is_prod:
            return True
        return bool(self.smtp_host and self.turnstile_site_key and self.turnstile_secret_key and self.public_url)

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
