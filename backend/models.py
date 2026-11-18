"""Database tables."""

from datetime import UTC, datetime

from sqlalchemy import JSON, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """SQLite gives times back without a timezone; they are always stored in UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(10), default="user")  # "admin" or "user"
    is_active: Mapped[bool] = mapped_column(default=True)
    # Required for role "user" (older accounts may not have one yet). index=True makes the
    # unique rule a named index, which migrate.py can also add to an existing database.
    email: Mapped[str | None] = mapped_column(String(254), unique=True, index=True)
    email_verified: Mapped[bool] = mapped_column(default=False)
    # Set for generated or admin-reset passwords: the user must choose their own before anything else.
    must_change_password: Mapped[bool] = mapped_column(default=False)
    # Admins only: shown in approval and rejection emails, so the username never is.
    display_name: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AccessRequest(Base):
    """A visitor asking for an account. An admin approves or rejects it once the email is confirmed.

    status: "unverified" (email not confirmed yet), "pending", "approved" or "rejected".
    """

    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), index=True)
    email: Mapped[str] = mapped_column(String(254), index=True)
    # bcrypt hash of the password the visitor chose, never the password itself. Empty when
    # they asked for a generated one, and cleared once the request is decided.
    password_hash: Mapped[str | None] = mapped_column(String(100))
    wants_generated: Mapped[bool] = mapped_column(default=False)
    remarks: Mapped[str] = mapped_column(String(500), default="")
    terms_version: Mapped[str] = mapped_column(String(20))
    agreed_at: Mapped[datetime] = mapped_column(default=utcnow)
    ip: Mapped[str] = mapped_column(String(45), default="")
    status: Mapped[str] = mapped_column(String(10), default="unverified", index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(32))
    reviewed_at: Mapped[datetime | None]
    reject_reason: Mapped[str] = mapped_column(String(300), default="")
    email_status: Mapped[str] = mapped_column(String(10), default="not_sent")  # "not_sent", "sent" or "failed"
    email_error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class EmailToken(Base):
    """A one-time link sent by email. Only the SHA-256 of the token is stored, so a copy
    of the database can't be used to confirm anyone's email."""

    __tablename__ = "email_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    purpose: Mapped[str] = mapped_column(String(20))  # "verify_request" or "verify_user_email"
    ref_id: Mapped[int]  # the AccessRequest id or the User id, depending on purpose
    email: Mapped[str] = mapped_column(String(254))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class AllowedTarget(Base):
    """A host an admin has approved for active scans (port scan, website check).

    shared: everyone can scan it (targets admins add directly). A private target (approved
    from a user's request) can only be scanned by the users in TargetAccess, and by admins.
    """

    __tablename__ = "allowed_targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(253), unique=True)
    note: Mapped[str] = mapped_column(String(200), default="")
    added_by: Mapped[str] = mapped_column(String(32))
    shared: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TargetAccess(Base):
    """One user allowed to scan one private target."""

    __tablename__ = "target_access"
    __table_args__ = (UniqueConstraint("target_id", "user_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("allowed_targets.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    granted_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TargetRequest(Base):
    """A user asking to scan a website. An admin approves or rejects it (see admin.py).

    status: "pending", "approved", "rejected" or "cancelled" (by the user).
    email_status: "not_sent", "sent", "failed" or "no_email" (the user has no address).
    """

    __tablename__ = "target_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    host: Mapped[str] = mapped_column(String(253))
    reason: Mapped[str] = mapped_column(String(500), default="")
    permission_confirmed_at: Mapped[datetime] = mapped_column(default=utcnow)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)
    # The IPv4 addresses the host had when the request was made, comma-separated.
    resolved_ips: Mapped[str] = mapped_column(String(500), default="")
    reviewed_by: Mapped[str | None] = mapped_column(String(32))
    reviewed_at: Mapped[datetime | None]
    reject_reason: Mapped[str] = mapped_column(String(300), default="")
    email_status: Mapped[str] = mapped_column(String(10), default="not_sent")
    email_error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Scan(Base):
    """One tool run and its results, shown in the user's history."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tool: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(253))
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Activity(Base):
    """Who did what, when, and from where. Shown to admins.

    username is "system" for events with no person behind them (startup, migrations).
    """

    __tablename__ = "activity"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(50))
    detail: Mapped[str] = mapped_column(String(300), default="")
    ip: Mapped[str] = mapped_column(String(45), default="-")  # "-" outside a web request
    result: Mapped[str] = mapped_column(String(10), default="ok")  # "ok", "fail" or "denied"
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
