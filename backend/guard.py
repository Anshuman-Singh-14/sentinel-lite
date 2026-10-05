"""Safety checks shared by the tools: target allowlist, rate limit, activity log.

STUB: Role 1 implements this file. Until then check_target() refuses every
target ("fail closed"), so nothing can be scanned without approval.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.models import User


def check_target(db: Session, host: str) -> str:
    """Return the IP address to scan for `host`, or raise 403 if it isn't allowed.

    To do (Role 1): host must be in the AllowedTarget table; in production also
    block localhost, private IPs and the server's own IP.
    """
    raise HTTPException(403, "Target approval is not implemented yet")


def check_rate_limit(user: User) -> None:
    """Raise 429 if the user has started too many scans in the last minute. To do (Role 1)."""


def log_activity(db: Session, user: User, action: str, detail: str = "") -> None:
    """Record who did what in the Activity table. To do (Role 1)."""
