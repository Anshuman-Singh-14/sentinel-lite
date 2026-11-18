"""What the homepage and the sidebar badge show: things waiting for someone.

Admins get counts of what needs their action (pending account and website requests,
decision emails that failed) and the newest of those as a short list. Everyone gets
their own recent website requests and whether their account still needs an email.

Read-only, so nothing is logged.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.auth import current_user
from backend.db import get_db
from backend.models import AccessRequest, TargetRequest, User, as_utc, utcnow

router = APIRouter(tags=["notifications"])

ITEM_LIMIT = 10  # newest entries in the admin's list
RECENT_DECISIONS = timedelta(days=7)  # how long an approval or rejection stays on a user's homepage
# Only decision emails can be resent from the admin page, so only those need an admin's action.
DECIDED = ("approved", "rejected")
EMAIL_KINDS = {"approved": "Approval", "rejected": "Rejection"}


def count(db: Session, query) -> int:
    return db.scalar(select(func.count()).select_from(query.subquery()))


def my_requests(db: Session, user: User) -> list[dict]:
    """The user's website requests that are pending, or were decided in the last 7 days.

    reviewed_by is left out on purpose: it is an admin's username, half of a login.
    """
    since = utcnow() - RECENT_DECISIONS
    rows = db.scalars(
        select(TargetRequest)
        .where(TargetRequest.user_id == user.id)
        .where(or_(TargetRequest.status == "pending",
                   TargetRequest.status.in_(DECIDED) & (TargetRequest.reviewed_at >= since)))
        .order_by(TargetRequest.id.desc())
    )
    return [
        {
            "id": row.id,
            "host": row.host,
            "status": row.status,
            "reject_reason": row.reject_reason,
            "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


def admin_notifications(db: Session) -> dict:
    pending_accounts = select(AccessRequest).where(AccessRequest.status == "pending")  # unverified ones don't count
    pending_websites = select(TargetRequest).where(TargetRequest.status == "pending")
    failed_accounts = select(AccessRequest).where(AccessRequest.email_status == "failed",
                                                  AccessRequest.status.in_(DECIDED))
    failed_websites = select(TargetRequest).where(TargetRequest.email_status == "failed",
                                                  TargetRequest.status.in_(DECIDED))
    usernames = dict(db.execute(select(User.id, User.username)).all())

    def requester(row: TargetRequest) -> str:
        return usernames.get(row.user_id, "(deleted user)")

    def newest(query, *order):
        # Each kind is newest first and capped, so merging them and keeping 10 gives the newest 10 overall.
        return db.scalars(query.order_by(*order).limit(ITEM_LIMIT))

    def item(kind: str, request_type: str, row, title: str, when, decision: str | None = None) -> dict:
        # request_type: which admin section handles it ("account" or "website"); decision: for a
        # failed email, the tab it is listed under ("approved" or "rejected").
        return {"kind": kind, "request_type": request_type, "id": row.id, "title": title, "decision": decision,
                "created_at": as_utc(when)}

    items = []
    for row in newest(pending_accounts, AccessRequest.created_at.desc()):
        items.append(item("account_request", "account", row, f"{row.username} requested an account", row.created_at))
    for row in newest(pending_websites, TargetRequest.created_at.desc()):
        items.append(item("website_request", "website", row, f"{requester(row)} requested {row.host}",
                          row.created_at))
    for row in newest(failed_accounts, AccessRequest.reviewed_at.desc()):
        items.append(item("email_failed", "account", row, f"{EMAIL_KINDS[row.status]} email to {row.username} failed",
                          row.reviewed_at or row.created_at, row.status))
    for row in newest(failed_websites, TargetRequest.reviewed_at.desc()):
        title = f"{EMAIL_KINDS[row.status]} email to {requester(row)} ({row.host}) failed"
        items.append(item("email_failed", "website", row, title, row.reviewed_at or row.created_at, row.status))
    items.sort(key=lambda entry: entry["created_at"], reverse=True)

    counts = {
        "account_requests_pending": count(db, pending_accounts),
        "website_requests_pending": count(db, pending_websites),
        "emails_failed": count(db, failed_accounts) + count(db, failed_websites),
    }
    newest_items = [entry | {"created_at": entry["created_at"].isoformat()} for entry in items[:ITEM_LIMIT]]
    return counts | {"total": sum(counts.values()), "items": newest_items}


@router.get("/api/notifications")
def notifications(user: User = Depends(current_user), db: Session = Depends(get_db)):
    mine = {"my_requests": my_requests(db, user), "needs_email": not user.email}
    if user.role == "admin":
        return admin_notifications(db) | mine
    return mine
