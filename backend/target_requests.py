"""Users asking for permission to scan a website (a "target").

The flow:
1. A logged-in user fills in the form on the My websites page: the host, why they want to
   scan it, and a tick confirming they own it or have the owner's written permission.
   The host is looked up straight away, and the addresses it had are saved with the request.
2. An admin approves or rejects it (see admin.py) and the user gets an email.
3. Approving makes the target private to the users given access (TargetAccess), so
   one person's approval never lets everyone else scan their website.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from backend import guard
from backend.auth import current_user
from backend.db import get_db
from backend.models import AllowedTarget, TargetAccess, TargetRequest, User, utcnow
from backend.validation import Hostname

router = APIRouter(tags=["website requests"])

PERMISSION_TEXT = "I own this website, or I have written permission from its owner to test it"

# Only requests that were really created count, so a typo or a refused host costs nothing.
request_limiter = guard.RateLimiter(5, window=3600)  # per user per hour


class NewTargetRequest(BaseModel):
    host: Hostname
    reason: str = Field(default="", max_length=500)
    confirm: bool

    @model_validator(mode="after")
    def check_confirm(self):
        if not self.confirm:
            raise ValueError(f"you must confirm: {PERMISSION_TEXT}")
        return self


def split_ips(text: str) -> list[str]:
    return [ip for ip in text.split(",") if ip]


def request_to_dict(target_request: TargetRequest) -> dict:
    return {
        "id": target_request.id,
        "host": target_request.host,
        "reason": target_request.reason,
        "status": target_request.status,
        "resolved_ips": split_ips(target_request.resolved_ips),
        "reject_reason": target_request.reject_reason,
        "created_at": target_request.created_at.isoformat(),
        "reviewed_at": target_request.reviewed_at.isoformat() if target_request.reviewed_at else None,
    }


@router.post("/api/target-requests")
def create_target_request(body: NewTargetRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if request_limiter.is_full(user.id):
        guard.rate_limited(db, user.username, "target_request")
        raise HTTPException(429, "Too many website requests. Please try again in an hour.")

    target = db.scalar(select(AllowedTarget).where(AllowedTarget.host == body.host))
    if target is not None and guard.can_scan(db, target, user):
        raise HTTPException(409, "You can already scan this website")
    pending = select(TargetRequest).where(
        TargetRequest.user_id == user.id, TargetRequest.host == body.host, TargetRequest.status == "pending"
    )
    if db.scalar(pending):
        raise HTTPException(409, f"You already have a pending request for {body.host}")

    ips = guard.resolve(body.host)  # 400 if it doesn't resolve
    # The same rule as guard.check_target: no point asking for something that is never scanned.
    bad_ip = guard.internal_address(ips)
    if bad_ip:
        raise HTTPException(400, f"{body.host} points to an internal address ({bad_ip}), which is never scanned.")

    target_request = TargetRequest(
        user_id=user.id, host=body.host, reason=body.reason.strip(), permission_confirmed_at=utcnow(),
        resolved_ips=",".join(ips)[:500],
    )
    db.add(target_request)
    db.commit()
    request_limiter.add(user.id)
    guard.log_activity(db, user, "target_requested", body.host)
    return request_to_dict(target_request)


@router.get("/api/target-requests")
def my_target_requests(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(TargetRequest).where(TargetRequest.user_id == user.id).order_by(TargetRequest.id.desc()).limit(200)
    )
    return [request_to_dict(row) for row in rows]


@router.post("/api/target-requests/{request_id}/cancel")
def cancel_target_request(request_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    target_request = db.get(TargetRequest, request_id)
    # Someone else's request gets the same answer as a missing one.
    if target_request is None or target_request.user_id != user.id:
        raise HTTPException(404, "Request not found")
    # The status check is in the UPDATE, so a cancel can't undo an approval made at the same moment.
    cancelled = db.execute(
        update(TargetRequest)
        .where(TargetRequest.id == request_id, TargetRequest.status == "pending")
        .values(status="cancelled")
    )
    if cancelled.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Only pending requests can be cancelled")
    db.commit()
    guard.log_activity(db, user, "target_request_cancelled", target_request.host)
    db.refresh(target_request)
    return request_to_dict(target_request)


@router.get("/api/targets/mine")
def my_targets(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """The targets this user can scan: shared ones, private ones they were given, or all for an admin."""
    query = select(AllowedTarget).order_by(AllowedTarget.host)
    if user.role != "admin":
        mine = select(TargetAccess.target_id).where(TargetAccess.user_id == user.id)
        query = query.where(or_(AllowedTarget.shared.is_(True), AllowedTarget.id.in_(mine)))
    return [
        {"id": t.id, "host": t.host, "note": t.note, "access": "shared" if t.shared else "private"}
        for t in db.scalars(query)
    ]
