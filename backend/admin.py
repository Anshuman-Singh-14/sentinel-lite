"""Admin routes: manage users, review account and website requests, approve scan targets, and view
or download the activity log.

The log exports take ?view=1 to open in a browser tab instead of downloading."""

import csv
import io
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from backend import guard, mailer
from backend.access_requests import deliver
from backend.activity_log import format_line
from backend.auth import generate_password, hash_password, require_admin, user_to_dict
from backend.db import get_db
from backend.guard import log_activity, mask_email
from backend.models import (AccessRequest, Activity, AllowedTarget, EmailToken, Scan, TargetAccess, TargetRequest,
                            User, utcnow)
from backend.reports import safe_cell
from backend.validation import DisplayName, Email, Hostname, Password, Username

router = APIRouter(prefix="/api/admin", tags=["admin"])

ACTIVITY_LIMIT = 200  # newest entries shown on the admin page (the downloads have all of them)
ACTIVITY_PAGE_MAX = 5000  # most entries the full-page log (/admin/activity) can ask for
ACTIVITY_CSV_COLUMNS = ["id", "time_utc", "ip", "username", "action", "result", "detail"]


class NewUser(BaseModel):
    username: Username
    password: Password
    role: Literal["admin", "user"] = "user"
    email: Email | None = None

    @model_validator(mode="after")
    def users_need_email(self):
        if self.role == "user" and self.email is None:
            raise ValueError("an email address is required for role user")
        return self


class UserChange(BaseModel):
    role: Literal["admin", "user"] | None = None
    is_active: bool | None = None
    password: Password | None = None
    # No email field: people change their own email (with a link to the new address), see access_requests.py.
    display_name: DisplayName | None = None  # admins only; "" clears it


class UserDeletion(BaseModel):
    confirm_username: str = Field(max_length=32)


class NewTarget(BaseModel):
    host: Hostname
    note: str = Field(default="", max_length=200)


class TargetChange(BaseModel):
    shared: bool


def target_to_dict(db: Session, target: AllowedTarget) -> dict:
    """Private targets also list who can scan them."""
    access = []
    if not target.shared:
        rows = db.execute(
            select(User.id, User.username).join(TargetAccess, TargetAccess.user_id == User.id)
            .where(TargetAccess.target_id == target.id).order_by(User.username)
        )
        access = [{"user_id": user_id, "username": username} for user_id, username in rows]
    return {
        "id": target.id,
        "host": target.host,
        "note": target.note,
        "added_by": target.added_by,
        "shared": target.shared,
        "access": access,
        "created_at": target.created_at.isoformat(),
    }


# --- Users ---


def check_email_free(db: Session, email: str | None, user_id: int | None = None) -> None:
    """Raise 409 if another user already has this email address."""
    if email is None:
        return
    other = db.scalar(select(User).where(User.email == email))
    if other is not None and other.id != user_id:
        raise HTTPException(409, f"{email} is already used by {other.username}")


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.username))
    return [user_to_dict(user) | {"created_at": user.created_at.isoformat()} for user in users]


@router.post("/users")
def create_user(body: NewUser, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, f"User {body.username} already exists")
    check_email_free(db, body.email)
    user = User(
        username=body.username, password_hash=hash_password(body.password), role=body.role, email=body.email
    )
    db.add(user)
    db.commit()
    log_activity(db, admin, "user_created", f"{user.username} ({user.role})")
    return user_to_dict(user)


@router.patch("/users/{user_id}")
def change_user(
    user_id: int, body: UserChange, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    # Stops the last admin from locking everyone out by accident.
    if user.id == admin.id and (body.role == "user" or body.is_active is False):
        raise HTTPException(400, "You can't remove your own admin rights or deactivate yourself")
    # Existing users without an email keep working; only turning someone into a user needs one.
    if body.role == "user" and user.role != "user" and not user.email:
        raise HTTPException(
            400, "This account needs an email address before it can be changed to role user. "
                 "They can add one under Change email.")
    if body.display_name is not None:
        if (body.role or user.role) != "admin":
            raise HTTPException(400, "Only admins have a display name")
        # Display names are emailed to the public, and a username is half of a login.
        if body.display_name and db.scalar(
            select(User).where(func.lower(User.username) == body.display_name.lower())
        ):
            raise HTTPException(400, "A display name can't be the same as a username")

    # (action, detail) for each thing that really changes, logged once the change is saved.
    events = []
    if body.role is not None and body.role != user.role:
        events.append(("user_role_changed", f"{user.username}: {user.role} -> {body.role}"))
        user.role = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        events.append(("user_activated" if body.is_active else "user_deactivated", user.username))
        user.is_active = body.is_active
    if body.password is not None:
        user.password_hash = hash_password(body.password)
        user.must_change_password = True  # the admin knows it, so the user picks a new one
        events.append(("user_password_reset", user.username))
    if body.display_name is not None and (body.display_name or None) != user.display_name:
        user.display_name = body.display_name or None  # "" clears it
        shown = f"'{user.display_name}'" if user.display_name else "cleared"
        events.append(("user_display_name_changed", f"{user.username}: {shown}"))
    db.commit()
    for action, detail in events:
        log_activity(db, admin, action, detail)
    return user_to_dict(user)


def is_last_active_admin(db: Session, user: User) -> bool:
    if user.role != "admin" or not user.is_active:
        return False
    active_admins = db.scalar(select(func.count()).where(User.role == "admin", User.is_active.is_(True)))
    return active_admins <= 1


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int, body: UserDeletion, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Delete an account, its scan history, its website access and its website requests.
    Account requests and activity entries stay: they are history and keep the username as plain text."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "You can't delete your own account")
    if body.confirm_username != user.username:
        raise HTTPException(400, f"Type the username {user.username} exactly to confirm")
    # The caller is always another active admin, so this is a safety net that should never trip.
    if is_last_active_admin(db, user):
        raise HTTPException(400, "You can't delete the last active admin")

    scans = db.execute(delete(Scan).where(Scan.user_id == user.id)).rowcount
    db.execute(delete(TargetAccess).where(TargetAccess.user_id == user.id))
    db.execute(delete(TargetRequest).where(TargetRequest.user_id == user.id))
    db.execute(delete(EmailToken).where(EmailToken.purpose == "verify_user_email", EmailToken.ref_id == user.id))
    username, role = user.username, user.role
    db.delete(user)
    db.commit()
    log_activity(db, admin, "user_deleted", f"{username} ({role}, {scans} scans deleted)")
    return {"ok": True}


def reviewer_name(db: Session, reviewed: AccessRequest | TargetRequest) -> str | None:
    """The reviewing admin's display name as it is now (None if unset or the admin is gone)."""
    reviewer = db.scalar(select(User).where(User.username == reviewed.reviewed_by))
    return reviewer.display_name if reviewer else None


# --- Account requests (see access_requests.py for how they are made) ---


class Rejection(BaseModel):
    reason: str = Field(default="", max_length=300)


def request_to_dict(access_request: AccessRequest) -> dict:
    return {
        "id": access_request.id,
        "username": access_request.username,
        "email": access_request.email,
        "wants_generated": access_request.wants_generated,
        "remarks": access_request.remarks,
        "ip": access_request.ip,
        "status": access_request.status,
        "created_at": access_request.created_at.isoformat(),
        "reviewed_by": access_request.reviewed_by,
        "reviewed_at": access_request.reviewed_at.isoformat() if access_request.reviewed_at else None,
        "reject_reason": access_request.reject_reason,
        "email_status": access_request.email_status,
        "email_error": access_request.email_error,
    }


def claim(db: Session, model: type[AccessRequest | TargetRequest], request_id: int, admin: User, new_status: str,
          **values) -> AccessRequest | TargetRequest:
    """Move a pending request (an account or a website request) to approved/rejected, or
    raise 409 if it isn't pending any more.

    The status check is part of the UPDATE itself, so when two admins click at the same
    moment exactly one of them gets the request (the other's UPDATE changes 0 rows).
    """
    if db.get(model, request_id) is None:
        raise HTTPException(404, "Request not found")
    result = db.execute(
        update(model)
        .where(model.id == request_id, model.status == "pending")
        # email_status now tracks the decision email, not the earlier confirmation email.
        .values(status=new_status, reviewed_by=admin.username, reviewed_at=utcnow(), email_status="not_sent",
                email_error="", **values)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "This request isn't waiting for review (another admin may have just handled it)")
    return db.get(model, request_id, populate_existing=True)


@router.get("/access-requests")
def list_access_requests(
    status: Literal["pending", "approved", "rejected"] = "pending",
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Unconfirmed ("unverified") requests are never shown: anyone could have typed that email."""
    rows = db.scalars(
        select(AccessRequest).where(AccessRequest.status == status).order_by(AccessRequest.id.desc()).limit(200)
    )
    return [request_to_dict(row) for row in rows]


@router.post("/access-requests/{request_id}/approve")
def approve_request(
    request_id: int, background: BackgroundTasks, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    access_request = claim(db, AccessRequest, request_id, admin, "approved")
    if db.scalar(select(User).where(User.username == access_request.username)):
        db.rollback()
        raise HTTPException(409, f"The username {access_request.username} has been taken since the request was made")
    if db.scalar(select(User).where(User.email == access_request.email)):
        db.rollback()
        raise HTTPException(409, f"{access_request.email} is already used by another account")

    password = None
    if access_request.password_hash is None:
        password = generate_password()
    user = User(
        username=access_request.username,
        password_hash=access_request.password_hash or hash_password(password),
        role="user",
        email=access_request.email,
        email_verified=True,  # they opened the link we emailed
        must_change_password=password is not None,
    )
    db.add(user)
    access_request.password_hash = None  # the user row has it now
    db.commit()
    log_activity(db, admin, "access_request_approved", f"{user.username} ({mask_email(user.email)})")
    if password:
        email = mailer.approved_generated(user.username, password, admin.display_name)
    else:
        email = mailer.approved(user.username, admin.display_name)
    background.add_task(deliver, access_request.id, user.username, user.email, *email)
    return request_to_dict(access_request)


@router.post("/access-requests/{request_id}/reject")
def reject_request(
    request_id: int,
    background: BackgroundTasks,
    body: Rejection | None = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    reason = body.reason.strip() if body else ""
    access_request = claim(db, AccessRequest, request_id, admin, "rejected", reject_reason=reason,
                           password_hash=None)
    db.commit()
    log_activity(db, admin, "access_request_rejected", access_request.username)
    email = mailer.rejected(access_request.username, reason, admin.display_name)
    background.add_task(deliver, access_request.id, access_request.username, access_request.email, *email)
    return request_to_dict(access_request)


@router.post("/access-requests/{request_id}/resend-email")
def resend_request_email(
    request_id: int, background: BackgroundTasks, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Try the decision email again after it failed."""
    access_request = db.get(AccessRequest, request_id)
    if access_request is None:
        raise HTTPException(404, "Request not found")
    if access_request.email_status != "failed":
        raise HTTPException(409, "Only failed emails can be resent")

    reviewer = reviewer_name(db, access_request)
    if access_request.status == "rejected":
        email = mailer.rejected(access_request.username, access_request.reject_reason, reviewer)
    elif access_request.status == "approved":
        user = db.scalar(select(User).where(User.username == access_request.username))
        # A deleted account's username can be taken again by someone else: never send them this email.
        if user is None or user.email != access_request.email:
            raise HTTPException(409, "That account no longer exists")
        if access_request.wants_generated:
            # The first temporary password was never stored, so make a new one.
            if not user.must_change_password:
                raise HTTPException(409, f"{user.username} has already logged in and chosen a password")
            password = generate_password()
            user.password_hash = hash_password(password)
            email = mailer.approved_generated(user.username, password, reviewer)
        else:
            email = mailer.approved(user.username, reviewer)
    else:
        raise HTTPException(409, "There is no email to resend for this request")

    access_request.email_status = "not_sent"
    access_request.email_error = ""
    db.commit()
    log_activity(db, admin, "access_request_email_resent", access_request.username)
    background.add_task(deliver, access_request.id, access_request.username, access_request.email, *email)
    return request_to_dict(access_request)


# --- Website requests (see target_requests.py for how they are made) ---


def current_ips(host: str) -> list[str]:
    """What the host resolves to now, so an admin can see if it changed since the request."""
    try:
        return guard.resolve(host)
    except HTTPException:
        return []


def target_request_to_dict(db: Session, target_request: TargetRequest, with_current_ips: bool = False) -> dict:
    requester = db.get(User, target_request.user_id)
    resolved = [ip for ip in target_request.resolved_ips.split(",") if ip]
    row = {
        "id": target_request.id,
        "username": requester.username if requester else "(deleted)",
        "host": target_request.host,
        "reason": target_request.reason,
        "status": target_request.status,
        "resolved_ips": resolved,
        "created_at": target_request.created_at.isoformat(),
        "reviewed_by": target_request.reviewed_by,
        "reviewed_at": target_request.reviewed_at.isoformat() if target_request.reviewed_at else None,
        "reject_reason": target_request.reject_reason,
        "email_status": target_request.email_status,
        "email_error": target_request.email_error,
    }
    if with_current_ips:
        now = current_ips(target_request.host)
        row["current_ips"] = now
        row["ips_changed"] = sorted(now) != sorted(resolved)
    return row


def requester_of(db: Session, target_request: TargetRequest) -> User:
    user = db.get(User, target_request.user_id)
    if user is None:
        raise HTTPException(409, "The user who asked no longer exists")
    return user


def email_requester(db: Session, background: BackgroundTasks, target_request: TargetRequest, user: User,
                    email: tuple[str, str]) -> None:
    """Send the decision email, or mark it "no_email" when the user has no address to send to."""
    if not user.email:
        target_request.email_status = "no_email"
        db.commit()
        return
    background.add_task(deliver, target_request.id, user.username, user.email, *email, model=TargetRequest)


@router.get("/target-requests")
def list_target_requests(
    status: Literal["pending", "approved", "rejected", "cancelled"] = "pending",
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rows = list(db.scalars(
        select(TargetRequest).where(TargetRequest.status == status).order_by(TargetRequest.id.desc()).limit(200)
    ))
    # Looking every host up again is only worth it while a decision is still to be made.
    return [target_request_to_dict(db, row, with_current_ips=status == "pending") for row in rows]


@router.post("/target-requests/{request_id}/approve")
def approve_target_request(
    request_id: int, background: BackgroundTasks, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    target_request = claim(db, TargetRequest, request_id, admin, "approved")
    user = db.get(User, target_request.user_id)
    if user is None:
        db.rollback()
        raise HTTPException(409, "The user who asked no longer exists")

    target = db.scalar(select(AllowedTarget).where(AllowedTarget.host == target_request.host))
    if target is None:
        # A new target approved for one person is private to them.
        target = AllowedTarget(host=target_request.host, note=f"requested by {user.username}",
                               added_by=admin.username, shared=False)
        db.add(target)
        db.flush()  # gives the target its id for the access row
    # An existing target keeps its shared setting; the access row counts if it is (or becomes) private.
    has_access = db.scalar(
        select(TargetAccess).where(TargetAccess.target_id == target.id, TargetAccess.user_id == user.id)
    )
    if has_access is None:
        db.add(TargetAccess(target_id=target.id, user_id=user.id, granted_by=admin.username))
    db.commit()
    log_activity(db, admin, "target_request_approved", f"{target.host} for {user.username}")
    email_requester(db, background, target_request, user,
                    mailer.target_approved(user.username, target.host, admin.display_name))
    return target_request_to_dict(db, target_request)


@router.post("/target-requests/{request_id}/reject")
def reject_target_request(
    request_id: int,
    background: BackgroundTasks,
    body: Rejection | None = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    reason = body.reason.strip() if body else ""
    target_request = claim(db, TargetRequest, request_id, admin, "rejected", reject_reason=reason)
    db.commit()
    user = db.get(User, target_request.user_id)
    log_activity(db, admin, "target_request_rejected",
                 f"{target_request.host} for {user.username if user else '(deleted)'}")
    if user is not None:
        email_requester(db, background, target_request, user,
                        mailer.target_rejected(user.username, target_request.host, reason, admin.display_name))
    return target_request_to_dict(db, target_request)


@router.post("/target-requests/{request_id}/resend-email")
def resend_target_request_email(
    request_id: int, background: BackgroundTasks, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Try the decision email again after it failed."""
    target_request = db.get(TargetRequest, request_id)
    if target_request is None:
        raise HTTPException(404, "Request not found")
    if target_request.email_status != "failed":
        raise HTTPException(409, "Only failed emails can be resent")
    user = requester_of(db, target_request)
    reviewer = reviewer_name(db, target_request)
    if target_request.status == "approved":
        email = mailer.target_approved(user.username, target_request.host, reviewer)
    elif target_request.status == "rejected":
        email = mailer.target_rejected(user.username, target_request.host, target_request.reject_reason, reviewer)
    else:
        raise HTTPException(409, "There is no email to resend for this request")

    target_request.email_status = "not_sent"
    target_request.email_error = ""
    db.commit()
    log_activity(db, admin, "target_request_email_resent", f"{target_request.host} for {user.username}")
    email_requester(db, background, target_request, user, email)
    return target_request_to_dict(db, target_request)


# --- Allowed targets ---


def get_target(db: Session, target_id: int) -> AllowedTarget:
    target = db.get(AllowedTarget, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    return target


@router.get("/targets")
def list_targets(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [target_to_dict(db, t) for t in db.scalars(select(AllowedTarget).order_by(AllowedTarget.host))]


@router.post("/targets")
def add_target(body: NewTarget, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(AllowedTarget).where(AllowedTarget.host == body.host)):
        raise HTTPException(409, f"{body.host} is already approved")
    # Targets an admin adds here can be scanned by everyone.
    target = AllowedTarget(host=body.host, note=body.note, added_by=admin.username, shared=True)
    db.add(target)
    db.commit()
    log_activity(db, admin, "target_added", target.host)
    return target_to_dict(db, target)


@router.patch("/targets/{target_id}")
def change_target(
    target_id: int, body: TargetChange, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Shared: everyone can scan it. Private: only the users with access (and admins)."""
    target = get_target(db, target_id)
    if target.shared != body.shared:
        target.shared = body.shared
        db.commit()
        log_activity(db, admin, "target_sharing_changed", f"{target.host}: {'shared' if body.shared else 'private'}")
    return target_to_dict(db, target)


@router.delete("/targets/{target_id}/access/{user_id}")
def remove_target_access(
    target_id: int, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    target = get_target(db, target_id)
    access = db.scalar(
        select(TargetAccess).where(TargetAccess.target_id == target.id, TargetAccess.user_id == user_id)
    )
    if access is None:
        raise HTTPException(404, "That user has no access to this target")
    user = db.get(User, user_id)
    db.delete(access)
    db.commit()
    log_activity(db, admin, "target_access_removed", f"{target.host} for {user.username if user else user_id}")
    return target_to_dict(db, target)


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = get_target(db, target_id)
    db.execute(delete(TargetAccess).where(TargetAccess.target_id == target.id))
    db.delete(target)
    db.commit()
    log_activity(db, admin, "target_removed", target.host)
    return {"ok": True}


# --- Activity log ---


# The log holds usernames and IP addresses, so browsers and proxies must not keep a copy.
NO_STORE = {"Cache-Control": "no-store"}


@router.get("/activity")
def list_activity(
    response: Response,
    limit: int = Query(ACTIVITY_LIMIT, ge=1, le=ACTIVITY_PAGE_MAX),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """The newest `limit` events, newest first."""
    response.headers.update(NO_STORE)
    entries = db.scalars(select(Activity).order_by(Activity.id.desc()).limit(limit))
    return [
        {
            "id": entry.id,
            "username": entry.username,
            "action": entry.action,
            "detail": entry.detail,
            "ip": entry.ip,
            "result": entry.result,
            "created_at": entry.created_at.isoformat(),
        }
        for entry in entries
    ]


def all_activity(db: Session):
    """Every event ever recorded, oldest first, like a log file."""
    return db.scalars(select(Activity).order_by(Activity.id))


def activity_to_csv(entries) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(ACTIVITY_CSV_COLUMNS)
    for entry in entries:
        row = [str(entry.id), entry.created_at.strftime("%Y-%m-%d %H:%M:%S"), entry.ip, entry.username,
               entry.action, entry.result, entry.detail]
        # safe_cell: a username like "=HYPERLINK(...)" typed at login must not run in Excel.
        # A lone "-" (no IP) is not a formula, so it stays readable.
        writer.writerow([cell if cell == "-" else safe_cell(cell) for cell in row])
    # The byte-order mark makes Excel read the file as UTF-8 instead of guessing.
    return "\ufeff" + output.getvalue()


def log_file_response(content: str, media_type: str, extension: str, view: bool) -> Response:
    """A download (saved as a file) or, with view=True, a page the browser shows in the tab.

    Views are always sent as text/plain: browsers download text/csv instead of showing it.
    """
    filename = f"sentinel-activity-{datetime.now(UTC):%Y-%m-%d}.{extension}"
    disposition = "inline" if view else "attachment"
    return Response(
        content,
        media_type="text/plain; charset=utf-8" if view else media_type,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"', **NO_STORE},
    )


def log_export(db: Session, admin: User, file_type: str, view: bool) -> None:
    # Logged first, so the view or download itself shows up as the last line.
    log_activity(db, admin, "activity_viewed" if view else "activity_exported", file_type)


@router.get("/activity/export.txt")
def export_activity_txt(
    view: bool = False, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    log_export(db, admin, "TXT", view)
    text = "".join(format_line(entry) + "\n" for entry in all_activity(db))
    return log_file_response(text, "text/plain; charset=utf-8", "txt", view)


@router.get("/activity/export.csv")
def export_activity_csv(
    view: bool = False, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    log_export(db, admin, "CSV", view)
    return log_file_response(activity_to_csv(all_activity(db)), "text/csv; charset=utf-8", "csv", view)
