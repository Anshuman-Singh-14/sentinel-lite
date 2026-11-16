"""Admin routes: manage users, review account requests, approve scan targets, and view
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

from backend import mailer
from backend.access_requests import deliver
from backend.activity_log import format_line
from backend.auth import generate_password, hash_password, require_admin, user_to_dict
from backend.db import get_db
from backend.guard import log_activity, mask_email
from backend.models import AccessRequest, Activity, AllowedTarget, EmailToken, Scan, User, utcnow
from backend.reports import safe_cell
from backend.validation import DisplayName, Email, Hostname, Password, Username

router = APIRouter(prefix="/api/admin", tags=["admin"])

ACTIVITY_LIMIT = 200  # newest entries shown on the admin page (the downloads have all of them)
ACTIVITY_PAGE_MAX = 5000  # most entries the full-page log (/admin/activity) can ask for
ACTIVITY_CSV_COLUMNS = ["id", "time_utc", "username", "action", "detail"]


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


def target_to_dict(target: AllowedTarget) -> dict:
    return {
        "id": target.id,
        "host": target.host,
        "note": target.note,
        "added_by": target.added_by,
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

    changes = []
    if body.role is not None:
        user.role = body.role
        changes.append(f"role={body.role}")
    if body.is_active is not None:
        user.is_active = body.is_active
        changes.append("activated" if body.is_active else "deactivated")
    if body.password is not None:
        user.password_hash = hash_password(body.password)
        user.must_change_password = True  # the admin knows it, so the user picks a new one
        changes.append("password reset")
    display_name_changed = False
    if body.display_name is not None and (body.display_name or None) != user.display_name:
        user.display_name = body.display_name or None  # "" clears it
        display_name_changed = True
    db.commit()
    if changes or not display_name_changed:
        log_activity(db, admin, "user_changed", f"{user.username}: {', '.join(changes) or 'no change'}")
    if display_name_changed:
        shown = f"'{user.display_name}'" if user.display_name else "cleared"
        log_activity(db, admin, "user_display_name_changed", f"{user.username}: {shown}")
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
    """Delete an account and its scan history. Account requests and activity entries stay:
    they are history and keep the username as plain text."""
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
    db.execute(delete(EmailToken).where(EmailToken.purpose == "verify_user_email", EmailToken.ref_id == user.id))
    username, role = user.username, user.role
    db.delete(user)
    db.commit()
    log_activity(db, admin, "user_deleted", f"{username} ({role}, {scans} scans deleted)")
    return {"ok": True}


def reviewer_name(db: Session, access_request: AccessRequest) -> str | None:
    """The reviewing admin's display name as it is now (None if unset or the admin is gone)."""
    reviewer = db.scalar(select(User).where(User.username == access_request.reviewed_by))
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


def claim(db: Session, request_id: int, admin: User, new_status: str, **values) -> AccessRequest:
    """Move a pending request to approved/rejected, or raise 409 if it isn't pending any more.

    The status check is part of the UPDATE itself, so when two admins click at the same
    moment exactly one of them gets the request (the other's UPDATE changes 0 rows).
    """
    if db.get(AccessRequest, request_id) is None:
        raise HTTPException(404, "Request not found")
    result = db.execute(
        update(AccessRequest)
        .where(AccessRequest.id == request_id, AccessRequest.status == "pending")
        # email_status now tracks the decision email, not the earlier confirmation email.
        .values(status=new_status, reviewed_by=admin.username, reviewed_at=utcnow(), email_status="not_sent",
                email_error="", **values)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "This request isn't waiting for review (another admin may have just handled it)")
    return db.get(AccessRequest, request_id, populate_existing=True)


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
    access_request = claim(db, request_id, admin, "approved")
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
    access_request = claim(db, request_id, admin, "rejected", reject_reason=reason, password_hash=None)
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


# --- Allowed targets ---


@router.get("/targets")
def list_targets(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [target_to_dict(t) for t in db.scalars(select(AllowedTarget).order_by(AllowedTarget.host))]


@router.post("/targets")
def add_target(body: NewTarget, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(AllowedTarget).where(AllowedTarget.host == body.host)):
        raise HTTPException(409, f"{body.host} is already approved")
    target = AllowedTarget(host=body.host, note=body.note, added_by=admin.username)
    db.add(target)
    db.commit()
    log_activity(db, admin, "target_added", target.host)
    return target_to_dict(target)


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(AllowedTarget, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
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
        row = [str(entry.id), entry.created_at.strftime("%Y-%m-%d %H:%M:%S"), entry.username, entry.action,
               entry.detail]
        # safe_cell: a username like "=HYPERLINK(...)" typed at login must not run in Excel.
        writer.writerow([safe_cell(cell) for cell in row])
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
