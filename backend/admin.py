"""Admin routes: manage users, allowed scan targets, and view the activity log."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import hash_password, require_admin, user_to_dict
from backend.db import get_db
from backend.guard import log_activity
from backend.models import Activity, AllowedTarget, User
from backend.validation import Hostname, Password, Username

router = APIRouter(prefix="/api/admin", tags=["admin"])

ACTIVITY_LIMIT = 200  # newest entries shown on the admin page


class NewUser(BaseModel):
    username: Username
    password: Password
    role: Literal["admin", "user"] = "user"


class UserChange(BaseModel):
    role: Literal["admin", "user"] | None = None
    is_active: bool | None = None
    password: Password | None = None


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


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.username))
    return [user_to_dict(user) | {"created_at": user.created_at.isoformat()} for user in users]


@router.post("/users")
def create_user(body: NewUser, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, f"User {body.username} already exists")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
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

    changes = []
    if body.role is not None:
        user.role = body.role
        changes.append(f"role={body.role}")
    if body.is_active is not None:
        user.is_active = body.is_active
        changes.append("activated" if body.is_active else "deactivated")
    if body.password is not None:
        user.password_hash = hash_password(body.password)
        changes.append("password reset")
    db.commit()
    log_activity(db, admin, "user_changed", f"{user.username}: {', '.join(changes) or 'no change'}")
    return user_to_dict(user)


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


@router.get("/activity")
def list_activity(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    entries = db.scalars(select(Activity).order_by(Activity.id.desc()).limit(ACTIVITY_LIMIT))
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
