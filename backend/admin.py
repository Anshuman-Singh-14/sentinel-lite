"""Admin routes: manage users, allowed scan targets, and view the activity log.

STUB: Role 1 implements these. The request bodies below are final, so the
frontend can be built against them.
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.auth import require_admin
from backend.db import get_db
from backend.models import User
from backend.validation import Hostname, Password, Username

router = APIRouter(prefix="/api/admin", tags=["admin"])

NOT_YET = HTTPException(501, "Not implemented yet")


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


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    raise NOT_YET


@router.post("/users")
def create_user(body: NewUser, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    raise NOT_YET


@router.patch("/users/{user_id}")
def change_user(
    user_id: int, body: UserChange, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    raise NOT_YET


@router.get("/targets")
def list_targets(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    raise NOT_YET


@router.post("/targets")
def add_target(body: NewTarget, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    raise NOT_YET


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    raise NOT_YET


@router.get("/activity")
def list_activity(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    raise NOT_YET
