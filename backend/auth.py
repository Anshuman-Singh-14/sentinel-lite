"""Login, logout and the "who is logged in" dependencies.

Passwords are stored as bcrypt hashes. After login the user's id is kept in a
signed session cookie (Starlette's SessionMiddleware, set up in app.py): the
browser can read nothing from it (httpOnly) and cannot change it without
breaking the signature made with SECRET_KEY.
"""

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import guard
from backend.db import get_db
from backend.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Checked when the username doesn't exist, so a wrong username takes as long as a
# wrong password and response times don't reveal which usernames are real.
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode()[:72], password_hash.encode())


def user_to_dict(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency for routes that need a logged-in user."""
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    # Reloading the user on every request means a deactivated account is locked out at once.
    if user is None or not user.is_active:
        raise HTTPException(401, "Please log in")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    """Dependency for admin-only routes."""
    if user.role != "admin":
        raise HTTPException(403, "Admins only")
    return user


class LoginRequest(BaseModel):
    username: str = Field(max_length=32)
    password: str = Field(max_length=200)


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Behind Caddy, uvicorn takes the real client IP from the X-Forwarded-For header.
    client_ip = request.client.host if request.client else "unknown"
    guard.check_login_rate(client_ip)
    user = db.scalar(select(User).where(User.username == body.username))
    password_ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH.decode())
    if user is None or not password_ok or not user.is_active:
        guard.record(db, body.username, "login_failed", f"from {client_ip}")
        raise HTTPException(401, "Wrong username or password")
    request.session.clear()
    request.session["user_id"] = user.id
    guard.log_activity(db, user, "login", f"from {client_ip}")
    return user_to_dict(user)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    if user:
        guard.log_activity(db, user, "logout")
    request.session.clear()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return user_to_dict(user)
