"""Login, logout, password changes and the "who is logged in" dependencies.

Passwords are stored as bcrypt hashes. After login the user's id is kept in a
signed session cookie (Starlette's SessionMiddleware, set up in app.py): the
browser can read nothing from it (httpOnly) and cannot change it without
breaking the signature made with SECRET_KEY.
"""

import secrets

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import guard
from backend.db import get_db
from backend.models import User, as_utc
from backend.validation import Password

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Checked when the username doesn't exist, so a wrong username takes as long as a
# wrong password and response times don't reveal which usernames are real.
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())

# Generated passwords leave out characters that look alike (0/O, 1/l/I), since people
# copy them from an email by eye.
GENERATED_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
GENERATED_LENGTH = 16

# While must_change_password is set, these are the only routes the user can call.
PASSWORD_CHANGE_PATHS = {"/api/auth/me", "/api/auth/logout", "/api/auth/change-password"}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode()[:72], password_hash.encode())


def generate_password() -> str:
    return "".join(secrets.choice(GENERATED_ALPHABET) for _ in range(GENERATED_LENGTH))


def client_ip(request: Request) -> str:
    # Behind Caddy, uvicorn takes the real client IP from the X-Forwarded-For header.
    return request.client.host if request.client else "unknown"


def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "email": user.email,
        "has_email": bool(user.email),
        "must_change_password": user.must_change_password,
        "display_name": user.display_name,
    }


def account_stamp(user: User) -> str:
    return as_utc(user.created_at).isoformat()


def start_session(request: Request, user: User) -> None:
    request.session.clear()
    request.session["user_id"] = user.id
    # SQLite can give a deleted account's id to the next new account, so the session also
    # remembers when its account was made and only ever works for that exact account.
    request.session["account"] = account_stamp(user)


def session_user(request: Request, db: Session) -> User | None:
    """The account this session was started for, or None if it no longer exists."""
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    if user is None or request.session.get("account") != account_stamp(user):
        return None
    return user


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency for routes that need a logged-in user."""
    user = session_user(request, db)
    # Reloading the user on every request means a deactivated or deleted account is locked out at once.
    if user is None or not user.is_active:
        raise HTTPException(401, "Please log in")
    # Checked here, on the server, so skipping the change-password page in the browser doesn't help.
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise HTTPException(403, "password_change_required")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    """Dependency for admin-only routes."""
    if user.role != "admin":
        raise HTTPException(403, "Admins only")
    return user


class LoginRequest(BaseModel):
    username: str = Field(max_length=32)
    password: str = Field(max_length=200)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: Password


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    guard.check_login_rate(ip)
    user = db.scalar(select(User).where(User.username == body.username))
    password_ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH.decode())
    if user is None or not password_ok or not user.is_active:
        guard.record(db, body.username, "login_failed", f"from {ip}")
        raise HTTPException(401, "Wrong username or password")
    start_session(request, user)
    guard.log_activity(db, user, "login", f"from {ip}")
    return user_to_dict(user)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    user = session_user(request, db)
    if user:
        guard.log_activity(db, user, "logout")
    request.session.clear()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return user_to_dict(user)


@router.post("/change-password")
def change_password(
    body: PasswordChange, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    # Shares the login limit, so this can't be used to guess the current password faster.
    guard.check_login_rate(client_ip(request))
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Your current password is wrong")
    if body.new_password == body.current_password:
        raise HTTPException(400, "The new password must be different from the current one")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    db.commit()
    # A fresh session after a password change.
    start_session(request, user)
    guard.log_activity(db, user, "password_changed")
    return user_to_dict(user)
