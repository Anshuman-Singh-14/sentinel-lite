"""The optional first-admin bootstrap used on cPanel (ADMIN_USERNAME / ADMIN_PASSWORD)."""

from sqlalchemy import select

from backend.auth import verify_password
from backend.cli import bootstrap_admin
from backend.config import settings
from backend.models import User


def set_admin_env(monkeypatch, username: str, password: str) -> None:
    monkeypatch.setattr(settings, "admin_username", username)
    monkeypatch.setattr(settings, "admin_password", password)


def test_creates_admin_when_no_users(db, monkeypatch):
    set_admin_env(monkeypatch, "boss", "long-password-1")
    bootstrap_admin()
    user = db.scalar(select(User))
    assert user.username == "boss" and user.role == "admin"
    assert verify_password("long-password-1", user.password_hash)


def test_does_nothing_when_users_exist(db, make_user, monkeypatch):
    make_user("alice")
    set_admin_env(monkeypatch, "boss", "long-password-1")
    bootstrap_admin()
    assert db.scalar(select(User).where(User.username == "boss")) is None


def test_does_nothing_without_settings(db, monkeypatch):
    set_admin_env(monkeypatch, "", "")
    bootstrap_admin()
    assert db.scalar(select(User)) is None


def test_skips_invalid_password(db, monkeypatch):
    set_admin_env(monkeypatch, "boss", "short")
    bootstrap_admin()
    assert db.scalar(select(User)) is None
