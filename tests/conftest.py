"""Shared test setup: a throwaway SQLite database and logged-in test clients."""

import os
import tempfile
from pathlib import Path

# Settings are read when backend.config is imported, so set them first.
os.environ["APP_ENV"] = "dev"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-1234"
os.environ["DATABASE_PATH"] = str(Path(tempfile.mkdtemp()) / "test.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend import guard  # noqa: E402
from backend.app import app  # noqa: E402
from backend.auth import hash_password  # noqa: E402
from backend.db import Base, SessionLocal, engine  # noqa: E402
from backend.models import User  # noqa: E402

PASSWORD = "password123"


@pytest.fixture
def db():
    """A fresh, empty database for every test."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        yield session


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Rate limits live in memory, so clear them or one test's requests count against the next."""
    guard.scan_limiter.reset()
    guard.login_limiter.reset()


@pytest.fixture
def make_user(db):
    def make(username: str, role: str = "user", is_active: bool = True) -> User:
        user = User(username=username, password_hash=hash_password(PASSWORD), role=role, is_active=is_active)
        db.add(user)
        db.commit()
        return user

    return make


@pytest.fixture
def client(db):
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username: str) -> TestClient:
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200
    return client


@pytest.fixture
def user_client(client, make_user):
    make_user("alice")
    return login(client, "alice")


@pytest.fixture
def admin_client(client, make_user):
    make_user("admin", role="admin")
    return login(client, "admin")
