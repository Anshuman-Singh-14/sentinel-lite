import pytest
from fastapi import HTTPException

from backend import guard
from backend.config import settings
from backend.models import AllowedTarget


def approve(db, host):
    db.add(AllowedTarget(host=host, added_by="admin"))
    db.commit()


def test_unapproved_target_is_refused(db):
    with pytest.raises(HTTPException) as error:
        guard.check_target(db, "8.8.8.8")
    assert error.value.status_code == 403


def test_approved_ip_is_allowed(db):
    approve(db, "8.8.8.8")
    assert guard.check_target(db, "8.8.8.8") == "8.8.8.8"


@pytest.mark.parametrize(
    ("ip", "internal"),
    [("127.0.0.1", True), ("10.0.0.5", True), ("192.168.1.1", True), ("169.254.1.1", True), ("8.8.8.8", False)],
)
def test_internal_ips_are_recognised(ip, internal):
    assert guard.is_internal_ip(ip) is internal


def test_production_blocks_private_ips_even_when_approved(db, monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    approve(db, "192.168.1.10")
    with pytest.raises(HTTPException) as error:
        guard.check_target(db, "192.168.1.10")
    assert error.value.status_code == 403


def test_production_blocks_the_servers_own_ip(db, monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(guard, "server_ips", lambda: {"203.0.113.7"})
    approve(db, "203.0.113.7")
    with pytest.raises(HTTPException):
        guard.check_target(db, "203.0.113.7")


def test_rate_limiter_blocks_then_recovers(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(guard.time, "monotonic", lambda: clock[0])
    limiter = guard.RateLimiter(limit=2, window=60)
    assert limiter.allow("alice") and limiter.allow("alice")
    assert not limiter.allow("alice")  # third event inside the window
    assert limiter.allow("bob")  # other users are not affected
    clock[0] += 60
    assert limiter.allow("alice")  # the window has passed


def test_scan_rate_limit_is_ten_per_minute(make_user):
    user = make_user("alice")
    for _ in range(10):
        guard.check_rate_limit(user)
    with pytest.raises(HTTPException) as error:
        guard.check_rate_limit(user)
    assert error.value.status_code == 429


def test_login_attempts_are_limited(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code == 429
