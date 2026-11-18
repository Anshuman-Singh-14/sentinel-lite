"""Every action that changes something is written to the activity log.

The first test is a safety net: it lists every POST, PATCH and DELETE route in the app
and compares it with EXPECTED below. Adding a route without updating EXPECTED fails it,
as a reminder to log what the new route does. The rest check that each event really
is written, with the right result and IP.
"""

import re
from pathlib import Path

import dns.exception
from conftest import PASSWORD, login
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import access_requests, app as app_module, cli, guard
from backend.access_requests import TERMS_VERSION
from backend.app import app
from backend.config import settings
from backend.models import Activity, AllowedTarget, User
from backend.tools import dns_check
from backend.tools.log_analyzer import MAX_BYTES

BACKEND = Path(__file__).resolve().parent.parent / "backend"

# Route -> the action names it can write. Keep in step with the code.
EXPECTED = {
    "POST /api/auth/login": {"login", "login_failed", "rate_limited"},
    "POST /api/auth/logout": {"logout"},
    "POST /api/auth/change-password": {"password_changed", "password_change_failed", "rate_limited"},
    "POST /api/access-requests": {"access_requested", "rate_limited"},
    "POST /api/email/verify": {"access_request_verified", "email_added", "email_changed"},
    "POST /api/account/email": {"email_change_requested", "email_change_failed", "rate_limited"},
    "POST /api/admin/users": {"user_created"},
    "PATCH /api/admin/users/{user_id}": {"user_role_changed", "user_activated", "user_deactivated",
                                          "user_password_reset", "user_display_name_changed"},
    "DELETE /api/admin/users/{user_id}": {"user_deleted"},
    "POST /api/admin/access-requests/{request_id}/approve": {"access_request_approved"},
    "POST /api/admin/access-requests/{request_id}/reject": {"access_request_rejected"},
    "POST /api/admin/access-requests/{request_id}/resend-email": {"access_request_email_resent"},
    "POST /api/target-requests": {"target_requested", "rate_limited"},
    "POST /api/target-requests/{request_id}/cancel": {"target_request_cancelled"},
    "POST /api/admin/target-requests/{request_id}/approve": {"target_request_approved"},
    "POST /api/admin/target-requests/{request_id}/reject": {"target_request_rejected"},
    "POST /api/admin/target-requests/{request_id}/resend-email": {"target_request_email_resent"},
    "POST /api/admin/targets": {"target_added"},
    "PATCH /api/admin/targets/{target_id}": {"target_sharing_changed"},
    "DELETE /api/admin/targets/{target_id}": {"target_removed"},
    "DELETE /api/admin/targets/{target_id}/access/{user_id}": {"target_access_removed"},
    "POST /api/tools/dns-check": {"dns_check", "scan_failed", "rate_limited"},
    "POST /api/tools/port-scan": {"port_scan", "scan_refused", "scan_failed", "rate_limited"},
    "POST /api/tools/web-check": {"web_check", "scan_refused", "scan_failed", "rate_limited"},
    "POST /api/tools/log-analyzer": {"log_analyzer", "scan_failed", "rate_limited"},
}
# Events that don't belong to one route.
OTHER_ACTIONS = {"admin_created", "app_started", "database_migrated", "admin_access_denied", "email_failed",
                 "activity_viewed", "activity_exported"}


def state_changing_routes() -> set[str]:
    """Every POST/PATCH/DELETE/PUT route, from the app's OpenAPI description (all /api routes are in it)."""
    return {
        f"{method.upper()} {path}"
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method in ("post", "patch", "delete", "put")
    }


def test_every_state_changing_route_is_in_the_logging_map():
    routes = state_changing_routes()
    missing = sorted(routes - EXPECTED.keys())
    assert not missing, (
        f"New state-changing route(s) {missing}: add activity logging (guard.log_activity / guard.record) "
        "and then add the route with its action names to EXPECTED in tests/test_logging_coverage.py"
    )
    stale = sorted(EXPECTED.keys() - routes)
    assert not stale, f"{stale} no longer exist: remove them from EXPECTED in tests/test_logging_coverage.py"


def test_every_expected_action_name_is_written_somewhere_in_the_backend():
    source = "\n".join(path.read_text(encoding="utf-8") for path in BACKEND.rglob("*.py"))
    for action in set().union(*EXPECTED.values()) | OTHER_ACTIONS:
        assert re.search(rf'["\']{action}["\']', source), f"no code writes the action {action!r}"


# --- Helpers ---


def last(db, action: str) -> Activity:
    db.expire_all()
    entry = db.query(Activity).filter_by(action=action).order_by(Activity.id.desc()).first()
    assert entry is not None, f"no {action} event was logged"
    return entry


def summary(entry: Activity) -> tuple:
    return entry.username, entry.detail, entry.result, entry.ip


# --- Section 2: clear names for user changes ---


def test_user_changes_have_their_own_names(admin_client, make_user, db):
    bob = make_user("bob")
    admin_client.patch(f"/api/admin/users/{bob.id}", json={"role": "admin"})
    assert summary(last(db, "user_role_changed")) == ("admin", "bob: user -> admin", "ok", "testclient")
    admin_client.patch(f"/api/admin/users/{bob.id}", json={"is_active": False})
    assert summary(last(db, "user_deactivated")) == ("admin", "bob", "ok", "testclient")
    admin_client.patch(f"/api/admin/users/{bob.id}", json={"is_active": True})
    assert summary(last(db, "user_activated")) == ("admin", "bob", "ok", "testclient")
    admin_client.patch(f"/api/admin/users/{bob.id}", json={"password": "reset-by-admin-1"})
    assert summary(last(db, "user_password_reset")) == ("admin", "bob", "ok", "testclient")
    assert "reset-by-admin-1" not in str([entry.detail for entry in db.query(Activity)])
    assert db.query(Activity).filter_by(action="user_changed").count() == 0


def test_a_patch_that_changes_nothing_logs_nothing(admin_client, make_user, db):
    bob = make_user("bob")
    before = db.query(Activity).count()
    admin_client.patch(f"/api/admin/users/{bob.id}", json={"role": "user", "is_active": True})
    db.expire_all()
    assert db.query(Activity).count() == before


# --- Section 3: events that were missing ---


def test_admin_created_from_the_command_line(db, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "cli-password-1")
    cli.create_admin("cliadmin")
    assert summary(last(db, "admin_created")) == ("system", "cliadmin (command line)", "ok", "-")


def test_admin_created_from_admin_user_at_startup(db, monkeypatch):
    monkeypatch.setenv("ADMIN_USER", "seeded")
    monkeypatch.setenv("ADMIN_PASSWORD", "seeded-password-1")
    app_module.seed_admin_user()
    assert summary(last(db, "admin_created")) == ("system", "seeded (from ADMIN_USER)", "ok", "-")
    assert db.query(User).filter_by(username="seeded", role="admin").count() == 1


def test_startup_logs_app_started_and_only_real_migrations(db, monkeypatch):
    with TestClient(app):
        pass
    assert summary(last(db, "app_started")) == ("system", "env=dev", "ok", "-")
    assert db.query(Activity).filter_by(action="database_migrated").count() == 0  # nothing to change

    monkeypatch.setattr(app_module, "init_db", lambda: ["added activity.ip", "added activity.result"])
    with TestClient(app):
        pass
    assert summary(last(db, "database_migrated")) == ("system", "added activity.ip, added activity.result", "ok", "-")


def test_login_failed_says_why_but_the_visitor_gets_the_same_answer(client, make_user, db):
    make_user("alice")
    make_user("gone", is_active=False)
    answers = []
    for username, password, reason in [("nobody", PASSWORD, "unknown user"), ("alice", "wrong-pass", "wrong password"),
                                       ("gone", PASSWORD, "account deactivated")]:
        response = client.post("/api/auth/login", json={"username": username, "password": password})
        answers.append((response.status_code, response.json()))
        assert summary(last(db, "login_failed")) == (username, reason, "fail", "testclient")
    assert answers == [(401, {"detail": "Wrong username or password"})] * 3


def test_rate_limits_are_logged_as_denied(client, make_user, db):
    alice = make_user("alice")
    alice.email = "alice@example.com"
    db.commit()

    for _ in range(5):
        client.post("/api/auth/login", json={"username": "mallory", "password": "x"})
    assert client.post("/api/auth/login", json={"username": "mallory", "password": "x"}).status_code == 429
    assert summary(last(db, "rate_limited")) == ("mallory", "login", "denied", "testclient")
    guard.login_limiter.reset()

    login(client, "alice")
    for _ in range(guard.SCANS_PER_MINUTE):
        guard.scan_limiter.allow(alice.id)
    assert client.post("/api/tools/dns-check", json={"domain": "example.com"}).status_code == 429
    assert summary(last(db, "rate_limited")) == ("alice", "scan", "denied", "testclient")

    for _ in range(3):
        access_requests.email_limiter.allow(alice.id)
    body = {"email": "new@example.com", "current_password": PASSWORD}
    assert client.post("/api/account/email", json=body).status_code == 429
    assert summary(last(db, "rate_limited")) == ("alice", "email_link", "denied", "testclient")

    for _ in range(3):
        access_requests.request_limiter.add("testclient")
    request_body = {"username": "newbie", "email": "n@example.com", "password": "chosen-pass-1", "agree": True,
                    "terms_version": TERMS_VERSION, "turnstile_token": "pass"}
    assert client.post("/api/access-requests", json=request_body).status_code == 429
    assert summary(last(db, "rate_limited")) == ("newbie", "access_request", "denied", "testclient")

    for _ in range(20):
        access_requests.attempt_limiter.allow("testclient")
    assert client.post("/api/access-requests", json=request_body).status_code == 429
    assert summary(last(db, "rate_limited")) == ("-", "access_request", "denied", "testclient")


def test_refused_scans_are_logged(user_client, db, monkeypatch):
    assert user_client.post("/api/tools/port-scan", json={"target": "example.com"}).status_code == 403
    assert summary(last(db, "scan_refused")) == ("alice", "port_scan example.com: not approved", "denied", "testclient")

    db.add(AllowedTarget(host="192.168.1.10", added_by="admin"))
    db.commit()
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(guard, "server_ips", lambda: set())
    assert user_client.post("/api/tools/web-check", json={"target": "192.168.1.10"}).status_code == 403
    assert summary(last(db, "scan_refused")) == ("alice", "web_check 192.168.1.10: internal address", "denied",
                                                 "testclient")


def test_failed_scans_are_logged(user_client, db, monkeypatch):
    def timeout(name, record_type):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns_check, "lookup", timeout)
    assert user_client.post("/api/tools/dns-check", json={"domain": "example.com"}).status_code == 502
    assert summary(last(db, "scan_failed")) == (
        "alice", "dns_check example.com: DNS lookup failed or timed out", "fail", "testclient")

    monkeypatch.setattr(dns_check, "lookup", lambda name, record_type: [])
    assert user_client.post("/api/tools/dns-check", json={"domain": "example.com"}).status_code == 404
    assert summary(last(db, "scan_failed"))[1] == "dns_check example.com: no DNS records"

    db.add(AllowedTarget(host="gone.example.com", added_by="admin"))
    db.commit()

    def no_address(host):
        raise HTTPException(400, f"Could not find an IPv4 address for {host}")

    monkeypatch.setattr(guard, "resolve", no_address)
    assert user_client.post("/api/tools/port-scan", json={"target": "gone.example.com"}).status_code == 400
    assert summary(last(db, "scan_failed"))[1] == "port_scan gone.example.com: DNS lookup failed"

    wrong_type = user_client.post("/api/tools/log-analyzer", files={"file": ("app.exe", b"MZ", "text/plain")})
    assert wrong_type.status_code == 400
    assert summary(last(db, "scan_failed"))[1:] == ("log_analyzer upload: upload refused: wrong type", "fail",
                                                    "testclient")
    too_big = user_client.post("/api/tools/log-analyzer", files={"file": ("big.log", b"a" * (MAX_BYTES + 1))})
    assert too_big.status_code == 413
    assert summary(last(db, "scan_failed"))[1] == "log_analyzer upload: upload refused: too big"


def test_non_admins_on_admin_routes_are_logged(user_client, db):
    assert user_client.get("/api/admin/users").status_code == 403
    assert summary(last(db, "admin_access_denied")) == ("alice", "GET /api/admin/users", "denied", "testclient")
    assert user_client.delete("/api/admin/targets/1").status_code == 403
    assert last(db, "admin_access_denied").detail == "DELETE /api/admin/targets/1"


def test_wrong_current_password_on_password_and_email_changes(user_client, db):
    response = user_client.post("/api/auth/change-password",
                                json={"current_password": "not-it-123", "new_password": "brand-new-pass"})
    assert response.status_code == 400
    assert summary(last(db, "password_change_failed")) == ("alice", "wrong current password", "fail", "testclient")
    response = user_client.post("/api/account/email", json={"email": "a@example.com", "current_password": "not-it"})
    assert response.status_code == 400
    assert summary(last(db, "email_change_failed")) == ("alice", "wrong current password", "fail", "testclient")


# --- Nothing secret reaches the log ---


def test_no_password_token_or_full_email_in_the_log_file(activity_log_file, user_client, outbox):
    user_client.post("/api/auth/login", json={"username": "alice", "password": "Guess-Secret-1"})
    user_client.post("/api/auth/change-password", json={"current_password": "Wrong-Secret-2",
                                                       "new_password": "Never-Logged-3"})
    user_client.post("/api/account/email", json={"email": "alice@private.example", "current_password": PASSWORD})
    token = re.search(r"token=([\w-]+)", outbox[-1]["body"]).group(1)
    user_client.post("/api/email/verify", json={"token": token})
    user_client.post("/api/auth/change-password", json={"current_password": PASSWORD,
                                                       "new_password": "Never-Logged-4"})

    log = activity_log_file.read_text(encoding="utf-8")
    assert " action=email_added " in log and " action=password_changed " in log
    for secret in ["Guess-Secret-1", "Wrong-Secret-2", "Never-Logged-3", "Never-Logged-4", PASSWORD, token,
                   "alice@private.example"]:
        assert secret not in log, secret
