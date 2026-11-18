"""GET /api/notifications: what the homepage and the sidebar badge show."""

import json
from datetime import timedelta

import pytest
from conftest import login
from fastapi.testclient import TestClient

from backend.app import app
from backend.models import AccessRequest, TargetRequest, utcnow


def account_request(db, username, status="pending", email_status="not_sent", minutes_ago=0, reviewed_by=None):
    row = AccessRequest(username=username, email=f"{username}@example.com", terms_version="v1", status=status,
                        email_status=email_status, created_at=utcnow() - timedelta(minutes=minutes_ago),
                        reviewed_by=reviewed_by, reviewed_at=utcnow() - timedelta(minutes=minutes_ago)
                        if status in ("approved", "rejected") else None)
    db.add(row)
    db.commit()
    return row


def website_request(db, user, host, status="pending", email_status="not_sent", minutes_ago=0, decided_days_ago=None,
                    reviewed_by=None, reject_reason=""):
    when = utcnow() - timedelta(minutes=minutes_ago)
    row = TargetRequest(user_id=user.id, host=host, status=status, email_status=email_status, created_at=when,
                        reviewed_by=reviewed_by, reject_reason=reject_reason,
                        reviewed_at=utcnow() - timedelta(days=decided_days_ago) if decided_days_ago is not None
                        else (when if status in ("approved", "rejected") else None))
    db.add(row)
    db.commit()
    return row


@pytest.fixture
def people(db, make_user):
    alice, bob = make_user("alice"), make_user("bob")
    alice.email = "alice@example.com"  # bob has no email
    admin = make_user("rootadmin", role="admin")
    db.commit()
    return alice, bob, admin


def client_for(username: str) -> TestClient:
    return login(TestClient(app), username)


def test_logged_out_gets_401(client):
    assert client.get("/api/notifications").status_code == 401


def test_admin_counts_per_kind(db, people):
    alice, bob, _admin = people
    account_request(db, "newbie1")
    account_request(db, "newbie2")
    account_request(db, "ghost", status="unverified")  # email not confirmed: not counted
    account_request(db, "failed1", status="approved", email_status="failed", reviewed_by="rootadmin")
    account_request(db, "sentok", status="approved", email_status="sent", reviewed_by="rootadmin")
    account_request(db, "unconfirmed", status="unverified", email_status="failed")  # no decision email to resend
    website_request(db, alice, "alice-site.com")
    website_request(db, bob, "bob-site.com", status="rejected", email_status="failed", reviewed_by="rootadmin")
    website_request(db, bob, "old.com", status="cancelled")

    data = client_for("rootadmin").get("/api/notifications").json()
    assert data["account_requests_pending"] == 2
    assert data["website_requests_pending"] == 1
    assert data["emails_failed"] == 2  # one from each request type
    assert data["total"] == 5
    titles = {item["title"] for item in data["items"]}
    assert titles == {
        "newbie1 requested an account",
        "newbie2 requested an account",
        "Approval email to failed1 failed",
        "alice requested alice-site.com",
        "Rejection email to bob (bob-site.com) failed",
    }
    kinds = {(item["kind"], item["request_type"], item["decision"]) for item in data["items"]}
    assert kinds == {("account_request", "account", None), ("website_request", "website", None),
                     ("email_failed", "account", "approved"), ("email_failed", "website", "rejected")}


def test_admin_items_are_newest_first_and_capped_at_ten(db, people):
    alice = people[0]
    for n in range(8):
        account_request(db, f"user{n}", minutes_ago=100 + n)  # user0 is the newest of these
    for n in range(8):
        website_request(db, alice, f"site{n}.com", minutes_ago=10 + n * 20)
    data = client_for("rootadmin").get("/api/notifications").json()
    assert data["total"] == 16
    assert len(data["items"]) == 10
    dates = [item["created_at"] for item in data["items"]]
    assert dates == sorted(dates, reverse=True)
    assert data["items"][0]["title"] == "alice requested site0.com"


def test_empty_admin_notifications(people):
    data = client_for("rootadmin").get("/api/notifications").json()
    assert (data["total"], data["items"], data["my_requests"], data["needs_email"]) == (0, [], [], True)


def test_user_gets_only_their_own_recent_requests(db, people):
    alice, bob, _admin = people
    website_request(db, alice, "pending.com", minutes_ago=5)
    website_request(db, alice, "approved.com", status="approved", decided_days_ago=2, reviewed_by="rootadmin")
    website_request(db, alice, "rejected.com", status="rejected", decided_days_ago=6, reviewed_by="rootadmin",
                    reject_reason="Not yours")
    website_request(db, alice, "old.com", status="approved", decided_days_ago=8, reviewed_by="rootadmin")
    website_request(db, alice, "cancelled.com", status="cancelled")
    website_request(db, bob, "bob-site.com")
    account_request(db, "newbie")

    data = client_for("alice").get("/api/notifications").json()
    assert set(data) == {"my_requests", "needs_email"}  # no admin counts
    assert [r["host"] for r in data["my_requests"]] == ["rejected.com", "approved.com", "pending.com"]  # newest first
    rejected = data["my_requests"][0]
    assert (rejected["status"], rejected["reject_reason"]) == ("rejected", "Not yours")
    assert rejected["reviewed_at"] is not None
    assert data["needs_email"] is False


def test_needs_email(people):
    assert client_for("bob").get("/api/notifications").json()["needs_email"] is True
    assert client_for("alice").get("/api/notifications").json()["needs_email"] is False


def test_admin_also_gets_their_own_requests(db, people):
    admin = people[2]
    website_request(db, admin, "admin-site.com")
    data = client_for("rootadmin").get("/api/notifications").json()
    assert [r["host"] for r in data["my_requests"]] == ["admin-site.com"]
    assert data["website_requests_pending"] == 1


def test_a_user_never_sees_an_admin_username(db, people):
    alice = people[0]
    website_request(db, alice, "approved.com", status="approved", decided_days_ago=1, reviewed_by="rootadmin")
    website_request(db, alice, "rejected.com", status="rejected", decided_days_ago=1, reviewed_by="rootadmin",
                    email_status="failed")
    account_request(db, "failed1", status="approved", email_status="failed", reviewed_by="rootadmin")
    response = client_for("alice").get("/api/notifications")
    assert response.status_code == 200
    assert "rootadmin" not in json.dumps(response.json())
    assert "rootadmin" not in response.text
