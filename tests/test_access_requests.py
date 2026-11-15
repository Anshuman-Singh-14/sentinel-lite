import re
from datetime import timedelta

from conftest import PASSWORD

from backend import mailer
from backend.access_requests import CHECK_EMAIL, TERMS_VERSION
from backend.config import settings
from backend.mailer import send as real_send  # imported before conftest swaps mailer.send for the outbox
from backend.models import AccessRequest, EmailToken, User, utcnow

CHOSEN = "chosen-pass-123"


def body(**changes) -> dict:
    return {
        "username": "newbie",
        "email": "newbie@example.com",
        "wants_generated": False,
        "password": CHOSEN,
        "remarks": "For my lab",
        "agree": True,
        "terms_version": TERMS_VERSION,
        "turnstile_token": "pass",
    } | changes


def token_in(email: dict) -> str:
    return re.search(r"token=([\w-]+)", email["body"]).group(1)


def submit_and_verify(client, outbox, **changes) -> None:
    assert client.post("/api/access-requests", json=body(**changes)).status_code == 200
    assert client.post("/api/email/verify", json={"token": token_in(outbox[-1])}).status_code == 200


def pending_id(admin_client) -> int:
    return admin_client.get("/api/admin/access-requests").json()[0]["id"]


# --- The public form ---


def test_config_gives_the_form_what_it_needs(client):
    config = client.get("/api/access-requests/config").json()
    assert config["enabled"] is True
    assert config["terms_version"] == TERMS_VERSION
    assert "Information Technology Act, 2000" in config["terms_text"]
    assert config["turnstile_site_key"] == "1x00000000000000000000AA"  # dev test key


def test_request_needs_agreement_terms_version_and_password_choice(client):
    assert client.post("/api/access-requests", json=body(agree=False)).status_code == 422
    assert client.post("/api/access-requests", json=body(terms_version="old")).status_code == 422
    assert client.post("/api/access-requests", json=body(password=None)).status_code == 422
    assert client.post("/api/access-requests", json=body(email="not-an-email")).status_code == 422
    assert client.post("/api/access-requests", json=body(remarks="x" * 501)).status_code == 422
    assert client.post("/api/access-requests", json=body(password=None, wants_generated=True)).status_code == 200


def test_turnstile_must_pass(client, db):
    response = client.post("/api/access-requests", json=body(turnstile_token="bot"))
    assert response.status_code == 400
    assert db.query(AccessRequest).count() == 0


def test_duplicate_username_is_refused(client, make_user):
    make_user("alice")
    taken = client.post("/api/access-requests", json=body(username="alice"))
    assert taken.status_code == 409
    assert "already taken" in taken.json()["detail"]
    assert client.post("/api/access-requests", json=body()).status_code == 200
    # An open request also holds its username.
    again = client.post("/api/access-requests", json=body(email="other@example.com"))
    assert again.status_code == 409


def test_email_conflicts_get_the_same_answer(client, db, outbox, make_user):
    alice = make_user("alice")
    alice.email = "alice@example.com"
    db.commit()
    first = client.post("/api/access-requests", json=body())
    used_by_user = client.post("/api/access-requests", json=body(username="other1", email="Alice@Example.com"))
    used_by_request = client.post("/api/access-requests", json=body(username="other2"))
    assert first.json() == used_by_user.json() == used_by_request.json() == {"message": CHECK_EMAIL}
    assert db.query(AccessRequest).count() == 1
    assert len(outbox) == 1


def test_chosen_password_is_stored_only_as_a_bcrypt_hash(client, db):
    client.post("/api/access-requests", json=body())
    stored = db.query(AccessRequest).one()
    assert stored.password_hash.startswith("$2b$")
    assert CHOSEN not in stored.password_hash
    assert stored.status == "unverified"
    assert stored.ip == "testclient"


def test_verification_token_is_hashed_expires_and_works_once(client, db, outbox):
    client.post("/api/access-requests", json=body())
    assert outbox[0]["to"] == "newbie@example.com"
    token = token_in(outbox[0])
    assert outbox[0]["body"].count(f"/verify-email?token={token}") == 1
    stored = db.query(EmailToken).one()
    assert stored.token_hash != token and token not in stored.token_hash and len(stored.token_hash) == 64

    stored.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    expired = client.post("/api/email/verify", json={"token": token})
    assert expired.status_code == 400 and "expired" in expired.json()["detail"]

    stored.expires_at = utcnow() + timedelta(hours=1)
    db.commit()
    assert client.post("/api/email/verify", json={"token": token}).status_code == 200
    again = client.post("/api/email/verify", json={"token": token})
    assert again.status_code == 400 and "already been used" in again.json()["detail"]
    wrong = client.post("/api/email/verify", json={"token": "x" * 43})
    assert wrong.status_code == 400 and "not valid" in wrong.json()["detail"]


def test_old_unverified_requests_are_deleted(client, db):
    client.post("/api/access-requests", json=body())
    db.query(AccessRequest).one().created_at = utcnow() - timedelta(hours=25)
    db.commit()
    # The next request clears it out, so its username is free again.
    assert client.post("/api/access-requests", json=body(email="second@example.com")).status_code == 200
    assert [r.email for r in db.query(AccessRequest)] == ["second@example.com"]


def test_rate_limit_is_three_per_hour_per_ip(client):
    statuses = [
        client.post("/api/access-requests", json=body(username=f"user{n}", email=f"u{n}@example.com")).status_code
        for n in range(4)
    ]
    assert statuses == [200, 200, 200, 429]


def test_prod_without_smtp_or_turnstile_disables_requests(client, monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    assert client.get("/api/access-requests/config").json()["enabled"] is False
    response = client.post("/api/access-requests", json=body())
    assert response.status_code == 503
    assert response.json()["detail"] == "Account requests are not available right now"
    assert client.get("/api/health").status_code == 200  # the rest of the site keeps working

    for name, value in [("smtp_host", "smtp.resend.com"), ("turnstile_site_key", "site"),
                        ("turnstile_secret_key", "secret"), ("public_url", "https://sentinellite.com")]:
        monkeypatch.setattr(settings, name, value)
    assert client.get("/api/access-requests/config").json()["enabled"] is True


def test_mailer_errors_never_contain_secrets(monkeypatch):
    class BrokenSMTP:
        def __init__(self, host, port, timeout):
            assert timeout == 10
            raise OSError("login failed for resend with password re_secret_key")

    monkeypatch.setattr(mailer.smtplib, "SMTP", BrokenSMTP)
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    try:
        real_send("someone@example.com", "Subject", "Temporary password: abc")
        raise AssertionError("expected MailError")
    except mailer.MailError as error:
        assert str(error) == "OSError"


# --- Admin review ---


def test_unverified_requests_are_hidden_from_admins(admin_client, outbox):
    admin_client.post("/api/access-requests", json=body())
    assert admin_client.get("/api/admin/access-requests").json() == []
    admin_client.post("/api/email/verify", json={"token": token_in(outbox[0])})
    [pending] = admin_client.get("/api/admin/access-requests?status=pending").json()
    assert pending["username"] == "newbie"
    assert pending["wants_generated"] is False
    assert "password_hash" not in pending
    assert admin_client.get("/api/admin/access-requests?status=unverified").status_code == 422


def test_approve_creates_a_user_who_can_log_in(admin_client, db, outbox):
    submit_and_verify(admin_client, outbox)
    approved = admin_client.post(f"/api/admin/access-requests/{pending_id(admin_client)}/approve")
    assert approved.status_code == 200
    assert approved.json()["email_status"] == "not_sent"  # sent after the response
    db.expire_all()
    stored = db.query(AccessRequest).one()
    assert stored.status == "approved" and stored.password_hash is None and stored.email_status == "sent"
    user = db.query(User).filter_by(username="newbie").one()
    assert (user.role, user.email, user.email_verified, user.must_change_password) == (
        "user", "newbie@example.com", True, False)
    assert outbox[-1]["subject"] == "Your Sentinel Lite account is ready"
    assert CHOSEN not in outbox[-1]["body"]

    admin_client.post("/api/auth/logout")
    login = admin_client.post("/api/auth/login", json={"username": "newbie", "password": CHOSEN})
    assert login.status_code == 200
    assert login.json()["has_email"] is True


def test_generated_password_user_must_change_it_first(admin_client, outbox):
    submit_and_verify(admin_client, outbox, password=None, wants_generated=True)
    admin_client.post(f"/api/admin/access-requests/{pending_id(admin_client)}/approve")
    password = re.search(r"Temporary password: (\S+)", outbox[-1]["body"]).group(1)
    assert len(password) == 16 and not set(password) & set("0O1lI")

    admin_client.post("/api/auth/logout")
    login = admin_client.post("/api/auth/login", json={"username": "newbie", "password": password})
    assert login.json()["must_change_password"] is True
    blocked = admin_client.get("/api/scans")
    assert blocked.status_code == 403 and blocked.json() == {"detail": "password_change_required"}
    assert admin_client.get("/api/auth/me").status_code == 200

    changed = admin_client.post(
        "/api/auth/change-password", json={"current_password": password, "new_password": "my-own-password"}
    )
    assert changed.status_code == 200
    assert admin_client.get("/api/scans").status_code == 200


def test_double_approval_is_safe(admin_client, db, outbox):
    submit_and_verify(admin_client, outbox)
    request_id = pending_id(admin_client)
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/approve").status_code == 200
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/approve").status_code == 409
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/reject", json={}).status_code == 409
    assert db.query(User).filter_by(username="newbie").count() == 1


def test_approval_rechecks_the_username(admin_client, db, outbox, make_user):
    submit_and_verify(admin_client, outbox)
    make_user("newbie")  # e.g. an admin created it by hand in the meantime
    request_id = pending_id(admin_client)
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/approve").status_code == 409
    db.expire_all()
    assert db.get(AccessRequest, request_id).status == "pending"  # rolled back, can still be rejected


def test_reject_sends_an_email_and_creates_no_user(admin_client, db, outbox):
    submit_and_verify(admin_client, outbox)
    request_id = pending_id(admin_client)
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/reject",
                             json={"reason": "x" * 301}).status_code == 422
    rejected = admin_client.post(f"/api/admin/access-requests/{request_id}/reject",
                                 json={"reason": "Please use your college email."})
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert outbox[-1]["to"] == "newbie@example.com"
    assert "Please use your college email." in outbox[-1]["body"]
    assert db.query(User).filter_by(username="newbie").count() == 0
    db.expire_all()
    assert db.get(AccessRequest, request_id).password_hash is None


def test_failed_email_is_recorded_and_can_be_resent(admin_client, db, outbox, monkeypatch):
    submit_and_verify(admin_client, outbox, password=None, wants_generated=True)
    request_id = pending_id(admin_client)

    def fail(to, subject, body):
        raise mailer.MailError("SMTPAuthenticationError (SMTP code 535)")

    monkeypatch.setattr(mailer, "send", fail)
    admin_client.post(f"/api/admin/access-requests/{request_id}/approve")
    [approved] = admin_client.get("/api/admin/access-requests?status=approved").json()
    assert approved["email_status"] == "failed"
    assert approved["email_error"] == "SMTPAuthenticationError (SMTP code 535)"
    actions = [entry["action"] for entry in admin_client.get("/api/admin/activity").json()]
    assert "email_failed" in actions

    monkeypatch.setattr(mailer, "send", lambda to, subject, body: outbox.append({"to": to, "body": body}))
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/resend-email").status_code == 200
    new_password = re.search(r"Temporary password: (\S+)", outbox[-1]["body"]).group(1)
    admin_client.post("/api/auth/logout")
    assert admin_client.post("/api/auth/login", json={"username": "newbie", "password": new_password}).status_code == 200


def test_resend_only_after_a_failure(admin_client, outbox):
    submit_and_verify(admin_client, outbox)
    request_id = pending_id(admin_client)
    admin_client.post(f"/api/admin/access-requests/{request_id}/approve")
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/resend-email").status_code == 409


def test_non_admins_cannot_reach_request_endpoints(client, user_client):
    for method, url in [
        ("get", "/api/admin/access-requests"),
        ("post", "/api/admin/access-requests/1/approve"),
        ("post", "/api/admin/access-requests/1/reject"),
        ("post", "/api/admin/access-requests/1/resend-email"),
    ]:
        assert getattr(user_client, method)(url).status_code == 403, url
    user_client.post("/api/auth/logout")
    assert client.get("/api/admin/access-requests").status_code == 401


# --- Existing users adding an email ---


def test_existing_user_adds_an_email(user_client, outbox):
    assert user_client.get("/api/auth/me").json()["has_email"] is False
    response = user_client.post("/api/account/email", json={"email": "Alice@Example.com"})
    assert response.status_code == 200
    assert outbox[-1]["to"] == "alice@example.com"
    assert user_client.post("/api/email/verify", json={"token": token_in(outbox[-1])}).status_code == 200
    me = user_client.get("/api/auth/me").json()
    assert me["email"] == "alice@example.com" and me["has_email"] is True


def test_adding_a_taken_email_looks_the_same_but_sends_nothing(user_client, make_user, db, outbox):
    bob = make_user("bob")
    bob.email = "bob@example.com"
    db.commit()
    taken = user_client.post("/api/account/email", json={"email": "bob@example.com"})
    free = user_client.post("/api/account/email", json={"email": "free@example.com"})
    assert taken.status_code == free.status_code == 200
    assert taken.json()["message"].replace("bob@", "free@") == free.json()["message"]
    assert [email["to"] for email in outbox] == ["free@example.com"]


# --- What reaches the activity log ---


def test_emails_passwords_and_tokens_never_reach_the_activity_log(activity_log_file, admin_client, outbox):
    submit_and_verify(admin_client, outbox, password=None, wants_generated=True)
    verify_token = token_in(outbox[0])
    admin_client.post(f"/api/admin/access-requests/{pending_id(admin_client)}/approve")
    temporary = re.search(r"Temporary password: (\S+)", outbox[-1]["body"]).group(1)
    admin_client.post("/api/auth/logout")
    admin_client.post("/api/auth/login", json={"username": "newbie", "password": temporary})
    admin_client.post("/api/auth/change-password",
                      json={"current_password": temporary, "new_password": "my-own-password"})

    log = activity_log_file.read_text(encoding="utf-8")
    for event in ["access_requested", "access_request_verified", "access_request_approved", "password_changed"]:
        assert f"| {event} |" in log, event
    assert "n***@example.com" in log
    for secret in ["newbie@example.com", temporary, "my-own-password", PASSWORD, verify_token]:
        assert secret not in log
