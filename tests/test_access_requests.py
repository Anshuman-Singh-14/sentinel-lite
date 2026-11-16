import re
from datetime import timedelta

from conftest import PASSWORD, login

from backend import mailer
from backend.access_requests import CHECK_EMAIL, TERMS_VERSION
from backend.config import settings
from backend.mailer import send as real_send  # imported before conftest swaps mailer.send for the outbox
from backend.models import AccessRequest, Activity, EmailToken, User, utcnow

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


def test_rate_limit_is_three_created_requests_per_hour_per_ip(client):
    statuses = [
        client.post("/api/access-requests", json=body(username=f"user{n}", email=f"u{n}@example.com")).status_code
        for n in range(4)
    ]
    assert statuses == [200, 200, 200, 429]


def test_refused_attempts_do_not_use_up_the_request_limit(client, make_user):
    make_user("alice")
    for _ in range(3):
        assert client.post("/api/access-requests", json=body(username="alice")).status_code == 409
    assert client.post("/api/access-requests", json=body()).status_code == 200


def test_every_attempt_counts_towards_twenty_per_hour(client):
    attempts = [body(turnstile_token="bot"), body(agree=False), body(email="not-an-email")]
    for n in range(20):
        assert client.post("/api/access-requests", json=attempts[n % 3]).status_code in (400, 422)
    refused = client.post("/api/access-requests", json=body())
    assert refused.status_code == 429
    assert "Too many" in refused.json()["detail"]


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


def test_dev_console_email_shows_the_link_unbroken(monkeypatch, capsys):
    monkeypatch.setattr(settings, "smtp_host", "")
    verify_link = f"{settings.public_base_url}/verify-email?token=" + "Ab_-" * 11  # longer than a 78-char line
    real_send("newbie@example.com", *mailer.verify_request("newbie", verify_link))
    printed = capsys.readouterr().out
    assert verify_link in printed.splitlines()
    assert "To: newbie@example.com" in printed and "Subject: Confirm your email for Sentinel Lite" in printed
    assert "=3D" not in printed and "=20" not in printed


def test_dev_links_use_the_address_run_py_opens(monkeypatch):
    monkeypatch.setattr(settings, "public_url", "")
    assert settings.public_base_url == "http://127.0.0.1:8000"


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


# --- Who reviewed it: the display name, never the username ---

REVIEWER = "keeper7"  # an admin username that can't appear in an email by accident


def fail_to_send(to, subject, body):
    raise mailer.MailError("SMTPConnectError")


def reviewer_client(client, make_user, display_name=None):
    make_user(REVIEWER, role="admin").display_name = display_name
    return login(client, REVIEWER)


def decide_three(admin_client, outbox) -> list[str]:
    """Approve one chosen-password and one generated-password request, reject a third; return the bodies."""
    bodies = []
    for n, (action, changes) in enumerate([("approve", {}), ("approve", {"password": None, "wants_generated": True}),
                                           ("reject", {})]):
        submit_and_verify(admin_client, outbox, username=f"newbie{n}", email=f"n{n}@example.com", **changes)
        admin_client.post(f"/api/admin/access-requests/{pending_id(admin_client)}/{action}", json={})
        bodies.append(outbox[-1]["body"])
    return bodies


def test_decision_emails_show_the_reviewers_display_name(client, make_user, db, outbox):
    admin_client = reviewer_client(client, make_user, "Priya Sharma")
    db.commit()
    bodies = decide_three(admin_client, outbox)
    assert "Temporary password" in bodies[1] and "not approved" in bodies[2]
    for body in bodies:
        assert "Reviewed by Priya Sharma" in body
        assert REVIEWER not in body


def test_decision_emails_without_a_display_name_say_an_administrator(client, make_user, outbox):
    admin_client = reviewer_client(client, make_user)
    for body in decide_three(admin_client, outbox):
        assert "Reviewed by an administrator" in body
        assert REVIEWER not in body


def test_resent_email_uses_the_reviewers_current_display_name(client, make_user, db, outbox, monkeypatch):
    admin_client = reviewer_client(client, make_user, "Old Name")
    db.commit()
    submit_and_verify(admin_client, outbox)
    request_id = pending_id(admin_client)
    with monkeypatch.context() as patched:
        patched.setattr(mailer, "send", fail_to_send)
        admin_client.post(f"/api/admin/access-requests/{request_id}/reject", json={})

    db.query(User).filter_by(username=REVIEWER).one().display_name = "New Name"
    db.commit()
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/resend-email").status_code == 200
    assert "Reviewed by New Name" in outbox[-1]["body"]
    assert "Old Name" not in outbox[-1]["body"] and REVIEWER not in outbox[-1]["body"]


def test_resend_never_goes_to_someone_who_reused_a_deleted_username(admin_client, db, outbox, monkeypatch):
    submit_and_verify(admin_client, outbox, password=None, wants_generated=True)
    request_id = pending_id(admin_client)
    with monkeypatch.context() as patched:
        patched.setattr(mailer, "send", fail_to_send)
        admin_client.post(f"/api/admin/access-requests/{request_id}/approve")

    newbie = db.query(User).filter_by(username="newbie").one()
    assert admin_client.request("DELETE", f"/api/admin/users/{newbie.id}",
                                json={"confirm_username": "newbie"}).status_code == 200
    admin_client.post("/api/admin/users", json={"username": "newbie", "password": PASSWORD, "email": "other@x.com"})
    sent_before = len(outbox)
    assert admin_client.post(f"/api/admin/access-requests/{request_id}/resend-email").status_code == 409
    assert len(outbox) == sent_before


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


# --- Adding or changing your own email ---

LINK_SENT = "If that address can be used, we've sent a confirmation link to it."


def change_email(client, email, password=PASSWORD):
    return client.post("/api/account/email", json={"email": email, "current_password": password})


def give_alice_an_email(db, email="alice@old.com") -> User:
    alice = db.query(User).filter_by(username="alice").one()
    alice.email, alice.email_verified = email, True
    db.commit()
    return alice


def test_existing_user_adds_a_first_email(user_client, outbox):
    assert user_client.get("/api/auth/me").json()["has_email"] is False
    response = change_email(user_client, "Alice@Example.com")
    assert response.status_code == 200 and response.json()["message"] == LINK_SENT
    assert [email["to"] for email in outbox] == ["alice@example.com"]
    assert user_client.post("/api/email/verify", json={"token": token_in(outbox[-1])}).status_code == 200
    me = user_client.get("/api/auth/me").json()
    assert me["email"] == "alice@example.com" and me["has_email"] is True
    assert len(outbox) == 1  # no previous address, so no "your email was changed" notice


def test_wrong_current_password_is_refused_and_nothing_is_sent(user_client, outbox):
    response = change_email(user_client, "alice@example.com", password="not-my-password")
    assert response.status_code == 400
    assert response.json()["detail"] == "Your current password is wrong"
    assert change_email(user_client, "alice@example.com", password="").status_code == 400
    assert outbox == []


def test_change_keeps_the_old_email_until_confirmed_then_notifies_it(user_client, db, outbox):
    give_alice_an_email(db)
    assert change_email(user_client, "alice@new.com").status_code == 200
    assert [email["to"] for email in outbox] == ["alice@new.com"]  # the link goes to the new address only
    assert user_client.get("/api/auth/me").json()["email"] == "alice@old.com"

    confirmed = user_client.post("/api/email/verify", json={"token": token_in(outbox[0])})
    assert confirmed.status_code == 200
    db.expire_all()
    alice = db.query(User).filter_by(username="alice").one()
    assert (alice.email, alice.email_verified) == ("alice@new.com", True)

    notice = outbox[-1]
    assert notice["to"] == "alice@old.com"
    assert "The email on your Sentinel Lite account alice was changed to a***@new.com." in notice["body"]
    assert "contact an administrator" in notice["body"]
    assert "alice@new.com" not in notice["body"]
    assert "token" not in notice["body"] and "http" not in notice["body"]


def test_same_address_is_refused(user_client, db, outbox):
    give_alice_an_email(db)
    assert change_email(user_client, "Alice@Old.com").status_code == 400
    assert outbox == []


def test_an_address_used_by_another_account_gets_the_same_answer_and_nothing_is_sent(
    user_client, make_user, db, outbox
):
    bob = make_user("bob")
    bob.email = "bob@example.com"
    db.commit()
    taken = change_email(user_client, "bob@example.com")
    assert taken.status_code == 200 and taken.json()["message"] == LINK_SENT
    assert outbox == []
    assert db.query(EmailToken).count() == 0


def test_a_newer_request_invalidates_the_older_link(user_client, db, outbox):
    give_alice_an_email(db)
    change_email(user_client, "first@example.com")
    change_email(user_client, "second@example.com")
    first, second = token_in(outbox[0]), token_in(outbox[1])
    assert user_client.post("/api/email/verify", json={"token": first}).status_code == 400
    assert user_client.post("/api/email/verify", json={"token": second}).status_code == 200
    assert user_client.get("/api/auth/me").json()["email"] == "second@example.com"


def test_change_link_expires_and_works_once(user_client, db, outbox):
    change_email(user_client, "alice@example.com")
    token = token_in(outbox[0])
    stored = db.query(EmailToken).one()
    assert stored.token_hash != token  # only the hash is stored
    stored.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert "expired" in user_client.post("/api/email/verify", json={"token": token}).json()["detail"]

    stored.expires_at = utcnow() + timedelta(hours=1)
    db.commit()
    assert user_client.post("/api/email/verify", json={"token": token}).status_code == 200
    again = user_client.post("/api/email/verify", json={"token": token})
    assert again.status_code == 400 and "already been used" in again.json()["detail"]


def test_confirming_rechecks_that_the_address_is_still_free(user_client, make_user, db, outbox):
    change_email(user_client, "alice@example.com")
    bob = make_user("bob")
    bob.email = "alice@example.com"  # taken in the meantime
    db.commit()
    assert user_client.post("/api/email/verify", json={"token": token_in(outbox[0])}).status_code == 409


def test_link_requests_are_limited_to_three_an_hour(user_client, outbox):
    for n in range(3):
        assert change_email(user_client, f"a{n}@example.com").status_code == 200
    assert change_email(user_client, "a3@example.com").status_code == 429
    assert len(outbox) == 3


def test_email_change_activity_is_masked(activity_log_file, user_client, db, outbox):
    change_email(user_client, "alice@first.com")
    user_client.post("/api/email/verify", json={"token": token_in(outbox[-1])})
    change_email(user_client, "alice@second.com")
    user_client.post("/api/email/verify", json={"token": token_in(outbox[-1])})

    entries = [(a.action, a.detail) for a in db.query(Activity).filter_by(username="alice").order_by(Activity.id)]
    assert [entry for entry in entries if entry[0] != "login"] == [
        ("email_change_requested", "a***@first.com"),
        ("email_added", "a***@first.com"),
        ("email_change_requested", "a***@second.com"),
        ("email_changed", "a***@first.com -> a***@second.com"),
    ]
    log = activity_log_file.read_text(encoding="utf-8")
    assert "| email_changed |" in log
    assert "alice@first.com" not in log and "alice@second.com" not in log


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
