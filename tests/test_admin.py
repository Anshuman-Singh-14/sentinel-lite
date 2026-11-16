import pytest
from conftest import PASSWORD, login
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import admin as admin_routes
from backend.app import app
from backend.models import AccessRequest, Activity, EmailToken, Scan, User, utcnow


def test_admin_creates_user_who_can_log_in(admin_client):
    weak = admin_client.post("/api/admin/users", json={"username": "bob", "password": "short", "email": "b@x.com"})
    assert weak.status_code == 422
    response = admin_client.post(
        "/api/admin/users", json={"username": "bob", "password": PASSWORD, "email": "Bob@Example.com"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "user"
    assert response.json()["email"] == "bob@example.com"  # stored lowercased
    usernames = [user["username"] for user in admin_client.get("/api/admin/users").json()]
    assert usernames == ["admin", "bob"]

    admin_client.post("/api/auth/logout")
    login = admin_client.post("/api/auth/login", json={"username": "bob", "password": PASSWORD})
    assert login.status_code == 200


def test_email_is_required_for_users_but_not_admins(admin_client):
    no_email = admin_client.post("/api/admin/users", json={"username": "bob", "password": PASSWORD})
    assert no_email.status_code == 422
    bad_email = admin_client.post("/api/admin/users", json={"username": "bob", "password": PASSWORD, "email": "nope"})
    assert bad_email.status_code == 422
    admin = admin_client.post("/api/admin/users", json={"username": "root2", "password": PASSWORD, "role": "admin"})
    assert admin.status_code == 200
    assert admin.json()["has_email"] is False

    # Turning an admin without an email into a user needs an email first, which only they can add.
    admin_id = admin.json()["id"]
    assert admin_client.patch(f"/api/admin/users/{admin_id}", json={"role": "user"}).status_code == 400
    assert admin_client.patch(f"/api/admin/users/{admin_id}", json={"role": "user", "email": "r@x.com"}).status_code == 400


def test_role_user_works_once_the_account_has_an_email(admin_client, make_user, db):
    root = make_user("root2", role="admin")
    root.email = "root2@example.com"  # added by root2 themselves under Change email
    db.commit()
    changed = admin_client.patch(f"/api/admin/users/{root.id}", json={"role": "user"})
    assert changed.status_code == 200
    assert changed.json()["role"] == "user"


def test_patch_ignores_an_email_field(admin_client, make_user, db):
    bob = make_user("bob")
    bob.email, bob.email_verified = "bob@example.com", True
    db.commit()
    assert admin_client.patch(f"/api/admin/users/{bob.id}", json={"email": "evil@example.com"}).status_code == 200
    both = admin_client.patch(f"/api/admin/users/{bob.id}", json={"email": "evil@example.com", "is_active": False})
    assert both.status_code == 200 and both.json()["is_active"] is False
    db.expire_all()
    assert (bob.email, bob.email_verified) == ("bob@example.com", True)


def test_emails_are_unique(admin_client):
    admin_client.post("/api/admin/users", json={"username": "bob", "password": PASSWORD, "email": "b@x.com"})
    same = admin_client.post("/api/admin/users", json={"username": "eve", "password": PASSWORD, "email": "B@x.com"})
    assert same.status_code == 409


def test_existing_users_without_email_can_still_be_changed(admin_client, make_user):
    old = make_user("old")  # created before emails existed
    assert admin_client.patch(f"/api/admin/users/{old.id}", json={"is_active": False}).status_code == 200


def test_password_reset_forces_a_change(admin_client, make_user):
    bob = make_user("bob")
    admin_client.patch(f"/api/admin/users/{bob.id}", json={"password": "reset-by-admin-1"})
    admin_client.post("/api/auth/logout")
    login = admin_client.post("/api/auth/login", json={"username": "bob", "password": "reset-by-admin-1"})
    assert login.json()["must_change_password"] is True
    assert admin_client.get("/api/scans").json() == {"detail": "password_change_required"}


def test_admin_cannot_demote_themselves(admin_client):
    me = admin_client.get("/api/auth/me").json()
    response = admin_client.patch(f"/api/admin/users/{me['id']}", json={"role": "user"})
    assert response.status_code == 400


def test_add_list_and_remove_target(admin_client):
    added = admin_client.post("/api/admin/targets", json={"host": "Example.COM", "note": "lab"}).json()
    assert added["host"] == "example.com"  # hostnames are stored lowercased
    assert [t["host"] for t in admin_client.get("/api/admin/targets").json()] == ["example.com"]
    assert admin_client.post("/api/admin/targets", json={"host": "example.com"}).status_code == 409
    assert admin_client.delete(f"/api/admin/targets/{added['id']}").status_code == 200
    assert admin_client.get("/api/admin/targets").json() == []


def test_activity_log_records_logins_and_admin_actions(admin_client):
    admin_client.post("/api/admin/targets", json={"host": "example.com"})
    actions = [entry["action"] for entry in admin_client.get("/api/admin/activity").json()]
    assert actions == ["target_added", "login", "app_started"]  # newest first


def test_activity_list_takes_a_limit(admin_client, db):
    db.add_all(Activity(username="admin", action="login", detail=f"event {n}") for n in range(300))
    db.commit()
    assert len(admin_client.get("/api/admin/activity").json()) == 200  # the admin page default
    assert len(admin_client.get("/api/admin/activity?limit=5000").json()) == 302  # 300 + app_started + login
    assert len(admin_client.get("/api/admin/activity?limit=10").json()) == 10
    assert admin_client.get("/api/admin/activity?limit=0").status_code == 422
    assert admin_client.get("/api/admin/activity?limit=5001").status_code == 422


def test_only_admins_can_list_activity(client, user_client):
    assert user_client.get("/api/admin/activity").status_code == 403
    assert user_client.get("/api/admin/activity?limit=5000").status_code == 403
    user_client.post("/api/auth/logout")
    assert client.get("/api/admin/activity?limit=5000").status_code == 401


# --- Deleting users ---


def delete(client, user, confirm=None):
    return client.request("DELETE", f"/api/admin/users/{user.id}", json={"confirm_username": confirm or user.username})


def test_delete_removes_the_user_and_their_scans_and_keeps_history(admin_client, make_user, db):
    bob = make_user("bob")
    alice = make_user("alice")
    db.add_all([Scan(user_id=bob.id, tool="dns_check", target="example.com"),
                Scan(user_id=bob.id, tool="web_check", target="example.com"),
                Scan(user_id=alice.id, tool="dns_check", target="example.org")])
    db.add_all([EmailToken(token_hash="a" * 64, purpose="verify_user_email", ref_id=bob.id, email="b@x.com",
                           expires_at=utcnow()),
                EmailToken(token_hash="b" * 64, purpose="verify_request", ref_id=bob.id, email="r@x.com",
                           expires_at=utcnow())])
    db.add(AccessRequest(username="bob", email="b@x.com", terms_version="v1", status="approved"))
    db.add(Activity(username="bob", action="login", detail="from 127.0.0.1"))
    db.commit()
    bob_id = bob.id
    db.expunge_all()

    response = delete(admin_client, bob)
    assert response.status_code == 200
    assert db.get(User, bob_id) is None
    assert [scan.target for scan in db.query(Scan)] == ["example.org"]  # alice's scan stays
    # Only bob's "add my email" link goes; a request token with the same number belongs to a request.
    assert [token.purpose for token in db.query(EmailToken)] == ["verify_request"]
    assert db.query(AccessRequest).count() == 1
    assert db.query(Activity).filter_by(username="bob", action="login").count() == 1
    last = admin_client.get("/api/admin/activity").json()[0]
    assert (last["action"], last["detail"]) == ("user_deleted", "bob (user, 2 scans deleted)")

    # The username and email are free again.
    again = admin_client.post("/api/admin/users", json={"username": "bob", "password": PASSWORD, "email": "b@x.com"})
    assert again.status_code == 200


def test_delete_needs_the_exact_username(admin_client, make_user, db):
    bob = make_user("bob")
    assert delete(admin_client, bob, confirm="Bob").status_code == 400
    assert delete(admin_client, bob, confirm="bob ").status_code == 400
    assert admin_client.request("DELETE", f"/api/admin/users/{bob.id}", json={}).status_code == 422
    assert admin_client.request("DELETE", "/api/admin/users/999", json={"confirm_username": "x"}).status_code == 404
    db.expire_all()
    assert db.get(User, bob.id) is not None


def test_admin_cannot_delete_themselves(admin_client, db):
    me = db.query(User).filter_by(username="admin").one()
    response = delete(admin_client, me)
    assert response.status_code == 400
    assert "your own account" in response.json()["detail"]


def test_last_active_admin_cannot_be_deleted(db, make_user):
    """Through the API the caller is always another active admin, so call the route directly."""
    caller = make_user("boss", role="admin", is_active=False)
    only_admin = make_user("root", role="admin")
    with pytest.raises(HTTPException) as refused:
        admin_routes.delete_user(only_admin.id, admin_routes.UserDeletion(confirm_username="root"), caller, db)
    assert refused.value.status_code == 400
    assert "last active admin" in refused.value.detail


def test_another_admin_can_be_deleted(admin_client, make_user):
    other = make_user("root2", role="admin")
    assert delete(admin_client, other).status_code == 200
    assert admin_client.get("/api/admin/activity").json()[0]["detail"] == "root2 (admin, 0 scans deleted)"


def test_only_admins_can_delete(client, user_client, make_user):
    bob = make_user("bob")
    assert delete(user_client, bob).status_code == 403
    user_client.post("/api/auth/logout")
    assert delete(client, bob).status_code == 401


def test_deleted_users_session_stops_working(admin_client, make_user, db):
    bob = make_user("bob")
    bob_id = bob.id
    with TestClient(app) as bob_client:
        login(bob_client, "bob")
        assert bob_client.get("/api/auth/me").status_code == 200
        assert delete(admin_client, bob).status_code == 200
        assert bob_client.get("/api/auth/me").status_code == 401

        # SQLite gives the freed id to the next new account; bob's old cookie must not work for it.
        db.expunge_all()
        carol = make_user("carol")
        assert carol.id == bob_id
        assert bob_client.get("/api/auth/me").status_code == 401


# --- Display names ---


def set_name(client, user, name):
    return client.patch(f"/api/admin/users/{user.id}", json={"display_name": name})


def test_admin_display_name_is_set_trimmed_and_cleared(admin_client, make_user):
    root = make_user("root2", role="admin")
    response = set_name(admin_client, root, "  Priya Sharma  ")
    assert response.status_code == 200
    assert response.json()["display_name"] == "Priya Sharma"
    assert set_name(admin_client, root, "प्रिया शर्मा").json()["display_name"] == "प्रिया शर्मा"
    assert set_name(admin_client, root, "José O'Neil-Smith Jr.").status_code == 200
    assert set_name(admin_client, root, "").json()["display_name"] is None

    details = [(e["action"], e["detail"]) for e in admin_client.get("/api/admin/activity").json()[:3]]
    assert details == [
        ("user_display_name_changed", "root2: cleared"),
        ("user_display_name_changed", "root2: 'José O'Neil-Smith Jr.'"),
        ("user_display_name_changed", "root2: 'प्रिया शर्मा'"),
    ]


def test_display_name_validation(admin_client, make_user):
    root = make_user("root2", role="admin")
    assert set_name(admin_client, root, "x" * 51).status_code == 422
    assert set_name(admin_client, root, "x" * 50).status_code == 200
    for bad in ["<b>Boss</b>", "a@b.com", "two\nlines", "Admin!", "x_y"]:
        assert set_name(admin_client, root, bad).status_code == 422, bad


def test_display_name_cannot_be_a_username(admin_client, make_user):
    root = make_user("root2", role="admin")
    make_user("alice")
    for taken in ["ALICE", "Root2", "admin"]:
        response = set_name(admin_client, root, taken)
        assert response.status_code == 400, taken
        assert response.json()["detail"] == "A display name can't be the same as a username"


def test_display_name_is_only_for_admins(admin_client, make_user):
    bob = make_user("bob")
    assert set_name(admin_client, bob, "Bob B").status_code == 400
    assert set_name(admin_client, bob, "").status_code == 400
