from conftest import PASSWORD

from backend.models import Activity


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

    # Turning an admin without an email into a user needs an email first.
    admin_id = admin.json()["id"]
    assert admin_client.patch(f"/api/admin/users/{admin_id}", json={"role": "user"}).status_code == 400
    changed = admin_client.patch(f"/api/admin/users/{admin_id}", json={"role": "user", "email": "r@x.com"})
    assert changed.status_code == 200
    assert changed.json()["email"] == "r@x.com"


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
    assert actions == ["target_added", "login"]  # newest first


def test_activity_list_takes_a_limit(admin_client, db):
    db.add_all(Activity(username="admin", action="login", detail=f"event {n}") for n in range(300))
    db.commit()
    assert len(admin_client.get("/api/admin/activity").json()) == 200  # the admin page default
    assert len(admin_client.get("/api/admin/activity?limit=5000").json()) == 301  # 300 + the real login
    assert len(admin_client.get("/api/admin/activity?limit=10").json()) == 10
    assert admin_client.get("/api/admin/activity?limit=0").status_code == 422
    assert admin_client.get("/api/admin/activity?limit=5001").status_code == 422


def test_only_admins_can_list_activity(client, user_client):
    assert user_client.get("/api/admin/activity").status_code == 403
    assert user_client.get("/api/admin/activity?limit=5000").status_code == 403
    user_client.post("/api/auth/logout")
    assert client.get("/api/admin/activity?limit=5000").status_code == 401
