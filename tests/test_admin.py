from conftest import PASSWORD


def test_admin_creates_user_who_can_log_in(admin_client):
    response = admin_client.post("/api/admin/users", json={"username": "bob", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["role"] == "user"
    usernames = [user["username"] for user in admin_client.get("/api/admin/users").json()]
    assert usernames == ["admin", "bob"]

    admin_client.post("/api/auth/logout")
    login = admin_client.post("/api/auth/login", json={"username": "bob", "password": PASSWORD})
    assert login.status_code == 200


def test_weak_password_is_rejected(admin_client):
    response = admin_client.post("/api/admin/users", json={"username": "bob", "password": "short"})
    assert response.status_code == 422


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
