from conftest import PASSWORD

from backend import guard


def test_login_sets_session(client, make_user):
    make_user("alice")
    response = client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["role"] == "user"
    assert client.get("/api/auth/me").json()["username"] == "alice"


def test_wrong_password_and_unknown_user_look_the_same(client, make_user):
    make_user("alice")
    wrong_password = client.post("/api/auth/login", json={"username": "alice", "password": "nope-nope"})
    unknown_user = client.post("/api/auth/login", json={"username": "bob", "password": PASSWORD})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_inactive_user_cannot_log_in(client, make_user):
    make_user("alice", is_active=False)
    response = client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 401


def test_routes_need_login(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/tools/dns-check", json={"domain": "example.com"}).status_code == 401


def test_logout_ends_session(user_client):
    user_client.post("/api/auth/logout")
    assert user_client.get("/api/auth/me").status_code == 401


def test_admin_routes_refuse_normal_users(user_client):
    assert user_client.get("/api/admin/users").status_code == 403


def test_passwords_are_stored_hashed(make_user):
    user = make_user("alice")
    assert PASSWORD not in user.password_hash
    assert user.password_hash.startswith("$2b$")


def change(client, current, new):
    return client.post("/api/auth/change-password", json={"current_password": current, "new_password": new})


def test_user_changes_password(user_client, db):
    assert change(user_client, "wrong-password", "brand-new-pass").status_code == 400
    assert change(user_client, PASSWORD, PASSWORD).status_code == 400  # must differ
    assert change(user_client, PASSWORD, "short").status_code == 422
    response = change(user_client, PASSWORD, "brand-new-pass")
    assert response.status_code == 200
    assert user_client.get("/api/auth/me").status_code == 200  # still logged in

    guard.login_limiter.reset()  # the attempts above count against the login limit
    user_client.post("/api/auth/logout")
    assert user_client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD}).status_code == 401
    assert user_client.post("/api/auth/login", json={"username": "alice", "password": "brand-new-pass"}).status_code == 200


def test_must_change_password_blocks_everything_else(client, make_user, db):
    user = make_user("alice")
    user.must_change_password = True
    db.commit()
    client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})

    assert client.get("/api/auth/me").json()["must_change_password"] is True
    for response in [client.get("/api/scans"), client.post("/api/tools/dns-check", json={"domain": "example.com"})]:
        assert response.status_code == 403
        assert response.json() == {"detail": "password_change_required"}

    assert change(client, PASSWORD, "brand-new-pass").json()["must_change_password"] is False
    assert client.get("/api/scans").status_code == 200


def test_change_password_uses_the_login_rate_limit(user_client):
    statuses = [change(user_client, "wrong-password", "brand-new-pass").status_code for _ in range(5)]
    assert statuses[-1] == 429  # the login itself used one of the 5 attempts


def test_security_headers_except_csp_on_api_docs(client):
    assert "default-src 'self'" in client.get("/api/health").headers["content-security-policy"]
    docs = client.get("/api/docs")  # Swagger UI needs its CDN scripts, so no CSP there
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers
    assert docs.headers["x-frame-options"] == "DENY"
