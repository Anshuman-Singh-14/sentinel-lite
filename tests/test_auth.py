from conftest import PASSWORD


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


def test_security_headers_except_csp_on_api_docs(client):
    assert "default-src 'self'" in client.get("/api/health").headers["content-security-policy"]
    docs = client.get("/api/docs")  # Swagger UI needs its CDN scripts, so no CSP there
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers
    assert docs.headers["x-frame-options"] == "DENY"
