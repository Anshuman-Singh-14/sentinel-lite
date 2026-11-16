import csv
import io
import re

from conftest import PASSWORD

from backend.tools.log_analyzer import KEY_VALUE, SENTINEL_NEW_LINE, unquote

CSV_COLUMNS = ["id", "time_utc", "ip", "username", "action", "result", "detail"]


def fields(line: str) -> dict:
    """The key=value pairs of one new-format line, parsed the way the log analyzer does."""
    match = SENTINEL_NEW_LINE.match(line)
    assert match, line
    return {key: unquote(value) for key, value in KEY_VALUE.findall(match["fields"])}


def request_lines(path) -> list[dict]:
    """Every line written during requests (startup writes "system" lines first)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [fields(line) for line in lines if fields(line)["user"] != "system"]


def test_every_event_is_appended_to_the_log_file(activity_log_file, admin_client):
    admin_client.post("/api/admin/targets", json={"host": "example.com"})
    admin_client.post("/api/auth/logout")

    lines = activity_log_file.read_text(encoding="utf-8").splitlines()
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ ip=- user=system action=app_started result=ok "
                    r'detail="env=dev"$', lines[0])
    assert [(line["user"], line["action"], line["ip"], line["result"]) for line in request_lines(activity_log_file)] == [
        ("admin", "login", "testclient", "ok"),
        ("admin", "target_added", "testclient", "ok"),
        ("admin", "logout", "testclient", "ok"),
    ]
    assert lines[2].endswith(" action=target_added result=ok detail=example.com")
    assert lines[1].endswith(' action=login result=ok detail=""')


def test_a_username_cannot_add_fake_lines_or_fields_to_the_log(activity_log_file, client):
    tricky = 'x\n2026-01-01T00:00:00Z ip=1.2.3.4 user=admin action=login result=ok detail="a\\" b'
    client.post("/api/auth/login", json={"username": tricky[:32], "password": PASSWORD})
    client.post("/api/auth/login", json={"username": 'q" action=login', "password": PASSWORD})
    lines = request_lines(activity_log_file)
    assert len(lines) == 2  # one line per event, however the username looks
    assert lines[0]["user"] == " ".join(tricky[:32].split())  # the newline became a space
    assert lines[1] == {"ip": "testclient", "user": 'q" action=login', "action": "login_failed", "result": "fail",
                        "detail": "unknown user"}
    raw = activity_log_file.read_text(encoding="utf-8").splitlines()
    assert all(SENTINEL_NEW_LINE.match(line) for line in raw)
    assert 'user="q\\" action=login" action=login_failed' in raw[-1]


def test_admin_downloads_every_event_as_txt(admin_client):
    admin_client.post("/api/admin/targets", json={"host": "example.com"})
    response = admin_client.get("/api/admin/activity/export.txt")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith('attachment; filename="sentinel-activity-')
    actions = [fields(line)["action"] for line in response.text.splitlines()]
    assert actions == ["app_started", "login", "target_added", "activity_exported"]  # oldest first


def test_admin_downloads_every_event_as_csv(client, make_user):
    make_user("admin", role="admin")
    client.post("/api/auth/login", json={"username": "=HYPERLINK(1)", "password": "wrong-password"})
    client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})

    response = client.get("/api/admin/activity/export.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.content.startswith("\ufeff".encode())  # the byte-order mark Excel needs
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert rows[0] == CSV_COLUMNS
    assert [row[2:6] for row in rows[2:]] == [
        ["testclient", "'=HYPERLINK(1)", "login_failed", "fail"],  # neutralised so Excel won't run it
        ["testclient", "admin", "login", "ok"],
        ["testclient", "admin", "activity_exported", "ok"],
    ]
    assert rows[1][2:6] == ["-", "system", "app_started", "ok"]


def test_only_admins_can_download_the_activity_log(user_client):
    assert user_client.get("/api/admin/activity/export.txt").status_code == 403
    assert user_client.get("/api/admin/activity/export.csv").status_code == 403


def test_admin_views_the_log_in_the_browser(admin_client):
    txt = admin_client.get("/api/admin/activity/export.txt?view=1")
    assert txt.status_code == 200
    assert txt.headers["content-type"] == "text/plain; charset=utf-8"
    assert txt.headers["content-disposition"].startswith('inline; filename="sentinel-activity-')
    assert txt.text.splitlines()[-1].endswith(" user=admin action=activity_viewed result=ok detail=TXT")

    # Sent as text/plain, otherwise the browser would download the CSV instead of showing it.
    csv_view = admin_client.get("/api/admin/activity/export.csv?view=1")
    assert csv_view.status_code == 200
    assert csv_view.headers["content-type"] == "text/plain; charset=utf-8"
    assert csv_view.headers["content-disposition"].startswith("inline; ")
    rows = list(csv.reader(io.StringIO(csv_view.content.decode("utf-8-sig"))))
    assert rows[0] == CSV_COLUMNS
    assert [row[4] for row in rows[1:]] == ["app_started", "login", "activity_viewed", "activity_viewed"]


def test_activity_list_includes_ip_and_result(admin_client):
    admin_client.post("/api/admin/targets", json={"host": "example.com"})
    newest = admin_client.get("/api/admin/activity").json()[0]
    assert (newest["action"], newest["ip"], newest["result"]) == ("target_added", "testclient", "ok")


def test_downloads_are_unchanged_and_views_are_separate(admin_client):
    txt = admin_client.get("/api/admin/activity/export.txt")
    assert txt.headers["content-type"] == "text/plain; charset=utf-8"
    assert txt.headers["content-disposition"].startswith("attachment; ")
    csv_download = admin_client.get("/api/admin/activity/export.csv")
    assert csv_download.headers["content-type"] == "text/csv; charset=utf-8"
    assert csv_download.headers["content-disposition"].startswith("attachment; ")
    assert txt.headers["content-disposition"].split("filename=")[1].rstrip('"').endswith(".txt")
    assert csv_download.headers["content-disposition"].split("filename=")[1].rstrip('"').endswith(".csv")


def test_the_log_is_never_cached(admin_client):
    for url in [
        "/api/admin/activity",
        "/api/admin/activity?limit=5000",
        "/api/admin/activity/export.txt",
        "/api/admin/activity/export.csv",
        "/api/admin/activity/export.txt?view=1",
        "/api/admin/activity/export.csv?view=1",
    ]:
        assert admin_client.get(url).headers["cache-control"] == "no-store", url


def test_only_admins_can_view_the_activity_log(client, user_client):
    assert user_client.get("/api/admin/activity/export.txt?view=1").status_code == 403
    assert user_client.get("/api/admin/activity/export.csv?view=1").status_code == 403
    user_client.post("/api/auth/logout")
    for url in [
        "/api/admin/activity/export.txt",
        "/api/admin/activity/export.csv",
        "/api/admin/activity/export.txt?view=1",
        "/api/admin/activity/export.csv?view=1",
    ]:
        assert client.get(url).status_code == 401, url
