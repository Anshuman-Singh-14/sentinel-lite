import csv
import io

from conftest import PASSWORD


def test_every_event_is_appended_to_the_log_file(activity_log_file, admin_client):
    admin_client.post("/api/admin/targets", json={"host": "example.com"})
    admin_client.post("/api/auth/logout")

    lines = activity_log_file.read_text(encoding="utf-8").splitlines()
    assert [line.split(" | ")[1:3] for line in lines] == [
        ["admin", "login"],
        ["admin", "target_added"],
        ["admin", "logout"],
    ]
    assert lines[1].endswith("| example.com")


def test_a_username_cannot_add_fake_lines_to_the_log(activity_log_file, client):
    client.post("/api/auth/login", json={"username": "x\nfake | admin | login", "password": PASSWORD})
    lines = activity_log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert "| x fake | admin | login | login_failed |" in lines[0]


def test_admin_downloads_every_event_as_txt(admin_client):
    admin_client.post("/api/admin/targets", json={"host": "example.com"})
    response = admin_client.get("/api/admin/activity/export.txt")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith('attachment; filename="sentinel-activity-')
    actions = [line.split(" | ")[2] for line in response.text.splitlines()]
    assert actions == ["login", "target_added", "activity_exported"]  # oldest first


def test_admin_downloads_every_event_as_csv(client, make_user):
    make_user("admin", role="admin")
    client.post("/api/auth/login", json={"username": "=HYPERLINK(1)", "password": "wrong-password"})
    client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})

    response = client.get("/api/admin/activity/export.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert rows[0] == ["id", "time_utc", "username", "action", "detail"]
    assert [row[2:4] for row in rows[1:]] == [
        ["'=HYPERLINK(1)", "login_failed"],  # neutralised so Excel won't run it
        ["admin", "login"],
        ["admin", "activity_exported"],
    ]


def test_only_admins_can_download_the_activity_log(user_client):
    assert user_client.get("/api/admin/activity/export.txt").status_code == 403
    assert user_client.get("/api/admin/activity/export.csv").status_code == 403
