from sqlalchemy import select

from backend.models import User
from backend.results import make_finding, save_scan


def add_scan(db, username, target="example.com"):
    user = db.scalar(select(User).where(User.username == username))
    findings = [make_finding("port.database_exposed", port=3306, service="MySQL")]
    return save_scan(db, user, "port_scan", target, {"ip": "203.0.113.9"}, findings)


def test_history_shows_only_your_own_scans(db, make_user, user_client):
    make_user("bob")
    mine = add_scan(db, "alice")
    theirs = add_scan(db, "bob")

    history = user_client.get("/api/scans").json()
    assert [scan["id"] for scan in history] == [mine["id"]]
    assert history[0]["counts"] == {"high": 1, "medium": 0, "low": 0}
    assert user_client.get(f"/api/scans/{theirs['id']}").status_code == 404
    assert user_client.get(f"/api/scans/{theirs['id']}/export.csv").status_code == 404


def test_csv_export_neutralises_formulas(db, user_client):
    scan = add_scan(db, "alice", target='=HYPERLINK("http://evil.example")')
    csv_text = user_client.get(f"/api/scans/{scan['id']}/export.csv").text
    assert "A database port is reachable" in csv_text
    assert "'=HYPERLINK" in csv_text


def test_html_report_escapes_content(db, user_client):
    scan = add_scan(db, "alice", target="<script>alert(1)</script>")
    response = user_client.get(f"/api/scans/{scan['id']}/report")
    assert "&lt;script&gt;" in response.text
    assert "<script>" not in response.text
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
