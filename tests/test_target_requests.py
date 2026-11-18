"""Website (target) requests: users ask, admins approve or reject, private targets."""

import pytest
from conftest import login
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import guard, mailer
from backend.app import app
from backend.config import settings
from backend.models import Activity, AllowedTarget, TargetAccess, TargetRequest, User
from backend.tools import port_scan

# Fake DNS, so no test touches the network.
FAKE_DNS = {
    "alice-site.com": ["93.184.216.34"],
    "shared-site.com": ["93.184.216.35"],
    "inside.example.com": ["10.0.0.5"],
}


@pytest.fixture(autouse=True)
def fake_network(monkeypatch):
    def resolve(host):
        if host in FAKE_DNS:
            return list(FAKE_DNS[host])
        raise HTTPException(400, f"Could not find an IPv4 address for {host}")

    async def no_open_ports(ip, ports):
        return []

    monkeypatch.setattr(guard, "resolve", resolve)
    monkeypatch.setattr(guard, "server_ips", lambda: set())
    monkeypatch.setattr(port_scan, "scan", no_open_ports)


def body(**changes) -> dict:
    return {"host": "alice-site.com", "reason": "My portfolio site", "confirm": True} | changes


@pytest.fixture
def people(db, make_user):
    """alice and bob (users with emails) and an admin with a display name."""
    alice, bob = make_user("alice"), make_user("bob")
    alice.email, bob.email = "alice@example.com", "bob@example.com"
    admin = make_user("rootadmin", role="admin")
    admin.display_name = "Priya Sharma"
    db.commit()
    return alice, bob, admin


def client_for(username: str) -> TestClient:
    return login(TestClient(app), username)


@pytest.fixture
def clients(people, client):
    """Separate logged-in clients, so each keeps its own session cookie."""
    return client_for("alice"), client_for("bob"), client_for("rootadmin")


def scan(client: TestClient, host: str) -> int:
    return client.post("/api/tools/port-scan", json={"target": host}).status_code


def last(db, action: str) -> Activity:
    db.expire_all()
    entry = db.query(Activity).filter_by(action=action).order_by(Activity.id.desc()).first()
    assert entry is not None, f"no {action} event was logged"
    return entry


def request_and_approve(alice_client, admin_client) -> int:
    request_id = alice_client.post("/api/target-requests", json=body()).json()["id"]
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/approve").status_code == 200
    return request_id


# --- Making a request ---


def test_request_is_saved_with_its_resolved_ips(clients, db):
    alice_client, _bob, _admin = clients
    response = alice_client.post("/api/target-requests", json=body(host="Alice-Site.COM"))
    assert response.status_code == 200
    saved = db.query(TargetRequest).one()
    assert (saved.host, saved.status, saved.resolved_ips) == ("alice-site.com", "pending", "93.184.216.34")
    assert saved.permission_confirmed_at is not None
    assert [r["host"] for r in alice_client.get("/api/target-requests").json()] == ["alice-site.com"]
    assert last(db, "target_requested").detail == "alice-site.com"


def test_request_validation(clients, db, monkeypatch):
    alice_client, _bob, _admin = clients
    assert alice_client.post("/api/target-requests", json=body(confirm=False)).status_code == 422
    assert alice_client.post("/api/target-requests", json=body(reason="x" * 501)).status_code == 422
    assert alice_client.post("/api/target-requests", json=body(host="not a host")).status_code == 422
    assert alice_client.post("/api/target-requests", json=body(host="nowhere.example.com")).status_code == 400

    # Internal addresses are only refused on the real server, like guard.check_target.
    monkeypatch.setattr(settings, "app_env", "prod")
    inside = alice_client.post("/api/target-requests", json=body(host="inside.example.com"))
    assert inside.status_code == 400 and "internal address" in inside.json()["detail"]
    monkeypatch.setattr(settings, "app_env", "dev")
    assert db.query(TargetRequest).count() == 0

    assert alice_client.post("/api/target-requests", json=body()).status_code == 200
    again = alice_client.post("/api/target-requests", json=body())
    assert again.status_code == 409 and "pending request" in again.json()["detail"]


def test_request_for_a_target_you_can_already_scan_is_refused(clients, db):
    alice_client, _bob, _admin = clients
    db.add(AllowedTarget(host="shared-site.com", added_by="rootadmin", shared=True))
    db.commit()
    response = alice_client.post("/api/target-requests", json=body(host="shared-site.com"))
    assert response.status_code == 409
    assert response.json()["detail"] == "You can already scan this website"


def test_rate_limit_is_five_requests_per_hour(clients, db, monkeypatch):
    alice_client, _bob, _admin = clients
    FAKE_DNS.update({f"site{n}.com": ["93.184.216.40"] for n in range(6)})
    statuses = [alice_client.post("/api/target-requests", json=body(host=f"site{n}.com")).status_code
                for n in range(6)]
    assert statuses == [200] * 5 + [429]
    entry = last(db, "rate_limited")
    assert (entry.username, entry.detail, entry.result) == ("alice", "target_request", "denied")


def test_cancel_only_your_own_pending_request(clients, db):
    alice_client, bob_client, admin_client = clients
    request_id = alice_client.post("/api/target-requests", json=body()).json()["id"]
    assert bob_client.post(f"/api/target-requests/{request_id}/cancel").status_code == 404
    assert alice_client.post(f"/api/target-requests/{request_id}/cancel").json()["status"] == "cancelled"
    assert alice_client.post(f"/api/target-requests/{request_id}/cancel").status_code == 409
    assert last(db, "target_request_cancelled").detail == "alice-site.com"
    # A cancelled request can't be approved, and gave no access.
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/approve").status_code == 409
    assert db.query(TargetAccess).count() == 0
    assert scan(alice_client, "alice-site.com") == 403


# --- Who can scan what ---


def test_private_target_is_only_for_the_approved_user(clients, db, outbox):
    alice_client, bob_client, admin_client = clients
    assert scan(alice_client, "alice-site.com") == 403
    refused = alice_client.post("/api/tools/port-scan", json={"target": "alice-site.com"})
    assert "not an approved target" in refused.json()["detail"]

    request_and_approve(alice_client, admin_client)
    target = db.query(AllowedTarget).one()
    assert (target.host, target.shared, target.added_by) == ("alice-site.com", False, "rootadmin")
    assert scan(alice_client, "alice-site.com") == 200
    assert scan(bob_client, "alice-site.com") == 403
    assert scan(admin_client, "alice-site.com") == 200

    mine = alice_client.get("/api/targets/mine").json()
    assert [(t["host"], t["access"]) for t in mine] == [("alice-site.com", "private")]
    assert bob_client.get("/api/targets/mine").json() == []
    assert last(db, "target_request_approved").detail == "alice-site.com for alice"


def test_shared_targets_work_for_everyone_and_admins_scan_everything(clients, db, people):
    alice_client, bob_client, admin_client = clients
    alice, bob, admin = people
    db.add_all([AllowedTarget(host="shared-site.com", added_by="rootadmin", shared=True),
                AllowedTarget(host="alice-site.com", added_by="rootadmin", shared=False)])
    db.commit()
    assert scan(alice_client, "shared-site.com") == scan(bob_client, "shared-site.com") == 200
    assert guard.check_target(db, "alice-site.com", admin) == "93.184.216.34"
    with pytest.raises(HTTPException):
        guard.check_target(db, "alice-site.com", bob)
    assert [t["access"] for t in bob_client.get("/api/targets/mine").json()] == ["shared"]
    assert len(admin_client.get("/api/targets/mine").json()) == 2


def test_approve_twice_gives_one_access_row(clients, db):
    alice_client, _bob, admin_client = clients
    request_id = request_and_approve(alice_client, admin_client)
    second = admin_client.post(f"/api/admin/target-requests/{request_id}/approve")
    assert second.status_code == 409
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/reject").status_code == 409
    assert db.query(TargetAccess).count() == 1
    assert db.query(Activity).filter_by(action="target_request_approved").count() == 1


def test_approving_an_existing_target_keeps_its_shared_setting(clients, db):
    alice_client, _bob, admin_client = clients
    db.add(AllowedTarget(host="alice-site.com", added_by="rootadmin", shared=False))
    db.commit()
    request_and_approve(alice_client, admin_client)
    db.expire_all()
    target = db.query(AllowedTarget).one()
    assert target.shared is False
    assert db.query(TargetAccess).filter_by(target_id=target.id).count() == 1

    # Shared stays shared too; the access row is still added for if it is made private later.
    db.add(AllowedTarget(host="shared-site.com", added_by="rootadmin", shared=True))
    db.commit()
    shared = db.query(AllowedTarget).filter_by(host="shared-site.com").one()
    db.add(TargetRequest(user_id=db.query(User).filter_by(username="alice").one().id, host="shared-site.com"))
    db.commit()
    request_id = db.query(TargetRequest).filter_by(host="shared-site.com").one().id
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/approve").status_code == 200
    db.expire_all()
    assert shared.shared is True
    assert db.query(TargetAccess).filter_by(target_id=shared.id).count() == 1


def test_reject_gives_no_access_and_emails_the_reason(clients, db, outbox):
    alice_client, _bob, admin_client = clients
    request_id = alice_client.post("/api/target-requests", json=body()).json()["id"]
    response = admin_client.post(f"/api/admin/target-requests/{request_id}/reject", json={"reason": "Not yours"})
    assert response.json()["status"] == "rejected"
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/reject",
                             json={"reason": "x" * 301}).status_code == 422
    assert db.query(TargetAccess).count() == 0 and db.query(AllowedTarget).count() == 0
    assert scan(alice_client, "alice-site.com") == 403
    assert alice_client.get("/api/target-requests").json()[0]["reject_reason"] == "Not yours"
    assert outbox[-1]["to"] == "alice@example.com" and "Not yours" in outbox[-1]["body"]
    assert last(db, "target_request_rejected").detail == "alice-site.com for alice"


def test_removing_access_refuses_the_next_scan(clients, db):
    alice_client, _bob, admin_client = clients
    request_and_approve(alice_client, admin_client)
    target = admin_client.get("/api/admin/targets").json()[0]
    assert [a["username"] for a in target["access"]] == ["alice"]
    user_id = target["access"][0]["user_id"]
    after = admin_client.delete(f"/api/admin/targets/{target['id']}/access/{user_id}")
    assert after.status_code == 200 and after.json()["access"] == []
    assert admin_client.delete(f"/api/admin/targets/{target['id']}/access/{user_id}").status_code == 404
    assert scan(alice_client, "alice-site.com") == 403
    assert last(db, "target_access_removed").detail == "alice-site.com for alice"


def test_switching_between_shared_and_private(clients, db):
    alice_client, bob_client, admin_client = clients
    request_and_approve(alice_client, admin_client)
    target_id = admin_client.get("/api/admin/targets").json()[0]["id"]

    shared = admin_client.patch(f"/api/admin/targets/{target_id}", json={"shared": True})
    assert shared.json()["shared"] is True
    assert last(db, "target_sharing_changed").detail == "alice-site.com: shared"
    assert scan(bob_client, "alice-site.com") == 200

    admin_client.patch(f"/api/admin/targets/{target_id}", json={"shared": False})
    assert last(db, "target_sharing_changed").detail == "alice-site.com: private"
    assert scan(bob_client, "alice-site.com") == 403
    assert scan(alice_client, "alice-site.com") == 200  # her access row was kept

    count = db.query(Activity).filter_by(action="target_sharing_changed").count()
    admin_client.patch(f"/api/admin/targets/{target_id}", json={"shared": False})  # no change: not logged
    db.expire_all()
    assert db.query(Activity).filter_by(action="target_sharing_changed").count() == count


def test_admin_added_targets_are_shared_and_deleting_one_removes_its_access(clients, db):
    alice_client, bob_client, admin_client = clients
    added = admin_client.post("/api/admin/targets", json={"host": "shared-site.com"}).json()
    assert added["shared"] is True and added["access"] == []
    request_and_approve(alice_client, admin_client)
    private_id = db.query(AllowedTarget).filter_by(host="alice-site.com").one().id
    assert admin_client.delete(f"/api/admin/targets/{private_id}").status_code == 200
    assert db.query(TargetAccess).count() == 0


def test_deleting_a_user_removes_their_access_and_requests(clients, db, people):
    alice_client, _bob, admin_client = clients
    alice = people[0]
    request_and_approve(alice_client, admin_client)
    alice_client.post("/api/target-requests", json=body(host="shared-site.com"))
    assert db.query(TargetRequest).count() == 2
    response = admin_client.request("DELETE", f"/api/admin/users/{alice.id}", json={"confirm_username": "alice"})
    assert response.status_code == 200
    db.expire_all()
    assert db.query(TargetAccess).count() == 0
    assert db.query(TargetRequest).count() == 0


# --- Emails ---


def test_emails_name_the_display_name_never_the_admin_username(clients, db, outbox, people):
    alice_client, _bob, admin_client = clients
    request_and_approve(alice_client, admin_client)
    approved = outbox[-1]
    assert approved["to"] == "alice@example.com" and "alice-site.com" in approved["subject"]
    assert "Reviewed by Priya Sharma" in approved["body"]
    assert "rootadmin" not in approved["body"] and "rootadmin" not in approved["subject"]
    assert db.query(TargetRequest).one().email_status == "sent"

    people[2].display_name = None
    db.commit()
    request_id = alice_client.post("/api/target-requests", json=body(host="shared-site.com")).json()["id"]
    admin_client.post(f"/api/admin/target-requests/{request_id}/reject")
    assert "Reviewed by an administrator" in outbox[-1]["body"]
    assert "rootadmin" not in outbox[-1]["body"]


def test_no_email_when_the_requester_has_no_address(clients, db, outbox, people):
    alice_client, _bob, admin_client = clients
    people[0].email = None
    db.commit()
    request_id = request_and_approve(alice_client, admin_client)
    assert outbox == []
    assert db.get(TargetRequest, request_id).email_status == "no_email"
    assert admin_client.get("/api/admin/target-requests?status=approved").json()[0]["email_status"] == "no_email"


def test_failed_email_can_be_resent(clients, db, outbox, monkeypatch):
    alice_client, _bob, admin_client = clients

    def broken(to, subject, text):
        raise mailer.MailError("SMTPServerDisconnected")

    monkeypatch.setattr(mailer, "send", broken)
    request_id = request_and_approve(alice_client, admin_client)
    db.expire_all()
    saved = db.get(TargetRequest, request_id)
    assert (saved.email_status, saved.email_error) == ("failed", "SMTPServerDisconnected")
    assert last(db, "email_failed").username == "alice"

    monkeypatch.setattr(mailer, "send", lambda to, subject, text: outbox.append({"to": to, "body": text}))
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/resend-email").status_code == 200
    assert "Reviewed by Priya Sharma" in outbox[-1]["body"]
    db.expire_all()
    assert db.get(TargetRequest, request_id).email_status == "sent"
    assert admin_client.post(f"/api/admin/target-requests/{request_id}/resend-email").status_code == 409
    assert last(db, "target_request_email_resent").detail == "alice-site.com for alice"


# --- The admin list and permissions ---


def test_admin_list_shows_requested_and_current_ips(clients):
    alice_client, _bob, admin_client = clients
    alice_client.post("/api/target-requests", json=body())
    row = admin_client.get("/api/admin/target-requests").json()[0]
    assert (row["username"], row["resolved_ips"], row["current_ips"], row["ips_changed"]) == (
        "alice", ["93.184.216.34"], ["93.184.216.34"], False)

    FAKE_DNS["alice-site.com"] = ["198.51.100.9"]
    try:
        row = admin_client.get("/api/admin/target-requests?status=pending").json()[0]
        assert row["current_ips"] == ["198.51.100.9"] and row["ips_changed"] is True
    finally:
        FAKE_DNS["alice-site.com"] = ["93.184.216.34"]
    assert admin_client.get("/api/admin/target-requests?status=approved").json() == []
    assert admin_client.get("/api/admin/target-requests?status=bogus").status_code == 422


def test_non_admins_get_403_on_the_admin_routes(clients, db):
    alice_client, _bob, _admin = clients
    request_id = alice_client.post("/api/target-requests", json=body()).json()["id"]
    for method, path, json in [
        ("GET", "/api/admin/target-requests", None),
        ("POST", f"/api/admin/target-requests/{request_id}/approve", None),
        ("POST", f"/api/admin/target-requests/{request_id}/reject", {"reason": ""}),
        ("POST", f"/api/admin/target-requests/{request_id}/resend-email", None),
        ("PATCH", "/api/admin/targets/1", {"shared": True}),
        ("DELETE", "/api/admin/targets/1/access/1", None),
    ]:
        assert alice_client.request(method, path, json=json).status_code == 403, path
    assert db.query(TargetAccess).count() == 0
    assert db.get(TargetRequest, request_id).status == "pending"
