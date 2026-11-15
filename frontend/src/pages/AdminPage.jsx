import { useState } from "react";
import { api } from "../api.js";
import ActivityLog from "../components/ActivityLog.jsx";
import { formatDate } from "../format.js";
import { useList } from "../useList.js";

export default function AdminPage({ user }) {
  return (
    <section>
      <h1>Admin</h1>
      <AccessRequests />
      <Targets />
      <Users currentUser={user} />
      <Activity />
    </section>
  );
}

// A row of tab buttons; `count` (optional) is shown as a small badge.
function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          type="button"
          role="tab"
          aria-selected={tab.value === value}
          className={tab.value === value ? "tab active" : "tab"}
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
          {tab.count > 0 && <span className="count-badge">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}

const EMAIL_STATUS = { not_sent: "sending…", sent: "sent", failed: "failed" };

function AccessRequests() {
  const pending = useList("/api/admin/access-requests?status=pending");
  const [status, setStatus] = useState("pending");
  const shown = useList(`/api/admin/access-requests?status=${status}`);

  async function act(request, action, body) {
    try {
      await api(`/api/admin/access-requests/${request.id}/${action}`, { method: "POST", body });
      shown.setError("");
    } catch (err) {
      shown.setError(err.message);
    }
    shown.reload();
    pending.reload();
  }

  function approve(request) {
    if (window.confirm(`Create the account ${request.username} for ${request.email}?`)) act(request, "approve");
  }

  function reject(request) {
    const reason = window.prompt(`Reject ${request.username}? Optional reason (it is emailed to them):`, "");
    if (reason !== null) act(request, "reject", { reason: reason.slice(0, 300) });
  }

  return (
    <div className="admin-section">
      <h2>
        Account requests {pending.items.length > 0 && <span className="count-badge">{pending.items.length}</span>}
      </h2>
      <p className="muted small">
        Requests appear here once the visitor has confirmed their email. Approving creates the account and emails
        them; rejecting emails them your reason.
      </p>
      <Tabs
        value={status}
        onChange={setStatus}
        tabs={[
          { value: "pending", label: "Pending", count: pending.items.length },
          { value: "approved", label: "Approved" },
          { value: "rejected", label: "Rejected" },
        ]}
      />
      {shown.error && <p className="error">{shown.error}</p>}
      {pending.error && <p className="error">{pending.error}</p>}
      <div className="table-scroll">
        <table className="data">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Password</th>
              <th>Remarks</th>
              <th>Submitted</th>
              <th>IP</th>
              {status !== "pending" && <th>Decision</th>}
              <th>Email</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shown.items.length === 0 && (
              <tr>
                <td colSpan={9} className="muted">
                  No {status} requests.
                </td>
              </tr>
            )}
            {shown.items.map((request) => (
              <tr key={request.id}>
                <td>{request.username}</td>
                <td>{request.email}</td>
                <td>{request.wants_generated ? "generate one" : "chose own"}</td>
                <td className="remarks">{request.remarks || <span className="muted">none</span>}</td>
                <td>{formatDate(request.created_at)}</td>
                <td>
                  <code>{request.ip}</code>
                </td>
                {status !== "pending" && (
                  <td>
                    by {request.reviewed_by}
                    {request.reject_reason && <div className="muted small">{request.reject_reason}</div>}
                  </td>
                )}
                <td>
                  {EMAIL_STATUS[request.email_status]}
                  {request.email_error && <div className="error small">{request.email_error}</div>}
                </td>
                <td className="actions">
                  {request.status === "pending" && (
                    <>
                      <button type="button" onClick={() => approve(request)}>
                        Approve
                      </button>
                      <button type="button" className="link-button" onClick={() => reject(request)}>
                        Reject
                      </button>
                    </>
                  )}
                  {request.email_status === "failed" && (
                    <button type="button" className="link-button" onClick={() => act(request, "resend-email")}>
                      Resend
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Targets() {
  const targets = useList("/api/admin/targets");
  const [host, setHost] = useState("");
  const [note, setNote] = useState("");

  async function add(event) {
    event.preventDefault();
    try {
      await api("/api/admin/targets", { method: "POST", body: { host, note } });
      setHost("");
      setNote("");
      targets.setError("");
      targets.reload();
    } catch (err) {
      targets.setError(err.message);
    }
  }

  async function remove(target) {
    if (!window.confirm(`Stop allowing scans of ${target.host}?`)) return;
    await api(`/api/admin/targets/${target.id}`, { method: "DELETE" });
    targets.reload();
  }

  return (
    <div className="admin-section">
      <h2>Approved scan targets</h2>
      <p className="muted small">
        The port scan and website check only run against these hosts. Only add systems you own or have written
        permission to test.
      </p>
      <form className="card row" onSubmit={add}>
        <label>
          Host or IPv4 address
          <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="example.com" required />
        </label>
        <label>
          Note (optional)
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Our test server" maxLength={200} />
        </label>
        <button type="submit">Approve</button>
      </form>
      {targets.error && <p className="error">{targets.error}</p>}
      <table className="data">
        <thead>
          <tr>
            <th>Host</th>
            <th>Note</th>
            <th>Added by</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {targets.items.map((target) => (
            <tr key={target.id}>
              <td>
                <code>{target.host}</code>
              </td>
              <td>{target.note}</td>
              <td>{target.added_by}</td>
              <td>
                <button type="button" className="link-button" onClick={() => remove(target)}>
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const NEW_USER = { username: "", email: "", password: "", role: "user" };

function Users({ currentUser }) {
  const users = useList("/api/admin/users");
  const [form, setForm] = useState(NEW_USER);
  const [tab, setTab] = useState("user"); // which role's list is shown
  const shown = users.items.filter((user) => user.role === tab);

  async function create(event) {
    event.preventDefault();
    try {
      // Email is optional for admins: send null rather than an empty string.
      await api("/api/admin/users", { method: "POST", body: { ...form, email: form.email || null } });
      setForm(NEW_USER);
      users.setError("");
      users.reload();
    } catch (err) {
      users.setError(err.message);
    }
  }

  async function change(user, body) {
    try {
      await api(`/api/admin/users/${user.id}`, { method: "PATCH", body });
      users.setError("");
      users.reload();
    } catch (err) {
      users.setError(err.message);
    }
  }

  function resetPassword(user) {
    const password = window.prompt(`New password for ${user.username} (at least 8 characters):`);
    if (password) change(user, { password });
  }

  function editEmail(user) {
    const email = window.prompt(`Email address for ${user.username}:`, user.email ?? "");
    if (email) change(user, { email });
  }

  function changeRole(user, role) {
    // Normal users need an email, so ask for one when an admin without one is changed to user.
    if (role === "user" && !user.email) {
      const email = window.prompt(`${user.username} needs an email address to become a user:`);
      if (email) change(user, { role, email });
      return;
    }
    change(user, { role });
  }

  return (
    <div className="admin-section">
      <h2>Users</h2>
      <form className="card row" onSubmit={create}>
        <label>
          Username
          <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        </label>
        <label>
          Email {form.role === "admin" && "(optional)"}
          <input
            type="email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            maxLength={254}
            required={form.role === "user"}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            minLength={8}
            autoComplete="new-password"
            required
          />
        </label>
        <label>
          Role
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <button type="submit">Create user</button>
      </form>
      {users.error && <p className="error">{users.error}</p>}
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "user", label: "Users", count: users.items.filter((u) => u.role === "user").length },
          { value: "admin", label: "Admins", count: users.items.filter((u) => u.role === "admin").length },
        ]}
      />
      <table className="data">
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {shown.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                Nobody here yet.
              </td>
            </tr>
          )}
          {shown.map((user) => {
            const isMe = user.id === currentUser.id;
            return (
              <tr key={user.id}>
                <td>
                  {user.username} {isMe && <span className="muted">(you)</span>}
                </td>
                <td>{user.email ?? <span className="muted">none</span>}</td>
                <td>
                  <select value={user.role} disabled={isMe} onChange={(e) => changeRole(user, e.target.value)}>
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select>
                </td>
                <td>{user.is_active ? "active" : "deactivated"}</td>
                <td className="actions">
                  {!isMe && (
                    <button type="button" className="link-button" onClick={() => change(user, { is_active: !user.is_active })}>
                      {user.is_active ? "Deactivate" : "Activate"}
                    </button>
                  )}
                  <button type="button" className="link-button" onClick={() => resetPassword(user)}>
                    Reset password
                  </button>
                  <button type="button" className="link-button" onClick={() => editEmail(user)}>
                    Edit email
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Activity() {
  return (
    <div className="admin-section">
      <h2>Activity log</h2>
      <p className="muted small">
        The latest 200 events: logins, scans, downloads and admin changes. Open the full log in a new tab, or view
        or download it as TXT or CSV to see every event.
      </p>
      <ActivityLog limit={200} boxed showOpenLink />
    </div>
  );
}
