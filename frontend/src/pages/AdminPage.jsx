import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import AccessBadge from "../components/AccessBadge.jsx";
import ActivityLog from "../components/ActivityLog.jsx";
import { formatDate, formatShortDate } from "../format.js";
import { useList } from "../useList.js";

export default function AdminPage({ user }) {
  return (
    <section>
      <h1>Admin</h1>
      <AccessRequests />
      <TargetRequests />
      <Targets />
      <Users currentUser={user} />
      <Activity />
    </section>
  );
}

// A row of tab buttons; `count` (optional) is shown as a small grey badge, or a red one
// when the tab has `alert: true` (things waiting for an admin).
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
          {tab.count > 0 && <span className={tab.alert ? "count-badge alert" : "count-badge"}>{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}

const EMAIL_STATUS = { not_sent: "sending…", sent: "sent", failed: "failed", no_email: "no email address" };

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
        Account requests{" "}
        {pending.items.length > 0 && <span className="count-badge alert">{pending.items.length}</span>}
      </h2>
      <p className="muted small">
        Requests appear here once the visitor has confirmed their email. Approving creates the account and emails
        them; rejecting emails them your reason.
      </p>
      <Tabs
        value={status}
        onChange={setStatus}
        tabs={[
          { value: "pending", label: "Pending", count: pending.items.length, alert: true },
          { value: "approved", label: "Approved" },
          { value: "rejected", label: "Rejected" },
        ]}
      />
      {shown.error && <p className="error">{shown.error}</p>}
      {pending.error && <p className="error">{pending.error}</p>}
      <div className="table-scroll">
        <table className="data requests">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Password</th>
              <th>Remarks</th>
              <th>Submitted</th>
              <th>IP</th>
              {status !== "pending" && <th>Decision</th>}
              <th>Email status</th>
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
                <td className="nowrap">{request.wants_generated ? "generate one" : "chose own"}</td>
                <td className="remarks">{request.remarks || <span className="muted">none</span>}</td>
                <td className="nowrap" title={formatDate(request.created_at)}>
                  {formatShortDate(request.created_at)}
                </td>
                <td className="nowrap">
                  <code>{request.ip}</code>
                </td>
                {status !== "pending" && (
                  <td>
                    <span className="nowrap">by {request.reviewed_by}</span>
                    {request.reject_reason && <div className="muted small">Reason: {request.reject_reason}</div>}
                  </td>
                )}
                <td className="nowrap">
                  {EMAIL_STATUS[request.email_status]}
                  {request.email_error && <div className="error small">{request.email_error}</div>}
                </td>
                <td className="actions nowrap">
                  {request.status === "pending" && (
                    <>
                      <button type="button" onClick={() => approve(request)}>
                        Approve
                      </button>
                      <button type="button" className="danger" onClick={() => reject(request)}>
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

// Users asking to scan a website. Approving lets only that user scan it (a new target is
// added as private); rejecting emails them the reason.
function TargetRequests() {
  const pending = useList("/api/admin/target-requests?status=pending");
  const [status, setStatus] = useState("pending");
  const shown = useList(`/api/admin/target-requests?status=${status}`);
  const columns = status === "pending" ? 7 : 8;

  async function act(request, action, body) {
    try {
      await api(`/api/admin/target-requests/${request.id}/${action}`, { method: "POST", body });
      shown.setError("");
    } catch (err) {
      shown.setError(err.message);
    }
    shown.reload();
    pending.reload();
  }

  function approve(request) {
    if (window.confirm(`Let ${request.username} scan ${request.host}?`)) act(request, "approve");
  }

  function reject(request) {
    const reason = window.prompt(
      `Reject the request from ${request.username} for ${request.host}? Optional reason (it is emailed to them):`,
      "",
    );
    if (reason !== null) act(request, "reject", { reason: reason.slice(0, 300) });
  }

  return (
    <div className="admin-section">
      <h2>
        Website requests{" "}
        {pending.items.length > 0 && <span className="count-badge alert">{pending.items.length}</span>}
      </h2>
      <p className="muted small">
        Users asking to scan a website. Approving lets only that user scan it (a new target is added as private).
        Check that the current IPs still match the ones from the request.
      </p>
      <Tabs
        value={status}
        onChange={setStatus}
        tabs={[
          { value: "pending", label: "Pending", count: pending.items.length, alert: true },
          { value: "approved", label: "Approved" },
          { value: "rejected", label: "Rejected" },
        ]}
      />
      {shown.error && <p className="error">{shown.error}</p>}
      {pending.error && <p className="error">{pending.error}</p>}
      <div className="table-scroll">
        <table className="data requests">
          <thead>
            <tr>
              <th>User</th>
              <th>Website</th>
              <th>Reason</th>
              <th>Submitted</th>
              <th>IPs</th>
              {status !== "pending" && <th>Decision</th>}
              <th>Email status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shown.items.length === 0 && (
              <tr>
                <td colSpan={columns} className="muted">
                  No {status} requests.
                </td>
              </tr>
            )}
            {shown.items.map((request) => (
              <tr key={request.id}>
                <td>{request.username}</td>
                <td className="nowrap">
                  <code>{request.host}</code>
                </td>
                <td className="remarks">{request.reason || <span className="muted">none</span>}</td>
                <td className="nowrap" title={formatDate(request.created_at)}>
                  {formatShortDate(request.created_at)}
                </td>
                <td className="nowrap">
                  <RequestIps request={request} />
                </td>
                {status !== "pending" && (
                  <td>
                    <span className="nowrap">by {request.reviewed_by}</span>
                    {request.reject_reason && <div className="muted small">Reason: {request.reject_reason}</div>}
                  </td>
                )}
                <td className="nowrap">
                  {request.status === "pending" ? <span className="muted">-</span> : EMAIL_STATUS[request.email_status]}
                  {request.email_error && <div className="error small">{request.email_error}</div>}
                </td>
                <td className="actions nowrap">
                  {request.status === "pending" && (
                    <>
                      <button type="button" onClick={() => approve(request)}>
                        Approve
                      </button>
                      <button type="button" className="danger" onClick={() => reject(request)}>
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

// The IPs the website had when it was requested and, while pending, the ones it has now.
// A difference is highlighted: the name may now point at someone else's server.
function RequestIps({ request }) {
  const requested = request.resolved_ips.join(", ") || "none";
  if (!request.current_ips) return <code>{requested}</code>;
  const current = request.current_ips.join(", ") || "does not resolve";
  return (
    <div className={request.ips_changed ? "ip-changed" : undefined}>
      <div>
        <span className="muted small">requested </span>
        <code>{requested}</code>
      </div>
      <div>
        <span className="muted small">now </span>
        <code>{current}</code>
        {request.ips_changed && <strong className="small"> changed</strong>}
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

  async function send(path, options) {
    try {
      await api(path, options);
      targets.setError("");
    } catch (err) {
      targets.setError(err.message);
    }
    targets.reload();
  }

  function remove(target) {
    if (window.confirm(`Stop allowing scans of ${target.host}?`)) {
      send(`/api/admin/targets/${target.id}`, { method: "DELETE" });
    }
  }

  function setShared(target, shared) {
    const question = shared
      ? `Let every user scan ${target.host}?`
      : `Make ${target.host} private? Only the users listed with access (and admins) will be able to scan it.`;
    if (window.confirm(question)) send(`/api/admin/targets/${target.id}`, { method: "PATCH", body: { shared } });
  }

  function removeAccess(target, access) {
    if (window.confirm(`Stop ${access.username} from scanning ${target.host}?`)) {
      send(`/api/admin/targets/${target.id}/access/${access.user_id}`, { method: "DELETE" });
    }
  }

  return (
    <div className="admin-section">
      <h2>Approved scan targets</h2>
      <p className="muted small">
        The port scan and website check only run against these hosts. Shared hosts (the ones added here) can be
        scanned by every user; private ones only by the users listed. Only add systems you own or have written
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
            <th>Access</th>
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
              <td>
                <AccessBadge shared={target.shared} />
                {!target.shared && (
                  <ul className="access-list small">
                    {target.access.length === 0 && <li className="muted">nobody yet (admins only)</li>}
                    {target.access.map((access) => (
                      <li key={access.user_id}>
                        {access.username}{" "}
                        <button
                          type="button"
                          className="link-button danger-link"
                          onClick={() => removeAccess(target, access)}
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </td>
              <td>{target.note}</td>
              <td>{target.added_by}</td>
              <td>
                <span className="user-actions">
                  <button type="button" className="link-button" onClick={() => setShared(target, !target.shared)}>
                    {target.shared ? "Make private" : "Make shared"}
                  </button>
                  <button type="button" className="link-button danger-link" onClick={() => remove(target)}>
                    Remove
                  </button>
                </span>
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
  const [deleting, setDeleting] = useState(null); // the user in the delete dialog
  const shown = users.items.filter((user) => user.role === tab);
  const columns = tab === "admin" ? 6 : 5;

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

  function editDisplayName(user) {
    const name = window.prompt(
      `Display name for ${user.username}, shown in approval and rejection emails (leave empty to clear):`,
      user.display_name ?? "",
    );
    if (name !== null) change(user, { display_name: name });
  }

  function changeRole(user, role) {
    // The server refuses role "user" for an account without an email, and says why.
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
      {tab === "admin" && (
        <p className="muted small">
          Display name: shown to people in approval and rejection emails instead of the username.
        </p>
      )}
      <div className="table-scroll">
        <table className="data users">
          <thead>
            <tr>
              <th>Username</th>
              {tab === "admin" && <th>Display name</th>}
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 && (
              <tr>
                <td colSpan={columns} className="muted">
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
                  {tab === "admin" && <td>{user.display_name ?? <span className="muted">none</span>}</td>}
                  <td>{user.email ?? <span className="muted">none</span>}</td>
                  <td>
                    <select
                      className="role-select"
                      value={user.role}
                      disabled={isMe}
                      onChange={(e) => changeRole(user, e.target.value)}
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>
                    <span className={user.is_active ? "status-badge active" : "status-badge"}>
                      {user.is_active ? "active" : "deactivated"}
                    </span>
                  </td>
                  <td>
                    <span className="user-actions">
                      {!isMe && (
                        <button type="button" className="link-button" onClick={() => change(user, { is_active: !user.is_active })}>
                          {user.is_active ? "Deactivate" : "Activate"}
                        </button>
                      )}
                      <button type="button" className="link-button" onClick={() => resetPassword(user)}>
                        Reset password
                      </button>
                      {tab === "admin" && (
                        <button type="button" className="link-button" onClick={() => editDisplayName(user)}>
                          Edit display name
                        </button>
                      )}
                      {!isMe && (
                        <button type="button" className="link-button danger-link" onClick={() => setDeleting(user)}>
                          Delete
                        </button>
                      )}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {deleting && (
        <DeleteUserDialog
          key={deleting.id}
          user={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={() => {
            setDeleting(null);
            users.setError("");
            users.reload();
          }}
        />
      )}
    </div>
  );
}

// Asks the admin to type the username before an account is deleted for good.
// A native <dialog>: Escape and Cancel close it, and the page behind can't be clicked.
function DeleteUserDialog({ user, onClose, onDeleted }) {
  const dialog = useRef(null);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    dialog.current.showModal();
  }, []);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    try {
      await api(`/api/admin/users/${user.id}`, { method: "DELETE", body: { confirm_username: typed } });
      onDeleted();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <dialog ref={dialog} className="card confirm-dialog" onClose={onClose} aria-labelledby="delete-user-title">
      <form onSubmit={submit}>
        <h3 id="delete-user-title">Delete {user.username}?</h3>
        <p>
          This permanently deletes <strong>{user.username}</strong> and their scan history. Type the username to
          confirm.
        </p>
        <label>
          Username
          <input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            autoFocus
          />
        </label>
        {error && <p className="error">{error}</p>}
        <div className="dialog-buttons">
          <button type="button" className="link-button" onClick={() => dialog.current.close()}>
            Cancel
          </button>
          <button type="submit" className="danger" disabled={typed !== user.username || busy}>
            Delete
          </button>
        </div>
      </form>
    </dialog>
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
