import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { formatDate } from "../format.js";

export default function AdminPage({ user }) {
  return (
    <section>
      <h1>Admin</h1>
      <Targets />
      <Users currentUser={user} />
      <Activity />
    </section>
  );
}

// Loads a list from the API and gives back a function to reload it after a change.
function useList(path) {
  const [items, setItems] = useState([]);
  const [error, setError] = useState("");
  const reload = useCallback(() => {
    api(path)
      .then(setItems)
      .catch((err) => setError(err.message));
  }, [path]);
  useEffect(reload, [reload]);
  return { items, error, setError, reload };
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

function Users({ currentUser }) {
  const users = useList("/api/admin/users");
  const [form, setForm] = useState({ username: "", password: "", role: "user" });

  async function create(event) {
    event.preventDefault();
    try {
      await api("/api/admin/users", { method: "POST", body: form });
      setForm({ username: "", password: "", role: "user" });
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

  return (
    <div className="admin-section">
      <h2>Users</h2>
      <form className="card row" onSubmit={create}>
        <label>
          Username
          <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
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
      <table className="data">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {users.items.map((user) => {
            const isMe = user.id === currentUser.id;
            return (
              <tr key={user.id}>
                <td>
                  {user.username} {isMe && <span className="muted">(you)</span>}
                </td>
                <td>
                  <select value={user.role} disabled={isMe} onChange={(e) => change(user, { role: e.target.value })}>
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
  const activity = useList("/api/admin/activity");
  return (
    <div className="admin-section">
      <h2>Activity log</h2>
      <p className="muted small">
        The latest 200 events: logins, scans and admin changes.{" "}
        <button type="button" className="link-button" onClick={activity.reload}>
          Refresh
        </button>
      </p>
      {activity.error && <p className="error">{activity.error}</p>}
      <table className="data">
        <thead>
          <tr>
            <th>When</th>
            <th>User</th>
            <th>Action</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {activity.items.map((entry) => (
            <tr key={entry.id}>
              <td>{formatDate(entry.created_at)}</td>
              <td>{entry.username}</td>
              <td>{entry.action.replaceAll("_", " ")}</td>
              <td>{entry.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
