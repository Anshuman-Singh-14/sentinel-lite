import { useState } from "react";
import { api } from "../api.js";
import PasswordMeter from "../components/PasswordMeter.jsx";

// `forced`: shown on its own after logging in with a generated or admin-reset password.
// The server refuses every other request until the password is changed.
export default function ChangePasswordPage({ forced = false, onChanged, onLogout }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (next !== confirm) {
      setError("The two new passwords don't match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const user = await api("/api/auth/change-password", {
        method: "POST",
        body: { current_password: current, new_password: next },
      });
      setCurrent("");
      setNext("");
      setConfirm("");
      setDone(true);
      onChanged(user);
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  const form = (
    <form className="card narrow" onSubmit={submit}>
      <h1>Change password</h1>
      {forced && (
        <p className="notice">Your password was set for you. Choose your own password before you continue.</p>
      )}
      <label>
        {forced ? "Temporary password" : "Current password"}
        <input
          type="password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          autoComplete="current-password"
          required
        />
      </label>
      <label>
        New password (at least 8 characters)
        <input
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password"
          minLength={8}
          required
        />
      </label>
      <PasswordMeter password={next} />
      <label>
        Repeat new password
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          required
        />
      </label>
      {error && <p className="error">{error}</p>}
      {done && <p>Password changed.</p>}
      <button type="submit" disabled={busy}>
        {busy ? "Saving…" : "Change password"}
      </button>
      {forced && (
        <p className="small">
          <button type="button" className="link-button" onClick={onLogout}>
            Log out
          </button>
        </p>
      )}
    </form>
  );

  return forced ? <div className="login">{form}</div> : <section>{form}</section>;
}
