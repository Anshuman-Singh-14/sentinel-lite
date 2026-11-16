import { useState } from "react";
import { api } from "../api.js";

// Add a first email or change it. The server sends a link to the new address and keeps the
// current one until that link is opened, so a typo can't lock anyone out of their emails.
export default function ChangeEmailPage({ user }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [sentTo, setSentTo] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/account/email", { method: "POST", body: { email, current_password: password } });
      setSentTo(email);
      setPassword("");
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  return (
    <section>
      <form className="card narrow" onSubmit={submit}>
        <h1>Change email</h1>
        <p>
          Current email: {user.email ? <strong>{user.email}</strong> : <span className="muted">none</span>}
        </p>
        {sentTo ? (
          <p className="notice">
            We sent a confirmation link to <strong>{sentTo}</strong>. Your email stays{" "}
            {user.email ? <strong>{user.email}</strong> : "none"} until you click it.
          </p>
        ) : (
          <>
            <label>
              New email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                maxLength={254}
                autoComplete="email"
                required
              />
            </label>
            <label>
              Current password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </label>
            {error && <p className="error">{error}</p>}
            <button type="submit" disabled={busy}>
              {busy ? "Sending…" : "Send confirmation link"}
            </button>
          </>
        )}
      </form>
    </section>
  );
}
