import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // The link is hidden when the server has account requests switched off.
  const [requestsEnabled, setRequestsEnabled] = useState(false);

  useEffect(() => {
    api("/api/access-requests/config")
      .then((config) => setRequestsEnabled(config.enabled))
      .catch(() => setRequestsEnabled(false));
  }, []);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onLogin(await api("/api/auth/login", { method: "POST", body: { username, password } }));
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <h1>Sentinel Lite</h1>
        <p className="muted">A defensive security toolkit that explains its findings.</p>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
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
          {busy ? "Logging in…" : "Log in"}
        </button>
        {requestsEnabled ? (
          <p className="muted small">
            No account? <Link to="/request-access">Request credentials</Link>
          </p>
        ) : (
          <p className="muted small">Accounts are created by an admin.</p>
        )}
      </form>
    </div>
  );
}
