import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { NAV } from "../components/Layout.jsx";
import { useRequest } from "../useRequest.js";

export default function DashboardPage({ user }) {
  return (
    <section>
      <h1>Welcome, {user.username}</h1>
      {user.role === "user" && !user.has_email && <AddEmailBanner user={user} />}
      <p className="muted">
        Pick a tool. Every result explains what was found, how serious it is, and how to fix it.
      </p>
      {NAV.map((group) => (
        <div key={group.heading}>
          <h2>{group.heading}</h2>
          <div className="tiles">
            {group.links.map((link) => (
              <Link key={link.to} to={link.to} className="card tile">
                {link.label}
              </Link>
            ))}
          </div>
        </div>
      ))}
    </section>
  );
}

// Older accounts were made before emails were required. Hiding the banner is remembered in
// this browser only; storage can be blocked (private windows), so every access is guarded.
function AddEmailBanner({ user }) {
  const storageKey = `email-banner-hidden-${user.id}`;
  const [hidden, setHidden] = useState(() => {
    try {
      return localStorage.getItem(storageKey) === "1";
    } catch {
      return false;
    }
  });
  const [email, setEmail] = useState("");
  const send = useRequest();

  if (hidden) return null;

  function hide() {
    try {
      localStorage.setItem(storageKey, "1");
    } catch {
      // not remembered, but still hidden for now
    }
    setHidden(true);
  }

  function submit(event) {
    event.preventDefault();
    send.run(() => api("/api/account/email", { method: "POST", body: { email } }));
  }

  return (
    <div className="notice banner">
      <p>
        <strong>Add an email address to your account</strong> so admins can reach you and you can get account emails.
      </p>
      {send.data ? (
        <p>{send.data.message}</p>
      ) : (
        <form className="row" onSubmit={submit}>
          <label>
            Email
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} required />
          </label>
          <button type="submit" disabled={send.busy}>
            {send.busy ? "Sending…" : "Send confirmation link"}
          </button>
        </form>
      )}
      {send.error && <p className="error">{send.error}</p>}
      <button type="button" className="link-button small" onClick={hide}>
        Dismiss
      </button>
    </div>
  );
}
