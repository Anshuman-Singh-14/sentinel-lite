import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import PasswordMeter from "../components/PasswordMeter.jsx";
import Turnstile from "../components/Turnstile.jsx";

const REMARKS_MAX = 500;
const EMPTY = { email: "", username: "", wantsGenerated: false, password: "", confirm: "", remarks: "", agree: false };

export default function RequestAccessPage() {
  const [config, setConfig] = useState(null);
  const [configError, setConfigError] = useState("");
  const [form, setForm] = useState(EMPTY);
  const [token, setToken] = useState("");
  const [widgetKey, setWidgetKey] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState("");

  useEffect(() => {
    api("/api/access-requests/config")
      .then(setConfig)
      .catch((err) => setConfigError(err.message));
  }, []);

  function set(field, value) {
    setForm({ ...form, [field]: value });
  }

  async function submit(event) {
    event.preventDefault();
    if (!form.wantsGenerated && form.password !== form.confirm) {
      setError("The two passwords don't match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await api("/api/access-requests", {
        method: "POST",
        body: {
          email: form.email,
          username: form.username,
          wants_generated: form.wantsGenerated,
          password: form.wantsGenerated ? null : form.password,
          remarks: form.remarks,
          agree: form.agree,
          terms_version: config.terms_version,
          turnstile_token: token,
        },
      });
      setDone(result.message);
    } catch (err) {
      setError(err.message);
      // Each Turnstile token works once, so show a fresh widget for the next try.
      setToken("");
      setWidgetKey((key) => key + 1);
    }
    setBusy(false);
  }

  if (done) {
    return (
      <div className="login">
        <div className="card narrow">
          <h1>Check your email</h1>
          <p>{done}</p>
          <p className="muted small">
            The link expires in 24 hours. If nothing arrives, check your spam folder. After you confirm, an admin
            reviews the request and you get another email with their decision.
          </p>
          <Link to="/">Back to log in</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="login">
      <form className="card wide" onSubmit={submit}>
        <h1>Request credentials</h1>
        <p className="muted">
          Ask for a Sentinel Lite account. We email you a link to confirm your address, then an admin reviews the
          request.
        </p>
        {configError && <p className="error">{configError}</p>}
        {config && !config.enabled && <p className="error">Account requests are not available right now.</p>}

        <label>
          Email
          <input type="email" value={form.email} onChange={(e) => set("email", e.target.value)} autoComplete="email" maxLength={254} required />
        </label>
        <label>
          Username
          <input
            value={form.username}
            onChange={(e) => set("username", e.target.value)}
            autoComplete="username"
            pattern="[A-Za-z0-9_.\-]{3,32}"
            title="3 to 32 letters, numbers, dots, dashes or underscores"
            required
          />
        </label>

        <fieldset>
          <legend>Password</legend>
          <label className="inline">
            <input type="radio" name="choice" checked={!form.wantsGenerated} onChange={() => set("wantsGenerated", false)} />
            Choose my own password
          </label>
          <label className="inline">
            <input type="radio" name="choice" checked={form.wantsGenerated} onChange={() => set("wantsGenerated", true)} />
            Generate one for me (emailed when approved; you change it at first login)
          </label>
        </fieldset>
        {!form.wantsGenerated && (
          <>
            <label>
              Password (at least 8 characters)
              <input
                type="password"
                value={form.password}
                onChange={(e) => set("password", e.target.value)}
                autoComplete="new-password"
                minLength={8}
                required
              />
            </label>
            <PasswordMeter password={form.password} />
            <label>
              Repeat password
              <input
                type="password"
                value={form.confirm}
                onChange={(e) => set("confirm", e.target.value)}
                autoComplete="new-password"
                required
              />
            </label>
          </>
        )}

        <label>
          Why do you need an account? (optional)
          <textarea
            rows={3}
            value={form.remarks}
            onChange={(e) => set("remarks", e.target.value)}
            maxLength={REMARKS_MAX}
          />
          <span className="muted small counter">
            {form.remarks.length}/{REMARKS_MAX}
          </span>
        </label>

        {config && (
          <>
            <h2>Agreement</h2>
            <div className="terms" tabIndex={0}>
              {config.terms_text}
            </div>
            <label className="inline">
              <input type="checkbox" checked={form.agree} onChange={(e) => set("agree", e.target.checked)} required />
              I have read and agree to these terms.
            </label>
            <Turnstile key={widgetKey} siteKey={config.turnstile_site_key} onToken={setToken} />
          </>
        )}

        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy || !config?.enabled || !token}>
          {busy ? "Sending…" : "Send request"}
        </button>
        <p className="muted small">
          Already have an account? <Link to="/">Log in</Link>
        </p>
      </form>
    </div>
  );
}
