import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import AccessBadge from "../components/AccessBadge.jsx";
import { formatDate, formatShortDate } from "../format.js";
import { useList } from "../useList.js";

const REASON_MAX = 500;
const PERMISSION_TEXT = "I own this website, or I have written permission from its owner to test it";

// The websites I can scan, my requests for more, and the form to ask for one.
// The port scan and website check pages link here with ?host=... when a scan is refused.
export default function MyWebsitesPage() {
  const targets = useList("/api/targets/mine");
  const requests = useList("/api/target-requests");

  function reloadAll() {
    targets.reload();
    requests.reload();
  }

  return (
    <section>
      <h1>My websites</h1>
      <p className="muted">
        The port scan and website check only run against websites an admin has approved. Shared ones can be scanned
        by everyone; private ones only by the people they were approved for.
      </p>
      <RequestForm onSent={reloadAll} />
      <h2>Websites I can scan</h2>
      {targets.error && <p className="error">{targets.error}</p>}
      <table className="data">
        <thead>
          <tr>
            <th>Website</th>
            <th>Access</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {targets.items.length === 0 && !targets.error && (
            <tr>
              <td colSpan={3} className="muted">
                None yet. Request one above.
              </td>
            </tr>
          )}
          {targets.items.map((target) => (
            <tr key={target.id}>
              <td>
                <code>{target.host}</code>
              </td>
              <td>
                <AccessBadge shared={target.access === "shared"} />
              </td>
              <td>{target.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <MyRequests list={requests} onChanged={reloadAll} />
    </section>
  );
}

function RequestForm({ onSent }) {
  const [searchParams] = useSearchParams();
  const [form, setForm] = useState({ host: searchParams.get("host") ?? "", reason: "", confirm: false });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function set(field, value) {
    setForm({ ...form, [field]: value });
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api("/api/target-requests", { method: "POST", body: form });
      setMessage(`Request for ${form.host.trim().toLowerCase()} sent. You'll get an email when an admin decides.`);
      setForm({ host: "", reason: "", confirm: false });
      onSent();
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  return (
    <form className="card tool-form" onSubmit={submit}>
      <h2>Request a website</h2>
      <label>
        Website (hostname or IPv4 address, no https://)
        <input value={form.host} onChange={(e) => set("host", e.target.value)} placeholder="example.com" required />
      </label>
      <label>
        Why do you want to scan it?
        <textarea
          rows={3}
          value={form.reason}
          onChange={(e) => set("reason", e.target.value)}
          maxLength={REASON_MAX}
          placeholder="e.g. It's my portfolio site and I want to check its security headers."
        />
        <span className="muted small counter">
          {form.reason.length}/{REASON_MAX}
        </span>
      </label>
      <label className="inline">
        <input type="checkbox" checked={form.confirm} onChange={(e) => set("confirm", e.target.checked)} required />
        {PERMISSION_TEXT}
      </label>
      {error && <p className="error">{error}</p>}
      {message && <p className="success">{message}</p>}
      <button type="submit" disabled={busy || !form.confirm}>
        {busy ? "Sending…" : "Send request"}
      </button>
    </form>
  );
}

const STATUS_LABEL = { pending: "pending", approved: "approved", rejected: "rejected", cancelled: "cancelled" };

function MyRequests({ list, onChanged }) {
  async function cancel(request) {
    if (!window.confirm(`Cancel your request for ${request.host}?`)) return;
    try {
      await api(`/api/target-requests/${request.id}/cancel`, { method: "POST" });
      list.setError("");
    } catch (err) {
      list.setError(err.message);
    }
    onChanged();
  }

  return (
    <>
      <h2>My requests</h2>
      {list.error && <p className="error">{list.error}</p>}
      <table className="data">
        <thead>
          <tr>
            <th>Website</th>
            <th>Sent</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {list.items.length === 0 && !list.error && (
            <tr>
              <td colSpan={4} className="muted">
                No requests yet.
              </td>
            </tr>
          )}
          {list.items.map((request) => (
            <tr key={request.id}>
              <td>
                <code>{request.host}</code>
              </td>
              <td className="nowrap" title={formatDate(request.created_at)}>
                {formatShortDate(request.created_at)}
              </td>
              <td>
                <span className={`status-badge request-${request.status}`}>{STATUS_LABEL[request.status]}</span>
                {request.reject_reason && <div className="muted small">Reason: {request.reject_reason}</div>}
              </td>
              <td>
                {request.status === "pending" && (
                  <button type="button" className="link-button" onClick={() => cancel(request)}>
                    Cancel
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
