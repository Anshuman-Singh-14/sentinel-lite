import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { NAV } from "../components/Layout.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { formatDate, formatShortDate } from "../format.js";
import { adminLink } from "../useNotifications.js";

const RECENT_SCANS = 5;
// The tool groups shown as tiles (the sidebar's "Results" group is not a tool).
const TOOL_GROUPS = NAV.filter((group) => group.heading !== "Results");

// The homepage after login: what Sentinel Lite is, what needs attention, recent scans, and the tools.
// `notifications` comes from useNotifications() in App.jsx (it also feeds the sidebar badge).
export default function DashboardPage({ user, notifications }) {
  const { reload } = notifications;
  useEffect(reload, [reload]); // fresh numbers every time the homepage is opened

  return (
    <section>
      <h1>Welcome, {user.username}</h1>
      <p className="muted intro">
        Sentinel Lite is a defensive security toolkit. Run safe checks on domains, servers and websites you&apos;re
        allowed to test, and get every finding explained with how to fix it.
      </p>
      {user.role === "user" && !user.has_email && <AddEmailBanner user={user} />}
      {notifications.error && <p className="error">{notifications.error}</p>}
      <div className="home-panels">
        {user.role === "admin" ? (
          <AttentionPanel data={notifications.data} />
        ) : (
          <MyRequestsPanel requests={notifications.data?.my_requests} />
        )}
        <RecentScans />
      </div>
      {TOOL_GROUPS.map((group) => (
        <div key={group.heading}>
          <h2>{group.heading}</h2>
          <div className="tiles">
            {group.links.map((link) => (
              <Link key={link.to} to={link.to} className="card tile">
                {link.label}
                <span className="tile-description">{link.description}</span>
              </Link>
            ))}
          </div>
        </div>
      ))}
    </section>
  );
}

// Admins: what is waiting for them, as three count tiles and the newest entries.
function AttentionPanel({ data }) {
  if (!data) return <div className="card home-panel muted">Loading…</div>;
  const firstFailedEmail = data.items.find((item) => item.kind === "email_failed");
  const tiles = [
    { label: "Account requests", count: data.account_requests_pending, to: "/admin#account-requests" },
    { label: "Website requests", count: data.website_requests_pending, to: "/admin#website-requests" },
    {
      label: "Failed emails",
      count: data.emails_failed,
      to: firstFailedEmail ? adminLink(firstFailedEmail) : "/admin?tab=approved#account-requests",
    },
  ];
  return (
    <div className="card home-panel">
      <h2>Needs your attention</h2>
      <div className="count-tiles">
        {tiles.map((tile) => (
          <Link key={tile.label} to={tile.to} className={tile.count > 0 ? "count-tile waiting" : "count-tile"}>
            <span className="count-number">{tile.count}</span>
            <span className="small">{tile.label}</span>
          </Link>
        ))}
      </div>
      {data.items.length === 0 ? (
        <p className="muted">Nothing needs your attention.</p>
      ) : (
        <ul className="home-list">
          {data.items.map((item) => (
            <li key={`${item.kind}-${item.request_type}-${item.id}`}>
              <Link to={adminLink(item)}>{item.title}</Link>
              <span className="muted small nowrap" title={formatDate(item.created_at)}>
                {formatShortDate(item.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// Users: their website requests that are pending or were decided in the last 7 days.
function MyRequestsPanel({ requests }) {
  return (
    <div className="card home-panel">
      <h2>My website requests</h2>
      {!requests && <p className="muted">Loading…</p>}
      {requests?.length === 0 && (
        <p className="muted">
          Want to scan your own website? <Link to="/my-websites">Request access.</Link>
        </p>
      )}
      {requests?.length > 0 && (
        <>
          <ul className="home-list">
            {requests.map((request) => (
              <li key={request.id}>
                <span>
                  <code>{request.host}</code>{" "}
                  <span className={`status-badge request-${request.status}`}>{request.status}</span>
                  {request.reject_reason && <span className="muted small block">Reason: {request.reject_reason}</span>}
                </span>
                <span className="muted small nowrap" title={formatDate(request.reviewed_at ?? request.created_at)}>
                  {formatShortDate(request.reviewed_at ?? request.created_at)}
                </span>
              </li>
            ))}
          </ul>
          <p className="small">
            <Link to="/my-websites">Go to My websites</Link>
          </p>
        </>
      )}
    </div>
  );
}

// The user's 5 latest scans, from the same API as the Scan history page.
function RecentScans() {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/api/scans")
      .then((all) => setScans(all.slice(0, RECENT_SCANS)))
      .catch((err) => setError(err.message));
  }, []);

  return (
    <div className="card home-panel">
      <h2>Recent scans</h2>
      {error && <p className="error">{error}</p>}
      {!scans && !error && <p className="muted">Loading…</p>}
      {scans?.length === 0 && <p className="muted">No scans yet. Pick a tool below to run one.</p>}
      {scans?.length > 0 && (
        <ul className="home-list">
          {scans.map((scan) => (
            <li key={scan.id}>
              <span>
                <Link to={`/history/${scan.id}`}>{scan.label}</Link> <code>{scan.target}</code>
                <span className="counts block small">
                  {["high", "medium", "low"].map((level) => (
                    <span key={level}>
                      <SeverityBadge severity={level} /> {scan.counts[level]}
                    </span>
                  ))}
                </span>
              </span>
              <span className="muted small nowrap" title={formatDate(scan.created_at)}>
                {formatShortDate(scan.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="small">
        <Link to="/history">See all</Link>
      </p>
    </div>
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

  if (hidden) return null;

  function hide() {
    try {
      localStorage.setItem(storageKey, "1");
    } catch {
      // not remembered, but still hidden for now
    }
    setHidden(true);
  }

  return (
    <div className="notice banner">
      <p>
        <strong>Add an email address to your account</strong> so admins can reach you and you can get account emails.
      </p>
      <p>
        <Link to="/account/email">Add your email address</Link>
      </p>
      <button type="button" className="link-button small" onClick={hide}>
        Dismiss
      </button>
    </div>
  );
}
