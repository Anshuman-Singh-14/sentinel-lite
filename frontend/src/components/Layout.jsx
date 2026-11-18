import { NavLink } from "react-router-dom";

// The sidebar. Each group is a heading with links under it. The tools' descriptions are shown
// on the homepage tiles.
export const NAV = [
  {
    heading: "Network tools",
    links: [
      { to: "/dns-check", label: "DNS & email check", description: "A domain's address and mail records, and whether SPF and DMARC stop forged email." },
      { to: "/port-scan", label: "Port scan", description: "Which TCP ports on an approved server accept connections, and what runs there." },
      { to: "/web-check", label: "Website check", description: "HTTPS, certificate expiry and 6 key security headers on an approved website." },
    ],
  },
  { heading: "Logs", links: [{ to: "/log-analyzer", label: "Log analyzer", description: "Password guessing, spraying, probing and suspicious IPs in an uploaded log." }] },
  {
    heading: "Browser-only tools",
    links: [
      { to: "/password", label: "Password strength", description: "How long a password would survive a guessing attack, and how to improve it." },
      { to: "/hash", label: "Hash generator", description: "A fingerprint of text or a file, to check that it wasn't altered." },
      { to: "/encoder", label: "Encoder / decoder", description: "Base64 and URL encoding, both ways (encoding is not encryption)." },
    ],
  },
  {
    heading: "Results",
    links: [
      { to: "/history", label: "Scan history" },
      { to: "/my-websites", label: "My websites" },
    ],
  },
];

const ADMIN_NAV = { heading: "Admin", links: [{ to: "/admin", label: "Users, targets & activity" }] };

// attentionCount: for admins, how many things wait for them (shown as a red badge on the admin link).
export default function Layout({ user, onLogout, attentionCount = 0, children }) {
  const groups = user.role === "admin" ? [...NAV, ADMIN_NAV] : NAV;
  return (
    <div className="layout">
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          Sentinel Lite
        </NavLink>
        {groups.map((group) => (
          <nav key={group.heading}>
            <h2>{group.heading}</h2>
            {group.links.map((link) => (
              <NavLink key={link.to} to={link.to}>
                {link.label}
                {link.to === "/admin" && attentionCount > 0 && (
                  <span className="count-badge alert" aria-label={`${attentionCount} need your attention`}>
                    {attentionCount}
                  </span>
                )}
              </NavLink>
            ))}
          </nav>
        ))}
        <div className="account">
          <span className="account-name">
            {user.username} ({user.role})
          </span>
          <span className="account-links">
            <NavLink to="/account/email">Change email</NavLink>
            <NavLink to="/account/password">Change password</NavLink>
            <button type="button" className="link-button" onClick={onLogout}>
              Log out
            </button>
          </span>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
