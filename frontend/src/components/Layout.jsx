import { NavLink } from "react-router-dom";

// The sidebar. Each group is a heading with links under it.
export const NAV = [
  {
    heading: "Network tools",
    links: [
      { to: "/dns-check", label: "DNS & email check" },
      { to: "/port-scan", label: "Port scan" },
      { to: "/web-check", label: "Website check" },
    ],
  },
  { heading: "Logs", links: [{ to: "/log-analyzer", label: "Log analyzer" }] },
  {
    heading: "Browser-only tools",
    links: [
      { to: "/password", label: "Password strength" },
      { to: "/hash", label: "Hash generator" },
      { to: "/encoder", label: "Encoder / decoder" },
    ],
  },
  { heading: "Results", links: [{ to: "/history", label: "Scan history" }] },
];

const ADMIN_NAV = { heading: "Admin", links: [{ to: "/admin", label: "Users, targets & activity" }] };

export default function Layout({ user, onLogout, children }) {
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
              </NavLink>
            ))}
          </nav>
        ))}
        <div className="account">
          <span>
            {user.username} ({user.role})
          </span>
          <button type="button" className="link-button" onClick={onLogout}>
            Log out
          </button>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
