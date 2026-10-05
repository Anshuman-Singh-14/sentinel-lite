import { Link } from "react-router-dom";
import { NAV } from "../components/Layout.jsx";

export default function DashboardPage({ user }) {
  return (
    <section>
      <h1>Welcome, {user.username}</h1>
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
