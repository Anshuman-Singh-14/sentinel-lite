import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { formatDate } from "../format.js";

export default function HistoryPage() {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/api/scans")
      .then(setScans)
      .catch((err) => setError(err.message));
  }, []);

  return (
    <section>
      <h1>Scan history</h1>
      <p className="muted">Your last 100 scans. Only you can see them.</p>
      {error && <p className="error">{error}</p>}
      {scans && scans.length === 0 && <p>No scans yet. Pick a tool from the menu to run one.</p>}
      {scans && scans.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>When</th>
              <th>Tool</th>
              <th>Target</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>
                  <Link to={`/history/${scan.id}`}>{formatDate(scan.created_at)}</Link>
                </td>
                <td>{scan.label}</td>
                <td>
                  <code>{scan.target}</code>
                </td>
                <td className="counts">
                  {["high", "medium", "low"]
                    .filter((level) => scan.counts[level] > 0)
                    .map((level) => (
                      <span key={level}>
                        <SeverityBadge severity={level} /> {scan.counts[level]}
                      </span>
                    ))}
                  {scan.counts.high + scan.counts.medium + scan.counts.low === 0 && <span className="muted">none</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
