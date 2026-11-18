import { Link } from "react-router-dom";
import ScanResult from "./ScanResult.jsx";

// Shared frame for the server-side tools: heading, intro, the tool's form, then
// either an error or the result. `request` comes from useRequest().
// `target` (port scan, website check): the host typed in, so a scan refused because the
// target isn't approved can link straight to the request form with it filled in.
export default function ToolPage({ title, intro, request, target, children }) {
  const notApproved = request.status === 403 && request.error.includes("not an approved target");
  const host = target?.trim().toLowerCase();
  return (
    <section>
      <h1>{title}</h1>
      <p className="muted">{intro}</p>
      {children}
      {request.busy && <p className="muted">Working… this can take a few seconds.</p>}
      {request.error && (
        <div className="error card">
          <p className="tool-error">{request.error}</p>
          {notApproved && host && (
            <p className="tool-error">
              <Link to={`/my-websites?host=${encodeURIComponent(host)}`}>Request access to {host}</Link>
            </p>
          )}
        </div>
      )}
      {request.data && <ScanResult scan={request.data} />}
    </section>
  );
}
