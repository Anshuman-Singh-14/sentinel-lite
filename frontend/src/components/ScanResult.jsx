import { formatDate } from "../format.js";
import FindingsList from "./FindingsList.jsx";

// A finished scan: the key facts, the explained findings, export links and the raw data.
export default function ScanResult({ scan }) {
  return (
    <div className="scan-result">
      <div className="result-header">
        <h2>
          Results for <code>{scan.target}</code>
        </h2>
        <p className="muted small">
          {formatDate(scan.created_at)} ·{" "}
          <a href={`/api/scans/${scan.id}/export.csv`}>Download CSV</a> ·{" "}
          <a href={`/api/scans/${scan.id}/report`} target="_blank" rel="noopener noreferrer">
            Printable report
          </a>
        </p>
      </div>
      <Summary tool={scan.tool} summary={scan.summary} />
      <h2>Findings ({scan.findings.length})</h2>
      <FindingsList findings={scan.findings} />
      <details className="raw">
        <summary>Raw data</summary>
        <pre>{JSON.stringify(scan.summary, null, 2)}</pre>
      </details>
    </div>
  );
}

function Summary({ tool, summary }) {
  if (tool === "dns_check") return <DnsSummary summary={summary} />;
  if (tool === "port_scan") return <PortSummary summary={summary} />;
  if (tool === "web_check") return <WebSummary summary={summary} />;
  if (tool === "log_analyzer") return <LogSummary summary={summary} />;
  return null;
}

function Facts({ rows }) {
  return (
    <table className="facts">
      <tbody>
        {rows.map(([name, value]) => (
          <tr key={name}>
            <th>{name}</th>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const list = (items) => (items.length ? items.join(", ") : "none");
const yesNo = (value) => (value === null || value === undefined ? "unknown" : value ? "yes" : "no");

function DnsSummary({ summary }) {
  return (
    <Facts
      rows={[
        ["A (IPv4 addresses)", list(summary.a)],
        ["MX (mail servers)", list(summary.mx)],
        ["SPF record", summary.spf ?? "none"],
        ["DMARC record", summary.dmarc ?? "none"],
        ["Other TXT records", summary.txt.length],
      ]}
    />
  );
}

function PortSummary({ summary }) {
  return (
    <>
      <Facts
        rows={[
          ["IP address scanned", summary.ip],
          ["Ports checked", summary.ports_scanned],
          ["Open", summary.open.length],
          ["Closed", summary.closed_count],
        ]}
      />
      {summary.open.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>Open port</th>
              <th>Usual service</th>
            </tr>
          </thead>
          <tbody>
            {summary.open.map((row) => (
              <tr key={row.port}>
                <td>{row.port}</td>
                <td>{row.service}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

const HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];

function WebSummary({ summary }) {
  return (
    <>
      <Facts
        rows={[
          ["HTTPS works", yesNo(summary.https)],
          ["Certificate expires", summary.certificate_expires ? formatDate(summary.certificate_expires) : "unknown"],
          ["HTTP redirects to HTTPS", yesNo(summary.http_redirects_to_https)],
        ]}
      />
      {summary.https && (
        <table className="data">
          <thead>
            <tr>
              <th>Security header</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {HEADERS.map((name) => (
              <tr key={name}>
                <td>{name}</td>
                <td>{summary.headers[name] ? <code>{summary.headers[name]}</code> : <em>missing</em>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function LogSummary({ summary }) {
  return (
    <>
      <Facts
        rows={[
          ["Lines in file", summary.lines],
          ["Events recognised", summary.recognized_events],
        ]}
      />
      {summary.top_ips.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>Most suspicious IPs</th>
              <th>Failed logins</th>
              <th>401/403</th>
              <th>404</th>
            </tr>
          </thead>
          <tbody>
            {summary.top_ips.map((row) => (
              <tr key={row.ip}>
                <td>{row.ip}</td>
                <td>{row.failed_logins}</td>
                <td>{row.auth_failures}</td>
                <td>{row.not_found}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
