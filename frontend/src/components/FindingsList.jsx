import SeverityBadge from "./SeverityBadge.jsx";

// One card per finding: what was found, how serious it is, why it matters, how to fix it.
//
// Each finding looks like:
//   { key, title, severity: "low" | "medium" | "high", explanation, fix, details: {...} }
export default function FindingsList({ findings }) {
  if (findings.length === 0) {
    return <p className="card no-findings">No problems found.</p>;
  }
  return (
    <div className="findings">
      {findings.map((finding, index) => (
        <article key={index} className={`card finding finding-${finding.severity}`}>
          <header>
            <SeverityBadge severity={finding.severity} />
            <h3>{finding.title}</h3>
          </header>
          {Object.keys(finding.details).length > 0 && (
            <p className="details">
              {Object.entries(finding.details).map(([name, value]) => (
                <span key={name}>
                  {name.replaceAll("_", " ")}: <code>{String(value)}</code>
                </span>
              ))}
            </p>
          )}
          <p>{finding.explanation}</p>
          <p>
            <strong>How to fix: </strong>
            {finding.fix}
          </p>
        </article>
      ))}
    </div>
  );
}
