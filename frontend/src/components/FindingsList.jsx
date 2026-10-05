// Shows a scan's findings. STUB: Role 3 replaces the raw JSON with cards that
// show title, severity, explanation and fix for each finding.
//
// Each finding looks like:
//   { key, title, severity: "low" | "medium" | "high", explanation, fix, details: {...} }
export default function FindingsList({ findings }) {
  if (findings.length === 0) return <p>No problems found.</p>;
  return <pre>{JSON.stringify(findings, null, 2)}</pre>;
}
