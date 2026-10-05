// A coloured label: "high" red, "medium" orange, "low" green (see styles.css).
export default function SeverityBadge({ severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}
