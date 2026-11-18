// "Shared" (everyone can scan it) or "Private" (only the users it was approved for).
export default function AccessBadge({ shared }) {
  return (
    <span className={shared ? "status-badge shared" : "status-badge private"}>{shared ? "Shared" : "Private"}</span>
  );
}
