import { apiUrl } from "../api.js";
import { formatDate } from "../format.js";
import { useList } from "../useList.js";

// The activity log table and its links, used on /admin (in a scroll box)
// and on /admin/activity (the full page).
//   limit: how many of the newest events to load (the backend allows 1-5000)
//   boxed: put the table in a fixed-height box with its own scrollbar
//   showOpenLink: show "Open in new tab" (not needed on the full page itself)
export default function ActivityLog({ limit, boxed = false, showOpenLink = false }) {
  const activity = useList(`/api/admin/activity?limit=${limit}`);
  return (
    <>
      <ActivityToolbar onRefresh={activity.reload} showOpenLink={showOpenLink} />
      {activity.error && <p className="error">{activity.error}</p>}
      <div className={boxed ? "table-scroll" : undefined}>
        <ActivityTable entries={activity.items} error={activity.error} />
      </div>
    </>
  );
}

// Three small groups of links (page actions, views, downloads) that wrap on narrow screens.
// Views and "Open in new tab" open a new tab; downloads save a file.
function ActivityToolbar({ onRefresh, showOpenLink }) {
  const txt = apiUrl("/api/admin/activity/export.txt");
  const csv = apiUrl("/api/admin/activity/export.csv");
  return (
    <div className="log-toolbar small">
      <span>
        <button type="button" className="link-button" onClick={onRefresh}>
          Refresh
        </button>
        {showOpenLink && (
          <>
            {" · "}
            <a href="/admin/activity" target="_blank" rel="noopener">
              Open in new tab ↗
            </a>
          </>
        )}
      </span>
      <span>
        <span className="muted">View:</span>{" "}
        <a href={`${txt}?view=1`} target="_blank" rel="noopener">
          TXT ↗
        </a>
        {" · "}
        <a href={`${csv}?view=1`} target="_blank" rel="noopener">
          CSV ↗
        </a>
      </span>
      <span>
        <span className="muted">Download:</span> <a href={txt}>TXT</a>
        {" · "}
        <a href={csv}>CSV</a>
      </span>
    </div>
  );
}

function ActivityTable({ entries, error }) {
  return (
    <table className="data">
      <thead>
        <tr>
          <th>When</th>
          <th>User</th>
          <th>Action</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((entry) => (
          <tr key={entry.id}>
            <td>{formatDate(entry.created_at)}</td>
            <td>{entry.username}</td>
            <td>{entry.action.replaceAll("_", " ")}</td>
            <td>{entry.detail}</td>
          </tr>
        ))}
        {entries.length === 0 && !error && (
          <tr>
            <td colSpan={4} className="muted">
              No activity yet.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
