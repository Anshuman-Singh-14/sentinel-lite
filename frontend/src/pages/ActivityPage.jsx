import ActivityLog from "../components/ActivityLog.jsx";

// The activity log as a full page (/admin/activity), opened from the admin page.
export default function ActivityPage() {
  return (
    <section>
      <h1>Activity log</h1>
      <p className="muted small">
        The latest 5,000 events, newest first. The TXT and CSV views and downloads include every event.
      </p>
      <ActivityLog limit={5000} />
    </section>
  );
}
