import { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";

const REFRESH_MS = 60 * 1000;

// What needs someone's attention (GET /api/notifications): the homepage panels and,
// for admins, the sidebar badge. Admins' counts are refreshed every minute while the
// tab is visible, and straight away when they come back to the tab.
//   const notifications = useNotifications(user);
//   notifications.data / notifications.error / notifications.reload()
export function useNotifications(user) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const isAdmin = user?.role === "admin";
  // Nothing loads until the account is usable (a forced password change comes first).
  const userId = user && !user.must_change_password ? user.id : null;

  const reload = useCallback(() => {
    if (!userId) return;
    api("/api/notifications")
      .then((result) => {
        setData(result);
        setError("");
      })
      .catch((err) => setError(err.message));
  }, [userId]);

  useEffect(reload, [reload]);

  useEffect(() => {
    if (!isAdmin) return undefined;
    const refreshIfVisible = () => {
      if (document.visibilityState === "visible") reload();
    };
    const timer = setInterval(refreshIfVisible, REFRESH_MS);
    document.addEventListener("visibilitychange", refreshIfVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshIfVisible);
    };
  }, [isAdmin, reload]);

  return { data, error, reload };
}

// Where on the admin page an entry from the notifications list is handled.
// Failed emails are shown under the tab of the decision they were about.
export function adminLink(item) {
  const section = item.request_type === "website" ? "website-requests" : "account-requests";
  const tab = item.kind === "email_failed" ? `?tab=${item.decision}` : "";
  return `/admin${tab}#${section}`;
}
