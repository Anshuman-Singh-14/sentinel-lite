"""The activity log as a plain-text file: one line per event, newest at the bottom.

guard.record() saves each event in the database and then calls append() here, so the
file keeps growing with every login, scan and admin change. On the server you can
watch it live with:  docker compose exec backend tail -f /data/activity.log
"""

import threading

from backend.config import settings
from backend.models import Activity

# Several requests can finish at the same moment; the lock stops their lines mixing.
_lock = threading.Lock()


def one_line(text: str) -> str:
    """Collapse newlines and tabs into spaces.

    Without this, a username such as "x\\n2026-01-01 ... | admin | login" typed into
    the login form would add a fake line to the log (log injection).
    """
    return " ".join(text.split())


def format_line(entry: Activity) -> str:
    """e.g. 2026-10-30 06:51:12 UTC | admin | login | from 203.0.113.9"""
    when = entry.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")  # times are stored in UTC
    return " | ".join([when, one_line(entry.username), entry.action, one_line(entry.detail)])


def append(entry: Activity) -> None:
    path = settings.activity_log_file
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock, path.open("a", encoding="utf-8") as log_file:
            log_file.write(format_line(entry) + "\n")
    except OSError as error:
        # The event is already safe in the database, so a full disk or a permissions
        # problem shouldn't turn someone's login or scan into an error.
        print(f"[!] Could not write to the activity log {path}: {error}")
