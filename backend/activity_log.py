"""The activity log as a plain-text file: one line per event, newest at the bottom.

guard.record() saves each event in the database and then calls append() here, so the
file keeps growing with every login, scan and admin change. On the server you can
watch it live with:  docker compose exec backend tail -f /data/activity.log

Each line is key=value pairs, easy to read and easy for tools (or our own log
analyzer) to parse:

    2026-11-16T06:10:01Z ip=203.0.113.9 user=alice action=login result=ok detail=""

Lines written before this format (2026-10-30 06:51:12 UTC | alice | login | from ...)
stay in the file as they are; the log analyzer reads both.
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


NEEDS_QUOTES = (" ", '"', "\\", "=")


def field(value: str) -> str:
    """One value, on one line. Quoted, with backslashes and quotes escaped, if it is empty
    or has a space, quote, backslash or "=", so a username like 'x" action=login' stays
    one value instead of adding a fake field."""
    value = one_line(value)
    if value and not any(char in value for char in NEEDS_QUOTES):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def format_line(entry: Activity) -> str:
    """e.g. 2026-11-16T06:10:01Z ip=203.0.113.9 user=alice action=login result=ok detail="" """
    when = entry.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")  # times are stored in UTC
    pairs = [("ip", entry.ip), ("user", entry.username), ("action", entry.action), ("result", entry.result),
             ("detail", entry.detail)]
    return when + "".join(f" {key}={field(value or '')}" for key, value in pairs)


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
