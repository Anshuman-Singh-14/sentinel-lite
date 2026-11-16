"""Log analyzer: failed-login bursts, password spraying and other suspicious activity in logs.

Understands these formats:
  sshd (auth.log):  Oct  5 10:00:01 web1 sshd[812]: Failed password for root from 203.0.113.9 port 4242 ssh2
                    (also "sshd-session[812]:", used by newer OpenSSH, e.g. Ubuntu 24.04)
    On servers that only allow SSH keys, bots never get a password prompt, so there are no
    "Failed password" lines. Their attempts show up as pre-authentication lines instead:
      sshd[16419]: Invalid user ubuntu from 222.210.35.197 port 46162
      sshd[16419]: Connection closed by invalid user ubuntu 222.210.35.197 port 46162 [preauth]
      sshd[16193]: Connection closed by authenticating user root 195.178.110.217 port 58846 [preauth]
    One connection often writes two of these lines, so attempts are counted once per sshd
    process id (pid).
  nginx access log: 203.0.113.9 - - [05/Oct/2026:10:00:01 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "curl"
  Sentinel Lite's own activity log, both line formats and the CSV download:
    2026-11-16T06:10:01Z ip=203.0.113.9 user=alice action=login_failed result=fail detail="wrong password"
    2026-10-30 06:51:12 UTC | alice | login_failed | from 203.0.113.9          (older lines)
    id,time_utc,ip,username,action,result,detail                                (CSV, ip/result optional)

Uploads (.log/.txt/.csv, max 5 MB) are read into memory and never saved to disk.
"""

import csv
import io
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartParser

from backend import guard
from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.results import make_finding, save_scan

LABEL = "Log analyzer"
MAX_BYTES = 5 * 1024 * 1024
FORM_OVERHEAD = 64 * 1024  # room for the multipart headers around the file
ALLOWED_EXTENSIONS = (".log", ".txt", ".csv")

CONNECTION_WINDOW = timedelta(minutes=2)  # lines of one sshd pid this close together are one connection
BURST_COUNT = 5  # this many failed logins ...
BURST_WINDOW = timedelta(seconds=60)  # ... from one IP within this time is a burst
SPRAY_USERS = 5  # one IP failing logins for this many different usernames ...
SPRAY_WINDOW = timedelta(minutes=10)  # ... within this time is password spraying
PROBING_COUNT = 5  # this many refused scans by one user ...
PROBING_WINDOW = timedelta(minutes=10)  # ... within this time is target probing
RATE_LIMIT_COUNT = 5  # this many rate-limit hits by one user or IP ...
RATE_LIMIT_WINDOW = timedelta(hours=1)  # ... within this time is abuse
SCAN_USERNAMES = 5  # one IP trying this many usernames that don't exist ...
SCAN_WINDOW = timedelta(hours=1)  # ... within this time is a username scan
AUTH_FAILURE_LIMIT = 10  # 401/403 responses to one IP
NOT_FOUND_LIMIT = 20  # 404 responses to one IP
MAX_FINDINGS_PER_RULE = 10  # report at most the 10 worst IPs or users for each rule
TOP_IPS = 10

# Starlette normally moves uploads larger than 1 MB into a temporary file on disk.
# Raising the limit keeps the whole (max 5 MB) upload in memory, so it is never stored.
MultiPartParser.spool_max_size = MAX_BYTES + FORM_OVERHEAD

SYSLOG_LINE = re.compile(
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<clock>\d\d:\d\d:\d\d)"  # Oct  5 10:00:01
    r"|(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*)"  # or 2026-10-05T10:00:01.123+00:00
    r" \S+ sshd(?:-session)?(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
IP = r"(?P<ip>[0-9a-fA-F.:]+)"  # IPv4 or IPv6
# Each pattern is one failed attempt; the "invalid" group is set when the user doesn't exist.
# Usernames are \S* rather than \S+: bots sometimes send an empty one ("Invalid user  from ...").
FAILED_ATTEMPTS = [
    re.compile(r"^Failed (?:password|publickey|none|keyboard-interactive(?:/pam)?) for "
               r"(?P<invalid>invalid user )?(?P<user>\S*) from " + IP),
    re.compile(r"^(?P<invalid>Invalid) user (?P<user>\S*) from " + IP + r" port \d+"),
    # The end of a connection that never logged in. "Disconnected from user azureuser ..."
    # (no "invalid"/"authenticating") is a normal logout and doesn't match.
    re.compile(r"^(?:Connection closed by|Disconnected from) (?:(?P<invalid>invalid)|authenticating) user "
               r"(?P<user>\S*) " + IP + r" port \d+ \[preauth\]"),
]
ACCEPTED_LOGIN = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from " + IP)
NGINX_LINE = re.compile(r'^(?P<ip>[0-9a-fA-F.:]+) \S+ \S+ \[[^\]]+\] "[^"]*" (?P<status>\d{3}) ')

# Sentinel Lite's activity log. The username in old lines can itself contain " | ",
# so the action (lowercase letters and _) anchors the split.
SENTINEL_OLD_LINE = re.compile(
    r"^(?P<time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC \| (?P<user>.*) \| (?P<action>[a-z_]+) \| (?P<detail>.*)$"
)
SENTINEL_NEW_LINE = re.compile(r"^(?P<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (?P<fields>.*)$")
KEY_VALUE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
FROM_IP = re.compile(r"\bfrom (?P<ip>[0-9a-fA-F.:]+)")
SENTINEL_CSV_HEADER = "id,time_utc,"

router = APIRouter()


@dataclass
class Event:
    # "failed_login", "accepted_login", "auth_failure" (401/403), "not_found" (404),
    # "scan_refused" or "rate_limited"
    kind: str
    ip: str
    time: datetime | None = None
    user: str | None = None
    target: str | None = None
    pid: str | None = None  # the sshd process id, to count one attempt per connection
    invalid_user: bool = False  # sshd said the username doesn't exist
    failed_line: bool = False  # sshd's own "Failed ..." line: each one is a separate guess


def syslog_time(match: re.Match) -> datetime:
    if match["iso"]:
        return datetime.fromisoformat(match["iso"])
    # Classic syslog lines have no year. Only the gaps between lines matter here,
    # so any leap year works (2000 lets "Feb 29" parse).
    return datetime.strptime(f"2000 {match['month']} {match['day']} {match['clock']}", "%Y %b %d %H:%M:%S")


# --- Sentinel Lite's own log ---


def unquote(value: str) -> str:
    """'"a \\"b\\""' -> 'a "b"' (the reverse of activity_log.field)."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def sentinel_event(time: datetime, ip: str, user: str, action: str, detail: str) -> Event | None:
    """Turn one activity log entry into an Event, or None if it isn't one the rules use."""
    if ip in ("", "-") and (found := FROM_IP.search(detail)):
        ip = found["ip"]  # older entries kept the IP in the detail: "from 203.0.113.9"
    ip = ip or "-"
    if action in ("login_failed", "login"):
        if ip == "-":
            return None  # nothing to group by
        return Event("failed_login" if action == "login_failed" else "accepted_login", ip, time, user)
    if action == "scan_refused":
        # detail: "port_scan example.com: not approved"
        target = detail.split(":")[0].split(" ")[-1] if detail else None
        return Event("scan_refused", ip, time, user, target)
    if action == "rate_limited":
        return Event("rate_limited", ip, time, user)
    return None


def parse_sentinel_line(line: str) -> Event | None:
    if match := SENTINEL_NEW_LINE.match(line):
        fields = {key: unquote(value) for key, value in KEY_VALUE.findall(match["fields"])}
        if "action" not in fields:
            return None
        time = datetime.strptime(match["time"], "%Y-%m-%dT%H:%M:%SZ")
        return sentinel_event(time, fields.get("ip", "-"), fields.get("user", "-"), fields["action"],
                              fields.get("detail", ""))
    if match := SENTINEL_OLD_LINE.match(line):
        time = datetime.strptime(match["time"], "%Y-%m-%d %H:%M:%S")
        return sentinel_event(time, "-", match["user"], match["action"], match["detail"])
    return None


def csv_cell(value: str | None) -> str:
    """Undo the "'" the CSV download puts before cells like "=HYPERLINK(...)" (reports.safe_cell)."""
    value = value or ""
    return value[1:] if value[:1] == "'" and value[1:2] in ("=", "+", "-", "@") else value


def parse_sentinel_csv(text: str) -> list[Event]:
    """The admin page's CSV download, with or without the ip and result columns."""
    events = []
    for row in csv.DictReader(io.StringIO(text)):
        try:
            time = datetime.strptime(row["time_utc"], "%Y-%m-%d %H:%M:%S")
        except (KeyError, TypeError, ValueError):
            continue
        event = sentinel_event(time, csv_cell(row.get("ip")), csv_cell(row.get("username")),
                               csv_cell(row.get("action")), csv_cell(row.get("detail")))
        if event:
            events.append(event)
    return events


# --- Server logs ---


def parse_line(line: str) -> Event | None:
    if match := SYSLOG_LINE.match(line):
        message = match["message"]
        for pattern in FAILED_ATTEMPTS:
            if failed := pattern.search(message):
                return Event("failed_login", failed["ip"], syslog_time(match), failed["user"], pid=match["pid"],
                             invalid_user=bool(failed["invalid"]), failed_line=message.startswith("Failed "))
        if accepted := ACCEPTED_LOGIN.search(message):
            return Event("accepted_login", accepted["ip"], syslog_time(match), accepted["user"], pid=match["pid"])
        return None
    if match := NGINX_LINE.match(line):
        status = match["status"]
        if status in ("401", "403"):
            return Event("auth_failure", match["ip"])
        if status == "404":
            return Event("not_found", match["ip"])
        return None
    return parse_sentinel_line(line)


@dataclass
class Connection:
    """What one sshd process (pid) has written so far."""

    counted: Event  # the attempt counted for it
    last_seen: datetime  # time of its latest line
    has_failed_line: bool  # a "Failed ..." line has been counted


def one_attempt_per_connection(events: list[Event]) -> list[Event]:
    """Stop one connection's lines being counted as several attempts.

    One connection often writes "Invalid user ..." and then "Connection closed by invalid
    user ... [preauth]", or "Failed password ..." and then its closing line. They share the
    sshd pid. Those extra lines only count if the connection has no attempt yet. Each
    "Failed ..." line is a real guess (one connection may try several passwords), so it
    counts, except that the first one replaces an attempt counted from an "Invalid user"
    line before it. Pids are reused over time, so lines more than CONNECTION_WINDOW apart
    are separate connections. Lines without a pid are kept as they are.
    """
    kept = []
    connections: dict[str, Connection] = {}
    for event in events:
        if event.kind != "failed_login" or event.pid is None:
            kept.append(event)
            continue
        connection = connections.get(event.pid)
        if connection is None or event.time - connection.last_seen > CONNECTION_WINDOW:
            connections[event.pid] = Connection(event, event.time, event.failed_line)
            kept.append(event)
            continue
        connection.last_seen = event.time
        if event.failed_line and connection.has_failed_line:  # another guess in the same connection
            connection.counted = event
            kept.append(event)
            continue
        # Part of the attempt already counted: only keep what it adds.
        connection.counted.invalid_user = connection.counted.invalid_user or event.invalid_user
        connection.has_failed_line = connection.has_failed_line or event.failed_line
    return kept


# --- Rules ---


def largest_burst(times: list[datetime], window: timedelta = BURST_WINDOW) -> int:
    """The most events that fall inside any one `window` (a sliding window)."""
    times = sorted(times)
    best = start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def most_usernames_in_window(attempts: list[tuple[datetime, str]], window: timedelta) -> int:
    """The most DIFFERENT usernames tried inside any one `window`."""
    attempts = sorted(attempts)
    in_window: Counter = Counter()
    best = start = 0
    for when, username in attempts:
        in_window[username] += 1
        while when - attempts[start][0] > window:
            old_username = attempts[start][1]
            in_window[old_username] -= 1
            if not in_window[old_username]:
                del in_window[old_username]
            start += 1
        best = max(best, len(in_window))
    return best


def analyze_text(text: str) -> tuple[dict, list[dict]]:
    lines = text.splitlines()
    if lines and lines[0].lstrip("\ufeff").startswith(SENTINEL_CSV_HEADER):
        events = parse_sentinel_csv(text.lstrip("\ufeff"))
    else:
        events = one_attempt_per_connection([event for event in map(parse_line, lines) if event])
    failed_attempts = sum(event.kind == "failed_login" for event in events)
    summary = {"lines": len(lines), "recognized_events": len(events), "failed_attempts": failed_attempts,
               "top_ips": []}
    if not events:
        return summary, [make_finding("log.no_lines_recognized")]

    counts: dict[str, Counter] = defaultdict(Counter)  # ip -> {kind: count}
    failure_times: dict[str, list[datetime]] = defaultdict(list)
    failed_usernames: dict[str, list[tuple[datetime, str]]] = defaultdict(list)  # ip -> (time, username)
    invalid_usernames: dict[str, list[tuple[datetime, str]]] = defaultdict(list)  # the same, users that don't exist
    success_after_failures: dict[str, int] = {}  # ip -> failed logins before it got in
    refused_scans: dict[str, list[datetime]] = defaultdict(list)  # user -> times
    rate_limit_hits: dict[str, list[datetime]] = defaultdict(list)  # "user alice" / "IP 1.2.3.4" -> times
    for event in events:
        failures_so_far = counts[event.ip]["failed_login"]
        if event.kind == "accepted_login" and failures_so_far >= BURST_COUNT:
            success_after_failures.setdefault(event.ip, failures_so_far)
        counts[event.ip][event.kind] += 1
        if event.kind == "failed_login":
            failure_times[event.ip].append(event.time)
            if event.user is not None:  # "" (an empty username) still counts as a name tried
                failed_usernames[event.ip].append((event.time, event.user))
                if event.invalid_user:
                    invalid_usernames[event.ip].append((event.time, event.user))
        elif event.kind == "scan_refused" and event.user:
            refused_scans[event.user].append(event.time)
        elif event.kind == "rate_limited":
            if event.user and event.user != "-":
                rate_limit_hits[f"user {event.user}"].append(event.time)
            if event.ip != "-":
                rate_limit_hits[f"IP {event.ip}"].append(event.time)

    findings = worst(
        [(n, make_finding("log.success_after_failures", ip=ip, failures_before=n))
         for ip, n in success_after_failures.items()]
    )
    bursts = {ip: largest_burst(times) for ip, times in failure_times.items()}
    findings += worst(
        [(size, make_finding("log.failed_login_burst", ip=ip, failures_in_60s=size))
         for ip, size in bursts.items() if size >= BURST_COUNT]
    )
    sprays = {ip: most_usernames_in_window(tries, SPRAY_WINDOW) for ip, tries in failed_usernames.items()}
    findings += worst(
        [(users, make_finding("log.password_spray", ip=ip, usernames_in_10_min=users))
         for ip, users in sprays.items() if users >= SPRAY_USERS]
    )
    scans = {ip: most_usernames_in_window(tries, SCAN_WINDOW) for ip, tries in invalid_usernames.items()}
    findings += worst(
        [(users, make_finding("log.ssh_username_scan", ip=ip, invalid_usernames_in_1_hour=users))
         for ip, users in scans.items() if users >= SCAN_USERNAMES]
    )
    probes = {user: largest_burst(times, PROBING_WINDOW) for user, times in refused_scans.items()}
    findings += worst(
        [(n, make_finding("log.target_probing", user=user, refused_scans_in_10_min=n))
         for user, n in probes.items() if n >= PROBING_COUNT]
    )
    limited = {who: largest_burst(times, RATE_LIMIT_WINDOW) for who, times in rate_limit_hits.items()}
    findings += worst(
        [(n, make_finding("log.rate_limit_abuse", who=who, hits_in_1_hour=n))
         for who, n in limited.items() if n >= RATE_LIMIT_COUNT]
    )
    findings += worst(
        [(c["auth_failure"], make_finding("log.http_auth_burst", ip=ip, responses=c["auth_failure"]))
         for ip, c in counts.items() if c["auth_failure"] >= AUTH_FAILURE_LIMIT]
    )
    findings += worst(
        [(c["not_found"], make_finding("log.many_not_found", ip=ip, responses=c["not_found"]))
         for ip, c in counts.items() if c["not_found"] >= NOT_FOUND_LIMIT]
    )
    summary["top_ips"] = top_ips(counts)
    return summary, findings


def worst(scored: list[tuple[int, dict]]) -> list[dict]:
    """Keep the MAX_FINDINGS_PER_RULE findings with the highest score."""
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [finding for _, finding in scored[:MAX_FINDINGS_PER_RULE]]


def top_ips(counts: dict[str, Counter]) -> list[dict]:
    rows = [
        {
            "ip": ip,
            "failed_logins": c["failed_login"],
            "auth_failures": c["auth_failure"],
            "not_found": c["not_found"],
            "total": c["failed_login"] + c["auth_failure"] + c["not_found"],
        }
        for ip, c in counts.items()
    ]
    rows = [row for row in rows if row["total"] > 0]
    return sorted(rows, key=lambda row: row["total"], reverse=True)[:TOP_IPS]


# --- Upload ---


class UploadRefused(HTTPException):
    """An upload that was turned away. `reason` is the short version for the activity log."""

    def __init__(self, status_code: int, message: str, reason: str):
        super().__init__(status_code, message)
        self.reason = reason


async def read_upload(request: Request) -> tuple[str, bytes]:
    """Return (file name, contents) of the uploaded file, enforcing the size and type limits."""
    length = request.headers.get("content-length", "")
    if not length.isdigit():
        raise UploadRefused(411, "The upload must say how big it is (Content-Length)", "no size given")
    if int(length) > MAX_BYTES + FORM_OVERHEAD:
        raise UploadRefused(413, "The file is larger than 5 MB", "too big")
    form = await request.form(max_files=1, max_fields=1)
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise UploadRefused(400, "Choose a .log, .txt or .csv file to upload", "no file")
        name = Path(upload.filename or "upload.log").name[:100]
        if not name.lower().endswith(ALLOWED_EXTENSIONS):
            raise UploadRefused(400, "Only .log, .txt and .csv files are accepted", "wrong type")
        data = await upload.read(MAX_BYTES + 1)
    finally:
        await form.close()
    if len(data) > MAX_BYTES:
        raise UploadRefused(413, "The file is larger than 5 MB", "too big")
    return name, data


@router.post("/log-analyzer")
async def log_analyzer(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Upload as multipart form data with the file in a field called "file"."""
    guard.check_rate_limit(db, user)
    try:
        name, data = await read_upload(request)
    except UploadRefused as refused:
        guard.log_activity(db, user, "scan_failed", f"log_analyzer upload: upload refused: {refused.reason}", "fail")
        raise
    text = data.decode("utf-8-sig", errors="replace")  # -sig: drops the byte-order mark of our CSV download
    # Parsing 5 MB takes a moment; run it in a worker thread so other requests aren't held up.
    summary, findings = await run_in_threadpool(analyze_text, text)
    guard.log_activity(db, user, "log_analyzer", name)
    return save_scan(db, user, "log_analyzer", name, summary, findings)
