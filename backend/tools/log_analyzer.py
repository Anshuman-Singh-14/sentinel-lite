"""Log analyzer: failed-login bursts and top suspicious IPs in auth/nginx logs.

Understands two common formats:
  sshd (auth.log):  Oct  5 10:00:01 web1 sshd[812]: Failed password for root from 203.0.113.9 port 4242 ssh2
  nginx access log: 203.0.113.9 - - [05/Oct/2026:10:00:01 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "curl"

Uploads (.log/.txt, max 5 MB) are read into memory and never saved to disk.
"""

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
ALLOWED_EXTENSIONS = (".log", ".txt")

BURST_COUNT = 5  # this many failed logins ...
BURST_WINDOW = timedelta(seconds=60)  # ... from one IP within this time is a burst
AUTH_FAILURE_LIMIT = 10  # 401/403 responses to one IP
NOT_FOUND_LIMIT = 20  # 404 responses to one IP
MAX_FINDINGS_PER_RULE = 10  # report at most the 10 worst IPs for each rule
TOP_IPS = 10

# Starlette normally moves uploads larger than 1 MB into a temporary file on disk.
# Raising the limit keeps the whole (max 5 MB) upload in memory, so it is never stored.
MultiPartParser.spool_max_size = MAX_BYTES + FORM_OVERHEAD

SYSLOG_LINE = re.compile(
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<clock>\d\d:\d\d:\d\d)"  # Oct  5 10:00:01
    r"|(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*)"  # or 2026-10-05T10:00:01.123+00:00
    r" \S+ sshd(?:\[\d+\])?: (?P<message>.*)$"
)
FAILED_LOGIN = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?\S+ from (?P<ip>[0-9a-fA-F.:]+)")
ACCEPTED_LOGIN = re.compile(r"Accepted (?:password|publickey) for \S+ from (?P<ip>[0-9a-fA-F.:]+)")
NGINX_LINE = re.compile(r'^(?P<ip>[0-9a-fA-F.:]+) \S+ \S+ \[[^\]]+\] "[^"]*" (?P<status>\d{3}) ')

router = APIRouter()


@dataclass
class Event:
    kind: str  # "failed_login", "accepted_login", "auth_failure" (401/403) or "not_found" (404)
    ip: str
    time: datetime | None = None


def syslog_time(match: re.Match) -> datetime:
    if match["iso"]:
        return datetime.fromisoformat(match["iso"])
    # Classic syslog lines have no year. Only the gaps between lines matter here,
    # so any leap year works (2000 lets "Feb 29" parse).
    return datetime.strptime(f"2000 {match['month']} {match['day']} {match['clock']}", "%Y %b %d %H:%M:%S")


def parse_line(line: str) -> Event | None:
    if match := SYSLOG_LINE.match(line):
        if failed := FAILED_LOGIN.search(match["message"]):
            return Event("failed_login", failed["ip"], syslog_time(match))
        if accepted := ACCEPTED_LOGIN.search(match["message"]):
            return Event("accepted_login", accepted["ip"], syslog_time(match))
        return None
    if match := NGINX_LINE.match(line):
        status = match["status"]
        if status in ("401", "403"):
            return Event("auth_failure", match["ip"])
        if status == "404":
            return Event("not_found", match["ip"])
    return None


def largest_burst(times: list[datetime]) -> int:
    """The most failures that fall inside any one BURST_WINDOW (a sliding window)."""
    times = sorted(times)
    best = start = 0
    for end in range(len(times)):
        while times[end] - times[start] > BURST_WINDOW:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze_text(text: str) -> tuple[dict, list[dict]]:
    lines = text.splitlines()
    events = [event for event in map(parse_line, lines) if event]
    summary = {"lines": len(lines), "recognized_events": len(events), "top_ips": []}
    if not events:
        return summary, [make_finding("log.no_lines_recognized")]

    counts: dict[str, Counter] = defaultdict(Counter)  # ip -> {kind: count}
    failure_times: dict[str, list[datetime]] = defaultdict(list)
    success_after_failures: dict[str, int] = {}  # ip -> failed logins before it got in
    for event in events:
        failures_so_far = counts[event.ip]["failed_login"]
        if event.kind == "accepted_login" and failures_so_far >= BURST_COUNT:
            success_after_failures.setdefault(event.ip, failures_so_far)
        counts[event.ip][event.kind] += 1
        if event.kind == "failed_login":
            failure_times[event.ip].append(event.time)

    findings = worst(
        [(n, make_finding("log.success_after_failures", ip=ip, failures_before=n))
         for ip, n in success_after_failures.items()]
    )
    bursts = {ip: largest_burst(times) for ip, times in failure_times.items()}
    findings += worst(
        [(size, make_finding("log.failed_login_burst", ip=ip, failures_in_60s=size))
         for ip, size in bursts.items() if size >= BURST_COUNT]
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


async def read_upload(request: Request) -> tuple[str, bytes]:
    """Return (file name, contents) of the uploaded file, enforcing the size and type limits."""
    length = request.headers.get("content-length", "")
    if not length.isdigit():
        raise HTTPException(411, "The upload must say how big it is (Content-Length)")
    if int(length) > MAX_BYTES + FORM_OVERHEAD:
        raise HTTPException(413, "The file is larger than 5 MB")
    form = await request.form(max_files=1, max_fields=1)
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise HTTPException(400, "Choose a .log or .txt file to upload")
        name = Path(upload.filename or "upload.log").name[:100]
        if not name.lower().endswith(ALLOWED_EXTENSIONS):
            raise HTTPException(400, "Only .log and .txt files are accepted")
        data = await upload.read(MAX_BYTES + 1)
    finally:
        await form.close()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "The file is larger than 5 MB")
    return name, data


@router.post("/log-analyzer")
async def log_analyzer(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Upload as multipart form data with the file in a field called "file"."""
    guard.check_rate_limit(user)
    name, data = await read_upload(request)
    text = data.decode("utf-8", errors="replace")
    # Parsing 5 MB takes a moment; run it in a worker thread so other requests aren't held up.
    summary, findings = await run_in_threadpool(analyze_text, text)
    guard.log_activity(db, user, "log_analyzer", name)
    return save_scan(db, user, "log_analyzer", name, summary, findings)
