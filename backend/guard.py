"""Safety checks shared by the tools: target allowlist, rate limits, activity log."""

import ipaddress
import threading
import time
from collections import defaultdict, deque
from contextvars import ContextVar
from typing import NoReturn

import dns.exception
import dns.resolver
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import activity_log
from backend.config import settings
from backend.models import Activity, AllowedTarget, TargetAccess, User

DNS_TIMEOUT = 3  # seconds
SCANS_PER_MINUTE = 10
LOGINS_PER_MINUTE = 5

# Public resolvers rather than this computer's DNS settings, which on laptops often
# point at a VPN or office server that isn't reachable.
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
resolver.timeout = 1.5  # per server, so the second one gets a turn within DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT


# --- Which targets may be scanned ---


def resolve(host: str) -> list[str]:
    """The IPv4 addresses of `host` (or the host itself if it is already an IP)."""
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ValueError:
        pass
    try:
        answer = resolver.resolve(host, "A")
    except dns.exception.DNSException:
        raise HTTPException(400, f"Could not find an IPv4 address for {host}") from None
    return [record.address for record in answer]


def is_internal_ip(ip: str) -> bool:
    """True for addresses that aren't normal public internet hosts:
    localhost, private networks (10.x, 192.168.x, ...), link-local, reserved and multicast."""
    address = ipaddress.ip_address(ip)
    return not address.is_global or address.is_multicast


def server_ips() -> set[str]:
    """The public IPs of this server, found by looking up our own DOMAIN."""
    if settings.domain == "localhost":
        return set()
    try:
        return set(resolve(settings.domain))
    except HTTPException:
        return set()


def internal_address(ips: list[str]) -> str | None:
    """On the real server, the first of `ips` that must never be scanned (internal or our own), else None.

    In development everything is allowed, so scanning a test server on localhost works.
    """
    if not settings.is_prod:
        return None
    own_ips = server_ips()
    for ip in ips:
        if is_internal_ip(ip) or ip in own_ips:
            return ip
    return None


def can_scan(db: Session, target: AllowedTarget, user: User) -> bool:
    """Admins can scan every target; others a shared one, or a private one they were given access to."""
    if user.role == "admin" or target.shared:
        return True
    access = select(TargetAccess).where(TargetAccess.target_id == target.id, TargetAccess.user_id == user.id)
    return db.scalar(access) is not None


def check_target(db: Session, host: str, user: User, tool: str = "") -> str:
    """Return the IP address to scan for `host`, or raise 403 if this user may not scan it.

    Refusals are logged as scan_refused and lookup failures as scan_failed.
    """

    def refuse(why: str, message: str) -> NoReturn:
        log_activity(db, user, "scan_refused", f"{tool} {host}: {why}", "denied")
        raise HTTPException(403, message)

    approved = db.scalar(select(AllowedTarget).where(AllowedTarget.host == host))
    if approved is None or not can_scan(db, approved, user):
        refuse("not approved",
               f"{host} is not an approved target. Request access on the My websites page, or ask an admin.")

    try:
        ips = resolve(host)
    except HTTPException:
        log_activity(db, user, "scan_failed", f"{tool} {host}: DNS lookup failed", "fail")
        raise
    # On the real server, never scan ourselves or the private network we sit in,
    # even if an admin approved the name by mistake (or its DNS changed since).
    bad_ip = internal_address(ips)
    if bad_ip:
        refuse("internal address", f"{host} points to an internal address ({bad_ip}), which is never scanned.")
    return ips[0]


# --- Rate limits ---


class RateLimiter:
    """Allows at most `limit` events per key in any `window`-second period.

    Kept in memory, so it resets when the server restarts. That is fine for
    a single server process, which is how Sentinel Lite runs.
    """

    def __init__(self, limit: int, window: int = 60):
        self.limit = limit
        self.window = window
        self.events: dict[object, deque] = defaultdict(deque)
        self.lock = threading.Lock()  # FastAPI may call this from several threads at once

    def _recent(self, key: object, now: float) -> deque:
        events = self.events[key]
        while events and now - events[0] >= self.window:
            events.popleft()  # forget events older than the window
        return events

    def allow(self, key: object) -> bool:
        """Check and count in one step: True (and counted) if the key is under its limit."""
        now = time.monotonic()
        with self.lock:
            events = self._recent(key, now)
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def is_full(self, key: object) -> bool:
        """Check without counting, for limits that only count successes (see add())."""
        with self.lock:
            return len(self._recent(key, time.monotonic())) >= self.limit

    def add(self, key: object) -> None:
        """Count one event without checking, e.g. after a request has succeeded."""
        with self.lock:
            self.events[key].append(time.monotonic())

    def reset(self) -> None:
        with self.lock:
            self.events.clear()


scan_limiter = RateLimiter(SCANS_PER_MINUTE)
login_limiter = RateLimiter(LOGINS_PER_MINUTE)


def check_rate_limit(db: Session, user: User) -> None:
    """Raise 429 if the user has started too many scans in the last minute."""
    if not scan_limiter.allow(user.id):
        rate_limited(db, user.username, "scan")
        raise HTTPException(429, "Too many scans. Please wait a minute and try again.")


def check_login_rate(db: Session, ip: str, username: str) -> None:
    """Raise 429 after too many login attempts from one IP address (slows password guessing).

    Also used before checking a current password (password and email changes)."""
    if not login_limiter.allow(ip):
        rate_limited(db, username, "login")
        raise HTTPException(429, "Too many login attempts. Please wait a minute and try again.")


# --- Activity log ---


SYSTEM = "system"  # the username for events with no person behind them (startup, migrations)

# The visitor's IP for the request being handled. A middleware in app.py sets it, so every
# event records it without each route passing it along. Outside a request it stays "-".
current_ip: ContextVar[str] = ContextVar("current_ip", default="-")


def record(db: Session, username: str, action: str, detail: str = "", result: str = "ok") -> None:
    """Save an event in the Activity table, then add it to the activity log file.

    result: "ok", "fail" (e.g. a wrong password or a scan that couldn't finish) or
    "denied" (refused by a rule: rate limit, unapproved target, admins only).
    """
    entry = Activity(username=username[:32], action=action, detail=detail[:300], ip=current_ip.get()[:45],
                     result=result)
    db.add(entry)
    db.commit()
    activity_log.append(entry)


def log_activity(db: Session, user: User, action: str, detail: str = "", result: str = "ok") -> None:
    """Record who did what in the Activity table (shown to admins)."""
    record(db, user.username, action, detail, result)


def rate_limited(db: Session, username: str, what: str) -> None:
    """what: "scan", "login", "access_request", "email_link" or "target_request"."""
    record(db, username, "rate_limited", what, "denied")


def mask_email(email: str) -> str:
    """alice@gmail.com -> a***@gmail.com. Full email addresses never go in the activity log."""
    name, _, domain = email.partition("@")
    return f"{name[:1]}***@{domain}"
