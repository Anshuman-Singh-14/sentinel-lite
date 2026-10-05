"""Safety checks shared by the tools: target allowlist, rate limits, activity log."""

import ipaddress
import threading
import time
from collections import defaultdict, deque

import dns.exception
import dns.resolver
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import Activity, AllowedTarget, User

DNS_TIMEOUT = 3  # seconds
SCANS_PER_MINUTE = 10
LOGINS_PER_MINUTE = 5


# --- Which targets may be scanned ---


def resolve(host: str) -> list[str]:
    """The IPv4 addresses of `host` (or the host itself if it is already an IP)."""
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ValueError:
        pass
    try:
        answer = dns.resolver.resolve(host, "A", lifetime=DNS_TIMEOUT)
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


def check_target(db: Session, host: str) -> str:
    """Return the IP address to scan for `host`, or raise 403 if it isn't allowed."""
    approved = db.scalar(select(AllowedTarget).where(AllowedTarget.host == host))
    if approved is None:
        raise HTTPException(403, f"{host} is not an approved target. Ask an admin to add it.")

    ips = resolve(host)
    # On the real server, never scan ourselves or the private network we sit in,
    # even if an admin approved the name by mistake (or its DNS changed since).
    if settings.is_prod:
        own_ips = server_ips()
        for ip in ips:
            if is_internal_ip(ip) or ip in own_ips:
                raise HTTPException(403, f"{host} points to an internal address ({ip}), which is never scanned.")
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

    def allow(self, key: object) -> bool:
        now = time.monotonic()
        with self.lock:
            events = self.events[key]
            while events and now - events[0] >= self.window:
                events.popleft()  # forget events older than the window
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def reset(self) -> None:
        with self.lock:
            self.events.clear()


scan_limiter = RateLimiter(SCANS_PER_MINUTE)
login_limiter = RateLimiter(LOGINS_PER_MINUTE)


def check_rate_limit(user: User) -> None:
    """Raise 429 if the user has started too many scans in the last minute."""
    if not scan_limiter.allow(user.id):
        raise HTTPException(429, "Too many scans. Please wait a minute and try again.")


def check_login_rate(ip: str) -> None:
    """Raise 429 after too many login attempts from one IP address (slows password guessing)."""
    if not login_limiter.allow(ip):
        raise HTTPException(429, "Too many login attempts. Please wait a minute and try again.")


# --- Activity log ---


def record(db: Session, username: str, action: str, detail: str = "") -> None:
    db.add(Activity(username=username[:32], action=action, detail=detail[:300]))
    db.commit()


def log_activity(db: Session, user: User, action: str, detail: str = "") -> None:
    """Record who did what in the Activity table (shown to admins)."""
    record(db, user.username, action, detail)
