"""Website check: HTTPS, certificate expiry and 6 security headers.

Three steps, each with a timeout:
1. Open a TLS connection on port 443 and read the certificate's expiry date.
2. Request https://<target>/ and look for the 6 security headers.
3. Request http://<target>/ and see whether it redirects to HTTPS.
"""

import socket
import ssl
from collections.abc import Mapping
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend import guard
from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.results import make_finding, save_scan
from backend.validation import Hostname

LABEL = "Website check"
TIMEOUT = 5  # seconds
EXPIRY_WARNING_DAYS = 30
CERT_HAS_EXPIRED = 10  # OpenSSL's error code for an expired certificate

# Header name (lowercase) -> finding key when the header is missing
SECURITY_HEADERS = {
    "strict-transport-security": "web.missing_hsts",
    "content-security-policy": "web.missing_csp",
    "x-frame-options": "web.missing_x_frame_options",
    "x-content-type-options": "web.missing_x_content_type_options",
    "referrer-policy": "web.missing_referrer_policy",
    "permissions-policy": "web.missing_permissions_policy",
}

router = APIRouter()


class WebCheckRequest(BaseModel):
    target: Hostname


def certificate_expiry(host: str) -> datetime:
    """Connect on port 443 and return when the (verified) certificate expires."""
    context = ssl.create_default_context()  # checks the certificate chain and the hostname
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            not_after = tls.getpeercert()["notAfter"]
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)


def check_expiry(expires: datetime, now: datetime) -> list[dict]:
    days_left = (expires - now).days
    if expires <= now:
        return [make_finding("web.cert_expired", expired_on=expires.date().isoformat())]
    if days_left < EXPIRY_WARNING_DAYS:
        return [make_finding("web.cert_expiring_soon", days_left=days_left)]
    return []


def check_headers(headers: Mapping[str, str]) -> list[dict]:
    """One finding per missing security header. Header names are case-insensitive."""
    present = {name.lower() for name in headers}
    return [make_finding(key, header=name) for name, key in SECURITY_HEADERS.items() if name not in present]


def redirects_to_https(status_code: int, location: str | None) -> bool:
    return 300 <= status_code < 400 and (location or "").lower().startswith("https://")


def run_checks(host: str) -> tuple[dict, list[dict]]:
    summary = {"https": False, "certificate_expires": None, "headers": {}, "http_redirects_to_https": None}

    try:
        expires = certificate_expiry(host)
    except ssl.SSLCertVerificationError as error:  # must come before OSError, it is a subclass
        key = "web.cert_expired" if error.verify_code == CERT_HAS_EXPIRED else "web.cert_invalid"
        return summary, [make_finding(key, reason=error.verify_message)]
    except OSError:  # refused, timed out, or no TLS on port 443
        return summary, [make_finding("web.no_https")]
    summary["https"] = True
    summary["certificate_expires"] = expires.isoformat()
    findings = check_expiry(expires, datetime.now(UTC))

    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
        try:
            response = client.get(f"https://{host}/")
        except httpx.HTTPError:
            return summary, findings + [make_finding("web.no_https")]
        summary["status_code"] = response.status_code
        summary["headers"] = {name: response.headers[name] for name in SECURITY_HEADERS if name in response.headers}
        findings += check_headers(response.headers)

        try:
            plain = client.get(f"http://{host}/")
            summary["http_redirects_to_https"] = redirects_to_https(plain.status_code, plain.headers.get("location"))
        except httpx.HTTPError:
            pass  # nothing listening on port 80 is fine: there is no insecure version to fall back to
    if summary["http_redirects_to_https"] is False:
        findings.append(make_finding("web.http_not_redirected"))
    return summary, findings


@router.post("/web-check")
def web_check(body: WebCheckRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    guard.check_rate_limit(user)
    guard.check_target(db, body.target)
    summary, findings = run_checks(body.target)
    guard.log_activity(db, user, "web_check", body.target)
    return save_scan(db, user, "web_check", body.target, summary, findings)
