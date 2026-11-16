"""Account requests from the login page, and the one-time email links.

The flow:
1. A visitor fills in the request form (with a Cloudflare Turnstile check). The request
   is saved as "unverified" and a link is emailed to them.
2. Opening the link and pressing "Confirm my email" makes the request "pending".
3. An admin approves or rejects it (see admin.py) and the visitor gets an email.

Logged-in accounts use the same kind of link to add an email or change theirs.
"""

import hashlib
import secrets
from datetime import timedelta

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from backend import guard, mailer
from backend.auth import client_ip, current_user, hash_password, verify_password
from backend.config import settings
from backend.db import SessionLocal, get_db
from backend.models import AccessRequest, EmailToken, User, as_utc, utcnow
from backend.validation import Email, Password, Username

router = APIRouter(tags=["account requests"])

TERMS_VERSION = "2026-11-v1"
TERMS_TEXT = """\
1. Sentinel Lite is a defensive security toolkit provided for learning and for checking systems you own or are \
authorised to test.
2. You will only scan websites, servers and networks that you own, or that you have written permission from the \
owner to test.
3. You are solely responsible for every action taken with your account, including all scans, uploads and requests, \
and you accept full liability for any consequences, damage or legal claims arising from them.
4. You will not share your credentials, try to bypass the tool's limits, or use it to attack, disrupt or gain \
unauthorised access to any system. Unauthorised access may be an offence under the Information Technology Act, 2000 \
and other laws.
5. Your activity, including your IP address, is logged and may be reviewed by administrators. Accounts may be \
suspended or removed at any time.
6. Sentinel Lite is provided as is, without any warranty. The project team is not liable for any loss or damage \
arising from its use."""

TOKEN_LIFETIME = timedelta(hours=24)
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_TIMEOUT = 5  # seconds
OPEN_STATUSES = ("unverified", "pending")

# Same answer whether or not the email is already in use, so the form can't be used to
# find out which addresses have accounts.
CHECK_EMAIL = "Thanks! Check your email and open the link to confirm your request."
UNAVAILABLE = "Account requests are not available right now"

# Two limits per IP per hour: 3 requests that were actually created, and 20 attempts of
# any kind, so typos and taken usernames don't lock people out but the form can't be hammered.
request_limiter = guard.RateLimiter(3, window=3600)
attempt_limiter = guard.RateLimiter(20, window=3600)
email_limiter = guard.RateLimiter(3, window=3600)  # "add my email" links per user per hour


class NewAccessRequest(BaseModel):
    username: Username
    email: Email
    wants_generated: bool = False
    password: Password | None = None
    remarks: str = Field(default="", max_length=500)
    agree: bool
    terms_version: str = Field(max_length=20)
    turnstile_token: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def check_choices(self):
        if not self.agree:
            raise ValueError("you must accept the agreement")
        if self.terms_version != TERMS_VERSION:
            raise ValueError("the agreement has changed, please reload the page and read it again")
        if self.wants_generated:
            self.password = None
        elif self.password is None:
            raise ValueError("choose a password, or ask for one to be generated")
        return self


class TokenBody(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class EmailChange(BaseModel):
    email: Email
    current_password: str = Field(max_length=200)


# --- One-time email links ---


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token(db: Session, purpose: str, ref_id: int, email: str) -> str:
    """Create a token, store only its hash, and return the token itself for the email link."""
    token = secrets.token_urlsafe(32)
    db.add(EmailToken(
        token_hash=hash_token(token), purpose=purpose, ref_id=ref_id, email=email,
        expires_at=utcnow() + TOKEN_LIFETIME,
    ))
    return token


def use_token(db: Session, token: str) -> EmailToken:
    """Mark a token as used (once only) and return it, or raise 400 with a clear reason."""
    row = db.scalar(select(EmailToken).where(EmailToken.token_hash == hash_token(token)))
    if row is None:
        raise HTTPException(400, "This link is not valid. Check that you opened the whole link from the email.")
    if row.used_at is not None:
        raise HTTPException(400, "This link has already been used.")
    if as_utc(row.expires_at) < utcnow():
        raise HTTPException(400, "This link has expired. Links work for 24 hours; please start again.")
    # The WHERE makes this safe if the link is opened twice at the same moment.
    claimed = db.execute(
        update(EmailToken).where(EmailToken.id == row.id, EmailToken.used_at.is_(None)).values(used_at=utcnow())
    )
    if claimed.rowcount != 1:
        raise HTTPException(400, "This link has already been used.")
    return row


def link(token: str) -> str:
    return f"{settings.public_base_url}/verify-email?token={token}"


def deliver(request_id: int | None, username: str, to: str, subject: str, body: str) -> None:
    """Send one email. Runs as a background task, after the response has gone out.

    The result is stored on the access request (if there is one) so admins can see it
    and press Resend. Failures are logged with the email masked.
    """
    try:
        mailer.send(to, subject, body)
        status, error = "sent", ""
    except mailer.MailError as failure:
        status, error = "failed", str(failure)
    with SessionLocal() as db:
        if request_id is not None:
            access_request = db.get(AccessRequest, request_id)
            if access_request is not None:
                access_request.email_status = status
                access_request.email_error = error[:300]
                db.commit()
        if status == "failed":
            guard.record(db, username, "email_failed", f'"{subject}" to {guard.mask_email(to)}: {error}')


def delete_stale_requests(db: Session) -> None:
    """Forget requests whose email was never confirmed within 24 hours, and old used-up links."""
    cutoff = utcnow() - TOKEN_LIFETIME
    db.execute(delete(AccessRequest).where(AccessRequest.status == "unverified", AccessRequest.created_at < cutoff))
    db.execute(delete(EmailToken).where(EmailToken.expires_at < cutoff))
    db.commit()


def delete_stale_requests_now() -> None:
    """For app startup, which has no request session."""
    with SessionLocal() as db:
        delete_stale_requests(db)


def verify_turnstile(token: str, ip: str) -> bool:
    """Ask Cloudflare whether the Turnstile widget was solved. Any error counts as a fail."""
    _site_key, secret = settings.turnstile_keys
    try:
        response = httpx.post(
            TURNSTILE_VERIFY_URL,
            data={"secret": secret, "response": token, "remoteip": ip},
            timeout=TURNSTILE_TIMEOUT,
        )
        return response.json().get("success") is True
    except (httpx.HTTPError, ValueError):
        return False


# --- Requesting an account (no login) ---


@router.get("/api/access-requests/config")
def request_config():
    """Everything the request form needs. The agreement text lives only here."""
    return {
        "enabled": settings.access_requests_enabled,
        "terms_version": TERMS_VERSION,
        "terms_text": TERMS_TEXT,
        "turnstile_site_key": settings.turnstile_keys[0],
    }


TOO_MANY = "Too many account requests from your network. Please try again in an hour."


def count_attempt(request: Request) -> str:
    """Counts every attempt, even ones with an invalid body: FastAPI runs dependencies
    before it validates the body. Returns the client's IP."""
    ip = client_ip(request)
    if not attempt_limiter.allow(ip):
        raise HTTPException(429, TOO_MANY)
    return ip


@router.post("/api/access-requests")
def create_request(
    body: NewAccessRequest,
    background: BackgroundTasks,
    ip: str = Depends(count_attempt),
    db: Session = Depends(get_db),
):
    if not settings.access_requests_enabled:
        raise HTTPException(503, UNAVAILABLE)
    if request_limiter.is_full(ip):
        raise HTTPException(429, TOO_MANY)
    if not verify_turnstile(body.turnstile_token, ip):
        raise HTTPException(400, "The human check failed. Please try it again.")
    delete_stale_requests(db)

    open_request = select(AccessRequest).where(AccessRequest.status.in_(OPEN_STATUSES))
    if db.scalar(select(User).where(User.username == body.username)) or db.scalar(
        open_request.where(AccessRequest.username == body.username)
    ):
        raise HTTPException(409, f"The username {body.username} is already taken. Please choose another one.")
    if db.scalar(select(User).where(User.email == body.email)) or db.scalar(
        open_request.where(AccessRequest.email == body.email)
    ):
        return {"message": CHECK_EMAIL}  # nothing is created, but the answer looks the same

    access_request = AccessRequest(
        username=body.username,
        email=body.email,
        # Hashed straight away: the chosen password is never stored or logged as text.
        password_hash=hash_password(body.password) if body.password else None,
        wants_generated=body.wants_generated,
        remarks=body.remarks.strip(),
        terms_version=body.terms_version,
        ip=ip,
    )
    db.add(access_request)
    db.flush()  # gives the request its id for the token
    token = new_token(db, "verify_request", access_request.id, body.email)
    db.commit()
    request_limiter.add(ip)  # only requests that were really created count towards the 3
    guard.record(db, body.username, "access_requested", f"{guard.mask_email(body.email)} from {ip}")
    background.add_task(
        deliver, access_request.id, body.username, body.email, *mailer.verify_request(body.username, link(token))
    )
    return {"message": CHECK_EMAIL}


@router.post("/api/email/verify")
def verify_email(body: TokenBody, background: BackgroundTasks, db: Session = Depends(get_db)):
    """A POST (from the "Confirm my email" button), not a GET: email security scanners
    open every link in an email, and that must not confirm anything."""
    token = use_token(db, body.token)
    if token.purpose == "verify_request":
        access_request = db.get(AccessRequest, token.ref_id)
        if access_request is None or access_request.status != "unverified":
            raise HTTPException(400, "This request is no longer waiting for confirmation.")
        access_request.status = "pending"
        db.commit()
        guard.record(db, access_request.username, "access_request_verified", guard.mask_email(access_request.email))
        return {"message": "Email confirmed. An admin will review your request, and you'll get an email "
                           "when they decide."}

    user = db.get(User, token.ref_id)
    if user is None or not user.is_active:
        raise HTTPException(400, "This link is not valid.")
    other = db.scalar(select(User).where(User.email == token.email, User.id != user.id))
    if other is not None:
        db.rollback()
        raise HTTPException(409, "This email address is already used by another account.")
    old_email = user.email
    user.email = token.email
    user.email_verified = True
    db.commit()
    new_masked = guard.mask_email(token.email)
    if old_email is None:
        guard.log_activity(db, user, "email_added", new_masked)
        return {"message": "Email confirmed and added to your account."}
    guard.log_activity(db, user, "email_changed", f"{guard.mask_email(old_email)} -> {new_masked}")
    # Tell the old address, so a change the owner didn't make doesn't go unnoticed.
    background.add_task(deliver, None, user.username, old_email, *mailer.email_changed(user.username, new_masked))
    return {"message": "Email confirmed. Your account now uses this address."}


# --- Adding or changing the email of an account ---

# The same answer whether or not the address is free, so this can't be used to find other accounts.
EMAIL_LINK_SENT = "If that address can be used, we've sent a confirmation link to it."


@router.post("/api/account/email")
def change_email(
    body: EmailChange,
    request: Request,
    background: BackgroundTasks,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Send a confirmation link to the new address. The account keeps its current email
    until the link is opened (see verify_email above)."""
    if not settings.mail_enabled:
        raise HTTPException(503, "Email is not available right now")
    # The password is asked for so a stolen session alone can't move the account's email.
    # It shares the login limit, so this can't be used to guess passwords faster.
    guard.check_login_rate(client_ip(request))
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Your current password is wrong")
    if body.email == user.email:
        raise HTTPException(400, "That is already your email address")
    if not email_limiter.allow(user.id):
        raise HTTPException(429, "Too many emails sent. Please try again in an hour.")

    # Only the newest link works: earlier unused ones are thrown away.
    db.execute(delete(EmailToken).where(
        EmailToken.purpose == "verify_user_email", EmailToken.ref_id == user.id, EmailToken.used_at.is_(None)
    ))
    taken = db.scalar(select(User).where(User.email == body.email)) or db.scalar(
        select(AccessRequest).where(AccessRequest.email == body.email, AccessRequest.status.in_(OPEN_STATUSES))
    )
    token = None if taken else new_token(db, "verify_user_email", user.id, body.email)
    db.commit()
    guard.log_activity(db, user, "email_change_requested", guard.mask_email(body.email))
    if token:
        email = mailer.verify_user_email(user.username, link(token))
        background.add_task(deliver, None, user.username, body.email, *email)
    return {"message": EMAIL_LINK_SENT}
