"""Plain-text emails over SMTP with STARTTLS.

Any SMTP server works. Production uses Resend: SMTP_HOST=smtp.resend.com, port 587,
SMTP_USERNAME=resend and SMTP_PASSWORD=<API key>. In dev with no SMTP_HOST, each
email is printed to the console instead, so the whole flow can be tried locally.

Routes never call send() directly: they hand it to FastAPI's BackgroundTasks, so no
request waits on the mail server.
"""

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid

from backend.config import settings

SMTP_TIMEOUT = 10  # seconds, for connecting and for each SMTP command


class MailError(Exception):
    """Sending failed. The message is safe to store and show to admins: it names the
    kind of error only, never the password, the email body or a token."""


def send(to: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = settings.mail_from
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = make_msgid(domain="sentinellite.com")
    message.set_content(body)

    if not settings.smtp_host:
        if settings.is_prod:
            raise MailError("SMTP is not configured")
        # Headers plus the decoded body, not the raw MIME text: that is quoted-printable,
        # which splits long links and turns "=" into "=3D".
        print(
            "\n----- email (not sent: SMTP_HOST is empty) -----\n"
            f"From: {message['From']}\nTo: {message['To']}\nSubject: {message['Subject']}\n\n"
            f"{message.get_content()}-----",
            flush=True,
        )
        return

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    except smtplib.SMTPResponseException as error:
        # The server's own text can echo what we sent, so keep only the code.
        raise MailError(f"{type(error).__name__} (SMTP code {error.smtp_code})") from None
    except (smtplib.SMTPException, OSError) as error:
        raise MailError(type(error).__name__) from None


# --- The emails ---

SIGNATURE = "\n\n-- \nSentinel Lite\n{url}\n"


def _body(text: str) -> str:
    return text.strip() + SIGNATURE.format(url=settings.public_base_url)


def verify_request(username: str, link: str) -> tuple[str, str]:
    return "Confirm your email for Sentinel Lite", _body(f"""
Hello {username},

Someone (hopefully you) asked for a Sentinel Lite account with this email address.
To confirm it, open this link and press "Confirm my email":

{link}

The link works once and expires in 24 hours. After you confirm, an admin will review
the request and you'll get another email with their decision.

If this wasn't you, ignore this email and nothing will happen.
""")


def reviewed_by(display_name: str | None) -> str:
    """The last line of a decision email. Only the admin's display name is ever used:
    a username is half of a login, so it never goes in an email."""
    return f"Reviewed by {display_name or 'an administrator'}"


def approved(username: str, reviewer: str | None) -> tuple[str, str]:
    return "Your Sentinel Lite account is ready", _body(f"""
Hello {username},

Your account request was approved. Log in with the username {username} and the
password you chose:

{settings.public_base_url}/

{reviewed_by(reviewer)}
""")


def approved_generated(username: str, password: str, reviewer: str | None) -> tuple[str, str]:
    return "Your Sentinel Lite account is ready", _body(f"""
Hello {username},

Your account request was approved. Log in here:

{settings.public_base_url}/

Username:           {username}
Temporary password: {password}

You will be asked to choose your own password straight after logging in.
Delete this email once you have done that.

{reviewed_by(reviewer)}
""")


def rejected(username: str, reason: str, reviewer: str | None) -> tuple[str, str]:
    because = f"\nThe admin's reason:\n\n{reason}\n" if reason else ""
    return "Your Sentinel Lite account request", _body(f"""
Hello {username},

Sorry, your request for a Sentinel Lite account was not approved.
{because}
No account was created. You're welcome to send a new request later.

{reviewed_by(reviewer)}
""")


def verify_user_email(username: str, link: str) -> tuple[str, str]:
    return "Confirm your new email for Sentinel Lite", _body(f"""
Hello {username},

To use this email address for your Sentinel Lite account, open this link and press
"Confirm my email":

{link}

The link works once and expires in 24 hours. If you didn't ask for this, ignore this email.
""")


def email_changed(username: str, masked_new_email: str) -> tuple[str, str]:
    """Sent to the OLD address after a change. No link at all, not even the site address in
    the usual signature: a warning email with a link is what a phishing email looks like."""
    return "The email on your Sentinel Lite account was changed", f"""Hello {username},

The email on your Sentinel Lite account {username} was changed to {masked_new_email}.
If this wasn't you, contact an administrator.

--
Sentinel Lite
"""
