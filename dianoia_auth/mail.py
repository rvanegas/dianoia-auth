"""Sign-in codes by email.

Sent through SES's SMTP interface, on the `twohands.co` identity (and
`rvanegas.co`'s during the overlap), through a configuration set of its own,
`dianoia-auth`, so its bounces and complaints are told apart (rvanegas-site's
PROJECTS.md). Configured from the environment, the box's ~/dianoia-auth/.env:
AUTH_SMTP_HOST, AUTH_SMTP_PORT (587), AUTH_SMTP_USER, AUTH_SMTP_PASSWORD,
AUTH_MAIL_FROM, AUTH_SES_CONFIGURATION_SET.

**The sender is the domain of the host asked** (`sender`), so the code and
the page it is typed into name one domain: AUTH_MAIL_FROM at AUTH_PUBLIC_URL,
and `sign-in@<domain>` at another of the issuers (tokens.py). COMPATIBILITY
for the overlap; it goes with AUTH_ALSO_URLS.

Without AUTH_SMTP_HOST nothing is sent, and sign-in says mail is unavailable;
AUTH_MAIL_LOG=1 prints the code to stderr instead, for a local server.
"""

from __future__ import annotations

import os
import smtplib
import sys
from email.message import EmailMessage
from urllib.parse import urlparse

from dianoia_auth import tokens


class MailUnavailable(RuntimeError):
    pass


def _domain(url: str) -> str:
    return (urlparse(url).hostname or "localhost").removeprefix("auth.")


def sender() -> str:
    """Who the code is from: AUTH_MAIL_FROM as the issuer itself, else the domain of the issuer asked."""
    issuer = tokens.issuer()
    configured = os.environ.get("AUTH_MAIL_FROM")
    if configured and issuer == tokens.primary():
        return configured
    domain = _domain(issuer)
    return f"{domain} <sign-in@{domain}>"


def send_code(to: str, code: str, client_name: str) -> None:
    env = os.environ.get
    host = env("AUTH_SMTP_HOST")
    if not host:
        if env("AUTH_MAIL_LOG") == "1":
            print(f"sign-in code for {to}: {code}", file=sys.stderr, flush=True)
            return
        raise MailUnavailable("sign-in mail is not configured on this server")
    message = EmailMessage()
    message["From"] = sender()
    message["To"] = to
    message["Subject"] = f"Your sign-in code: {code}"
    message["X-SES-CONFIGURATION-SET"] = env("AUTH_SES_CONFIGURATION_SET", "dianoia-auth")
    message.set_content(
        f"Your code to sign in is {code}.\n\n"
        f"{client_name} asked for it. It works for ten minutes, once.\n\n"
        "If you did not ask to sign in, ignore this message: nothing happens without the code.\n"
    )
    try:
        with smtplib.SMTP(host, int(env("AUTH_SMTP_PORT", "587")), timeout=20) as smtp:
            smtp.starttls()
            smtp.login(env("AUTH_SMTP_USER", ""), env("AUTH_SMTP_PASSWORD", ""))
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailUnavailable(f"the sign-in mail could not be sent: {exc}") from exc
