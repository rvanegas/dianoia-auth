"""Sign-in codes by email.

Sent through SES's SMTP interface, on the `rvanegas.co` identity, through a
configuration set of its own, `dianoia-auth`, so its bounces and complaints are told apart
(rvanegas-site's PROJECTS.md). Configured from the environment, the box's
~/dianoia-auth/.env: AUTH_SMTP_HOST, AUTH_SMTP_PORT (587), AUTH_SMTP_USER,
AUTH_SMTP_PASSWORD, AUTH_MAIL_FROM, AUTH_SES_CONFIGURATION_SET.

Without AUTH_SMTP_HOST nothing is sent, and sign-in says mail is unavailable;
AUTH_MAIL_LOG=1 prints the code to stderr instead, for a local server.
"""

from __future__ import annotations

import os
import smtplib
import sys
from email.message import EmailMessage


class MailUnavailable(RuntimeError):
    pass


def send_code(to: str, code: str, client_name: str) -> None:
    env = os.environ.get
    host = env("AUTH_SMTP_HOST")
    if not host:
        if env("AUTH_MAIL_LOG") == "1":
            print(f"sign-in code for {to}: {code}", file=sys.stderr, flush=True)
            return
        raise MailUnavailable("sign-in mail is not configured on this server")
    message = EmailMessage()
    message["From"] = env("AUTH_MAIL_FROM", "rvanegas.co <sign-in@rvanegas.co>")
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
