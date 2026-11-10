"""Handing a sign-in to a browser: an application signs its person in to a browser of their own.

The Floor opens noesis's web client in the person's own browser, an app of
its own, which shares no cookies with the sheet they signed in through; so
that browser knows nobody here, and noesis asked them to sign in again
(2026-11-10). With a handoff it does not:

- **The application asks for a code** (`POST /handoff`), proving two things
  at once: that it is the application, by its client id and secret, and that
  it acts for this person, by a person's access token issued to that same
  client. Neither alone is enough: the secret alone would sign in anybody,
  and a token alone, which a browser app holds, is fifteen minutes that a
  session would make thirty days.
- **The code is one use, a minute long, and names where it goes on to**,
  a public client's own origin (the browser apps that read /me) and nowhere
  else, so the link is never an open redirect and is worthless once used or
  read from a history a minute later.
- **Redeeming it (`GET /handoff`) makes the browser's session**, as a code
  sign-in would, and goes on to `next`, whose own sign-in then passes
  straight through. A browser already signed in as the same person just goes
  on; one signed in as somebody else is asked which, rather than switched
  silently.

Codes live a minute, in memory, as pending sign-ins do (provider.py).
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

CODE_TTL = 60


@dataclass(frozen=True)
class Handoff:
    user: str
    client_id: str
    next: str
    expires_at: float


_codes: dict[str, Handoff] = {}
_lock = threading.Lock()


def _sweep(now: float) -> None:
    for code, found in list(_codes.items()):
        if found.expires_at < now:
            del _codes[code]


def issue(user: str, client_id: str, next_url: str) -> str:
    """A new code for `user`, made by `client_id`, going on to `next_url`."""
    code = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _sweep(now)
        _codes[code] = Handoff(user, client_id, next_url, now + CODE_TTL)
    return code


def peek(code: str) -> Handoff | None:
    """The code's handoff, if it is live, left to be redeemed."""
    with _lock:
        found = _codes.get(code)
    return found if found is not None and found.expires_at >= time.time() else None


def redeem(code: str) -> Handoff | None:
    """The code's handoff, if it is live; it is used up either way."""
    with _lock:
        found = _codes.pop(code, None)
    return found if found is not None and found.expires_at >= time.time() else None
