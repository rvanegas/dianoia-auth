"""Sessions and consents: signing in once, for every client (Phase 2, SSO).

A **session** is a browser signed in here. Verifying an emailed code makes
one, kept in a cookie on `auth.rvanegas.co` alone (`HttpOnly`, `Secure`,
`SameSite=Lax`) and in auth.db by its hash. While it lasts, a client's
sign-in skips the code: The Floor, noesis, Roxana and claude.ai each send
the person to /authorize, and the page they land on already knows them.

- **It lasts thirty days from its last use**, renewed at most daily, and
  ends at once when the account is disabled, when the person signs out here
  (/logout, or /account), or when they sign out everywhere.
- **Signing out here ends the session alone.** Each application's own
  grant lasts until that application signs out or the person revokes it on
  /account: there is no back-channel logout.

A **consent** is what a person has let a client have. The first sign-in to a
client (by code, or with a session) says what it asks and stores the answer;
afterwards a session signs in to that client without a page, unless it asks
for a scope not yet granted, or for `prompt=consent`.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from dianoia_auth import accounts
from dianoia_auth.store import connect, sha

SESSION_TTL = 30 * 24 * 60 * 60
RENEW_AFTER = 24 * 60 * 60


@dataclass(frozen=True)
class Session:
    sha: str
    user: str
    created_at: float
    seen_at: float
    agent: str


def create(user: str, agent: str = "") -> str:
    """A new session for `user`; its token, for the cookie."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        db.execute("INSERT INTO sessions (sha, user, created_at, seen_at, expires_at, agent) VALUES (?, ?, ?, ?, ?, ?)",
                   (sha(token), user, now, now, now + SESSION_TTL, agent[:200]))
    return token


def current(token: str | None) -> Session | None:
    """The session a cookie names, if it is live and its account active; renewed when a day old."""
    if not token:
        return None
    now = time.time()
    with connect() as db:
        row = db.execute("SELECT sha, user, created_at, seen_at, expires_at, agent FROM sessions WHERE sha = ?",
                         (sha(token),)).fetchone()
        if row is None or row[4] < now:
            return None
        if now - row[3] > RENEW_AFTER:
            db.execute("UPDATE sessions SET seen_at = ?, expires_at = ? WHERE sha = ?", (now, now + SESSION_TTL, row[0]))
    if not accounts.is_active(row[1]):
        return None
    return Session(row[0], row[1], row[2], row[3], row[5])


def end(token: str | None) -> None:
    if token:
        with connect() as db:
            db.execute("DELETE FROM sessions WHERE sha = ?", (sha(token),))


def end_one(user: str, session_sha: str) -> None:
    """Ends one of a person's sessions, by its id on /account."""
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE sha = ? AND user = ?", (session_sha, user))


def of(user: str) -> list[Session]:
    with connect() as db:
        rows = db.execute("SELECT sha, user, created_at, seen_at, agent FROM sessions WHERE user = ? AND expires_at > ? "
                          "ORDER BY seen_at DESC", (user, time.time())).fetchall()
    return [Session(*row) for row in rows]


def everywhere(user: str) -> None:
    """Signs a person out everywhere: every session, and every application's grant."""
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE user = ?", (user,))
        db.execute("DELETE FROM refresh WHERE user = ?", (user,))
        db.execute("DELETE FROM consents WHERE user = ?", (user,))


# --- consents ----------------------------------------------------------------

def granted(user: str, client_id: str) -> set[str]:
    with connect() as db:
        row = db.execute("SELECT scopes FROM consents WHERE user = ? AND client_id = ?", (user, client_id)).fetchone()
    return set(row[0].split()) if row else set()


def covers(user: str, client_id: str, scopes: list[str]) -> bool:
    """Whether the person has already let this client have these scopes."""
    with connect() as db:
        row = db.execute("SELECT 1 FROM consents WHERE user = ? AND client_id = ?", (user, client_id)).fetchone()
    return row is not None and set(scopes) <= granted(user, client_id)


def grant(user: str, client_id: str, scopes: list[str]) -> None:
    held = granted(user, client_id) | set(scopes)
    with connect() as db:
        db.execute("INSERT INTO consents (user, client_id, scopes, granted_at) VALUES (?, ?, ?, ?) "
                   "ON CONFLICT (user, client_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at",
                   (user, client_id, " ".join(sorted(held)), time.time()))


def grants(user: str) -> list[tuple[str, float]]:
    """The clients a person has let in, and since when, newest first."""
    with connect() as db:
        rows = db.execute("SELECT client_id, granted_at FROM consents WHERE user = ? ORDER BY granted_at DESC",
                          (user,)).fetchall()
        held = {r[0] for r in db.execute("SELECT DISTINCT client_id FROM refresh WHERE user = ?", (user,))}
    found = {client_id: at for client_id, at in rows}
    for client_id in held - found.keys():
        found[client_id] = 0.0  # a grant carried from noesis, made before consents were kept
    return sorted(found.items(), key=lambda kv: -kv[1])


def revoke(user: str, client_id: str) -> None:
    """Takes back what a client was let have: its consent and every refresh token it holds for the person."""
    with connect() as db:
        db.execute("DELETE FROM consents WHERE user = ? AND client_id = ?", (user, client_id))
        db.execute("DELETE FROM refresh WHERE user = ? AND client_id = ?", (user, client_id))
