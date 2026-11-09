"""The people who sign in, by emailed code (moved from noesis, 2026-11-08).

Sign-up is open: the first sign-in with an address makes its account, under
the name reserved for it (names.py) or one derived from the address. What an
account may do in each application is that application's: noesis keeps its
plans and allowances, The Floor its own settings. Here an account is a user
name, an address, whether it is disabled, and the display name it is shown
by in every application (since 2026-11-09); a disabled account's refresh
tokens and sessions stop working at once, and its access tokens within their
quarter hour (tokens.py). A person deletes their own account (`delete`, from
/account), and each project is told (departures.py).
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass

from dianoia_auth.store import connect, transaction

# Sign-in mail: (key prefix, window in seconds, most sends in it).
SEND_LIMITS = (("email", 60 * 60, 5), ("ip", 60 * 60, 10), ("all", 24 * 60 * 60, 300))

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# A user name chosen or derived since 2026-11-02: what The Floor's usernames
# are, compared without case, so one name can be a person's in every
# application. Older names (with -, or shorter) stand until renamed.
MIN_USER_NAME = 4
MAX_USER_NAME = 30
USER_NAME_RE = re.compile(rf"^[a-z0-9_]{{{MIN_USER_NAME},{MAX_USER_NAME}}}$")
# Any name an account may have had before: an operator's link may use one.
OLD_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
# How many derived names are tried before one is given up on.
NAME_TRIES = 1000
# A display name: any words a person goes by, one line, this long at most.
MAX_DISPLAY_NAME = 60


@dataclass(frozen=True)
class Account:
    user: str
    email: str
    created_at: float
    disabled: bool


_COLUMNS = "user, email, created_at, disabled"


def _account(row) -> Account | None:
    if row is None:
        return None
    user, email, created_at, disabled = row
    return Account(user, email, created_at, bool(disabled))


def normalize_email(value: str) -> str | None:
    email = value.strip().lower()
    return email if len(email) <= 254 and _EMAIL_RE.match(email) else None


def account_for_email(email: str) -> Account | None:
    with connect() as db:
        return _account(db.execute(f"SELECT {_COLUMNS} FROM accounts WHERE email = ?", (email,)).fetchone())


def account(user: str) -> Account | None:
    with connect() as db:
        return _account(db.execute(f"SELECT {_COLUMNS} FROM accounts WHERE user = ?", (user,)).fetchone())


def accounts() -> list[Account]:
    with connect() as db:
        return [_account(r) for r in db.execute(f"SELECT {_COLUMNS} FROM accounts ORDER BY created_at")]


def taken(db: sqlite3.Connection, user: str) -> bool:
    """A user name in use: an account's, a reservation's, or held for use elsewhere."""
    return any(db.execute(f"SELECT 1 FROM {table} WHERE user = ?", (user,)).fetchone()
               for table in ("accounts", "reservations", "held"))


def user_stem(text: str) -> str | None:
    """A user name's start from an address's local part or a suggested name; None when nothing is left."""
    local = text.split("@", 1)[0].split("+", 1)[0].lower()
    stem = re.sub(r"[^a-z0-9_]+", "_", local).strip("_")[:MAX_USER_NAME - 4].strip("_")
    return stem or None


def candidates(stem: str):
    """The names a stem offers, best first: itself when long enough, then numbered, as The Floor numbers."""
    for n in range(1, NAME_TRIES + 1):
        if n == 1 and len(stem) >= MIN_USER_NAME:
            yield stem
        elif n > 1 or len(stem) < MIN_USER_NAME:
            yield f"{stem}{n:0{max(1, MIN_USER_NAME - len(stem))}d}"


def free_name(db: sqlite3.Connection, stems) -> str:
    """The first free name the stems offer, in their order; "user…" when none is left."""
    for stem in [*stems, "user"]:
        for name in candidates(stem):
            if not taken(db, name):
                return name
    raise RuntimeError("no free user name")


def reservation_for_email(email: str) -> tuple[str, str] | None:
    """The name held for an address with no account yet, and the application that holds it."""
    with connect() as db:
        return db.execute("SELECT user, client FROM reservations WHERE email = ?", (email,)).fetchone()


def create_account(email: str) -> Account:
    """The account for an address, made now if it has none: under its reserved name, or one made unique from it."""
    with transaction() as db:
        existing = db.execute(f"SELECT {_COLUMNS} FROM accounts WHERE email = ?", (email,)).fetchone()
        if existing:
            return _account(existing)
        held = db.execute("SELECT user FROM reservations WHERE email = ?", (email,)).fetchone()
        if held:
            user = held[0]
            db.execute("DELETE FROM reservations WHERE email = ?", (email,))
        else:
            user = free_name(db, [s for s in [user_stem(email)] if s])
        now = time.time()
        db.execute("INSERT INTO accounts (user, email, created_at) VALUES (?, ?, ?)", (user, email, now))
    return Account(user, email, now, False)


def link(email: str, user: str) -> Account:
    """An account under a name held for use elsewhere (an operator's user at noesis): the operator's."""
    address = normalize_email(email)
    if address is None or not OLD_NAME_RE.match(user):
        raise ValueError(f"not an address and a user name: {email!r}, {user!r}")
    with transaction() as db:
        held = db.execute("SELECT 1 FROM reservations WHERE (user = ?) != (email = ?) AND (user = ? OR email = ?)",
                          (user, address, user, address)).fetchone()
        if held:
            raise ValueError(f"{user} or {address} is reserved for another")
        db.execute("DELETE FROM reservations WHERE user = ? AND email = ?", (user, address))
        db.execute("DELETE FROM held WHERE user = ?", (user,))
        db.execute("INSERT INTO accounts (user, email, created_at) VALUES (?, ?, ?)", (user, address, time.time()))
    return account(user)


def hold(user: str, why: str) -> None:
    """Keeps a name from being given out, since something elsewhere is called by it."""
    with connect() as db:
        db.execute("INSERT INTO held (user, why) VALUES (?, ?) ON CONFLICT (user) DO UPDATE SET why = excluded.why",
                   (user, why))


def delete(user: str) -> None:
    """A person's own deletion of their account (/account/delete): everything kept
    here for them, at once, and each project owed word of it (departures.py).
    The name stays held, so it is never given to somebody else; the address is
    free, and signing in with it again makes a new account under a new name."""
    from dianoia_auth import departures
    now = time.time()
    with transaction() as db:
        found = db.execute("SELECT email FROM accounts WHERE user = ?", (user,)).fetchone()
        if found is None:
            raise ValueError(f"no account {user!r}")
        db.execute("DELETE FROM reservations WHERE user = ? OR email = ?", (user, found[0]))
        for table in ("accounts", "refresh", "sessions", "passkeys", "consents", "display_names"):
            db.execute(f"DELETE FROM {table} WHERE user = ?", (user,))
        db.execute("INSERT INTO held (user, why) VALUES (?, ?) ON CONFLICT (user) DO UPDATE SET why = excluded.why",
                   (user, f"deleted by its person, {time.strftime('%Y-%m-%d', time.gmtime(now))}"))
        for project in departures.projects():
            db.execute("INSERT OR REPLACE INTO departures (user, project, created_at) VALUES (?, ?, ?)",
                       (user, project, now))


def set_disabled(user: str, disabled: bool) -> None:
    with connect() as db:
        if db.execute("UPDATE accounts SET disabled = ? WHERE user = ?", (int(disabled), user)).rowcount != 1:
            raise ValueError(f"no account {user!r}")


def is_active(user: str) -> bool:
    found = account(user)
    return found is not None and not found.disabled


def allow_send(email: str, ip: str) -> bool:
    """Whether a code may go to this address from this client now; if so, counted."""
    now = time.time()
    keys = {"email": f"email:{email}", "ip": f"ip:{ip}", "all": "all"}
    with transaction() as db:
        db.execute("DELETE FROM sends WHERE at < ?", (now - max(w for _, w, _ in SEND_LIMITS),))
        for kind, window, most in SEND_LIMITS:
            (count,) = db.execute("SELECT COUNT(*) FROM sends WHERE key = ? AND at > ?",
                                  (keys[kind], now - window)).fetchone()
            if count >= most:
                return False
        db.executemany("INSERT INTO sends (key, at) VALUES (?, ?)", [(k, now) for k in keys.values()])
    return True


class InvalidDisplayName(ValueError):
    pass


def check_display_name(value: str) -> str:
    """A display name as kept: one line, trimmed, not too long; empty clears it."""
    name = " ".join(value.split())
    if len(name) > MAX_DISPLAY_NAME:
        raise InvalidDisplayName(f"A display name is at most {MAX_DISPLAY_NAME} characters.")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise InvalidDisplayName("A display name cannot hold control characters.")
    return name


def display_names(users: list[str]) -> dict[str, str | None]:
    """Each user's display name, None where they have none."""
    found: dict[str, str | None] = dict.fromkeys(users)
    with connect() as db:
        for user, name in db.execute(
                f"SELECT user, name FROM display_names WHERE user IN ({','.join('?' * len(users))})", users):
            found[user] = name
    return found


def display_name(user: str) -> str | None:
    return display_names([user])[user]


def set_display_name(user: str, value: str) -> str | None:
    """Sets the name an account or a reservation is shown by; empty clears it."""
    name = check_display_name(value)
    with transaction() as db:
        if not any(db.execute(f"SELECT 1 FROM {table} WHERE user = ?", (user,)).fetchone()
                   for table in ("accounts", "reservations")):
            raise InvalidDisplayName(f"{user} is not an account or a reservation")
        if name:
            db.execute("INSERT INTO display_names (user, name, set_at) VALUES (?, ?, ?) "
                       "ON CONFLICT (user) DO UPDATE SET name = excluded.name, set_at = excluded.set_at",
                       (user, name, time.time()))
        else:
            db.execute("DELETE FROM display_names WHERE user = ?", (user,))
    return name or None
