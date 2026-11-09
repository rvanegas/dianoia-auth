"""The register of people's names across applications: one user name per address.

Moved from noesis with sign-in (2026-11-08). An application with accounts of
its own (The Floor) asks here for the name of each person it signs up, so a
person is the same name everywhere and an address is one name throughout. The
Floor keeps the case its people type; the pair is the same name compared
without case.

- **A pair is an account's or a reservation's.** Somebody The Floor signed up
  who has never signed in here has a reservation: the address and the name are
  both taken, and nothing else exists. Their first sign-in makes the account
  under the reserved name (accounts.create_account).
- **A name chosen from now on** is accounts.USER_NAME_RE: lowercase letters,
  digits and _, four to thirty. Older names (with -, or shorter) stand.
- **Only a reservation changes.** An application may rename one, or move it to
  another address, while its person has no account here. **An account's name
  and address are fixed**: renaming one would have to reach every application
  that saved library ids or knows the person by name. The operator's
  scripts/rename_user.py is the exception, done by hand.
"""

from __future__ import annotations

import time

from auth import accounts
from auth.store import transaction

FIXED = "Your username and address are your account's, and cannot be changed once it exists."


class Taken(ValueError):
    """The name or the address is somebody else's, or is fixed."""


class Invalid(ValueError):
    """Not a user name given out here, or not an address."""


def _address(email: str) -> str:
    address = accounts.normalize_email(email)
    if address is None:
        raise Invalid("That is not an email address.")
    return address


def _check(user: str) -> str:
    name = user.strip().lstrip("@").lower()
    if not accounts.USER_NAME_RE.match(name):
        raise Invalid(f"A user name is {accounts.MIN_USER_NAME} to {accounts.MAX_USER_NAME} "
                      "lowercase letters, digits and underscores.")
    return name


def name_for(email: str, client: str, suggestions: list[str] | tuple[str, ...] = ()) -> tuple[str, bool]:
    """An address's name, and whether it is an account's; reserved now if it had none: the suggestions' first free, else the address's."""
    address = _address(email)
    with transaction() as db:
        row = db.execute("SELECT user FROM accounts WHERE email = ?", (address,)).fetchone()
        if row:
            return row[0], True
        row = db.execute("SELECT user FROM reservations WHERE email = ?", (address,)).fetchone()
        if row:
            return row[0], False
        stems = [s for s in (*map(accounts.user_stem, suggestions), accounts.user_stem(address)) if s]
        user = accounts.free_name(db, stems)
        db.execute("INSERT INTO reservations (user, email, client, created_at) VALUES (?, ?, ?, ?)",
                   (user, address, client, time.time()))
    return user, False


def choose(email: str, user: str, client: str) -> str:
    """Makes `user` the address's name: reserved if it has none, its reservation renamed if it has another."""
    address, name = _address(email), _check(user)
    with transaction() as db:
        if db.execute("SELECT 1 FROM accounts WHERE email = ?", (address,)).fetchone():
            raise Taken(FIXED)
        held = db.execute("SELECT user FROM reservations WHERE email = ?", (address,)).fetchone()
        if held and held[0] == name:
            return name
        if accounts.taken(db, name):
            raise Taken("That user name is taken.")
        if held:
            db.execute("UPDATE reservations SET user = ? WHERE email = ?", (name, address))
        else:
            db.execute("INSERT INTO reservations (user, email, client, created_at) VALUES (?, ?, ?, ?)",
                       (name, address, client, time.time()))
    return name


def move(email: str, new_email: str) -> None:
    """Moves a reservation to another address; an account's address is fixed."""
    address, target = _address(email), _address(new_email)
    if address == target:
        return
    with transaction() as db:
        if db.execute("SELECT 1 FROM accounts WHERE email = ?", (address,)).fetchone():
            raise Taken(FIXED)
        if (db.execute("SELECT 1 FROM accounts WHERE email = ?", (target,)).fetchone()
                or db.execute("SELECT 1 FROM reservations WHERE email = ?", (target,)).fetchone()):
            raise Taken("That address already has a username here, somebody else's.")
        db.execute("UPDATE reservations SET email = ? WHERE email = ?", (target, address))


def rename_account(old: str, new: str) -> str:
    """The operator's rename of an account (scripts/rename_user.py): the account and its grants.

    Nothing tells the applications: noesis's libraries and billing are renamed
    by its own scripts/rename_user.py, The Floor's username by hand.
    """
    new = _check(new)
    with transaction() as db:
        if accounts.taken(db, new):
            raise Taken("That user name is taken.")
        if not db.execute("SELECT 1 FROM accounts WHERE user = ?", (old,)).fetchone():
            raise Invalid(f"{old} is not an account")
        db.execute("UPDATE accounts SET user = ? WHERE user = ?", (new, old))
        db.execute("UPDATE refresh SET user = ? WHERE user = ?", (new, old))
    return new
