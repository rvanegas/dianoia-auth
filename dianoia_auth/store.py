"""Where auth keeps what it knows: one SQLite file, $AUTH_DATA_DIR/auth.db (mode 600).

- **accounts**: a person, by user name and address, and whether disabled.
- **reservations**: a name and an address held for somebody an application
  signed up who has not signed in yet (names.py); their first sign-in takes it.
- **held**: names in use elsewhere that are nobody's account here, such as
  noesis's operator users and its library directories, so they are never
  given out (filled by the migration, and by scripts/accounts.py hold).
- **sends**: the sign-in mail counter (accounts.allow_send).
- **clients**: each OAuth client, as the SDK describes it, with the scopes the
  operator allows it (provider.py).
- **refresh**: refresh tokens, by the SHA-256 of the token alone.

Codes and pending sign-ins live minutes, in memory (provider.py); access
tokens are signed, not stored (tokens.py).
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    user TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reservations (
    user TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    client TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS held (user TEXT PRIMARY KEY, why TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sends (key TEXT NOT NULL, at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS sends_key_at ON sends (key, at);
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    info TEXT NOT NULL,
    keeps_names INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS refresh (
    sha TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS refresh_user ON refresh (user);
"""


def data_dir() -> Path:
    return Path(os.environ.get("AUTH_DATA_DIR", "/data"))


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@contextmanager
def connect():
    path = data_dir() / "auth.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    if new:
        path.chmod(0o600)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(_SCHEMA)
        yield db
    finally:
        db.close()


@contextmanager
def transaction():
    """A connection inside BEGIN IMMEDIATE: committed on success, rolled back otherwise."""
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
