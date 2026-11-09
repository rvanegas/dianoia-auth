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
- **sessions**: a browser signed in here (sessions.py), by the SHA-256 of
  its cookie, which lets every client's sign-in skip the code.
- **consents**: what a person has let each client have, so a client is asked
  about once per scope, not at every sign-in.
- **passkeys**: a person's passkeys (passkeys.py), each its credential id,
  public key and signature count; the private half never leaves their device.
- **departures**: an account deleted here, one row per project still to be
  told (departures.py); the row is kept, done, as the record that it was.

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
CREATE TABLE IF NOT EXISTS sessions (
    sha TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    created_at REAL NOT NULL,
    seen_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user);
CREATE TABLE IF NOT EXISTS passkeys (
    credential_id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    used_at REAL
);
CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys (user);
CREATE TABLE IF NOT EXISTS consents (
    user TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at REAL NOT NULL,
    PRIMARY KEY (user, client_id)
);
CREATE TABLE IF NOT EXISTS departures (
    user TEXT NOT NULL,
    project TEXT NOT NULL,
    created_at REAL NOT NULL,
    tried_at REAL,
    done_at REAL,
    PRIMARY KEY (user, project)
);
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
