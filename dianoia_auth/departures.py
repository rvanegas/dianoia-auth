"""Telling each project that an account is gone (2026-11-09).

A person deletes their account on /account (accounts.delete). Each project
keeps something of theirs under their user name: noesis their libraries,
plan and spend, The Floor its own account. Each is told by
`DELETE <project>/users/<user>`, and deletes what it holds in its own way:
noesis marks the libraries at once and removes them thirty days later, The
Floor deletes its account as its own Settings would. Roxana holds nothing
that is anybody's.

- **The call carries a token signed here, as auth itself**: `sub` and
  `client_id` are `dianoia-auth`, its one scope `<project>:erase`, which
  names the project (its audience is auth's own, as every token The Floor
  checks must be). No client is ever granted an `:erase` scope
  (provider.py's scope lists do not name one), so only this module makes
  such a token, and each project checks it against the JWKS it already
  reads. No secret is shared.
- **Every project answers 204**, whether or not it knew the person, so a
  call can be made again.
- **A failed call is tried again**: the deletion records a row per project
  (`departures` in auth.db), tried at once and then hourly by the server
  (`retry_forever`) until it is done; `scripts/accounts.py departures` lists
  any still owed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from dianoia_auth import tokens
from dianoia_auth.store import connect

AUTH = "dianoia-auth"
PROJECTS = {"noesis": "https://noesis.rvanegas.co", "thefloor": "https://thefloor.rvanegas.co"}
RETRY_SECONDS = 60 * 60
TIMEOUT_SECONDS = 15

log = logging.getLogger(__name__)


def projects() -> dict[str, str]:
    """Each project told of a deletion, by name, at its public URL (AUTH_PROJECT_URLS, as JSON, overrides)."""
    configured = os.environ.get("AUTH_PROJECT_URLS")
    return json.loads(configured) if configured else dict(PROJECTS)


def scope(project: str) -> str:
    return f"{project}:erase"


def owed() -> list[tuple[str, str, float, float | None]]:
    """(user, project, created_at, tried_at) of each call not yet answered."""
    with connect() as db:
        return db.execute("SELECT user, project, created_at, tried_at FROM departures WHERE done_at IS NULL "
                          "ORDER BY created_at").fetchall()


def _call(url: str, project: str, user: str) -> bool:
    token, _ = tokens.issue(AUTH, AUTH, [scope(project)])
    request = urllib.request.Request(f"{url.rstrip('/')}/users/{urllib.parse.quote(user, safe='')}",
                                     method="DELETE", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError) as exc:
        log.warning("departures: %s did not take %s's deletion: %s", project, user, exc)
        return False


def tell(user: str | None = None) -> int:
    """Makes each call owed (one person's, or everybody's); how many are still owed after."""
    urls = projects()
    left = 0
    for who, project, _, _ in owed():
        if user is not None and who != user:
            continue
        url = urls.get(project)
        done = url is not None and _call(url, project, who)
        now = time.time()
        with connect() as db:
            db.execute("UPDATE departures SET tried_at = ?, done_at = ? WHERE user = ? AND project = ?",
                       (now, now if done else None, who, project))
        left += not done
    return left


async def retry_forever() -> None:
    """The server's: every call owed, at start and then hourly."""
    while True:
        try:
            await asyncio.to_thread(tell)
        except Exception:
            log.exception("departures: retrying failed")
        await asyncio.sleep(RETRY_SECONDS)
