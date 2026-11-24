#!/usr/bin/env python3
"""Give every registered client the same redirects under a new domain, beside its old ones.

An operator task, for the move from rvanegas.co to twohands.co (2026-11-23):
each redirect on a host under the old domain gets its twin under the new one,
added and nothing removed, so a client's people can sign in from either name
during the overlap. The origins /me answers by CORS follow, since they are
the public clients' redirects. Run again, it adds nothing new. COMPATIBILITY:
after the overlap, `--remove` takes the old domain's redirects away (bar
those a client still needs, named with --keep).

    docker compose run --rm -T dianoia-auth python scripts/add_redirects.py rvanegas.co twohands.co --dry-run

Secrets, scopes, grants and consents are untouched.
"""

from __future__ import annotations

import argparse
from urllib.parse import urlparse, urlunparse

from dianoia_auth.provider import provider
from dianoia_auth.store import connect


def _under(host: str | None, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith("." + domain))


def twin(uri: str, old: str, new: str) -> str | None:
    """The same redirect under the new domain, if it is under the old one."""
    parts = urlparse(uri)
    if not _under(parts.hostname, old):
        return None
    host = parts.hostname[: -len(old)] + new
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urlunparse(parts._replace(netloc=netloc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("old", help="the domain moved from, e.g. rvanegas.co")
    parser.add_argument("new", help="the domain moved to, e.g. twohands.co")
    parser.add_argument("--remove", action="store_true", help="take the old domain's redirects away instead")
    parser.add_argument("--keep", action="append", default=[], help="with --remove: a client id whose old ones stay")
    parser.add_argument("--dry-run", action="store_true", help="say what would change, and change nothing")
    args = parser.parse_args(argv)
    with connect() as db:
        rows = db.execute("SELECT client_id, keeps_names FROM clients ORDER BY client_id").fetchall()
    changed = 0
    for client_id, keeps_names in rows:
        client = provider.client(client_id)
        uris = [str(u) for u in client.redirect_uris or []]
        if args.remove:
            if client_id in args.keep:
                continue
            kept = [u for u in uris if not _under(urlparse(u).hostname, args.old)]
            if kept == uris or not kept:
                continue
            for uri in sorted(set(uris) - set(kept)):
                print(f"{client_id}: - {uri}")
            result = kept
        else:
            added = [t for t in (twin(u, args.old, args.new) for u in uris) if t and t not in uris]
            if not added:
                continue
            for uri in added:
                print(f"{client_id}: + {uri}")
            result = uris + added
        changed += 1
        if not args.dry_run:
            provider.save_client(type(client).model_validate({**client.model_dump(), "redirect_uris": result}),
                                 keeps_names=bool(keeps_names))
    print(f"{changed} client{'s' if changed != 1 else ''} {'would change' if args.dry_run else 'changed'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
