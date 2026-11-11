#!/usr/bin/env python3
"""Change what a registered client may have, keeping its id, secret and redirects.

An operator task. add_client.py replaces a registration whole, with a new
secret, which would leave every grant an application sealed with the old one
unopened (The Floor seals its people's refresh tokens with a key derived from
its secret); this changes the scopes alone, and whether it may vouch (add_client.py `--vouches`). Grants already made keep the
scopes they were made with until their person signs in again.

    docker compose run --rm -T dianoia-auth python scripts/client_scopes.py thefloor \\
        --scope "identity noesis:read noesis:import" --credentials noesis:keep --vouches
"""

from __future__ import annotations

import argparse

from dianoia_auth.provider import APPLICATION_SCOPES, PERSON_SCOPES, VOUCHED, provider
from dianoia_auth.store import connect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("client_id")
    parser.add_argument("--scope", default="", help="space-separated: what a person's grant may carry")
    parser.add_argument("--credentials", default="", help="space-separated: what its own tokens may carry")
    parser.add_argument("--vouches", action="store_true", help="it may vouch for its person's address")
    args = parser.parse_args(argv)
    person, own = args.scope.split(), args.credentials.split()
    if bad := [s for s in person if s not in PERSON_SCOPES] + [s for s in own if s not in APPLICATION_SCOPES]:
        raise SystemExit(f"✗ not a scope it may have: {' '.join(bad)}")
    client = provider.client(args.client_id)
    if client is None:
        raise SystemExit(f"✗ no registered client {args.client_id!r}")
    if (own or args.vouches) and not client.client_secret:
        raise SystemExit("✗ a public client has no secret, so no tokens or vouching of its own")
    if args.vouches and not person:
        raise SystemExit("✗ vouching grants a person's scopes: name them with --scope")
    grants = [g for g in client.grant_types if g not in ("client_credentials", VOUCHED)] + \
        (["client_credentials"] if own else []) + ([VOUCHED] if args.vouches else [])
    with connect() as db:
        keeps = db.execute("SELECT keeps_names FROM clients WHERE client_id = ?", (args.client_id,)).fetchone()[0]
    provider.save_client(client.model_copy(update={"scope": " ".join(person + own) or None, "grant_types": grants}),
                         keeps_names=bool(keeps))
    print(f"{args.client_id}: {' '.join(person + own) or 'nothing'}{', vouches' if args.vouches else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
