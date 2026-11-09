#!/usr/bin/env python3
"""The operator's view of the accounts: list them, link or hold a name, disable or enable one.

    docker compose run --rm -T auth python scripts/accounts.py list
    docker compose run --rm -T auth python scripts/accounts.py link ann@example.com ann
    docker compose run --rm -T auth python scripts/accounts.py hold rodvandur "noesis operator user"
    docker compose run --rm -T auth python scripts/accounts.py disable ann

Disabling refuses the account's refresh tokens at once and its access tokens
within their quarter hour (tokens.py). What an account may spend at noesis is
noesis's (its scripts/accounts.py).
"""

from __future__ import annotations

import argparse
import time

from auth import accounts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="every account")
    link = sub.add_parser("link", help="an account under a name held for use elsewhere")
    link.add_argument("email")
    link.add_argument("user")
    hold = sub.add_parser("hold", help="keep a name from being given out")
    hold.add_argument("user")
    hold.add_argument("why")
    for name in ("disable", "enable"):
        sub.add_parser(name).add_argument("user")
    args = parser.parse_args(argv)
    if args.command == "list":
        for found in accounts.accounts():
            created = time.strftime("%Y-%m-%d", time.gmtime(found.created_at))
            print(f"{found.user:<24} {found.email:<36} {created}{'  disabled' if found.disabled else ''}")
    elif args.command == "link":
        found = accounts.link(args.email, args.user)
        print(f"{found.user} is {found.email}")
    elif args.command == "hold":
        accounts.hold(args.user, args.why)
        print(f"{args.user} is held: {args.why}")
    else:
        accounts.set_disabled(args.user, args.command == "disable")
        print(f"{args.user} {args.command}d")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
