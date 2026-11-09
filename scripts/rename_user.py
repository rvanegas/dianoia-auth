#!/usr/bin/env python3
"""Rename an account, and its grants with it: the operator's exception to fixed names (names.py).

Nothing else is told. Rename the person at noesis with its own
scripts/rename_user.py (libraries, billing, speaker names), and at The Floor
by hand. Tokens already out name the old user until they expire, within a
quarter hour.

    docker compose run --rm -T dianoia-auth python scripts/rename_user.py old_name new_name
"""

from __future__ import annotations

import argparse

from dianoia_auth import names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("old")
    parser.add_argument("new")
    args = parser.parse_args(argv)
    try:
        new = names.rename_account(args.old, args.new)
    except (names.Taken, names.Invalid) as exc:
        raise SystemExit(f"✗ {exc}") from None
    print(f"{args.old} is now {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
