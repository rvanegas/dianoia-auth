#!/usr/bin/env python3
"""Carries The Floor's display names here, once: `username<TAB>display name` lines on stdin.

    docker compose run --rm -T dianoia-auth python scripts/display_names.py < floor-display-names.tsv
    docker compose run --rm -T dianoia-auth python scripts/display_names.py --apply < floor-display-names.tsv

The Floor's `ts export-display-names` writes the input. Since 2026-11-09 a
person's display name is kept here (accounts.py) and The Floor sets it here
first; this brings the names chosen there before. A name already kept here
is kept, so running it again changes nothing, and a user name that is neither
an account nor a reservation here is skipped. Without --apply it says what it
would do and writes nothing.
"""

from __future__ import annotations

import argparse
import sys

from dianoia_auth import accounts


def main(argv: list[str] | None = None, lines=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="write, rather than say what would be written")
    args = parser.parse_args(argv)
    counts = {"set": 0, "kept": 0, "skipped": 0}
    for line in lines if lines is not None else sys.stdin:
        user, _, name = line.rstrip("\n").partition("\t")
        user = user.strip().lower()
        if not user or not name.strip():
            continue
        if accounts.display_name(user) is not None:
            counts["kept"] += 1
            continue
        try:
            checked = accounts.check_display_name(name)
            if args.apply:
                accounts.set_display_name(user, checked)
            elif not _named(user):
                raise accounts.InvalidDisplayName(f"{user} is not an account or a reservation")
        except accounts.InvalidDisplayName as exc:
            print(f"skipped {user}: {exc}")
            counts["skipped"] += 1
            continue
        print(f"{'set' if args.apply else 'would set'} {user}: {checked}")
        counts["set"] += 1
    print(f"{counts['set']} {'set' if args.apply else 'to set'}, {counts['kept']} kept, {counts['skipped']} skipped")
    return 0


def _named(user: str) -> bool:
    from dianoia_auth.store import connect
    with connect() as db:
        return any(db.execute(f"SELECT 1 FROM {table} WHERE user = ?", (user,)).fetchone()
                   for table in ("accounts", "reservations"))


if __name__ == "__main__":
    sys.exit(main())
