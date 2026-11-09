#!/usr/bin/env python3
"""Carry sign-in's data from noesis into auth.db, once, at the cut-over (2026-11-08).

An operator task. Reads noesis's data directory, mounted read-only, and
writes auth's; noesis's copy is dropped by noesis's own migration after.

- **Accounts**, **reservations** and the **mail counter** from accounts.db,
  as they are; plans, allowances, spend and speaker names stay noesis's.
- **Held names**: noesis's operator users (users.toml) and library
  directories that are nobody's account, so they are never given out.
- **Clients** from oauth.json, their marks turned into scopes: identity-only
  → `identity`; import → `noesis:read noesis:import`; any other →
  `noesis:read`; keeping names → `--keeps-names`; keeping libraries →
  `noesis:keep` by client_credentials. noesis's web client, built in there,
  becomes the public client `noesis-web` at `<noesis-url>/web/`.
- **Refresh tokens**, by their hashes, so nobody signs in again: a token's
  `import` becomes `noesis:import`, one with no scopes gets what its client
  may have, and every one but an identity-only client's keeps `noesis:read`,
  since each reached noesis's /mcp. Access tokens are not carried: noesis's
  own expire within their hour, and every client refreshes.

    ssh commons 'cd ~/auth && docker compose run --rm -T -v /srv/noesis:/noesis:ro auth \\
        python scripts/migrate_from_noesis.py /noesis --noesis-url https://noesis.rvanegas.co'

Without --apply it prints what it would carry and changes nothing.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import tomllib
from pathlib import Path

from mcp.shared.auth import OAuthClientInformationFull

from auth.provider import IDENTITY, NOESIS_API, NOESIS_IMPORT, NOESIS_READ, PERSON_SCOPES, provider
from auth.store import transaction

WEB_CLIENT_ID = "noesis-web"


def _scopes(raw: dict) -> tuple[list[str], list[str]]:
    """A noesis client's marks as (a person's scopes, its own)."""
    if raw.get("identity_only"):
        person = [IDENTITY]
    elif raw.get("imports"):
        person = [NOESIS_READ, NOESIS_IMPORT]
    else:
        person = [NOESIS_READ]
    return person, (["noesis:keep"] if raw.get("keeps_libraries") else [])


def plan(source: Path, noesis_url: str) -> dict:
    db = sqlite3.connect(f"file:{source / 'accounts.db'}?mode=ro", uri=True)
    try:
        accounts = db.execute("SELECT user, email, created_at, disabled FROM accounts").fetchall()
        reservations = db.execute("SELECT user, email, client, created_at FROM reservations").fetchall()
        sends = db.execute("SELECT key, at FROM sends").fetchall()
    finally:
        db.close()
    named = {a[0] for a in accounts} | {r[0] for r in reservations}
    held = {}
    users = source / "users.toml"
    if users.exists():
        for entry in tomllib.loads(users.read_text(encoding="utf-8")).get("tokens", []):
            if entry.get("user") and entry["user"] != "*" and entry["user"] not in named:
                held[entry["user"]] = "noesis operator user"
    libraries = source / "libraries"
    if libraries.is_dir():
        for path in sorted(libraries.iterdir()):
            if path.is_dir() and path.name not in named and path.name not in held:
                held[path.name] = "noesis library directory"
    oauth = json.loads((source / "oauth.json").read_text(encoding="utf-8")) if (source / "oauth.json").exists() \
        else {"clients": {}, "refresh": {}}
    clients = []
    for client_id, raw in oauth.get("clients", {}).items():
        person, own = _scopes(raw)
        info = {k: v for k, v in raw.items()
                if k not in ("identity_only", "imports", "keeps_names", "keeps_libraries")}
        grants = list(info.get("grant_types") or ["authorization_code", "refresh_token"])
        if own and "client_credentials" not in grants:
            grants.append("client_credentials")
        client = OAuthClientInformationFull.model_validate(
            {**info, "grant_types": grants, "scope": " ".join(person + own)})
        clients.append((client, bool(raw.get("keeps_names"))))
    clients.append((OAuthClientInformationFull(
        client_id=WEB_CLIENT_ID, client_name="noesis on the web",
        redirect_uris=[f"{noesis_url.rstrip('/')}/web/"], token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        scope=f"{NOESIS_API} {NOESIS_READ}"), False))
    allowed = {c.client_id: [s for s in (c.scope or "").split() if s in PERSON_SCOPES] for c, _ in clients}
    refresh = []
    for digest, entry in oauth.get("refresh", {}).items():
        if entry["client_id"] not in allowed:
            continue
        scopes = [NOESIS_IMPORT if s == "import" else s for s in entry.get("scopes") or []]
        scopes = [s for s in scopes if s in allowed[entry["client_id"]]] or allowed[entry["client_id"]]
        # Every token but an identity-only client's reached noesis's /mcp.
        if NOESIS_READ in allowed[entry["client_id"]] and NOESIS_READ not in scopes:
            scopes = [NOESIS_READ, *scopes]
        refresh.append((digest, entry["client_id"], entry["user"], " ".join(scopes),
                        entry.get("resource"), entry["expires_at"]))
    return {"accounts": accounts, "reservations": reservations, "sends": sends,
            "held": sorted(held.items()), "clients": clients, "refresh": refresh}


def apply(found: dict) -> None:
    for client, keeps_names in found["clients"]:
        provider.save_client(client, keeps_names=keeps_names)
    with transaction() as db:
        db.executemany("INSERT OR REPLACE INTO accounts (user, email, created_at, disabled) VALUES (?, ?, ?, ?)",
                       found["accounts"])
        db.executemany("INSERT OR REPLACE INTO reservations (user, email, client, created_at) VALUES (?, ?, ?, ?)",
                       found["reservations"])
        db.executemany("INSERT INTO sends (key, at) VALUES (?, ?)", found["sends"])
        db.executemany("INSERT OR REPLACE INTO held (user, why) VALUES (?, ?)", found["held"])
        db.executemany("INSERT OR REPLACE INTO refresh (sha, client_id, user, scopes, resource, expires_at) "
                       "VALUES (?, ?, ?, ?, ?, ?)", found["refresh"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="noesis's data directory")
    parser.add_argument("--noesis-url", required=True, help="where noesis's web client is")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    found = plan(args.source, args.noesis_url)
    print(f"{len(found['accounts'])} accounts, {len(found['reservations'])} reservations, "
          f"{len(found['refresh'])} refresh tokens")
    for user, why in found["held"]:
        print(f"hold    {user:<24} {why}")
    for client, keeps_names in found["clients"]:
        print(f"client  {client.client_id:<24} {client.scope}{'  keeps names' if keeps_names else ''}")
    if args.apply:
        apply(found)
        print("applied")
    else:
        print("nothing changed: --apply to carry it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
