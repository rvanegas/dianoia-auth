#!/usr/bin/env python3
"""Register an application as an OAuth client of auth: its redirects, and the scopes it may have.

An operator task. Self-registration is open only to claude.ai's callbacks and
to localhost (provider.allowed_redirect), and gives `noesis:read` alone; every
other application is registered here. Its client id and secret are printed
once, as `KEY=value` lines, for the application's own configuration.

    docker compose run --rm -T auth python scripts/add_client.py thefloor --name "The Floor" \\
        --redirect https://thefloor.rvanegas.co/noesis/callback --scope "noesis:read noesis:import" \\
        --credentials noesis:keep --keeps-names

- `--scope`: what a person's grant to it may carry (provider.PERSON_SCOPES).
- `--credentials`: what its own tokens may carry (provider.APPLICATION_SCOPES),
  by the client_credentials grant; needs a secret.
- `--keeps-names`: it calls the register of names (/names) with its id and secret.
- `--public`: a browser app with no server of its own (Roxana, noesis's web
  client): PKCE and no secret, so only its id is printed; it may name several
  redirects, a localhost one for development among them. Its redirects'
  origins are the ones /me answers by CORS.
- `--no-redirect`: a service that only takes its own tokens (noesis, asking
  The Floor who belongs).

Registering the same id again replaces it, with a new secret: the old one
stops working, and grants already made stay.
"""

from __future__ import annotations

import argparse
import re
import secrets
import time
from urllib.parse import urlparse

from mcp.shared.auth import OAuthClientInformationFull

from auth.provider import APPLICATION_SCOPES, PERSON_SCOPES, provider


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("client_id", help="lowercase letters, digits and -")
    parser.add_argument("--name", required=True, help="what the sign-in page calls it")
    parser.add_argument("--redirect", action="append", default=[],
                        help="its callback, https; only a --public client may name several, or localhost")
    parser.add_argument("--no-redirect", action="store_true", help="no person signs in to it")
    parser.add_argument("--scope", default="", help="space-separated: what a person's grant may carry")
    parser.add_argument("--credentials", default="", help="space-separated: what its own tokens may carry")
    parser.add_argument("--keeps-names", action="store_true", help="it calls /names")
    parser.add_argument("--public", action="store_true", help="no secret: a browser app")
    parser.add_argument("--prefix", default="AUTH", help="the printed lines' prefix: <PREFIX>_CLIENT_ID")
    args = parser.parse_args(argv)
    person, own = args.scope.split(), args.credentials.split()
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", args.client_id):
        raise SystemExit(f"✗ not a client id: {args.client_id!r}")
    if bad := [s for s in person if s not in PERSON_SCOPES] + [s for s in own if s not in APPLICATION_SCOPES]:
        raise SystemExit(f"✗ not a scope it may have: {' '.join(bad)}")
    if args.public and (own or args.keeps_names):
        raise SystemExit("✗ a public client has no secret, so no tokens or names of its own")
    if bool(args.redirect) == args.no_redirect:
        raise SystemExit("✗ name its redirects, or say --no-redirect")
    if args.no_redirect and person:
        raise SystemExit("✗ nobody signs in to a client with no redirect")
    if len(args.redirect) > 1 and not args.public:
        raise SystemExit("✗ a client with a secret has one redirect")
    for uri in args.redirect:
        redirect = urlparse(uri)
        local = args.public and redirect.scheme == "http" and redirect.hostname in ("localhost", "127.0.0.1")
        if not (redirect.scheme == "https" and redirect.hostname) and not local:
            raise SystemExit(f"✗ the redirect must be an https URL: {uri!r}")
    secret = None if args.public else secrets.token_urlsafe(32)
    grants = (["authorization_code", "refresh_token"] if args.redirect else []) + \
        (["client_credentials"] if own else [])
    client = OAuthClientInformationFull(
        client_id=args.client_id,
        client_secret=secret,
        client_id_issued_at=int(time.time()),
        client_name=args.name,
        redirect_uris=args.redirect or None,
        token_endpoint_auth_method="none" if args.public else "client_secret_post",
        grant_types=grants or ["client_credentials"],
        response_types=["code"],
        scope=" ".join(person + own) or None,
    )
    provider.save_client(client, keeps_names=args.keeps_names)
    print(f"{args.prefix}_CLIENT_ID={args.client_id}")
    if secret:
        print(f"{args.prefix}_CLIENT_SECRET={secret}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
