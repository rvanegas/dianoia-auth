@~/src/technosophia/WORKING.md

# Working on dianoia-auth

**This file is capped at technosophia's 20,000 bytes**, which `ts instructions check` measures in the tests.

## What this is

**dianoia-auth** is the one sign-in for the projects coordinated in `~/src/rvanegas-site`: The Floor, noesis, dianoia and Roxana. *Dianoia* names the whole suite as well as its reasoning service, and this is the suite's sign-in, so its repository, package (`dianoia_auth`) and command carry the name while its host stays `auth.rvanegas.co`; the other projects call it *auth*. It is an OAuth authorization server, moved out of noesis on 2026-11-08 (rvanegas-site `planning/task/one-sign-in-for-every-project-at-auth-rvanegas-co.md`, which is the plan and its order: the move, then SSO, then passkeys). People sign in by an emailed code; **there are no passwords**, by decision.

Shared conventions, hosting, and the APIs between this project and its siblings are coordinated in `~/src/rvanegas-site` (`CLAUDE.md` there). Read `PROJECTS.md` § *Shared rules* and § *Calls between projects* before changing config, deploy, hostnames, credentials, or any call to or from another project, and record such a change there.

## Practices

technosophia's (`~/src/technosophia`), through `WORKING.md` above. No compatibility code, but **every project is a client here**: a change to what a token says, a route, or a scope's meaning is a change to their contract, made with them, and recorded in rvanegas-site's *Calls between projects*.

`planning/` is laid out as technosophia's `PLANNING.md` says.

## Commands

```bash
python -m pytest tests/                 # the suite; ts deploy runs it first
dianoia-auth --port 8002                # serve, after pip install -e .
```

## Architecture

- **`server.py`**: the FastAPI app. `/healthz`; the MCP SDK's OAuth routes (`create_auth_routes`: metadata, `/authorize`, `/token`, `/register`, `/revoke`), with `/token` also taking `client_credentials`, which the SDK does not (`_with_client_credentials`); `/.well-known/jwks.json`; `/login`, the emailed-code page `/authorize` sends people to; `GET /me` (who a token's person is; CORS for public clients' origins alone); `/names`, the register.
- **`sessions.py`**: signing in once, for every client (SSO). A verified code makes a session, a `__Host-session` cookie on `auth.rvanegas.co` alone (`HttpOnly`, `Secure`, `Lax`), kept by its hash, thirty days from last use, ended by disabling the account; with it `/login` finishes at once, asking only a client's first time what it may have (**consents**, per person and client). `prompt=login|consent|none` is honoured (the SDK drops it; `_with_prompt` passes it on). `/logout` ends the session alone, returning to the client's own origin; `/account` lists the apps let in (each removable, which ends its grant) and the browsers signed in, and signs out everywhere. No back-channel logout.
- **`provider.py`**: the SDK's provider interface. Clients, the sign-in, codes, refresh. **Scopes say what a token reaches**: a person's grant carries `PERSON_SCOPES` (`identity`, `noesis:read`, `noesis:import`, `noesis:api`), an application's own token `APPLICATION_SCOPES` (`noesis:keep`, `thefloor:members`), never the other way. The operator sets what each client may have; self-registration (claude.ai, localhost redirects only) gets `noesis:read`.
- **`tokens.py`**: access tokens are EdDSA JWTs, fifteen minutes, verified by resource servers against the JWKS without calling here; so disabling an account reaches them within that time, while refresh stops at once. The key is `$AUTH_DATA_DIR/signing-key.pem`, made on first use; rotation keeps `signing-key.old.pem` published until its tokens expire.
- **`accounts.py`**: an account is a user name, an address, and whether disabled; the first sign-in makes it. User names derive from the address (`USER_NAME_RE`, numbered as The Floor numbers), never one an account, a reservation or a held name has. The mail counter (`allow_send`).
- **`names.py`**: the register of names across applications: one name per address, reserved by an application (The Floor) before its person signs in here. An account's name and address are fixed but for the operator's `scripts/rename_user.py`.
- **`store.py`**: one SQLite file, `$AUTH_DATA_DIR/auth.db` (mode 600): accounts, reservations, held names, sends, clients, refresh tokens (by hash).
- **`mail.py`**: codes by SES SMTP (`AUTH_SMTP_*`; `AUTH_MAIL_LOG=1` prints them, for a local server).
- **`scripts/`**: the operator's. `add_client.py` (scopes, `--credentials`, `--keeps-names`, `--public`), `accounts.py` (list, link, hold, disable), `rename_user.py`, `migrate_from_noesis.py` (once, at the cut-over).

What stays with each application: noesis keeps plans, allowances, spend and speaker names, its minted tokens and its library-confined tokens; The Floor its own accounts' settings.

## Server

On the `commons` box: `Dockerfile` / `docker-compose.yml`, `python:3.13-slim`, on `127.0.0.1:8002`, as uid 1000, with `/srv/dianoia-auth` mounted at `/data`. `ts deploy` (`bin/ts.env`, `bin/hooks/`) runs the tests, syncs to `~/dianoia-auth`, rebuilds, and checks `/healthz` on the box and at `auth.rvanegas.co`. The box's `~/dianoia-auth/.env` holds `AUTH_PUBLIC_URL`, the `AUTH_SMTP_*` settings and secret, and the Turnstile keys.
