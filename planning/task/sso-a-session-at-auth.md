# SSO: a session at auth

Phase 2 of rvanegas-site's
`planning/task/one-sign-in-for-every-project-at-auth-rvanegas-co.md`, after
the move has been deployed.

A session cookie on `auth.rvanegas.co` (`HttpOnly`, `Secure`, `SameSite=Lax`,
30 days rolling, kept hashed), set when a code is verified and ended by
disabling the account. `/authorize` with a session skips the code and asks
consent once per person, client and scopes (`prompt=login` and
`prompt=consent` force them). `/account` lists granted applications and
signed-in browsers, revokes one, and signs out everywhere; `/logout` ends
the session alone, with no back-channel logout. The Floor's own sign-in is
replaced by this one (thefloor's task of the same name).

**The session built 2026-11-09** (branch `sso`): `sessions.py`, the consent
page, `prompt`, `/logout` and `/account`. Left: the clients' own sign-out
going through `/logout` (noesis's web client, Roxana), and The Floor's
sign-in, which is an installed-client change and has its own task there.
