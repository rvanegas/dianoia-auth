# Credentials

Every credential dianoia-auth holds: where it lives, what it can do, and what
losing it costs (technosophia's `SERVICES.md`). Values are never written here.
Read this before changing one, rotating one, or adding one.

- **SES SMTP** — `AUTH_SMTP_USER` and `AUTH_SMTP_PASSWORD` in `~/dianoia-auth/.env`
  on `commons` (local copy `~/.config/dianoia-auth/server.env`, `ts env-pull`).
  IAM user `dianoia-auth-ses`, key `…ZJRN` (2026-11-08), the password derived
  from it without being printed. It may send only through the `rvanegas.co`
  identity and configuration set `dianoia-auth`
  (rvanegas-site `iam/dianoia-auth-ses.json`), whose bounces and complaints go
  to SNS `ses-alerts`. A leak lets somebody send mail as `rvanegas.co`, which
  spends the shared identity's reputation; it reaches nothing else. Rotating:
  a second key, the password derived again into the box's `.env`, a restart,
  then the old key deleted. Nothing stored depends on it.
- **The signing key** — `/srv/dianoia-auth/signing-key.pem` on `commons` (mode
  600), made by the service on first start, never copied off the box. It signs
  every access token, which noesis, dianoia and The Floor's server accept for
  fifteen minutes, so **a leak lets somebody be anyone, everywhere, until it is
  rotated**. Rotating (`dianoia_auth/tokens.py`): rename it
  `signing-key.old.pem`, restart, delete the old one a quarter hour later;
  tokens already out keep working meanwhile, and nobody signs in again. Losing
  it costs only that: the next start makes another.
- **Client secrets** — in `auth.db`, not this project's to hold but each
  client's (The Floor's `NOESIS_CLIENT_SECRET`, noesis's
  `NOESIS_AUTH_CLIENT_SECRET`, claude.ai's own): kept in the clear, since the
  SDK compares them. A copy of `auth.db` lets somebody pose as any registered
  client; refresh tokens there are hashes and reach nothing.
- **Sessions** — the `__Host-session` cookie in each signed-in browser, kept
  in `auth.db` as a hash. A stolen cookie signs its thief in to every client,
  as that person, until it lapses (thirty days from last use) or the person
  signs out of it on `/account`; disabling the account ends it at once.
- **App Review's code** — `AUTH_REVIEW_ADDRESS` and `AUTH_REVIEW_CODE` in
  `~/dianoia-auth/.env` (since 2026-11-09), copied from The Floor's
  `REVIEW_IDENTIFIER`/`REVIEW_CODE` in `~/.config/thefloor/demo-account.txt`.
  **Public by design**: the code is published in the App Store review notes,
  so anyone who reads them can sign in as that account, which holds demo data
  alone (The Floor's `planning/DEMO-ACCOUNT.md`). Changing it means changing
  the review notes at the same time, or the next submission's sign-in fails.
