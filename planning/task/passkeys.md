# Passkeys

Phase 3 of rvanegas-site's
`planning/task/one-sign-in-for-every-project-at-auth-rvanegas-co.md`, after
SSO. No passwords, by decision (2026-11-08): the emailed code stays for
sign-up, a new device and recovery.

WebAuthn with `py_webauthn`, RP ID `auth.rvanegas.co`: a `passkeys` table
(user, credential id, public key, sign count, transports, name, created,
last used); `/login` offers a passkey first, with conditional UI in the
address field; *Add a passkey?* after a code sign-in on a device without
one, never before; `/account` lists, renames and removes them. The native
apps get the system prompt in their sign-in sheet unchanged. Turnstile and
the send limits stay on the code path.
