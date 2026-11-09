# One sign-in, a session and passkeys, and no passwords

Decided 2026-11-08 and built through 2026-11-09, the plan being rvanegas-site's
`planning/task/one-sign-in-for-every-project-at-auth-rvanegas-co.md`: signing
in once reaches The Floor, noesis, dianoia and Roxana, at this service, by an
emailed code or a passkey. Checked on real devices by the operator: the web,
an iPhone in Safari and in Chrome, The Floor's sign-in sheet, a Mac in Chrome,
and a passkey from the phone by QR code.

**Its own service, before anything else.** The sign-in was noesis's OAuth
server. It moved out first (the cut-over of 2026-11-09) because four apps
signing in through noesis would share noesis's slow deploy, because every
client registered against it would have to be moved later, and because the
session and passkeys would otherwise be built into noesis and dug out again.
*Dianoia* names the suite as well as its reasoning service, so the repository
is `dianoia-auth`; the host stays `auth.rvanegas.co`.

**Signed tokens, checked where they are used.** Access tokens are EdDSA JWTs
of fifteen minutes, which noesis, dianoia and The Floor check against the
published keys without calling here. The cost, accepted: disabling an
account reaches them within the quarter hour, while refresh stops at once.
Scopes, not per-client marks, say what a token reaches, and an application's
own token comes by `client_credentials`, so no secret is shared between two
services.

**A session, so one sign-in is one.** A `__Host-` cookie on this host alone,
thirty days from its last use. A client's first sign-in asks what it may have,
and later ones finish without a page. **After somebody signs out of an app,
its next sign-in asks `prompt=consent`, never `prompt=login`**: The Floor's
build 422 first asked for the code, which undid signing in once in the
commonest case, coming back as yourself (found by the operator, 2026-11-09).
No back-channel logout: signing out here ends the session, not each app's
grant, and `/account` signs out everywhere.

**One session per browser, and that is the boundary.** Safari and Chrome do
not share cookies, so a browser that has never signed in here asks once.
The Floor's sign-in sheet shares Safari's whatever the default browser; its
*Connect* first opened the default browser instead, which was Chrome, and
asked for a code (fixed in build 423). *Open noesis* still opens the default
browser and asks there once, which a passkey makes a tap.

**Passkeys, and no passwords.** A password is a secret to keep, a reset flow
(which is an emailed code anyway), and a thing to steal. A passkey keeps only
its public half here, and the browser binds it to this site, so a lookalike
page gets nothing. The emailed code stays, for signing up, a new device and
recovery. A passkey is offered once after a code sign-in on a device with
none, and on `/account`; *Not now* is remembered thirty days, through an offer
kept here so that its link can never redirect anywhere else. The script is
this site's own (`script-src 'self'`), nothing inline. Renaming a passkey was
left out: each is named by the device that made it.

**What was not done.** Account deletion that reaches every project (noesis's
task `deleting-an-account-reaches-every-project.md`), postponed by the
operator, like the cut-over's cleanup.
