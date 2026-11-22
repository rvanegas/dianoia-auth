# Unlimited is one mark kept here

Decided at The Floor's prompt on 2026-11-22, and built the same day. Whether
somebody is **unlimited** is one mark, kept here, and both noesis and The
Floor read it: unlimited in one is unlimited in both. Before, each kept its
own — noesis a plan (`free` or `unlimited`, its `scripts/accounts.py plan`),
The Floor a column (`transcripts_unlimited`, set by hand) — and nothing joined
them, so somebody made unlimited in one was free in the other (noesis's
`planning/task/revisit-unlimited-and-pro.md`).

**Why here rather than in either of them**: auth already knows every person
under the one name both use, including people who have never signed in to one
of the two (Liliana, unlimited at noesis, has no account at The Floor), and
both already ask it things with their own tokens. It reverses the 2026-11-08
line that what an account may do is each application's: that still holds for
everything else (noesis's allowances and spend, The Floor's Pro bought through
the App Store), and this is the one standing the two share.

- **Kept by user name** (`unlimited`), an account's or a reservation's, like
  display names, so The Floor's people carry it before they first sign in
  here. `rename_account` carries it; deleting the account ends it.
- **Set by the operator alone**: `scripts/accounts.py unlimited <user>…` and
  `limited <user>…`; `list` shows it. No route sets it.
- **Read** at `GET /unlimited`, the whole list, by an application's own token
  (`client_credentials`: its subject is its client id and its scopes are
  application scopes), never a person's: who is unlimited is not shown to
  people. Each application keeps the list a minute, so a change reaches them
  within that.

**The marks each project kept are carried here once**, with `scripts/accounts.py
unlimited` naming everybody either had marked, before either stops reading its
own; each then drops its own mark entirely.
