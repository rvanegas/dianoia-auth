# The Floor vouches for its person's address

Decided by the operator on 2026-11-11 and built the same day, with The
Floor's half (*Connect* on *Floor Settings*, `NoesisConnections.vouch`).

**What it answers.** Somebody who signed in to The Floor before 2026-11-09,
when The Floor still mailed its own codes, has no session here. Their first
*Connect* opened `/authorize` in The Floor's sheet, which had nobody to
continue as, so it asked for an address, and the passkey autofill on that
field signed them in. They had already proved that address to The Floor, and
The Floor refuses a grant for any other one, so the page asked for something
already known and could only be answered one way.

**What was built.** An extension grant at `/token`,
`urn:rvanegas:params:oauth:grant-type:vouched`: a confidential client the
operator has let vouch (`add_client.py` / `client_scopes.py --vouches`) sends
its id and secret and an address, and is granted the person scopes it may
have, as a sign-in would grant them. The account is made as a first sign-in
makes it, under a name The Floor reserved, and the consent is kept, so
`/account` lists The Floor and removing it ends the grant. A disabled account
is refused. Where auth refuses, The Floor opens the sign-in as before.

**What it costs, accepted.** The client's secret alone is now a grant for
anybody: it reads and files into every person's libraries, and, since
`/handoff` takes that secret and a token issued to that client, it signs a
browser in here as anybody, which reaches every project. Before, a leaked
secret reached nobody who had not also signed in. The operator chose this
over `login_hint` (the address filled in, a passkey or a code still asked),
which kept the old boundary.

**Not done.** No other client vouches. Tokens from a vouched grant are not
marked, so `/handoff` cannot tell them from a signed-in person's; marking
them and refusing the handoff would narrow the leak to libraries, at the
cost of *Open noesis* asking those people to sign in once.
