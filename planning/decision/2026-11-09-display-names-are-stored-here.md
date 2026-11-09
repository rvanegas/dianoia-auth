# Display names are stored here

Decided at noesis's prompt on 2026-11-09, and built the same day (noesis
`planning/decision/2026-11-09-a-channel-s-voices-are-its-members.md`). A
person's display name, the name others see them by, is stored here, so noesis
and Roxana name a person the way The Floor does.

- **Kept by user name** (`display_names`), so a reservation The Floor holds
  has one before its person first signs in here, and the account that takes
  the name takes the display name too. `rename_account` carries it. Empty
  clears it. A name is one line, trimmed, at most sixty characters.
- **Set by the person**: on `/account`, or through any client their token
  grants `identity` (`PUT /me/display_name`), The Floor among them.
- **Set by the application that keeps names**, by its pair
  (`PUT /names/display`): The Floor setting one for a user who never signed
  in here, for an account or a reservation alike.
- **Read** in `/me` (`display_name`, null if unset), in a person's access
  token as the standard `name` claim (the display name, else the user name),
  and by user name at `GET /names/display?user=…`, for at most 200 names,
  for any caller holding a token auth signed or a name keeper's pair. Nobody
  anonymous can read it: the names are shown to people who share a channel
  or a discussion, not published.
- **CORS** extends from `/me` to `/me/display_name` and `/names/display`,
  for public clients' origins alone, so Roxana's browser reads the names of
  the others in a discussion.
- **A passkey** carries the display name as its `user_display_name`.

**The names chosen at The Floor before this** are carried once:
The Floor's `ts export-display-names`, then `scripts/display_names.py`
(`--apply`) on this box, which keeps any name already kept here.

A name changed here reaches an application through the next token it gets or
the next lookup it makes; nothing is pushed.
