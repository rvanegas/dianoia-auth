# Display names are stored here

Decided 2026-11-09, at noesis's prompt (noesis
`planning/decision/2026-11-09-a-channel-s-voices-are-its-members.md`). A person's display
name, the name others see them by, is stored by auth alongside their user
name and sent from here to every project, so noesis and Roxana name a
person the way The Floor does.

- **Stored per account**, set by the person, and by The Floor when it sets
  its own display name (The Floor's task `display-names-are-auth-s.md`).
- **Carried in the JWT** as the standard `name` claim, and at an endpoint
  that answers a user name's display name for a service that has only the
  user name (Roxana naming the other people in a discussion, noesis naming a
  channel's members).
- **The passkey's `user_display_name`** (`passkeys.py`) is that name, where
  it is the user name now.

The names each service reads go through technosophia's `SERVICES.md`.
