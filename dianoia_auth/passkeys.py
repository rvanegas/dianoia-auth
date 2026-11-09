"""Passkeys: signing in without a code (Phase 3), by WebAuthn.

Decided 2026-11-08: emailed codes and passkeys, and no passwords. A passkey
is a key pair the person's device makes for this site alone; only its public
half is kept here, so nothing stored is worth stealing, and a lookalike site
gets nothing, since the browser binds the key to `auth.rvanegas.co`.

- **Added only by somebody signed in**: offered after a code sign-in on a
  device that has none (never before: a passkey is somebody who has proved
  their address making it quicker to come back), and on /account.
- **Used at /login**, by its own button or by the browser's autofill on the
  address field (conditional mediation); the emailed code stays for sign-up,
  a new device and recovery.
- **Discoverable** (resident keys): the device offers the account, so nobody
  types an address. The user handle is an opaque hash of the user name; the
  credential id is what finds the passkey here.
- **Each challenge is single use and lives five minutes**, kept in memory:
  a registration's by the session that asked, a sign-in's by the pending
  sign-in it belongs to.
- **A disabled account's passkeys sign nobody in**; removing one on /account
  deletes it here, though the device keeps its now useless private half.

RP ID is the issuer's host (`auth.rvanegas.co`), the origin the issuer.
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import urlparse

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from dianoia_auth import accounts, tokens
from dianoia_auth.store import connect

RP_NAME = "rvanegas.co"
CHALLENGE_TTL = 5 * 60
MAX_PER_USER = 20

_challenges: dict[tuple[str, str], tuple[bytes, float]] = {}


class PasskeyError(ValueError):
    """What to tell the person when a passkey could not be added or used."""


def rp_id() -> str:
    return urlparse(tokens.issuer()).hostname or "localhost"


def _remember(kind: str, key: str, challenge: bytes) -> None:
    now = time.time()
    for k, (_, expires) in list(_challenges.items()):
        if expires < now:
            del _challenges[k]
    _challenges[(kind, key)] = (challenge, now + CHALLENGE_TTL)


def _spend(kind: str, key: str) -> bytes | None:
    found = _challenges.pop((kind, key), None)
    return found[0] if found and found[1] > time.time() else None


def _user_handle(user: str) -> bytes:
    return hashlib.sha256(f"dianoia-auth:{user}".encode()).digest()


def of(user: str) -> list[dict]:
    with connect() as db:
        rows = db.execute("SELECT credential_id, name, created_at, used_at FROM passkeys WHERE user = ? "
                          "ORDER BY created_at", (user,)).fetchall()
    return [{"id": r[0], "name": r[1], "created_at": r[2], "used_at": r[3]} for r in rows]


def remove(user: str, credential_id: str) -> None:
    with connect() as db:
        db.execute("DELETE FROM passkeys WHERE user = ? AND credential_id = ?", (user, credential_id))


# --- adding one --------------------------------------------------------------

def registration_options(user: str, session_sha: str) -> str:
    """The options for the browser's navigator.credentials.create, as JSON."""
    existing = of(user)
    if len(existing) >= MAX_PER_USER:
        raise PasskeyError(f"At most {MAX_PER_USER} passkeys; remove one on your account first.")
    found = accounts.account(user)
    options = generate_registration_options(
        rp_id=rp_id(), rp_name=RP_NAME, user_id=_user_handle(user), user_name=found.email if found else user,
        user_display_name=user,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.PREFERRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"])) for p in existing],
    )
    _remember("register", session_sha, options.challenge)
    return options_to_json(options)


def register(user: str, session_sha: str, credential: dict, name: str) -> None:
    """Keeps the passkey the browser made, if it answers this session's challenge."""
    challenge = _spend("register", session_sha)
    if challenge is None:
        raise PasskeyError("That took too long; try again.")
    try:
        verified = verify_registration_response(credential=credential, expected_challenge=challenge,
                                                expected_rp_id=rp_id(), expected_origin=tokens.issuer())
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError("The passkey could not be added.") from exc
    transports = ",".join(credential.get("response", {}).get("transports") or [])
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO passkeys (credential_id, user, public_key, sign_count, transports, name, "
                   "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (bytes_to_base64url(verified.credential_id), user, verified.credential_public_key,
                    verified.sign_count, transports, name[:80], time.time()))


# --- signing in with one -----------------------------------------------------

def authentication_options(request_id: str) -> str:
    """The options for navigator.credentials.get, for a pending sign-in, as JSON: any of this site's passkeys."""
    options = generate_authentication_options(rp_id=rp_id(), user_verification=UserVerificationRequirement.PREFERRED)
    _remember("authenticate", request_id, options.challenge)
    return options_to_json(options)


def authenticate(request_id: str, credential: dict) -> str:
    """Whose passkey answered this sign-in's challenge: the user, its count advanced."""
    challenge = _spend("authenticate", request_id)
    if challenge is None:
        raise PasskeyError("That took too long; try again.")
    credential_id = credential.get("id") if isinstance(credential, dict) else None
    with connect() as db:
        row = db.execute("SELECT user, public_key, sign_count FROM passkeys WHERE credential_id = ?",
                         (credential_id,)).fetchone() if credential_id else None
    if row is None:
        raise PasskeyError("That passkey is not one this site knows; sign in with a code instead.")
    user, public_key, count = row
    try:
        verified = verify_authentication_response(credential=credential, expected_challenge=challenge,
                                                  expected_rp_id=rp_id(), expected_origin=tokens.issuer(),
                                                  credential_public_key=public_key,
                                                  credential_current_sign_count=count)
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError("The passkey could not be checked; sign in with a code instead.") from exc
    if not accounts.is_active(user):
        raise PasskeyError("This account cannot sign in.")
    with connect() as db:
        db.execute("UPDATE passkeys SET sign_count = ?, used_at = ? WHERE credential_id = ?",
                   (verified.new_sign_count, time.time(), credential_id))
    return user
