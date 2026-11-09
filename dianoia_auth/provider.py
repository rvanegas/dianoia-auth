"""The OAuth authorization server: the MCP SDK's provider interface, and the sign-in.

Moved from noesis's oauth.py (2026-11-08), where it was the identity for every
application; here it is that and nothing else. Every application reaches a
person's data through a grant from here: noesis (its web client, and
claude.ai's connector to it), dianoia through Roxana, The Floor.

- **Registration** is open to anyone, so **redirects are limited** to
  claude.ai's and claude.com's callbacks and to localhost (Claude Code), and
  a self-registered client is given `noesis:read` and nothing more. Every
  other client is the operator's (scripts/add_client.py).
- **Sign-in** is an email address and then a six-digit code mailed to it,
  kept as a hash with the pending sign-in, good for ten minutes and five
  tries; a new one costs a mail, which accounts.allow_send limits. The first
  sign-in makes the account.
- **Scopes say what a token reaches**, and the operator sets which each
  client may have (`scope` in its registration): `identity` (who signed in,
  and nothing else), `noesis:read` (noesis's MCP tools), `noesis:import`
  (filing conversations, and the speaker names), `noesis:api` (noesis's file
  and run API). Asking for none grants what the client may have.
- **An application's own tokens** come from the `client_credentials` grant,
  with its id and secret, and carry only APPLICATION_SCOPES, which no person's
  grant can: `noesis:keep` (The Floor, keeping libraries at noesis) and
  `thefloor:members` (noesis, asking The Floor who belongs). Their `sub` is
  the client id.
- **Access tokens are JWTs** (tokens.py); refresh tokens are opaque, kept as
  hashes in auth.db, rotated on every use, and refused once the account is
  disabled.
"""

from __future__ import annotations

import json
import secrets
import time
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from dianoia_auth import accounts, sessions, tokens
from dianoia_auth.store import connect, sha

REFRESH_TTL = 90 * 24 * 60 * 60
CODE_TTL = 5 * 60
SIGN_IN_TTL = 10 * 60
SIGN_IN_ATTEMPTS = 5
CODE_DIGITS = 6

IDENTITY = "identity"
NOESIS_READ = "noesis:read"
NOESIS_IMPORT = "noesis:import"
NOESIS_API = "noesis:api"
PERSON_SCOPES = (IDENTITY, NOESIS_READ, NOESIS_IMPORT, NOESIS_API)
APPLICATION_SCOPES = ("noesis:keep", "thefloor:members")
REGISTERED_SCOPE = NOESIS_READ

# OpenID Connect's `prompt` (`login`, `consent`, `none`), which the SDK's
# /authorize does not pass on: server.py reads it from the request.
PROMPT: ContextVar[str | None] = ContextVar("prompt", default=None)
# What a sign-in for /account itself, not for a client, is called.
ACCOUNT = "account"

ALLOWED_CALLBACKS = {
    ("https", "claude.ai", "/api/mcp/auth_callback"),
    ("https", "claude.com", "/api/mcp/auth_callback"),
}


def _origin(uri: str) -> str:
    u = urlparse(uri)
    return f"{u.scheme}://{u.netloc}"


def allowed_redirect(uri: str) -> bool:
    u = urlparse(uri)
    if (u.scheme, u.hostname, u.path) in ALLOWED_CALLBACKS:
        return True
    return u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1")


def scopes_of(client: OAuthClientInformationFull) -> list[str]:
    return (client.scope or "").split()


def what_it_asks(scopes: list[str]) -> str:
    """What the sign-in page says a grant of these scopes lets the application do."""
    if NOESIS_API in scopes:
        return "to keep your noesis libraries: to read and change them, and to run noesis's commands on them"
    if NOESIS_IMPORT in scopes:
        return ("to read your noesis libraries, and to add conversations to them when you send one "
                "— with the name you speak under there kept as yours")
    if NOESIS_READ in scopes:
        return "to read your noesis libraries"
    return "to know who you are: your user name and email address"


def review_code(address: str) -> str | None:
    """The fixed code of App Review's address (AUTH_REVIEW_ADDRESS, AUTH_REVIEW_CODE),
    which reviewers sign in with at every submission; None for any other address.

    The code is published in the review notes, so whoever reads them can sign
    in as that account: it holds demo data alone (The Floor's
    planning/DEMO-ACCOUNT.md). Both settings, or neither.
    """
    import os
    wanted = accounts.normalize_email(os.environ.get("AUTH_REVIEW_ADDRESS", ""))
    code = os.environ.get("AUTH_REVIEW_CODE", "").strip()
    if not wanted or len(code) != CODE_DIGITS or not code.isdigit():
        return None
    return code if address == wanted else None


@dataclass
class SignIn:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    scopes: list[str]
    expires_at: float
    attempts: int = 0
    email: str = ""
    code_sha: str = ""
    # `login` asks for the code even with a session; `consent` asks again what the client may have.
    prompt: str | None = None

    @property
    def for_account(self) -> bool:
        return self.client.client_id == ACCOUNT


class AuthProvider:
    def __init__(self) -> None:
        self.sign_ins: dict[str, SignIn] = {}
        self.codes: dict[str, AuthorizationCode] = {}

    # --- clients -----------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.client(client_id)

    def client(self, client_id: str) -> OAuthClientInformationFull | None:
        with connect() as db:
            row = db.execute("SELECT info FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return OAuthClientInformationFull.model_validate_json(row[0]) if row else None

    def save_client(self, client: OAuthClientInformationFull, keeps_names: bool = False) -> None:
        with connect() as db:
            db.execute("INSERT INTO clients (client_id, info, keeps_names) VALUES (?, ?, ?) "
                       "ON CONFLICT (client_id) DO UPDATE SET info = excluded.info, keeps_names = excluded.keeps_names",
                       (client.client_id, client.model_dump_json(), int(keeps_names)))

    def keeps_names(self, client_id: str, secret: str) -> bool:
        """A client marked as keeping names (scripts/add_client.py --keeps-names), whose secret this is."""
        with connect() as db:
            row = db.execute("SELECT info, keeps_names FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if not row or not row[1]:
            return False
        stored = json.loads(row[0]).get("client_secret") or ""
        return bool(stored) and secrets.compare_digest(stored.encode(), secret.encode())

    def browser_origins(self) -> set[str]:
        """The origins of public clients' redirects: the browser apps that read /me."""
        with connect() as db:
            infos = [json.loads(r[0]) for r in db.execute("SELECT info FROM clients")]
        return {_origin(uri) for info in infos if info.get("token_endpoint_auth_method") == "none"
                for uri in info.get("redirect_uris") or [] if not allowed_redirect(uri)}

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        bad = [str(u) for u in (client_info.redirect_uris or []) if not allowed_redirect(str(u))]
        if bad:
            raise RegistrationError(error="invalid_redirect_uri",
                                    error_description=f"not a redirect this server sends to: {', '.join(bad)}")
        if self.client(client_info.client_id) is not None:
            raise RegistrationError(error="invalid_client_metadata", error_description="that client id is taken")
        self.save_client(client_info.model_copy(update={"scope": REGISTERED_SCOPE}))

    # --- sign-in -----------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        now = time.time()
        self.sign_ins = {k: v for k, v in self.sign_ins.items() if v.expires_at > now}
        # The SDK has checked what was asked against what the client may have.
        scopes = params.scopes if params.scopes is not None else scopes_of(client)
        scopes = [s for s in scopes if s in PERSON_SCOPES]
        request_id = secrets.token_urlsafe(24)
        self.sign_ins[request_id] = SignIn(client, params, scopes, now + SIGN_IN_TTL, prompt=PROMPT.get())
        return f"{tokens.issuer()}/login?request={request_id}"

    def begin_account(self) -> str:
        """A sign-in for /account itself, which ends at /account rather than at a client."""
        page = f"{tokens.issuer()}/account"
        client = OAuthClientInformationFull(client_id=ACCOUNT, client_name="Your account", redirect_uris=[page])
        params = AuthorizationParams(state=None, scopes=[], code_challenge="-", redirect_uri=page,
                                     redirect_uri_provided_explicitly=True)
        request_id = secrets.token_urlsafe(24)
        self.sign_ins[request_id] = SignIn(client, params, [], time.time() + SIGN_IN_TTL, prompt="login")
        return request_id

    def pending(self, request_id: str) -> SignIn | None:
        sign_in = self.sign_ins.get(request_id)
        if sign_in is None or sign_in.expires_at < time.time() or sign_in.attempts >= SIGN_IN_ATTEMPTS:
            return None
        return sign_in

    def send_code(self, request_id: str, email: str, ip: str) -> str | None:
        """Mails a code for this sign-in; why not, if it was not sent."""
        from dianoia_auth import mail
        sign_in = self.pending(request_id)
        if sign_in is None:
            return "This sign-in has expired; start again from the app."
        address = accounts.normalize_email(email)
        if address is None:
            return "That is not an email address."
        review = review_code(address)
        if review is not None:
            # App Review's address: its code is fixed and published in the
            # review notes, so nothing is mailed and nothing is counted.
            code = review
        else:
            if not accounts.allow_send(address, ip):
                return "Too many codes were asked for; try again in an hour."
            code = f"{secrets.randbelow(10 ** CODE_DIGITS):0{CODE_DIGITS}d}"
            try:
                mail.send_code(address, code, sign_in.client.client_name or "An application")
            except mail.MailUnavailable:
                return "The code could not be sent; try again later."
        sign_in.email, sign_in.code_sha, sign_in.attempts = address, sha(code), 0
        sign_in.expires_at = time.time() + SIGN_IN_TTL
        return None

    def verify_code(self, request_id: str, code: str) -> tuple[str, str] | None:
        """Where the person goes and who they are, if the code is the one sent: the
        redirect back to the client with an OAuth code, or /account."""
        sign_in = self.pending(request_id)
        if sign_in is None or not sign_in.code_sha:
            return None
        sign_in.attempts += 1
        if not secrets.compare_digest(sha(code.strip()), sign_in.code_sha):
            return None
        found = accounts.create_account(sign_in.email)
        if found.disabled:
            return None
        return self.complete(request_id, found.user), found.user

    def complete(self, request_id: str, user: str) -> str:
        """Finishes a sign-in as `user`, whose code or session says who they are: the
        consent kept, and the redirect back to the client with an OAuth code."""
        sign_in = self.sign_ins.pop(request_id)
        params = sign_in.params
        if sign_in.for_account:
            return str(params.redirect_uri)
        sessions.grant(user, sign_in.client.client_id, sign_in.scopes)
        oauth_code = secrets.token_urlsafe(32)
        self.codes[oauth_code] = AuthorizationCode(
            code=oauth_code, scopes=sign_in.scopes, expires_at=time.time() + CODE_TTL,
            client_id=sign_in.client.client_id, code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource, subject=user,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=oauth_code, state=params.state)

    def needs_consent(self, request_id: str, user: str) -> bool:
        """Whether a session's sign-in must ask before finishing: a client not yet let have these scopes."""
        sign_in = self.sign_ins[request_id]
        if sign_in.for_account:
            return False
        return sign_in.prompt == "consent" or not sessions.covers(user, sign_in.client.client_id, sign_in.scopes)

    def restart(self, request_id: str) -> None:
        """Back to asking for an address: the code sent is forgotten."""
        sign_in = self.pending(request_id)
        if sign_in is not None:
            sign_in.email = sign_in.code_sha = ""

    def refuse(self, request_id: str, error: str = "access_denied") -> str | None:
        """The redirect back with an error: access_denied when the person declines, or
        login_required / consent_required when `prompt=none` cannot be met."""
        sign_in = self.sign_ins.pop(request_id, None)
        if sign_in is None:
            return None
        if sign_in.for_account:
            return str(sign_in.params.redirect_uri)
        return construct_redirect_uri(str(sign_in.params.redirect_uri), error=error, state=sign_in.params.state)

    # --- tokens ------------------------------------------------------------

    async def load_authorization_code(self, client, authorization_code: str) -> AuthorizationCode | None:
        code = self.codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    def _issue(self, client_id: str, user: str, scopes: list[str], resource: str | None) -> OAuthToken:
        access, ttl = tokens.issue(user, client_id, scopes, resource)
        refresh = secrets.token_urlsafe(32)
        with connect() as db:
            db.execute("DELETE FROM refresh WHERE expires_at < ?", (time.time(),))
            db.execute("INSERT INTO refresh (sha, client_id, user, scopes, resource, expires_at) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (sha(refresh), client_id, user, " ".join(scopes), resource, time.time() + REFRESH_TTL))
        return OAuthToken(access_token=access, expires_in=ttl, refresh_token=refresh, scope=" ".join(scopes) or None)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        self.codes.pop(authorization_code.code, None)
        return self._issue(client.client_id, authorization_code.subject or "",
                           authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        with connect() as db:
            row = db.execute("SELECT client_id, user, scopes, resource, expires_at FROM refresh WHERE sha = ?",
                             (sha(refresh_token),)).fetchone()
        if row is None:
            return None
        client_id, user, scopes, resource, expires_at = row
        if client_id != client.client_id or expires_at < time.time() or not accounts.is_active(user):
            return None
        return RefreshToken(token=refresh_token, client_id=client_id, scopes=scopes.split(),
                            expires_at=int(expires_at), resource=resource, subject=user)

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        with connect() as db:
            db.execute("DELETE FROM refresh WHERE sha = ?", (sha(refresh_token.token),))
        return self._issue(client.client_id, refresh_token.subject or "", scopes or refresh_token.scopes,
                           refresh_token.resource)

    def application_token(self, client: OAuthClientInformationFull, asked: list[str] | None) -> OAuthToken | None:
        """An application's own token (client_credentials): None if it may have none of what it asks."""
        allowed = [s for s in scopes_of(client) if s in APPLICATION_SCOPES]
        scopes = [s for s in asked if s in allowed] if asked else allowed
        if not scopes or (asked and len(scopes) != len(asked)):
            return None
        access, ttl = tokens.issue(client.client_id, client.client_id, scopes)
        return OAuthToken(access_token=access, expires_in=ttl, scope=" ".join(scopes))

    async def load_access_token(self, token: str) -> AccessToken | None:
        claims = tokens.verify(token)
        if claims is None:
            return None
        return AccessToken(token=token, client_id=claims["client_id"], scopes=claims["scope"].split(),
                           expires_at=claims["exp"], resource=claims["aud"], subject=claims["sub"])

    async def revoke_token(self, token) -> None:
        # An access token is signed, not stored: it lasts its quarter hour.
        if isinstance(token, RefreshToken):
            with connect() as db:
                db.execute("DELETE FROM refresh WHERE sha = ?", (sha(token.token),))


provider = AuthProvider()
