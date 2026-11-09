"""dianoia-auth's HTTP app, at auth.rvanegas.co: the OAuth routes, the sign-in page, /me and the register of names.

- `GET /healthz`: open, the deployed commit (dianoia_auth/deployed.json, stamped by
  `ts deploy`).
- The OAuth server, by the MCP SDK (`create_auth_routes`): metadata at
  /.well-known/oauth-authorization-server, /authorize, /token, /register,
  /revoke; and /token also takes `client_credentials` (provider.py, an
  application's own token), which the SDK does not.
- `/.well-known/jwks.json`: the keys access tokens are signed with
  (tokens.py), for resource servers to check them by.
- `/login`: the sign-in that /authorize sends people to: by emailed code,
  or, with a session here (sessions.py), at once, asking only a client's
  first time what it may have. `prompt=login|consent|none` is honoured.
- `/logout`: ends this browser's session, back to a client's own origin.
- `/account`: the person's own page: the apps they let in (each removable),
  their passkeys, where they are signed in, and signing out everywhere.
- `/passkeys…`: adding a passkey and signing in with one (passkeys.py), from
  this site's own pages through `/passkeys.js`.
- `GET /me`: who a token's person is, for any client's token; answered by
  CORS to the public clients' own origins.
- `/names`: the register of names (names.py), for applications marked as
  keeping names, by their id and secret as HTTP Basic.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import secrets
import time
from html import escape
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl, BaseModel
from starlette.requests import Request as StarletteRequest

from dianoia_auth import accounts, names, passkeys, sessions, tokens
from dianoia_auth.provider import PROMPT, REGISTERED_SCOPE, provider, what_it_asks
from dianoia_auth.store import sha

TURNSTILE_VERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

app = FastAPI(title="dianoia-auth", docs_url=None, redoc_url=None)


def _deployed() -> dict:
    try:
        return json.loads((Path(__file__).resolve().parent / "deployed.json").read_text())
    except (OSError, ValueError):
        return {}


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "commit": _deployed().get("commit")}


@app.get("/.well-known/jwks.json")
def jwks() -> Response:
    return JSONResponse(tokens.jwks(), headers={"Cache-Control": "public, max-age=300",
                                                "Access-Control-Allow-Origin": "*"})


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------

async def bearer(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "a bearer token is required")
    claims = tokens.verify(authorization.removeprefix("Bearer "))
    if claims is None:
        raise HTTPException(401, "unknown token")
    return claims


@app.get("/me")
def me(claims: dict = Depends(bearer)) -> dict:
    """Who signed in, and to which client: any client's person token."""
    found = accounts.account(claims["sub"])
    if found is None or found.disabled:
        raise HTTPException(401, "unknown token")
    return {"user": found.user, "email": found.email, "client": claims["client_id"],
            "scopes": claims["scope"].split()}


_ME_CORS = {"Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "authorization", "Access-Control-Max-Age": "600", "Vary": "Origin"}


@app.middleware("http")
async def me_cors(request: Request, call_next) -> Response:
    origin = request.headers.get("origin")
    if request.url.path != "/me" or not origin:
        return await call_next(request)
    allowed = origin in provider.browser_origins()
    if request.method == "OPTIONS":
        return Response(status_code=204, headers={**_ME_CORS, "Access-Control-Allow-Origin": origin} if allowed else {})
    response = await call_next(request)
    if allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


# ---------------------------------------------------------------------------
# The register of names
# ---------------------------------------------------------------------------

async def name_keeper(authorization: str | None = Header(default=None)) -> str:
    """The application calling the register, by its client id and secret (HTTP Basic)."""
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(401, "a client id and secret are required")
    try:
        client_id, _, secret = base64.b64decode(authorization.removeprefix("Basic ")).decode().partition(":")
    except (binascii.Error, UnicodeDecodeError):
        raise HTTPException(401, "a client id and secret are required") from None
    if not provider.keeps_names(client_id, secret):
        raise HTTPException(401, "not an application that keeps names")
    return client_id


def _naming(change):
    """A change to the register, its refusals as sentences."""
    try:
        return change()
    except names.Taken as exc:
        raise HTTPException(409, str(exc)) from None
    except names.Invalid as exc:
        raise HTTPException(400, str(exc)) from None


class NameFor(BaseModel):
    email: str
    suggest: list[str] = []


class NameChoice(BaseModel):
    email: str
    user: str


class AddressMove(BaseModel):
    email: str
    new_email: str


@app.post("/names")
def post_name(body: NameFor, client: str = Depends(name_keeper)) -> dict:
    """An address's name, and whether it is an account's; reserved for it now if it had none."""
    user, account = _naming(lambda: names.name_for(body.email, client, body.suggest[:5]))
    return {"user": user, "account": account}


@app.put("/names")
def put_name(body: NameChoice, client: str = Depends(name_keeper)) -> dict:
    """Makes a name the address's: reserved if it has none, renamed if it has another."""
    return {"user": _naming(lambda: names.choose(body.email, body.user, client))}


@app.put("/names/address")
def put_name_address(body: AddressMove, client: str = Depends(name_keeper)) -> dict:
    """A reservation moved to the address its person now signs in with at the application."""
    _naming(lambda: names.move(body.email, body.new_email))
    return {"moved": True}


# ---------------------------------------------------------------------------
# The sign-in page
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    """The person's address: the last X-Forwarded-For, Caddy's, since only Caddy reaches the port."""
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.rsplit(",", 1)[-1].strip() or (request.client.host if request.client else "")


def _human(form: dict, ip: str) -> bool:
    """Cloudflare Turnstile's verdict on the page's challenge; no check without its keys."""
    secret = os.environ.get("AUTH_TURNSTILE_SECRET")
    if not secret:
        return True
    from urllib.parse import urlencode
    from urllib.request import urlopen
    body = urlencode({"secret": secret, "response": form.get("cf-turnstile-response", ""),
                      "remoteip": ip}).encode()
    try:
        with urlopen(TURNSTILE_VERIFY, data=body, timeout=10) as response:
            return bool(json.loads(response.read()).get("success"))
    except (OSError, ValueError):
        return False


# A session (sessions.py) is a cookie on this host alone: __Host- where served
# over https, which the browser then refuses to scope wider or send in clear.
def _cookie_name() -> str:
    return "__Host-session" if tokens.issuer().startswith("https://") else "session"


def _session(request: Request):
    return sessions.current(request.cookies.get(_cookie_name()))


def _csrf(request: Request) -> str:
    """A form's proof that it came from this site's own page, for what a session alone could do."""
    return _csrf_for(request.cookies.get(_cookie_name(), ""))


def _csrf_for(token: str) -> str:
    return sha(f"csrf:{token}")[:32]


def _checked(request: Request, form: dict) -> bool:
    return bool(request.cookies.get(_cookie_name())) and secrets.compare_digest(form.get("csrf", ""), _csrf(request))


def _set_session(response: Response, token: str) -> Response:
    response.set_cookie(_cookie_name(), token, max_age=sessions.SESSION_TTL, path="/", httponly=True,
                        secure=tokens.issuer().startswith("https://"), samesite="lax")
    return response


def _clear_session(response: Response) -> Response:
    response.delete_cookie(_cookie_name(), path="/", httponly=True,
                           secure=tokens.issuer().startswith("https://"), samesite="lax")
    return response


# Scripts: this site's own (passkeys.js) and Turnstile's, nothing inline.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'self' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; "
        "frame-ancestors 'none'; base-uri 'none'")
_PASSKEYS_JS = '<script src="/passkeys.js" defer></script>'



def _page(title: str, body: str, script: str = "", status: int = 200, data: dict | None = None) -> HTMLResponse:
    # No form-action: the answer to a sign-in is a redirect to the client.
    # `data` becomes <body data-*>, what passkeys.js reads of the page.
    attributes = "".join(f' data-{k}="{escape(str(v))}"' for k, v in (data or {}).items())
    return HTMLResponse(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>{script}
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}}
input{{width:100%;font:inherit;padding:.4rem;box-sizing:border-box}}button{{font:inherit;margin:.8rem .6rem 0 0}}
.error{{color:#b00}}.hint{{color:#555;font-size:.9rem}}.cf-turnstile{{margin-top:.8rem}}
ul{{padding-left:1.1rem}}li{{margin:.4rem 0}}li form{{display:inline}}li button{{margin:0 0 0 .5rem}}</style></head><body{attributes}>
<h1>{escape(title)}</h1>
{body}
</body></html>""", status_code=status, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                                               "Referrer-Policy": "no-referrer", "Content-Security-Policy": _CSP})


def _asking(sign_in) -> str:
    if sign_in.for_account:
        return "<p>Sign in to see your account: the apps you have let in, and where you are signed in.</p>"
    client_name = escape(sign_in.client.client_name or "An application")
    redirect_host = escape(urlparse(str(sign_in.params.redirect_uri)).hostname or "")
    return f"<p><b>{client_name}</b> ({redirect_host}) asks {what_it_asks(sign_in.scopes)}.</p>"


def _login_page(request_id: str, sign_in, error: str = "") -> HTMLResponse:
    note = f'<p class="error">{escape(error)}</p>' if error else ""
    site_key = os.environ.get("AUTH_TURNSTILE_SITE_KEY", "")
    request_field = f'<input type="hidden" name="request" value="{escape(request_id)}">'
    deny = '<button name="action" value="deny" formnovalidate class="quiet">Deny</button>'
    if sign_in.code_sha:
        form = f"""<p>A code is on its way to <b>{escape(sign_in.email)}</b>. It works for ten minutes.</p>
<form method="post" action="/login">{request_field}
<label>Code<br><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" maxlength="6" required autofocus></label>
<button name="action" value="verify">Sign in</button><button name="action" value="restart" formnovalidate class="quiet">Use another address</button>{deny}
</form>"""
        script = ""
    else:
        challenge = f'<div class="cf-turnstile" data-sitekey="{escape(site_key)}"></div>' if site_key else ""
        form = f"""<form method="post" action="/login">{request_field}
<label>Your email address<br><input name="email" type="email" autocomplete="email webauthn" required autofocus></label>
{challenge}
<button name="action" value="send">Send me a code</button>{deny}
</form>
<p class="passkey"><button type="button" id="passkey-sign-in">Sign in with a passkey</button></p>
<p class="error passkey" id="passkey-error"></p>
<p class="hint">No account yet? Signing in makes one: one account for noesis, Roxana and The Floor,
and signing in once signs you in to each of them.</p>"""
        script = _PASSKEYS_JS + ('<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
                                 if site_key else "")
        return _page("Sign in", f"{_asking(sign_in)}\n{note}{form}", script,
                     data={"passkeys": "login", "request": request_id})
    return _page("Sign in", f"{_asking(sign_in)}\n{note}{form}", script)


def _consent_page(request: Request, request_id: str, sign_in, user: str) -> HTMLResponse:
    """A session's first sign-in to a client: who is signed in, what the client asks, and the choice."""
    found = accounts.account(user)
    fields = (f'<input type="hidden" name="request" value="{escape(request_id)}">'
              f'<input type="hidden" name="csrf" value="{_csrf(request)}">')
    return _page("Sign in", f"""{_asking(sign_in)}
<p>You are signed in as <b>{escape(user)}</b> ({escape(found.email if found else "")}).</p>
<form method="post" action="/login">{fields}
<button name="action" value="continue" autofocus>Continue as {escape(user)}</button><button name="action" value="other" class="quiet">Use another address</button><button name="action" value="deny" class="quiet">Deny</button>
</form>""")


@app.get("/login")
def login(request: Request, request_id: str = Query(alias="request")) -> Response:
    sign_in = provider.pending(request_id)
    if sign_in is None:
        return PlainTextResponse("This sign-in has expired; start again from the app.", status_code=400)
    session = _session(request)
    if session is not None and sign_in.prompt != "login":
        if not provider.needs_consent(request_id, session.user):
            return RedirectResponse(provider.complete(request_id, session.user), status_code=302)
        if sign_in.prompt == "none":
            return RedirectResponse(provider.refuse(request_id, "consent_required"), status_code=302)
        return _consent_page(request, request_id, sign_in, session.user)
    if sign_in.prompt == "none":
        return RedirectResponse(provider.refuse(request_id, "login_required"), status_code=302)
    return _login_page(request_id, sign_in)


@app.post("/login")
async def login_submit(request: Request) -> Response:
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode("utf-8", "replace")).items()}
    request_id, action = form.get("request", ""), form.get("action")
    if action == "deny":
        target = provider.refuse(request_id)
        return RedirectResponse(target, status_code=302) if target else PlainTextResponse("Expired.", status_code=400)
    sign_in = provider.pending(request_id)
    if sign_in is None:
        return PlainTextResponse("This sign-in has expired or had too many tries; start again.", status_code=400)
    if action == "continue":
        session = _session(request)
        if session is None or not _checked(request, form):
            return _login_page(request_id, sign_in, error="Your session here has ended; sign in again.")
        return RedirectResponse(provider.complete(request_id, session.user), status_code=302)
    if action == "other":
        sign_in.prompt = "login"
        return _login_page(request_id, sign_in)
    if action == "restart":
        provider.restart(request_id)
        return _login_page(request_id, sign_in)
    if action == "send":
        ip = _client_ip(request)
        if not await asyncio.to_thread(_human, form, ip):
            return _login_page(request_id, sign_in, error="The check that you are a person did not pass; try again.")
        why = await asyncio.to_thread(provider.send_code, request_id, form.get("email", ""), ip)
        return _login_page(request_id, sign_in, error=why or "")
    if action == "verify":
        done = provider.verify_code(request_id, form.get("code", ""))
        if done is not None:
            target, user = done
            sessions.end(request.cookies.get(_cookie_name()))
            token = sessions.create(user, request.headers.get("user-agent", ""))
            if not passkeys.of(user) and not request.cookies.get(_LATER_COOKIE):
                return _set_session(_offer_page(target, token), token)
            return _set_session(RedirectResponse(target, status_code=302), token)
        if provider.pending(request_id) is None:
            return PlainTextResponse("Too many wrong codes; start again from the app.", status_code=400)
        return _login_page(request_id, sign_in, error="That is not the code we sent.")
    return PlainTextResponse("Unknown action.", status_code=400)


# ---------------------------------------------------------------------------
# Passkeys (passkeys.py)
# ---------------------------------------------------------------------------

# "Not now" to the offer, remembered in this browser for thirty days.
_LATER_COOKIE = "passkeys_later"
_LATER_TTL = 30 * 24 * 60 * 60
# Where an offer goes on to, kept here so that "Not now" names an offer and
# never a URL: a link that redirected wherever it said would be an open one.
_offers: dict[str, tuple[str, float]] = {}


@app.get("/passkeys.js")
def passkeys_js() -> Response:
    script = (Path(__file__).resolve().parent / "static" / "passkeys.js").read_text(encoding="utf-8")
    return Response(script, media_type="text/javascript; charset=utf-8",
                    headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})


def _offer_page(target: str, token: str) -> HTMLResponse:
    """After a code sign-in on a device with no passkey: one, to come back without a code."""
    now = time.time()
    for key, (_, expires) in list(_offers.items()):
        if expires < now:
            del _offers[key]
    offer = secrets.token_urlsafe(16)
    _offers[offer] = (target, now + 10 * 60)
    return _page("Sign in faster next time", f"""<p>Add a passkey, and next time this device signs you in with
your fingerprint, face or screen lock instead of a code. It works for noesis, Roxana and The Floor.</p>
<p class="passkey"><button type="button" id="passkey-add" autofocus>Add a passkey</button>
<a href="/passkeys/later?offer={offer}">Not now</a></p>
<p class="error" id="passkey-error"></p>
<noscript><p><a href="/passkeys/later?offer={offer}">Continue</a></p></noscript>""",
                 _PASSKEYS_JS, data={"passkeys": "offer", "csrf": _csrf_for(token), "next": target})


@app.get("/passkeys/later")
def passkeys_later(offer: str = "") -> Response:
    found = _offers.pop(offer, None)
    if found is None:
        return PlainTextResponse("This sign-in has expired; start again from the app.", status_code=400)
    response = RedirectResponse(found[0], status_code=302)
    response.set_cookie(_LATER_COOKIE, "1", max_age=_LATER_TTL, path="/", httponly=True,
                        secure=tokens.issuer().startswith("https://"), samesite="lax")
    return response


def _signed_in(request: Request):
    """The session behind a passkey request from this site's own page, or 401/403."""
    session = _session(request)
    if session is None:
        raise HTTPException(401, "Your session here has ended; sign in again.")
    if not secrets.compare_digest(request.headers.get("x-csrf", ""), _csrf(request)):
        raise HTTPException(403, "Not from this site's page.")
    return session


def _device(agent: str) -> str:
    """A passkey's name, from what made it: enough to tell two apart on /account."""
    for marker, name in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Macintosh", "Mac"),
                         ("Windows", "Windows"), ("Linux", "Linux")):
        if marker in agent:
            return name
    return "A device"


@app.post("/passkeys/options")
def passkey_options(request: Request) -> Response:
    session = _signed_in(request)
    try:
        return Response(passkeys.registration_options(session.user, session.sha), media_type="application/json")
    except passkeys.PasskeyError as exc:
        raise HTTPException(400, str(exc)) from None


@app.post("/passkeys")
async def passkey_add(request: Request) -> dict:
    session = _signed_in(request)
    body = await request.json()
    try:
        passkeys.register(session.user, session.sha, body.get("credential") or {},
                          _device(request.headers.get("user-agent", "")))
    except passkeys.PasskeyError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"added": True}


@app.post("/passkeys/sign-in/options")
async def passkey_sign_in_options(request: Request) -> Response:
    body = await request.json()
    if provider.pending(str(body.get("request", ""))) is None:
        raise HTTPException(400, "This sign-in has expired; start again from the app.")
    return Response(passkeys.authentication_options(body["request"]), media_type="application/json")


@app.post("/passkeys/sign-in")
async def passkey_sign_in(request: Request) -> Response:
    """A passkey answers a pending sign-in: a session, as a code would make, and on to the client."""
    body = await request.json()
    request_id = str(body.get("request", ""))
    if provider.pending(request_id) is None:
        raise HTTPException(400, "This sign-in has expired; start again from the app.")
    try:
        user = passkeys.authenticate(request_id, body.get("credential") or {})
    except passkeys.PasskeyError as exc:
        raise HTTPException(400, str(exc)) from None
    sessions.end(request.cookies.get(_cookie_name()))
    token = sessions.create(user, request.headers.get("user-agent", ""))
    return _set_session(JSONResponse({"redirect": provider.complete(request_id, user)}), token)


# ---------------------------------------------------------------------------
# Signing out, and the person's own page
# ---------------------------------------------------------------------------

def _may_return_to(client_id: str | None, uri: str | None) -> bool:
    """A post-logout redirect: only to the origin of one of the client's own redirects."""
    if not client_id or not uri:
        return False
    client = provider.client(client_id)
    if client is None:
        return False
    origins = {f"{urlparse(str(u)).scheme}://{urlparse(str(u)).netloc}" for u in client.redirect_uris or []}
    target = urlparse(uri)
    return f"{target.scheme}://{target.netloc}" in origins and target.scheme in ("https", "http")


@app.get("/logout")
def logout(request: Request, client_id: str | None = None, post_logout_redirect_uri: str | None = None) -> Response:
    """Ends this browser's session here; the applications' own grants are theirs to end."""
    sessions.end(request.cookies.get(_cookie_name()))
    if _may_return_to(client_id, post_logout_redirect_uri):
        response: Response = RedirectResponse(post_logout_redirect_uri, status_code=302)
    else:
        response = _page("Signed out", "<p>You are signed out here. Apps you are signed in to stay signed in "
                                       "until you sign out of each, or sign out everywhere from your account.</p>")
    return _clear_session(response)


def _when(at: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(at)) if at else "before 2026-11-09"


@app.get("/account")
def account_page(request: Request) -> Response:
    session = _session(request)
    if session is None:
        return RedirectResponse(f"/login?request={provider.begin_account()}", status_code=302)
    found = accounts.account(session.user)
    csrf = f'<input type="hidden" name="csrf" value="{_csrf(request)}">'
    apps = []
    for client_id, at in sessions.grants(session.user):
        client = provider.client(client_id)
        name = escape(client.client_name if client and client.client_name else client_id)
        apps.append(f'<li><b>{name}</b>, since {_when(at)}<form method="post" action="/account">{csrf}'
                    f'<input type="hidden" name="client" value="{escape(client_id)}">'
                    f'<button name="action" value="revoke" class="quiet">Remove</button></form></li>')
    browsers = []
    for other in sessions.of(session.user):
        here = other.sha == session.sha
        label = escape(other.agent[:80] or "a browser")
        end = ("" if here else f'<form method="post" action="/account">{csrf}'
               f'<input type="hidden" name="session" value="{other.sha}">'
               f'<button name="action" value="end" class="quiet">Sign out</button></form>')
        browsers.append(f"<li>{'<b>This browser</b>' if here else label}, last used {_when(other.seen_at)}{end}</li>")
    keys = "".join(
        f'<li>{escape(key["name"] or "A passkey")}, added {_when(key["created_at"])}'
        f'{", last used " + _when(key["used_at"]) if key["used_at"] else ""}'
        f'<form method="post" action="/account">{csrf}<input type="hidden" name="passkey" value="{escape(key["id"])}">'
        f'<button name="action" value="remove_passkey" class="quiet">Remove</button></form></li>'
        for key in passkeys.of(session.user))
    return _page("Your account", f"""<p><b>{escape(session.user)}</b> ({escape(found.email if found else "")})</p>
<h2>Apps you have let in</h2>
<ul>{"".join(apps) or "<li>None.</li>"}</ul>
<h2>Passkeys</h2>
<ul>{keys or "<li>None. Add one to sign in on this device without a code.</li>"}</ul>
<p class="passkey"><button type="button" id="passkey-add">Add a passkey</button></p>
<p class="error" id="passkey-error"></p>
<h2>Where you are signed in</h2>
<ul>{"".join(browsers)}</ul>
<form method="post" action="/account">{csrf}
<button name="action" value="signout">Sign out</button><button name="action" value="everywhere" class="quiet">Sign out everywhere</button>
</form>
<p class="hint">Removing an app ends its access; it asks again the next time you use it. Signing out
everywhere ends every browser's session and every app's access.</p>""",
                 _PASSKEYS_JS, data={"passkeys": "account", "csrf": _csrf(request)})


@app.post("/account")
async def account_submit(request: Request) -> Response:
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode("utf-8", "replace")).items()}
    session = _session(request)
    if session is None or not _checked(request, form):
        return RedirectResponse("/account", status_code=303)
    action = form.get("action")
    if action == "revoke":
        sessions.revoke(session.user, form.get("client", ""))
    elif action == "end":
        sessions.end_one(session.user, form.get("session", ""))
    elif action == "remove_passkey":
        passkeys.remove(session.user, form.get("passkey", ""))
    elif action in ("signout", "everywhere"):
        if action == "everywhere":
            sessions.everywhere(session.user)
        sessions.end(request.cookies.get(_cookie_name()))
        return _clear_session(_page("Signed out", "<p>You are signed out"
                                    + (" everywhere: every browser, and every app." if action == "everywhere" else " here.")
                                    + "</p>"))
    return RedirectResponse("/account", status_code=303)


# ---------------------------------------------------------------------------
# The OAuth routes
# ---------------------------------------------------------------------------

def _with_client_credentials(token_app):
    """The SDK's /token, and before it the client_credentials grant it does not know."""
    authenticator = ClientAuthenticator(provider)

    async def asgi(scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await token_app(scope, receive, send)
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break

        async def replay():
            return {"type": "http.request", "body": body, "more_body": False}

        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
        if form.get("grant_type") != "client_credentials":
            return await token_app(scope, replay, send)
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        try:
            client = await authenticator.authenticate_request(StarletteRequest(scope, replay))
        except AuthenticationError as exc:
            response = JSONResponse({"error": "invalid_client", "error_description": exc.message},
                                    status_code=401, headers=headers)
            return await response(scope, receive, send)
        if "client_credentials" not in client.grant_types or not client.client_secret:
            response = JSONResponse({"error": "unauthorized_client"}, status_code=400, headers=headers)
            return await response(scope, receive, send)
        token = provider.application_token(client, form["scope"].split() if form.get("scope") else None)
        if token is None:
            response = JSONResponse({"error": "invalid_scope"}, status_code=400, headers=headers)
        else:
            response = JSONResponse(token.model_dump(exclude_none=True), headers=headers)
        return await response(scope, receive, send)

    return asgi


def _with_prompt(authorize_app):
    """The SDK's /authorize, with OpenID Connect's `prompt` passed on to the provider, which the SDK drops."""
    async def asgi(scope, receive, send):
        prompt = parse_qs(scope.get("query_string", b"").decode("utf-8", "replace")).get("prompt", [None])[0]
        token = PROMPT.set(prompt if prompt in ("login", "consent", "none") else None)
        try:
            await authorize_app(scope, receive, send)
        finally:
            PROMPT.reset(token)
    return asgi


for route in create_auth_routes(
    provider,
    issuer_url=AnyHttpUrl(tokens.issuer()),
    client_registration_options=ClientRegistrationOptions(
        enabled=True, valid_scopes=[REGISTERED_SCOPE], default_scopes=[REGISTERED_SCOPE]),
    revocation_options=RevocationOptions(enabled=True),
):
    if route.path == "/token":
        route.app = _with_client_credentials(route.app)
    elif route.path == "/authorize":
        route.app = _with_prompt(route.app)
    app.router.routes.append(route)


@app.get("/", include_in_schema=False)
def root() -> Response:
    return RedirectResponse("https://rvanegas.co/", status_code=302)


def main(argv: list[str] | None = None) -> int:
    import argparse

    import uvicorn
    parser = argparse.ArgumentParser(prog="dianoia-auth", description="the sign-in for rvanegas.co's projects")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args(argv)
    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=True, forwarded_allow_ips="*")
    return 0
