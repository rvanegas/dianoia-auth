"""dianoia-auth's HTTP app, at auth.rvanegas.co: the OAuth routes, the sign-in page, /me and the register of names.

- `GET /healthz`: open, the deployed commit (dianoia_auth/deployed.json, stamped by
  `ts deploy`).
- The OAuth server, by the MCP SDK (`create_auth_routes`): metadata at
  /.well-known/oauth-authorization-server, /authorize, /token, /register,
  /revoke; and /token also takes `client_credentials` (provider.py, an
  application's own token), which the SDK does not.
- `/.well-known/jwks.json`: the keys access tokens are signed with
  (tokens.py), for resource servers to check them by.
- `/login`: the sign-in, by emailed code, that /authorize sends people to.
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
from html import escape
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl, BaseModel
from starlette.requests import Request as StarletteRequest

from dianoia_auth import accounts, names, tokens
from dianoia_auth.provider import REGISTERED_SCOPE, provider, what_it_asks

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


def _login_page(request_id: str, sign_in, error: str = "") -> HTMLResponse:
    client_name = escape(sign_in.client.client_name or "An application")
    redirect_host = escape(urlparse(str(sign_in.params.redirect_uri)).hostname or "")
    asks = what_it_asks(sign_in.scopes)
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
<label>Your email address<br><input name="email" type="email" autocomplete="email" required autofocus></label>
{challenge}
<button name="action" value="send">Send me a code</button>{deny}
</form>
<p class="hint">No account yet? Signing in makes one: one account for noesis, Roxana and The Floor.</p>"""
        script = ('<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
                  if site_key else "")
    # No form-action: the answer to a sign-in is a redirect to the client.
    csp = ("default-src 'none'; style-src 'unsafe-inline'; script-src https://challenges.cloudflare.com; "
           "frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; "
           "frame-ancestors 'none'; base-uri 'none'")
    return HTMLResponse(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>{script}
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}}
input{{width:100%;font:inherit;padding:.4rem;box-sizing:border-box}}button{{font:inherit;margin:.8rem .6rem 0 0}}
.error{{color:#b00}}.hint{{color:#555;font-size:.9rem}}.cf-turnstile{{margin-top:.8rem}}</style></head><body>
<h1>Sign in</h1>
<p><b>{client_name}</b> ({redirect_host}) asks {asks}.</p>
{note}{form}
</body></html>""", headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                            "Referrer-Policy": "no-referrer", "Content-Security-Policy": csp})


@app.get("/login")
def login(request: str) -> Response:
    sign_in = provider.pending(request)
    if sign_in is None:
        return PlainTextResponse("This sign-in has expired; start again from the app.", status_code=400)
    return _login_page(request, sign_in)


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
        target = provider.verify_code(request_id, form.get("code", ""))
        if target is not None:
            return RedirectResponse(target, status_code=302)
        if provider.pending(request_id) is None:
            return PlainTextResponse("Too many wrong codes; start again from the app.", status_code=400)
        return _login_page(request_id, sign_in, error="That is not the code we sent.")
    return PlainTextResponse("Unknown action.", status_code=400)


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


for route in create_auth_routes(
    provider,
    issuer_url=AnyHttpUrl(tokens.issuer()),
    client_registration_options=ClientRegistrationOptions(
        enabled=True, valid_scopes=[REGISTERED_SCOPE], default_scopes=[REGISTERED_SCOPE]),
    revocation_options=RevocationOptions(enabled=True),
):
    if route.path == "/token":
        route.app = _with_client_credentials(route.app)
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
