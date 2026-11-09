"""A live auth server for the tests, and a data directory of its own for each test.

The issuer is fixed before the app is imported, since the SDK's metadata is
built then; the data directory is read on every call, so each test has its
own auth.db and key.
"""

import base64
import hashlib
import importlib.util
import io
import os
import re
import secrets
import socket
import threading
import time
from contextlib import redirect_stdout
from pathlib import Path

import httpx
import pytest
import uvicorn

REPO = Path(__file__).resolve().parent.parent

with socket.socket() as _s:
    _s.bind(("127.0.0.1", 0))
    PORT = _s.getsockname()[1]
URL = f"http://127.0.0.1:{PORT}"
os.environ["AUTH_PUBLIC_URL"] = URL
for _name in ("AUTH_SMTP_HOST", "AUTH_TURNSTILE_SECRET", "AUTH_TURNSTILE_SITE_KEY"):
    os.environ.pop(_name, None)

# The codes the server mailed, by address: mail.send_code, replaced.
SENT: dict[str, str] = {}
CALLBACK = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("dianoia_auth.mail.send_code", lambda to, code, client_name: SENT.__setitem__(to, code))
    return tmp_path


@pytest.fixture(scope="session")
def server():
    from dianoia_auth.server import app
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    while not uv.started:
        time.sleep(0.05)
    yield URL
    uv.should_exit = True
    thread.join(5)


@pytest.fixture
def live(server, data):
    return URL


def script(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def add_client(*argv) -> dict:
    """scripts/add_client.py, its printed lines as a dict."""
    out = io.StringIO()
    with redirect_stdout(out):
        script("add_client").main(list(argv))
    return dict(line.split("=", 1) for line in out.getvalue().split() if "=" in line)


def basic(client_id, secret):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register(url, redirect=CALLBACK, **extra):
    return httpx.post(f"{url}/register", json={
        "redirect_uris": [redirect], "client_name": "Claude",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post", **extra})


def authorize(url, client_id, challenge, redirect=CALLBACK, state="s1", **extra):
    r = httpx.get(f"{url}/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state, **extra})
    assert r.status_code == 302, r.text
    login = r.headers["location"]
    assert login.startswith(f"{url}/login?request="), login
    return login.split("request=")[1]


def sign_in(url, request_id, email="ann@example.com"):
    sent = httpx.post(f"{url}/login", data={"request": request_id, "email": email, "action": "send"})
    assert sent.status_code == 200 and "on its way" in sent.text, sent.text
    return past_offer(url, httpx.post(f"{url}/login", data={"request": request_id, "code": SENT[email], "action": "verify"}))


def past_offer(url, response, client=None):
    """A code sign-in on a device with no passkey is offered one first: "Not now", and on to the client."""
    if response.status_code == 200 and "/passkeys/later?offer=" in response.text:
        later = re.search(r'href="(/passkeys/later\?offer=[^"]+)"', response.text).group(1)
        return (client.get(later) if client is not None else httpx.get(f"{url}{later}"))
    return response


def code_of(response) -> str:
    from urllib.parse import parse_qs, urlparse
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]
