"""Signing in once, for every client (sessions.py): the session, consents, prompt, signing out, /account."""

import re
import time
from urllib.parse import parse_qs, urlparse

import httpx

from dianoia_auth import accounts, sessions
from dianoia_auth.store import connect
from conftest import SENT, add_client, pkce

ROXANA = "https://roxana.example/signin"
WEB = "https://noesis.example/web/"


def _clients():
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", ROXANA)
    add_client("noesis-web", "--name", "noesis on the web", "--public", "--scope", "noesis:api noesis:read",
               "--redirect", WEB)


def _authorize(browser, client_id, redirect, **extra):
    verifier, challenge = pkce()
    r = browser.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                                          "code_challenge": challenge, "code_challenge_method": "S256",
                                          "state": "s", **extra})
    assert r.status_code == 302, r.text
    return verifier, r.headers["location"]


def _code_in(location):
    return parse_qs(urlparse(location).query).get("code", [None])[0]


def _tokens(url, client_id, redirect, code, verifier):
    return httpx.post(f"{url}/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                           "client_id": client_id, "code_verifier": verifier}).json()


def _by_code(browser, login_url, email="ann@example.com"):
    """Through the emailed code, from a /login page: where it sends the browser."""
    request_id = parse_qs(urlparse(login_url).query)["request"][0]
    assert 'type="email"' in browser.get(login_url).text
    browser.post("/login", data={"request": request_id, "email": email, "action": "send"})
    back = browser.post("/login", data={"request": request_id, "code": SENT[email], "action": "verify"})
    assert back.status_code == 302, back.text
    return back.headers["location"]


def test_one_sign_in_reaches_every_client(live, monkeypatch):
    _clients()
    mailed = []
    monkeypatch.setattr("dianoia_auth.mail.send_code",
                        lambda to, code, client_name: (mailed.append(to), SENT.__setitem__(to, code)))
    with httpx.Client(base_url=live) as browser:
        # Roxana first, by code: the browser is signed in here from now on.
        verifier, login = _authorize(browser, "roxana", ROXANA)
        back = _by_code(browser, login)
        assert back.startswith(ROXANA) and browser.cookies.get("session")
        assert _tokens(live, "roxana", ROXANA, _code_in(back), verifier)["scope"] == "identity"
        # noesis's web client: no code, but asked once what it may have.
        verifier, login = _authorize(browser, "noesis-web", WEB)
        page = browser.get(login)
        assert "Continue as ann1" in page.text and "to keep your noesis libraries" in page.text
        assert 'type="email"' not in page.text
        request_id = parse_qs(urlparse(login).query)["request"][0]
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        # A form from elsewhere, without the page's token, does not continue.
        forged = browser.post("/login", data={"request": request_id, "action": "continue"})
        assert 'type="email"' in forged.text
        back = browser.post("/login", data={"request": request_id, "action": "continue", "csrf": csrf})
        assert back.headers["location"].startswith(WEB)
        issued = _tokens(live, "noesis-web", WEB, _code_in(back.headers["location"]), verifier)
        assert issued["scope"] == "noesis:api noesis:read"
        # And from then on, straight through: no page at all.
        verifier, login = _authorize(browser, "noesis-web", WEB)
        straight = browser.get(login)
        assert straight.status_code == 302 and _code_in(straight.headers["location"])
        assert mailed == ["ann@example.com"]  # one code, for both clients


def test_prompt_asks_again_or_not_at_all(live):
    _clients()
    with httpx.Client(base_url=live) as browser:
        # prompt=none with nobody signed in: back to the client at once, login_required.
        _, location = _authorize(browser, "roxana", ROXANA, prompt="none")
        assert "error=login_required" in browser.get(location).headers["location"]
        _, login = _authorize(browser, "roxana", ROXANA)
        _by_code(browser, login)
        # Signed in, but noesis's web client never let in: consent_required.
        _, location = _authorize(browser, "noesis-web", WEB, prompt="none")
        assert "error=consent_required" in browser.get(location).headers["location"]
        # prompt=login asks for the code whatever the session; prompt=consent asks again.
        _, location = _authorize(browser, "roxana", ROXANA, prompt="login")
        assert 'type="email"' in browser.get(location).text
        _, location = _authorize(browser, "roxana", ROXANA, prompt="consent")
        assert "Continue as ann1" in browser.get(location).text
        # "Use another address" leaves the session for the code.
        request_id = parse_qs(urlparse(location).query)["request"][0]
        assert 'type="email"' in browser.post("/login", data={"request": request_id, "action": "other"}).text


def test_signing_out_here_ends_the_session_and_returns_to_the_client(live):
    _clients()
    with httpx.Client(base_url=live) as browser:
        _, login = _authorize(browser, "roxana", ROXANA)
        _by_code(browser, login)
        # Back to the client's own origin, never anywhere else.
        assert browser.get("/logout", params={"client_id": "roxana", "post_logout_redirect_uri": "https://evil.example/"}
                           ).status_code == 200
        _, login = _authorize(browser, "roxana", ROXANA)
        assert 'type="email"' in browser.get(login).text
        _, login = _authorize(browser, "roxana", ROXANA)
        _by_code(browser, login)
        out = browser.get("/logout", params={"client_id": "roxana", "post_logout_redirect_uri": "https://roxana.example/"})
        assert out.status_code == 302 and out.headers["location"] == "https://roxana.example/"
        _, login = _authorize(browser, "roxana", ROXANA)
        assert 'type="email"' in browser.get(login).text


def test_a_session_ends_with_its_account_and_its_time(live):
    _clients()
    with httpx.Client(base_url=live) as browser:
        _, login = _authorize(browser, "roxana", ROXANA)
        _by_code(browser, login)
        accounts.set_disabled("ann1", True)
        _, login = _authorize(browser, "roxana", ROXANA)
        assert 'type="email"' in browser.get(login).text
        accounts.set_disabled("ann1", False)
        _, login = _authorize(browser, "roxana", ROXANA)
        assert browser.get(login).status_code == 302
        with connect() as db:
            db.execute("UPDATE sessions SET expires_at = ?", (time.time() - 1,))
        _, login = _authorize(browser, "roxana", ROXANA)
        assert 'type="email"' in browser.get(login).text


def test_the_account_page_lets_apps_and_browsers_go(live):
    _clients()
    with httpx.Client(base_url=live) as browser, httpx.Client(base_url=live) as phone:
        # Signed in on two browsers; the web client let in, with a grant.
        verifier, login = _authorize(browser, "noesis-web", WEB)
        issued = _tokens(live, "noesis-web", WEB, _code_in(_by_code(browser, login)), verifier)
        _, login = _authorize(phone, "roxana", ROXANA)
        _by_code(phone, login)
        page = browser.get("/account")
        assert "ann1" in page.text and "noesis on the web" in page.text and "Roxana" in page.text
        assert page.text.count("<li>") >= 3  # two apps, and the other browser besides this one
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        # Removing an app ends its grant.
        browser.post("/account", data={"action": "revoke", "client": "noesis-web", "csrf": csrf})
        refused = httpx.post(f"{live}/token", data={"grant_type": "refresh_token", "client_id": "noesis-web",
                                                    "refresh_token": issued["refresh_token"]})
        assert refused.status_code == 400 and "noesis on the web" not in browser.get("/account").text
        # Signing the other browser out.
        phone_session = next(s.sha for s in sessions.of("ann1")
                             if s.sha != sessions.current(browser.cookies.get("session")).sha)
        browser.post("/account", data={"action": "end", "session": phone_session, "csrf": csrf})
        _, login = _authorize(phone, "roxana", ROXANA)
        assert 'type="email"' in phone.get(login).text
        # Everywhere: this browser too, and every grant.
        browser.post("/account", data={"action": "everywhere", "csrf": csrf})
        assert sessions.of("ann1") == [] and sessions.grants("ann1") == []


def test_the_account_page_signs_in_for_itself(live):
    with httpx.Client(base_url=live) as browser:
        to_login = browser.get("/account")
        assert to_login.status_code == 302 and "/login?request=" in to_login.headers["location"]
        page = browser.get(to_login.headers["location"])
        assert "Sign in to see your account" in page.text
        assert _by_code(browser, to_login.headers["location"]).endswith("/account")
        assert "Your account" in browser.get("/account").text
        # Nobody else's form changes anything here.
        assert browser.post("/account", data={"action": "everywhere", "csrf": "forged"}).status_code == 303
        assert len(sessions.of("ann1")) == 1
