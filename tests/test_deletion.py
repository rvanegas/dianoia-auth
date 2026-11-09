"""A person deleting their own account (accounts.delete, /account/delete), and each project told (departures.py)."""

import re
import time

import httpx

from dianoia_auth import accounts, departures, passkeys, sessions, tokens
from dianoia_auth.store import connect
from test_sso import ROXANA, _authorize, _by_code, _clients, _code_in, _tokens


def _calls(monkeypatch, answer=True):
    made = []
    monkeypatch.setattr(departures, "_call", lambda url, project, user: (made.append((project, user)), answer)[1])
    return made


def _signed_in_to_delete(browser):
    """Through the account page's own sign-in, to the deletion page; a sign-in
    just made is recent enough, so it is made to look old first."""
    with connect() as db:
        db.execute("UPDATE sessions SET created_at = ?", (time.time() - 3600,))
    to_login = browser.get("/account/delete")
    assert to_login.status_code == 302 and "/login?request=" in to_login.headers["location"]
    assert "Sign in again to delete your account" in browser.get(to_login.headers["location"]).text
    assert _by_code(browser, to_login.headers["location"]).endswith("/account/delete")
    page = browser.get("/account/delete")
    assert "Delete your account" in page.text
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def test_deleting_removes_everything_here_and_holds_the_name(live, monkeypatch):
    made = _calls(monkeypatch)
    _clients()
    with httpx.Client(base_url=live) as browser:
        verifier, login = _authorize(browser, "roxana", ROXANA)
        issued = _tokens(live, "roxana", ROXANA, _code_in(_by_code(browser, login)), verifier)
        with connect() as db:
            db.execute("INSERT INTO passkeys (credential_id, user, public_key, created_at) VALUES ('k', 'ann1', x'00', 0)")
            db.execute("INSERT INTO reservations (user, email, client, created_at) VALUES "
                       "('ann_floor', 'ann@example.com', 'thefloor', 0)")
        csrf = _signed_in_to_delete(browser)
        done = browser.post("/account/delete", data={"csrf": csrf, "user": "ANN1 "})
        assert "ann1 is deleted" in done.text and not browser.cookies.get("session")
    assert accounts.account("ann1") is None and sessions.of("ann1") == [] and sessions.grants("ann1") == []
    assert passkeys.of("ann1") == [] and accounts.reservation_for_email("ann@example.com") is None
    refused = httpx.post(f"{live}/token", data={"grant_type": "refresh_token", "client_id": "roxana",
                                                "refresh_token": issued["refresh_token"]})
    assert refused.status_code == 400
    # The name is never given out again; the address makes a new account.
    with connect() as db:
        assert accounts.taken(db, "ann1")
    assert accounts.create_account("ann@example.com").user != "ann1"
    # Each project told, and nothing left owed.
    assert sorted(made) == [("noesis", "ann1"), ("thefloor", "ann1")] and departures.owed() == []


def test_deleting_asks_for_a_recent_sign_in_and_the_name(live, monkeypatch):
    made = _calls(monkeypatch)
    with httpx.Client(base_url=live) as browser:
        csrf = _signed_in_to_delete(browser)
        # A wrong name, or a form from elsewhere, deletes nothing.
        wrong = browser.post("/account/delete", data={"csrf": csrf, "user": "bob1"})
        assert "nothing was deleted" in wrong.text
        assert browser.post("/account/delete", data={"csrf": "forged", "user": "ann1"}).status_code == 303
        assert accounts.account("ann1") is not None
        # A session signed in long ago is sent to sign in again.
        with connect() as db:
            db.execute("UPDATE sessions SET created_at = ?", (time.time() - 3600,))
        assert browser.get("/account/delete").status_code == 302
        assert browser.post("/account/delete", data={"csrf": csrf, "user": "ann1"}).status_code == 303
        assert accounts.account("ann1") is not None and made == []


def test_a_project_that_does_not_answer_is_told_again(live, monkeypatch):
    accounts.create_account("ann@example.com")
    _calls(monkeypatch, answer=False)
    accounts.delete("ann1")
    assert departures.tell("ann1") == 2 and len(departures.owed()) == 2
    made = _calls(monkeypatch)
    assert departures.tell() == 0 and departures.owed() == [] and len(made) == 2


def test_the_call_carries_auths_own_token_for_that_project_alone(data, monkeypatch):
    sent = []

    class Answer:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: (sent.append(request), Answer())[1])
    accounts.create_account("ann@example.com")
    monkeypatch.setenv("AUTH_PROJECT_URLS", '{"noesis": "https://noesis.example"}')
    accounts.delete("ann1")
    assert departures.tell() == 0
    (request,) = sent
    assert request.get_method() == "DELETE" and request.full_url == "https://noesis.example/users/ann1"
    claims = tokens.verify(request.get_header("Authorization").removeprefix("Bearer "))
    assert claims["sub"] == claims["client_id"] == "dianoia-auth"
    assert claims["scope"] == "noesis:erase" and claims["aud"] == tokens.issuer()
