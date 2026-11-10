"""Handing a sign-in to a browser (handoff.py): The Floor signs its person in to their own browser, on to noesis."""

import re
import time

import httpx

from conftest import add_client, basic
from dianoia_auth import accounts, handoff, sessions, tokens

WEB = "https://noesis.example/web/"


def _setup():
    floor = add_client("thefloor", "--name", "The Floor", "--redirect", "https://floor.example/callback",
                       "--scope", "noesis:read noesis:import", "--keeps-names")
    add_client("noesis-web", "--name", "noesis on the web", "--public", "--scope", "noesis:api noesis:read",
               "--redirect", WEB)
    ann = accounts.create_account("ann@example.com").user
    person, _ = tokens.issue(ann, "thefloor", ["noesis:read", "noesis:import"])
    return basic("thefloor", floor["AUTH_CLIENT_SECRET"]), person, ann


def _code(url, pair, person, next_url=WEB + "?library=ann1%2Fnotes"):
    r = httpx.post(f"{url}/handoff", headers=pair, json={"token": person, "next": next_url})
    assert r.status_code == 200, r.text
    assert r.json()["url"].startswith(f"{url}/handoff?code=")
    return r.json()["url"].removeprefix(url)


def test_a_handoff_signs_a_browser_in_and_goes_on_to_noesis(live):
    url = live
    pair, person, ann = _setup()
    link = _code(url, pair, person)
    with httpx.Client(base_url=url) as browser:
        back = browser.get(link)
        assert back.status_code == 302 and back.headers["location"] == WEB + "?library=ann1%2Fnotes"
        assert sessions.current(browser.cookies.get("session")).user == ann
        # One use: the same link again is expired, and signs nobody in.
        with httpx.Client(base_url=url) as other:
            assert other.get(link).status_code == 400 and not other.cookies.get("session")
        # Already signed in as the same person: straight on, the session kept.
        held = browser.cookies.get("session")
        assert browser.get(_code(url, pair, person)).status_code == 302
        assert browser.cookies.get("session") == held


def test_it_takes_the_application_and_its_own_persons_token_together(live):
    url = live
    pair, person, ann = _setup()
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", "https://roxana.example/s")
    body = {"token": person, "next": WEB}
    # The token alone, or the secret wrong: no code.
    assert httpx.post(f"{url}/handoff", json=body).status_code == 401
    assert httpx.post(f"{url}/handoff", headers=basic("thefloor", "nope"), json=body).status_code == 401
    # A browser app has no secret to show.
    assert httpx.post(f"{url}/handoff", headers=basic("roxana", ""), json=body).status_code == 401
    # Another client's person token, or the application's own token, is not this person's here.
    roxanas, _ = tokens.issue(ann, "roxana", ["identity"])
    own, _ = tokens.issue("thefloor", "thefloor", ["noesis:keep"])
    for token in (roxanas, own, "not.a.token"):
        assert httpx.post(f"{url}/handoff", headers=pair, json={**body, "token": token}).status_code == 403
    # Only on to a browser app's own origin: never an open redirect.
    for elsewhere in ("https://evil.example/", "https://floor.example/callback", "javascript:alert(1)"):
        assert httpx.post(f"{url}/handoff", headers=pair, json={**body, "next": elsewhere}).status_code == 400
    # A disabled account is handed to nobody.
    accounts.set_disabled(ann, True)
    assert httpx.post(f"{url}/handoff", headers=pair, json=body).status_code == 403


def test_a_code_lasts_a_minute(live, monkeypatch):
    url = live
    pair, person, _ = _setup()
    link = _code(url, pair, person)
    later = time.time() + handoff.CODE_TTL + 1
    monkeypatch.setattr("dianoia_auth.handoff.time.time", lambda: later)
    with httpx.Client(base_url=url) as browser:
        assert browser.get(link).status_code == 400 and not browser.cookies.get("session")


def test_a_browser_signed_in_as_somebody_else_is_asked(live):
    url = live
    pair, person, ann = _setup()
    bob = accounts.create_account("bob@example.com").user
    with httpx.Client(base_url=url) as browser:
        browser.cookies.set("session", sessions.create(bob), domain="127.0.0.1")
        page = browser.get(_code(url, pair, person))
        assert page.status_code == 200 and f"signed in as <b>{bob}</b>" in page.text and f"Continue as {ann}" in page.text
        code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        # A form from elsewhere, without the page's token, switches nobody.
        assert browser.post("/handoff/choice", data={"code": code, "action": "switch"}).status_code == 400
        assert sessions.current(browser.cookies.get("session")).user == bob
        # Staying: on to noesis as Bob, the code used up.
        page = browser.get(_code(url, pair, person))
        code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)
        stay = browser.post("/handoff/choice", data={"code": code, "csrf": csrf, "action": "stay"})
        assert stay.status_code == 303 and stay.headers["location"].startswith(WEB)
        assert sessions.current(browser.cookies.get("session")).user == bob
        # Switching: Ann's session from now on, Bob's ended.
        page = browser.get(_code(url, pair, person))
        code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)
        switch = browser.post("/handoff/choice", data={"code": code, "csrf": csrf, "action": "switch"})
        assert switch.status_code == 302 and switch.headers["location"].startswith(WEB)
        assert sessions.current(browser.cookies.get("session")).user == ann
        assert sessions.of(bob) == []
