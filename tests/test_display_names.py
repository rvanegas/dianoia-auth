"""Display names: what a person is shown as in every application, kept here
and set by them or by The Floor, read in /me, tokens and a lookup."""

import httpx

import re

from conftest import add_client, authorize, basic, code_of, pkce, sign_in
from test_sign_in import _exchange
from test_sso import _by_code
from dianoia_auth import accounts, names, tokens


def _roxana(url, email="ann@example.com"):
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity",
               "--redirect", "https://roxana.example/signin")
    verifier, challenge = pkce()
    request_id = authorize(url, "roxana", challenge, redirect="https://roxana.example/signin")
    issued = _exchange(url, {"client_id": "roxana"}, code_of(sign_in(url, request_id, email)), verifier,
                            "https://roxana.example/signin").json()
    return issued, tokens.verify(issued["access_token"])["sub"]


def test_a_person_sets_their_name_and_every_token_and_lookup_carries_it(live):
    url = live
    issued, ann = _roxana(url)
    bearer = {"Authorization": f"Bearer {issued['access_token']}"}
    assert tokens.verify(issued["access_token"])["name"] == ann             # none set: the user name
    assert httpx.get(f"{url}/me", headers=bearer).json()["display_name"] is None
    origin = {"Origin": "https://roxana.example"}
    put = httpx.put(f"{url}/me/display_name", headers={**bearer, **origin}, json={"display_name": "  Ann   Example "})
    assert put.json() == {"display_name": "Ann Example"}
    assert put.headers["access-control-allow-origin"] == "https://roxana.example"
    assert httpx.get(f"{url}/me", headers=bearer).json()["display_name"] == "Ann Example"
    again = httpx.post(f"{url}/token", data={"grant_type": "refresh_token", "client_id": "roxana",
                                             "refresh_token": issued["refresh_token"]}).json()
    assert tokens.verify(again["access_token"])["name"] == "Ann Example"
    looked = httpx.get(f"{url}/names/display", params={"user": [ann.upper(), "nobody"]}, headers={**bearer, **origin})
    assert looked.json() == {"names": {ann: "Ann Example", "nobody": None}}
    assert looked.headers["access-control-allow-origin"] == "https://roxana.example"
    assert httpx.get(f"{url}/names/display", params={"user": ann}).status_code == 401
    assert httpx.put(f"{url}/me/display_name", headers=bearer, json={"display_name": "x" * 61}).status_code == 400
    assert httpx.put(f"{url}/me/display_name", headers=bearer, json={"display_name": ""}).json() == {"display_name": None}


def test_a_token_without_identity_cannot_set_it(live):
    url = live
    _, ann = _roxana(url)
    no_identity, _ = tokens.issue(ann, "claude", ["noesis:read"])
    assert httpx.put(f"{url}/me/display_name", headers={"Authorization": f"Bearer {no_identity}"},
                     json={"display_name": "Mallory"}).status_code == 403
    assert accounts.display_name(ann) is None


def test_the_floor_sets_its_people_s_names_even_before_they_sign_in_here(live):
    url = live
    floor = add_client("thefloor", "--name", "The Floor", "--redirect", "https://floor.example/callback",
                       "--scope", "identity", "--keeps-names")
    pair = basic("thefloor", floor["AUTH_CLIENT_SECRET"])
    reserved = httpx.post(f"{url}/names", headers=pair, json={"email": "bob@example.com", "suggest": ["bobby"]}).json()
    assert httpx.put(f"{url}/names/display", headers=pair,
                     json={"user": reserved["user"], "display_name": "Bob"}).json() == {"display_name": "Bob"}
    assert httpx.put(f"{url}/names/display", headers=pair,
                     json={"user": "nobody", "display_name": "X"}).status_code == 400
    assert httpx.put(f"{url}/names/display", json={"user": reserved["user"], "display_name": "X"}).status_code == 401
    # Bob's first sign-in takes the reserved name, and the name with it.
    _roxana(url, "bob@example.com")
    assert httpx.get(f"{url}/names/display", params={"user": reserved["user"]},
                     headers=pair).json() == {"names": {reserved["user"]: "Bob"}}
    # A rename carries it.
    names.rename_account(reserved["user"], "robert")
    assert accounts.display_name("robert") == "Bob"


def test_the_account_page_sets_it(live):
    with httpx.Client(base_url=live) as browser:
        _by_code(browser, browser.get("/account", follow_redirects=False).headers["location"])
        page = browser.get("/account").text
        assert "Your name" in page
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        browser.post("/account", data={"csrf": csrf, "action": "display_name", "display_name": "Ann"})
        assert 'value="Ann"' in browser.get("/account").text


def test_deleting_an_account_deletes_its_name(data):
    from dianoia_auth.store import connect
    import time
    with connect() as db:
        db.execute("INSERT INTO accounts (user, email, created_at) VALUES (?, ?, ?)", ("ann1", "ann@example.com", time.time()))
    accounts.set_display_name("ann1", "Ann")
    accounts.delete("ann1")
    assert accounts.display_name("ann1") is None
