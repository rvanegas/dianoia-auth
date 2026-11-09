"""Passkeys (passkeys.py): offered after a code, added, signing in without one, removed."""

import re
from urllib.parse import parse_qs, urlparse

import httpx

from dianoia_auth import accounts
from dianoia_auth.store import connect
from conftest import SENT, add_client, pkce
from softauthn import Authenticator

ROXANA = "https://roxana.example/signin"


def _authorize(browser):
    verifier, challenge = pkce()
    r = browser.get("/authorize", params={"response_type": "code", "client_id": "roxana", "redirect_uri": ROXANA,
                                          "code_challenge": challenge, "code_challenge_method": "S256", "state": "s"})
    return verifier, parse_qs(urlparse(r.headers["location"]).query)["request"][0]


def _code(browser, request_id, email="ann@example.com"):
    browser.post("/login", data={"request": request_id, "email": email, "action": "send"})
    return browser.post("/login", data={"request": request_id, "code": SENT[email], "action": "verify"})


def _data(page, name):
    return re.search(rf'data-{name}="([^"]*)"', page).group(1).replace("&amp;", "&")


def _add(browser, authenticator, csrf, origin):
    options = browser.post("/passkeys/options", headers={"X-CSRF": csrf}).json()
    return browser.post("/passkeys", json={"credential": authenticator.create(options, origin)},
                        headers={"X-CSRF": csrf})


def _with_passkey(browser, authenticator, request_id, origin):
    options = browser.post("/passkeys/sign-in/options", json={"request": request_id}).json()
    return browser.post("/passkeys/sign-in", json={"request": request_id,
                                                    "credential": authenticator.get(options, origin)})


def test_offered_after_a_code_added_and_then_signing_in_without_one(live):
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", ROXANA)
    key = Authenticator()
    with httpx.Client(base_url=live) as laptop:
        _, request_id = _authorize(laptop)
        offer = _code(laptop, request_id)
        # Offered, after the code and not before, and on to Roxana either way.
        assert offer.status_code == 200 and "Add a passkey" in offer.text
        assert _data(offer.text, "passkeys") == "offer" and _data(offer.text, "next").startswith(ROXANA)
        assert "script-src 'self'" in offer.headers["content-security-policy"]
        assert _add(laptop, key, _data(offer.text, "csrf"), live).json() == {"added": True}
    with httpx.Client(base_url=live) as elsewhere:
        # A browser that knows nobody: the passkey alone signs in, no code mailed.
        verifier, request_id = _authorize(elsewhere)
        page = elsewhere.get(f"/login?request={request_id}").text
        assert "Sign in with a passkey" in page and 'autocomplete="email webauthn"' in page
        sent_before = dict(SENT)
        done = _with_passkey(elsewhere, key, request_id, live)
        assert done.status_code == 200 and done.json()["redirect"].startswith(ROXANA) and SENT == sent_before
        code = parse_qs(urlparse(done.json()["redirect"]).query)["code"][0]
        issued = httpx.post(f"{live}/token", data={"grant_type": "authorization_code", "code": code,
                                                   "redirect_uri": ROXANA, "client_id": "roxana",
                                                   "code_verifier": verifier}).json()
        assert issued["scope"] == "identity"
        assert elsewhere.cookies.get("session")  # and a session there, as a code makes
        # Next time, no offer: this account has a passkey.
        _, request_id = _authorize(elsewhere)
        assert _code(elsewhere, request_id).status_code == 302


def test_a_passkey_answers_one_challenge_once_and_for_this_site_alone(live):
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", ROXANA)
    key, stranger = Authenticator(), Authenticator()
    with httpx.Client(base_url=live) as browser:
        _, request_id = _authorize(browser)
        offer = _code(browser, request_id)
        _add(browser, key, _data(offer.text, "csrf"), live)
        _, request_id = _authorize(browser)
        options = browser.post("/passkeys/sign-in/options", json={"request": request_id}).json()
        answer = key.get(options, live)
        # From another site's page: refused, and the challenge is spent with it.
        phished = key.get(options, "https://evil.example")
        assert browser.post("/passkeys/sign-in", json={"request": request_id, "credential": phished}).status_code == 400
        assert browser.post("/passkeys/sign-in", json={"request": request_id, "credential": answer}).status_code == 400
        # A passkey this site never registered.
        options = browser.post("/passkeys/sign-in/options", json={"request": request_id}).json()
        unknown = browser.post("/passkeys/sign-in", json={"request": request_id,
                                                          "credential": stranger.get(options, live)})
        assert unknown.status_code == 400 and "not one this site knows" in unknown.json()["detail"]
        # A disabled account's passkey signs nobody in.
        accounts.set_disabled("ann1", True)
        assert _with_passkey(browser, key, request_id, live).status_code == 400
        accounts.set_disabled("ann1", False)
        assert _with_passkey(browser, key, request_id, live).status_code == 200
        with connect() as db:
            assert db.execute("SELECT sign_count FROM passkeys").fetchone()[0] == key.counter


def test_only_a_signed_in_page_of_this_site_adds_one(live):
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", ROXANA)
    with httpx.Client(base_url=live) as browser:
        assert browser.post("/passkeys/options").status_code == 401
        _, request_id = _authorize(browser)
        _code(browser, request_id)
        assert browser.post("/passkeys/options").status_code == 403  # no token from the page
        assert browser.post("/passkeys/options", headers={"X-CSRF": "forged"}).status_code == 403


def test_not_now_is_remembered_and_names_an_offer_never_a_url(live):
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", ROXANA)
    with httpx.Client(base_url=live) as browser:
        _, request_id = _authorize(browser)
        offer = _code(browser, request_id)
        later = re.search(r'href="(/passkeys/later\?offer=[^"]+)"', offer.text).group(1)
        back = browser.get(later)
        assert back.status_code == 302 and back.headers["location"].startswith(ROXANA)
        assert browser.get(later).status_code == 400  # once
        assert browser.get("/passkeys/later", params={"offer": "https://evil.example"}).status_code == 400
        _, request_id = _authorize(browser)
        browser.get("/logout")
        assert _code(browser, request_id).status_code == 302  # not asked again here


def test_the_account_page_adds_lists_and_removes_them(live):
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity", "--redirect", ROXANA)
    key = Authenticator()
    with httpx.Client(base_url=live, headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0)"}) as phone:
        _, request_id = _authorize(phone)
        _code(phone, request_id)
        page = phone.get("/account").text
        assert "Passkeys" in page and _data(page, "passkeys") == "account"
        assert _add(phone, key, _data(page, "csrf"), live).json() == {"added": True}
        page = phone.get("/account").text
        assert "iPhone, added" in page
        passkey = re.search(r'name="passkey" value="([^"]+)"', page).group(1)
        phone.post("/account", data={"action": "remove_passkey", "passkey": passkey, "csrf": _data(page, "csrf")})
        assert "iPhone, added" not in phone.get("/account").text
        _, request_id = _authorize(phone)
        assert _with_passkey(phone, key, request_id, live).status_code == 400


def test_the_script_is_this_sites_own(live):
    script = httpx.get(f"{live}/passkeys.js")
    assert script.status_code == 200 and script.headers["content-type"].startswith("text/javascript")
    assert "navigator.credentials.get" in script.text and "mediation: \"conditional\"" in script.text
