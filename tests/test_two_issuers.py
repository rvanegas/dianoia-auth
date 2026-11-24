"""The move to twohands.co: one server answering as two issuers, each as the host asked (tokens.py).

COMPATIBILITY for the overlap; these go with AUTH_ALSO_URLS (rvanegas-site's
move-everything-from-rvanegas-co-to-twohands-co.md, step 8).
"""

import httpx
import jwt

from conftest import ALSO, ALSO_HOST, CALLBACK, SENT, add_client, code_of, pkce, register, script
from dianoia_auth import mail, passkeys, tokens
from dianoia_auth.provider import provider

OLD = {"Host": ALSO_HOST}


def test_metadata_names_the_issuer_asked(live):
    url = live
    assert httpx.get(f"{url}/.well-known/oauth-authorization-server").json()["issuer"].rstrip("/") == url
    old = httpx.get(f"{url}/.well-known/oauth-authorization-server", headers=OLD).json()
    assert old["issuer"].rstrip("/") == ALSO
    assert old["authorization_endpoint"] == f"{ALSO}/authorize" and old["token_endpoint"] == f"{ALSO}/token"
    # A host it is not answers as its own issuer.
    other = httpx.get(f"{url}/.well-known/oauth-authorization-server", headers={"Host": "elsewhere.example"})
    assert other.json()["issuer"].rstrip("/") == url


def test_a_sign_in_at_the_old_name_stays_there_and_its_token_is_good_at_both(live):
    url = live
    client = register(url).json()
    verifier, challenge = pkce()
    r = httpx.get(f"{url}/authorize", headers=OLD, params={
        "response_type": "code", "client_id": client["client_id"], "redirect_uri": CALLBACK,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s1"})
    login = r.headers["location"]
    assert login.startswith(f"{ALSO}/login?request="), login
    request_id = login.split("request=")[1]
    httpx.post(f"{url}/login", headers=OLD, data={"request": request_id, "email": "bea@example.com", "action": "send"})
    back = httpx.post(f"{url}/login", headers=OLD,
                      data={"request": request_id, "code": SENT["bea@example.com"], "action": "verify"})
    if back.status_code == 200:
        later = back.text.split('href="/passkeys/later?offer=')[1].split('"')[0]
        back = httpx.get(f"{url}/passkeys/later?offer={later}", headers=OLD)
    issued = httpx.post(f"{url}/token", headers=OLD, data={
        "grant_type": "authorization_code", "code": code_of(back), "redirect_uri": CALLBACK,
        "client_id": client["client_id"], "client_secret": client["client_secret"],
        "code_verifier": verifier}).json()
    claims = jwt.decode(issued["access_token"], options={"verify_signature": False})
    assert claims["iss"] == ALSO and claims["aud"] == ALSO
    bearer = {"Authorization": f"Bearer {issued['access_token']}"}
    assert httpx.get(f"{url}/me", headers=bearer).json()["user"] == claims["sub"]
    assert httpx.get(f"{url}/me", headers={**bearer, **OLD}).status_code == 200


def test_a_token_from_neither_issuer_is_refused(data):
    with tokens.answering(ALSO_HOST):
        token, _ = tokens.issue("ann", "x", ["noesis:read"])
    assert tokens.verify(token)["iss"] == ALSO
    forged = jwt.encode({**jwt.decode(token, options={"verify_signature": False}), "iss": "https://evil.example"},
                        tokens._key(), algorithm="EdDSA", headers={"kid": tokens._kid(tokens._key())})
    assert tokens.verify(forged) is None


def test_passkeys_and_mail_follow_the_host_asked(monkeypatch):
    monkeypatch.setenv("AUTH_PUBLIC_URL", "https://auth.twohands.co")
    monkeypatch.setenv("AUTH_ALSO_URLS", "https://auth.rvanegas.co")
    monkeypatch.setenv("AUTH_MAIL_FROM", "Two Hands <sign-in@twohands.co>")
    assert passkeys.rp_id() == "auth.twohands.co" and mail.sender() == "Two Hands <sign-in@twohands.co>"
    with tokens.answering("auth.rvanegas.co"):
        assert tokens.issuer() == "https://auth.rvanegas.co"
        assert passkeys.rp_id() == "auth.rvanegas.co" and mail.sender() == "rvanegas.co <sign-in@rvanegas.co>"
    with tokens.answering("auth.twohands.co"):
        assert mail.sender() == "Two Hands <sign-in@twohands.co>"
    monkeypatch.delenv("AUTH_MAIL_FROM")
    assert mail.sender() == "twohands.co <sign-in@twohands.co>"


def test_the_operator_adds_each_clients_redirects_under_the_new_domain(data, capsys):
    add_client("roxana", "--name", "Roxana", "--public", "--redirect", "https://roxana.rvanegas.co/auth/callback",
               "--redirect", "http://localhost:5173/auth/callback", "--scope", "identity")
    add_client("thefloor", "--name", "The Floor", "--redirect", "https://thefloor.rvanegas.co/noesis/callback",
               "--scope", "noesis:read", "--keeps-names")
    secret = provider.client("thefloor").client_secret
    move = script("add_redirects").main
    move(["rvanegas.co", "twohands.co", "--dry-run"])
    assert [str(u) for u in provider.client("roxana").redirect_uris] == [
        "https://roxana.rvanegas.co/auth/callback", "http://localhost:5173/auth/callback"]
    move(["rvanegas.co", "twohands.co"])
    assert "https://roxana.twohands.co/auth/callback" in [str(u) for u in provider.client("roxana").redirect_uris]
    assert "https://roxana.twohands.co" in provider.browser_origins()
    floor = provider.client("thefloor")
    assert [str(u) for u in floor.redirect_uris] == [
        "https://thefloor.rvanegas.co/noesis/callback", "https://thefloor.twohands.co/noesis/callback"]
    # Its secret and its standing as a keeper of names are untouched; run again, nothing changes.
    assert floor.client_secret == secret and provider.keeps_names("thefloor", secret)
    capsys.readouterr()
    move(["rvanegas.co", "twohands.co"])
    assert "0 clients changed" in capsys.readouterr().out
    # After the overlap: the old ones go, but for a client kept.
    move(["rvanegas.co", "twohands.co", "--remove", "--keep", "thefloor"])
    assert [str(u) for u in provider.client("roxana").redirect_uris] == [
        "http://localhost:5173/auth/callback", "https://roxana.twohands.co/auth/callback"]
    assert len(provider.client("thefloor").redirect_uris) == 2
