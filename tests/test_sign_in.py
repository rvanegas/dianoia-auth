"""The OAuth server end to end: registration, the emailed code, tokens, refresh, scopes."""

import httpx
import jwt
import pytest

from dianoia_auth import accounts, tokens
from conftest import CALLBACK, SENT, add_client, authorize, basic, code_of, past_offer, pkce, register, sign_in


def _exchange(url, client, code, verifier, redirect=CALLBACK):
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
            "client_id": client["client_id"], "code_verifier": verifier}
    if client.get("client_secret"):
        data["client_secret"] = client["client_secret"]
    return httpx.post(f"{url}/token", data=data)


def test_claude_ai_signs_in_with_an_emailed_code(live):
    url = live
    assert "token_endpoint" in httpx.get(f"{url}/.well-known/oauth-authorization-server").json()
    assert register(url, "https://evil.example/cb").status_code == 400
    client = register(url).json()
    assert client["scope"] == "noesis:read"
    verifier, challenge = pkce()
    request_id = authorize(url, client["client_id"], challenge, resource="https://noesis.example/mcp")
    page = httpx.get(f"{url}/login", params={"request": request_id})
    assert page.status_code == 200 and "Claude" in page.text and "claude.ai" in page.text
    assert "to read your noesis libraries" in page.text and 'type="email"' in page.text
    bad = httpx.post(f"{url}/login", data={"request": request_id, "email": "nope", "action": "send"})
    assert "not an email address" in bad.text
    sent = httpx.post(f"{url}/login", data={"request": request_id, "email": " Ann@Example.com ", "action": "send"})
    assert "on its way to <b>ann@example.com</b>" in sent.text
    code = SENT["ann@example.com"]
    wrong = httpx.post(f"{url}/login", data={
        "request": request_id, "code": f"{(int(code) + 1) % 10**6:06d}", "action": "verify"})
    assert wrong.status_code == 200 and "not the code" in wrong.text
    back = past_offer(url, httpx.post(f"{url}/login", data={"request": request_id, "code": code, "action": "verify"}))
    assert back.headers["location"].startswith(CALLBACK) and "state=s1" in back.headers["location"]
    issued = _exchange(url, client, code_of(back), verifier).json()
    assert issued["token_type"] == "Bearer" and issued["expires_in"] == tokens.ACCESS_TTL
    # A JWT anybody can check by the published keys: who, for whom, what for.
    keys = jwt.PyJWKSet.from_dict(httpx.get(f"{url}/.well-known/jwks.json").json())
    claims = jwt.decode(issued["access_token"], keys.keys[0].key, algorithms=["EdDSA"],
                        audience="https://noesis.example/mcp", issuer=url)
    # The first sign-in made the account, numbered since "ann" is under four.
    assert claims["sub"] == "ann1" and claims["client_id"] == client["client_id"]
    assert claims["scope"] == "noesis:read"
    # Refresh rotates: the new pair works, the old refresh token does not.
    refresh = {"grant_type": "refresh_token", "client_id": client["client_id"], "client_secret": client["client_secret"]}
    again = httpx.post(f"{url}/token", data={**refresh, "refresh_token": issued["refresh_token"]}).json()
    assert tokens.verify(again["access_token"])["sub"] == claims["sub"]
    assert httpx.post(f"{url}/token", data={**refresh, "refresh_token": issued["refresh_token"]}).status_code == 400
    # Disabling the account refuses refresh and /me at once.
    accounts.set_disabled(claims["sub"], True)
    assert httpx.post(f"{url}/token", data={**refresh, "refresh_token": again["refresh_token"]}).status_code == 400
    assert httpx.get(f"{url}/me", headers={"Authorization": f"Bearer {again['access_token']}"}).status_code == 401


def test_a_registered_client_asks_for_no_more_than_reading(live):
    url = live
    assert register(url, scope="noesis:api").status_code == 400
    client = register(url).json()
    _, challenge = pkce()
    r = httpx.get(f"{url}/authorize", params={
        "response_type": "code", "client_id": client["client_id"], "redirect_uri": CALLBACK,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s", "scope": "noesis:api"})
    assert "error=invalid_scope" in r.headers.get("location", "")


def test_wrong_codes_end_the_sign_in(live):
    url = live
    client = register(url).json()
    _, challenge = pkce()
    request_id = authorize(url, client["client_id"], challenge)
    httpx.post(f"{url}/login", data={"request": request_id, "email": "ann@example.com", "action": "send"})
    code = SENT["ann@example.com"]
    wrong = f"{(int(code) + 1) % 10**6:06d}"
    for _ in range(4):
        assert "not the code" in httpx.post(f"{url}/login", data={
            "request": request_id, "code": wrong, "action": "verify"}).text
    last = httpx.post(f"{url}/login", data={"request": request_id, "code": wrong, "action": "verify"})
    assert last.status_code == 400 and "Too many" in last.text
    assert httpx.post(f"{url}/login", data={"request": request_id, "code": code, "action": "verify"}).status_code == 400


def test_deny_sends_access_denied(live):
    url = live
    client = register(url).json()
    _, challenge = pkce()
    request_id = authorize(url, client["client_id"], challenge, state="s9")
    back = httpx.post(f"{url}/login", data={"request": request_id, "action": "deny"})
    assert back.status_code == 302 and "error=access_denied" in back.headers["location"]
    assert "state=s9" in back.headers["location"]


def test_roxana_learns_who_signed_in_and_me_answers_its_origin_alone(live):
    url = live
    add_client("roxana", "--name", "Roxana", "--public", "--scope", "identity",
               "--redirect", "https://roxana.example/signin", "--redirect", "http://localhost:3000/signin")
    verifier, challenge = pkce()
    redirect = "https://roxana.example/signin"
    request_id = authorize(url, "roxana", challenge, redirect=redirect)
    assert "to know who you are" in httpx.get(f"{url}/login", params={"request": request_id}).text
    issued = _exchange(url, {"client_id": "roxana"}, code_of(sign_in(url, request_id)), verifier, redirect).json()
    assert issued["scope"] == "identity"
    bearer = {"Authorization": f"Bearer {issued['access_token']}"}
    me = httpx.get(f"{url}/me", headers={**bearer, "Origin": "https://roxana.example"})
    assert me.json()["email"] == "ann@example.com" and me.json()["client"] == "roxana"
    assert me.headers["access-control-allow-origin"] == "https://roxana.example"
    other = httpx.get(f"{url}/me", headers={**bearer, "Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in other.headers
    # A browser app refreshes without a secret.
    again = httpx.post(f"{url}/token", data={"grant_type": "refresh_token", "client_id": "roxana",
                                             "refresh_token": issued["refresh_token"]})
    assert again.status_code == 200
    # Revoking the refresh token ends it (the SDK wants client_secret present, if empty).
    revoked = httpx.post(f"{url}/revoke", data={"token": again.json()["refresh_token"], "client_id": "roxana",
                                                "client_secret": ""})
    assert revoked.status_code == 200
    assert httpx.post(f"{url}/token", data={"grant_type": "refresh_token", "client_id": "roxana",
                                            "refresh_token": again.json()["refresh_token"]}).status_code == 400


def test_the_floor_gets_a_persons_grant_and_a_token_of_its_own(live):
    url = live
    floor = add_client("thefloor", "--name", "The Floor", "--redirect", "https://floor.example/callback",
                       "--scope", "noesis:read noesis:import", "--credentials", "noesis:keep", "--keeps-names")
    client = {"client_id": "thefloor", "client_secret": floor["AUTH_CLIENT_SECRET"]}
    verifier, challenge = pkce()
    redirect = "https://floor.example/callback"
    request_id = authorize(url, "thefloor", challenge, redirect=redirect)
    assert "add conversations to them" in httpx.get(f"{url}/login", params={"request": request_id}).text
    issued = _exchange(url, client, code_of(sign_in(url, request_id)), verifier, redirect).json()
    # A person's grant never carries the application's own scopes.
    assert issued["scope"] == "noesis:read noesis:import"
    own = httpx.post(f"{url}/token", data={"grant_type": "client_credentials", **client}).json()
    claims = tokens.verify(own["access_token"])
    assert claims["sub"] == "thefloor" and claims["scope"] == "noesis:keep" and "refresh_token" not in own
    assert httpx.post(f"{url}/token", data={"grant_type": "client_credentials", "scope": "noesis:read",
                                            **client}).json()["error"] == "invalid_scope"
    assert httpx.post(f"{url}/token", data={"grant_type": "client_credentials", "client_id": "thefloor",
                                            "client_secret": "nope"}).status_code == 401
    claude = register(url).json()
    assert httpx.post(f"{url}/token", data={"grant_type": "client_credentials", **claude}).status_code == 400


def test_the_operators_script_checks_what_it_registers(data):
    for bad in (["x", "--name", "x", "--redirect", "http://a.example/cb"],
                ["x", "--name", "x", "--redirect", "https://a.example/cb", "--scope", "everything"],
                ["x", "--name", "x", "--public", "--redirect", "https://a.example/cb", "--credentials", "noesis:keep"],
                ["x", "--name", "x"],
                ["X", "--name", "x", "--no-redirect"]):
        with pytest.raises(SystemExit):
            add_client(*bad)


def test_keys_rotate_without_cutting_off_tokens_out(data):
    old, _ = tokens.issue("ann", "roxana", ["identity"])
    (data / "signing-key.pem").rename(data / "signing-key.old.pem")
    new, _ = tokens.issue("ann", "roxana", ["identity"])
    assert tokens.verify(old)["sub"] == tokens.verify(new)["sub"] == "ann"
    assert len(tokens.jwks()["keys"]) == 2
    (data / "signing-key.old.pem").unlink()
    tokens._load.cache_clear()
    assert tokens.verify(old) is None and tokens.verify(new) is not None
    assert (data / "signing-key.pem").stat().st_mode & 0o777 == 0o600


def test_app_review_signs_in_with_its_fixed_code(live, monkeypatch):
    url = live
    monkeypatch.setenv("AUTH_REVIEW_ADDRESS", "Review@Example.com")
    monkeypatch.setenv("AUTH_REVIEW_CODE", "424242")
    mailed = []
    monkeypatch.setattr("dianoia_auth.mail.send_code", lambda to, code, name: mailed.append(to))
    client = register(url).json()
    _, challenge = pkce()
    request_id = authorize(url, client["client_id"], challenge)
    httpx.post(f"{url}/login", data={"request": request_id, "email": "review@example.com", "action": "send"})
    back = past_offer(url, httpx.post(f"{url}/login", data={"request": request_id, "code": "424242", "action": "verify"}))
    assert back.status_code == 302 and mailed == []
    # Anybody else is mailed a code of their own, and the fixed one is nothing to them.
    request_id = authorize(url, client["client_id"], challenge)
    httpx.post(f"{url}/login", data={"request": request_id, "email": "ann@example.com", "action": "send"})
    assert mailed == ["ann@example.com"]
    assert "not the code" in httpx.post(f"{url}/login", data={
        "request": request_id, "code": "424242", "action": "verify"}).text
    # A code that is not six digits is no code.
    monkeypatch.setenv("AUTH_REVIEW_CODE", "42")
    from dianoia_auth.provider import review_code
    assert review_code("review@example.com") is None


def test_the_operator_widens_a_clients_scopes_and_keeps_its_secret(data):
    from conftest import script
    from dianoia_auth.provider import provider
    floor = add_client("thefloor", "--name", "The Floor", "--redirect", "https://floor.example/callback",
                       "--scope", "noesis:read noesis:import", "--credentials", "noesis:keep", "--keeps-names")
    script("client_scopes").main(["thefloor", "--scope", "identity noesis:read noesis:import",
                                  "--credentials", "noesis:keep"])
    client = provider.client("thefloor")
    assert client.client_secret == floor["AUTH_CLIENT_SECRET"]
    assert client.scope == "identity noesis:read noesis:import noesis:keep"
    assert "client_credentials" in client.grant_types and provider.keeps_names("thefloor", floor["AUTH_CLIENT_SECRET"])
    with pytest.raises(SystemExit):
        script("client_scopes").main(["thefloor", "--scope", "everything"])
