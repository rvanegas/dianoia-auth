"""Vouching (provider.VOUCHED): The Floor connects its person's library on its own word for their address."""

import httpx

from conftest import add_client
from dianoia_auth import accounts, names, sessions, tokens
from dianoia_auth.provider import VOUCHED


def _floor(*extra):
    floor = add_client("thefloor", "--name", "The Floor", "--redirect", "https://floor.example/callback",
                       "--scope", "identity noesis:read noesis:import", "--credentials", "noesis:keep", *extra)
    return {"client_id": "thefloor", "client_secret": floor["AUTH_CLIENT_SECRET"]}


def _vouch(url, client, **fields):
    return httpx.post(f"{url}/token", data={"grant_type": VOUCHED, **client, **fields})


def test_an_application_vouching_is_granted_its_persons_scopes_with_no_page(live):
    url = live
    client = _floor("--vouches")
    ann = accounts.create_account("ann@example.com").user
    r = _vouch(url, client, email="Ann@Example.com")
    assert r.status_code == 200, r.text
    granted = r.json()
    claims = tokens.verify(granted["access_token"])
    assert claims["sub"] == ann and claims["client_id"] == "thefloor"
    assert set(granted["scope"].split()) == {"identity", "noesis:read", "noesis:import"}
    # A grant like any other: refreshed, and listed on /account as the app let in.
    again = httpx.post(f"{url}/token", data={"grant_type": "refresh_token",
                                             "refresh_token": granted["refresh_token"], **client})
    assert again.status_code == 200, again.text
    assert sessions.covers(ann, "thefloor", ["identity", "noesis:read", "noesis:import"])
    # Asking for less is granted less; asking for more than it may have, nothing.
    assert _vouch(url, client, email="ann@example.com", scope="noesis:read").json()["scope"] == "noesis:read"
    assert _vouch(url, client, email="ann@example.com", scope="noesis:api").json()["error"] == "invalid_scope"
    # Never an application's own scopes.
    assert _vouch(url, client, email="ann@example.com", scope="noesis:keep").json()["error"] == "invalid_scope"


def test_an_address_with_no_account_makes_one_as_a_first_sign_in_would(live):
    url = live
    client = _floor("--vouches")
    held, _ = names.name_for("bo@example.com", "thefloor", ["bo"])
    r = _vouch(url, client, email="bo@example.com")
    assert r.status_code == 200, r.text
    made = accounts.account_for_email("bo@example.com")
    assert made.user == held and tokens.verify(r.json()["access_token"])["sub"] == held


def test_only_an_application_the_operator_let_vouch(live):
    url = live
    accounts.create_account("ann@example.com")
    client = _floor()
    assert _vouch(url, client, email="ann@example.com").json()["error"] == "unauthorized_client"
    vouching = _floor("--vouches")
    assert _vouch(url, {**vouching, "client_secret": "nope"}, email="ann@example.com").status_code == 401
    assert _vouch(url, vouching, email="not an address").json()["error"] == "invalid_request"
    accounts.set_disabled(accounts.account_for_email("ann@example.com").user, True)
    assert _vouch(url, vouching, email="ann@example.com").json()["error"] == "invalid_grant"
