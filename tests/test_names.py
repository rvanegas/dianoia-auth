"""The register of names: one user name per address, across applications."""

import httpx
import pytest

from dianoia_auth import accounts, names
from conftest import add_client, basic, script


def test_user_names_come_from_the_address_and_are_unique(data):
    assert accounts.user_stem("Jane.Doe+floor@example.com") == "jane_doe"
    assert accounts.user_stem("..@example.com") is None
    assert accounts.create_account("ann@a.example").user == "ann1"
    assert accounts.create_account("ann@b.example").user == "ann2"
    assert accounts.create_account("zelda@c.example").user == "zelda"
    assert accounts.create_account("zelda@d.example").user == "zelda2"
    assert accounts.create_account("..@e.example").user == "user"
    assert accounts.create_account("zelda@c.example").user == "zelda"
    # A name held for use elsewhere is never given out.
    accounts.hold("carlos", "noesis library directory")
    assert accounts.create_account("carlos@f.example").user == "carlos2"
    assert (data / "auth.db").stat().st_mode & 0o777 == 0o600


def test_sign_in_mail_is_limited(data):
    for _ in range(5):
        assert accounts.allow_send("a@example.com", "1.1.1.1")
    assert not accounts.allow_send("a@example.com", "2.2.2.2")
    for n in range(5):
        assert accounts.allow_send(f"b{n}@example.com", "1.1.1.1")
    assert not accounts.allow_send("c@example.com", "1.1.1.1")
    assert accounts.allow_send("c@example.com", "3.3.3.3")


def test_a_reservation_holds_name_and_address_until_the_first_sign_in(data):
    assert names.name_for("Mei.Lin@example.com", "thefloor", ["Mei"]) == ("mei1", False)
    assert names.name_for("mei.lin@example.com", "thefloor", ["other"]) == ("mei1", False)
    assert names.name_for("mei@b.example", "thefloor", ["Mei"]) == ("mei2", False)
    assert accounts.account("mei1") is None
    assert accounts.create_account("mei.lin@example.com").user == "mei1"
    assert names.name_for("mei.lin@example.com", "thefloor") == ("mei1", True)


def test_a_reservation_is_chosen_renamed_and_moved_and_an_account_is_fixed(data):
    assert names.choose("ann@example.com", "@AnnaK", "thefloor") == "annak"
    with pytest.raises(names.Taken):
        names.choose("bob@example.com", "annak", "thefloor")
    for bad in ("bob", "bo-b"):
        with pytest.raises(names.Invalid):
            names.choose("bob@example.com", bad, "thefloor")
    assert names.choose("ann@example.com", "anna_k", "thefloor") == "anna_k"
    names.move("ann@example.com", "ann@new.example")
    assert accounts.reservation_for_email("ann@new.example") == ("anna_k", "thefloor")
    found = accounts.create_account("dee@example.com")
    with pytest.raises(names.Taken, match="cannot be changed"):
        names.choose("dee@example.com", "dee_other", "thefloor")
    with pytest.raises(names.Taken, match="cannot be changed"):
        names.move("dee@example.com", "dee@elsewhere.example")
    with pytest.raises(names.Taken):
        names.move("ann@new.example", "dee@example.com")
    assert accounts.account(found.user).email == "dee@example.com"


def test_the_operators_rename_and_link(data):
    found = accounts.create_account("busy@example.com")
    assert names.rename_account(found.user, "busy_one") == "busy_one"
    assert accounts.account("busy_one").email == "busy@example.com"
    accounts.hold("rod", "noesis operator user")
    assert accounts.link("rod@example.com", "rod").user == "rod"
    names.name_for("held@example.com", "thefloor", ["heldname"])
    with pytest.raises(ValueError):
        accounts.link("other@example.com", "heldname")


def test_the_register_answers_only_an_application_that_keeps_names(live):
    url = live
    floor = add_client("thefloor", "--name", "The Floor", "--redirect", "https://floor.example/callback",
                       "--keeps-names")
    add_client("other", "--name", "Other", "--redirect", "https://other.example/callback")
    good = basic("thefloor", floor["AUTH_CLIENT_SECRET"])
    assert httpx.post(f"{url}/names", json={"email": "a@example.com"}).status_code == 401
    assert httpx.post(f"{url}/names", json={"email": "a@example.com"},
                      headers=basic("thefloor", "nope")).status_code == 401
    assert httpx.post(f"{url}/names", json={"email": "a@example.com"},
                      headers=basic("other", "x")).status_code == 401
    made = httpx.post(f"{url}/names", json={"email": "Pat.Q@example.com", "suggest": ["Patty"]}, headers=good)
    assert made.json() == {"user": "patty", "account": False}
    assert httpx.put(f"{url}/names", json={"email": "pat.q@example.com", "user": "pat_q"},
                     headers=good).json() == {"user": "pat_q"}
    assert httpx.put(f"{url}/names", json={"email": "z@example.com", "user": "pat_q"},
                     headers=good).status_code == 409
    assert httpx.put(f"{url}/names", json={"email": "z@example.com", "user": "x"}, headers=good).status_code == 400
    assert httpx.put(f"{url}/names/address", json={"email": "pat.q@example.com", "new_email": "pat@example.com"},
                     headers=good).json() == {"moved": True}


def test_the_accounts_script(data, capsys):
    accounts.create_account("ann@example.com")
    accounts_script = script("accounts")
    accounts_script.main(["disable", "ann1"])
    assert accounts.account("ann1").disabled
    accounts_script.main(["enable", "ann1"])
    accounts_script.main(["hold", "rodvandur", "noesis operator user"])
    accounts_script.main(["link", "rod@example.com", "rodvandur"])
    accounts_script.main(["list"])
    out = capsys.readouterr().out
    assert "ann1" in out and "rodvandur" in out and "disabled" not in out.splitlines()[-1]
