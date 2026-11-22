"""The unlimited mark: one per user name, set by the operator, read by every
application with its own token (`GET /unlimited`), since 2026-11-22."""

import httpx
import pytest

from conftest import script
from dianoia_auth import accounts, names, tokens


def _bearer(sub, client_id, scopes):
    token, _ = tokens.issue(sub, client_id, scopes)
    return {"Authorization": f"Bearer {token}"}


def test_an_application_reads_who_the_operator_made_unlimited(live):
    url = live
    ann = accounts.create_account("ann@example.com").user
    bob = accounts.create_account("bob@example.com").user
    names.name_for("cy@example.com", "thefloor", ["cyrus"])           # a reservation: no account yet
    script("accounts").main(["unlimited", ann.upper(), "cyrus"])
    floor = _bearer("thefloor", "thefloor", ["noesis:keep"])
    noesis = _bearer("noesis", "noesis", ["thefloor:members"])
    assert httpx.get(f"{url}/unlimited", headers=floor).json() == {"users": sorted([ann, "cyrus"])}
    assert httpx.get(f"{url}/unlimited", headers=noesis).json() == {"users": sorted([ann, "cyrus"])}
    script("accounts").main(["limited", ann])
    assert httpx.get(f"{url}/unlimited", headers=floor).json() == {"users": ["cyrus"]}
    # The person who signs in under the reserved name has it.
    assert accounts.create_account("cy@example.com").user == "cyrus"
    assert accounts.unlimited_users() == ["cyrus"]
    assert bob not in accounts.unlimited_users()


def test_nobody_but_an_application_may_read_it(live):
    url = live
    ann = accounts.create_account("ann@example.com").user
    assert httpx.get(f"{url}/unlimited").status_code == 401
    assert httpx.get(f"{url}/unlimited", headers=_bearer(ann, "roxana", ["identity"])).status_code == 403
    # auth's own departure token is not an application's.
    assert httpx.get(f"{url}/unlimited",
                     headers=_bearer("dianoia-auth", "dianoia-auth", ["noesis:erase"])).status_code == 403


def test_only_a_name_auth_knows_is_marked(data):
    with pytest.raises(SystemExit):
        script("accounts").main(["unlimited", "nobody"])
    assert accounts.unlimited_users() == []


def test_a_rename_carries_it_and_a_deletion_ends_it(data):
    ann = accounts.create_account("ann@example.com").user
    accounts.set_unlimited(ann, True)
    names.rename_account(ann, "annie")
    assert accounts.unlimited_users() == ["annie"]
    accounts.delete("annie")
    assert accounts.unlimited_users() == []
