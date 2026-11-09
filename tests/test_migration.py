"""Carrying sign-in's data from noesis (scripts/migrate_from_noesis.py)."""

import hashlib
import json
import sqlite3

import httpx

from auth import accounts
from conftest import script


def _noesis(tmp_path):
    source = tmp_path / "noesis"
    source.mkdir()
    db = sqlite3.connect(source / "accounts.db")
    db.executescript("""
        CREATE TABLE accounts (user TEXT PRIMARY KEY, email TEXT, plan TEXT, created_at REAL,
                               disabled INTEGER, extra_usd REAL);
        CREATE TABLE reservations (user TEXT PRIMARY KEY, email TEXT, client TEXT, created_at REAL);
        CREATE TABLE sends (key TEXT, at REAL);
        INSERT INTO accounts VALUES ('ann', 'ann@example.com', 'free', 1.0, 0, 2.0);
        INSERT INTO accounts VALUES ('rodvandur', 'rod@example.com', 'unlimited', 1.0, 0, 0);
        INSERT INTO reservations VALUES ('mei1', 'mei@example.com', 'thefloor', 2.0);
        INSERT INTO sends VALUES ('all', 9999999999.0);
    """)
    db.commit()
    db.close()
    (source / "users.toml").write_text('[[tokens]]\nuser = "rodvandur"\nsha256 = "x"\n'
                                       '[[tokens]]\nuser = "nightly"\nsha256 = "y"\n')
    for name in ("ann", "thefloor", "olduser"):
        (source / "libraries" / name).mkdir(parents=True)
    future = 9999999999
    oauth = {
        "clients": {
            "roxana": {"client_id": "roxana", "client_name": "Roxana", "redirect_uris": ["https://roxana.example/signin"],
                       "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
                       "response_types": ["code"], "identity_only": True},
            "thefloor": {"client_id": "thefloor", "client_secret": "s3cret", "client_name": "The Floor",
                         "redirect_uris": ["https://floor.example/callback"], "token_endpoint_auth_method": "client_secret_post",
                         "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                         "imports": True, "keeps_names": True, "keeps_libraries": "https://floor.example/noesis"},
            "claude1": {"client_id": "claude1", "client_secret": "c", "client_name": "Claude",
                        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                        "token_endpoint_auth_method": "client_secret_post",
                        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]},
        },
        "access": {},
        "refresh": {
            hashlib.sha256(b"floor-refresh").hexdigest(): {"client_id": "thefloor", "user": "ann", "scopes": ["import"],
                                                           "resource": None, "expires_at": future},
            hashlib.sha256(b"claude-refresh").hexdigest(): {"client_id": "claude1", "user": "ann", "scopes": [],
                                                            "resource": "https://noesis.example/mcp", "expires_at": future},
            hashlib.sha256(b"web-refresh").hexdigest(): {"client_id": "noesis-web", "user": "rodvandur", "scopes": [],
                                                         "resource": None, "expires_at": future},
        },
    }
    (source / "oauth.json").write_text(json.dumps(oauth))
    return source


def test_the_migration_carries_accounts_clients_and_grants(live, tmp_path, capsys):
    url = live
    source = _noesis(tmp_path)
    migrate = script("migrate_from_noesis")
    migrate.main([str(source), "--noesis-url", "https://noesis.example"])
    assert "nothing changed" in capsys.readouterr().out and accounts.account("ann") is None
    migrate.main([str(source), "--noesis-url", "https://noesis.example", "--apply"])
    out = capsys.readouterr().out
    assert "hold    nightly" in out and "hold    olduser" in out and "hold    thefloor" in out
    assert "hold    rodvandur" not in out and "hold    ann " not in out
    assert accounts.account("ann").email == "ann@example.com"
    assert accounts.reservation_for_email("mei@example.com") == ("mei1", "thefloor")
    assert accounts.create_account("olduser@example.com").user == "olduser2"

    def refreshed(client_id, refresh, secret=None):
        data = {"grant_type": "refresh_token", "client_id": client_id, "refresh_token": refresh}
        if secret:
            data["client_secret"] = secret
        return httpx.post(f"{url}/token", data=data).json()

    assert refreshed("thefloor", "floor-refresh", "s3cret")["scope"] == "noesis:read noesis:import"
    assert refreshed("claude1", "claude-refresh", "c")["scope"] == "noesis:read"
    assert refreshed("noesis-web", "web-refresh")["scope"] == "noesis:api noesis:read"
    # The Floor keeps libraries: a token of its own, and the register.
    own = httpx.post(f"{url}/token", data={"grant_type": "client_credentials", "client_id": "thefloor",
                                           "client_secret": "s3cret"}).json()
    assert own["scope"] == "noesis:keep"
    from conftest import basic
    assert httpx.post(f"{url}/names", json={"email": "x@example.com"},
                      headers=basic("thefloor", "s3cret")).status_code == 200
