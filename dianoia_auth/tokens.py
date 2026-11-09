"""Access tokens: signed JWTs a resource server checks without calling here.

EdDSA (Ed25519), the private key in $AUTH_DATA_DIR/signing-key.pem (mode 600),
made on first use; the public half is served at /.well-known/jwks.json, with
`signing-key.old.pem`'s too while one is kept, so a rotation does not cut off
tokens already out. Rotating: move the key to `signing-key.old.pem`, restart,
and delete the old one after ACCESS_TTL.

Claims: `iss` this server, `sub` the user (or, for an application's own
token, its client id), `aud` the resource asked for (RFC 8707) or this server,
`client_id`, `scope`, `iat`, `exp`, `jti`, and for a person `name`, the
display name they are shown by, else their user name (since 2026-11-09).
**They last ACCESS_TTL**: a
resource server cannot ask whether the account was disabled since, so
disabling one reaches it within that time, while refresh stops at once.
"""

from __future__ import annotations

import os
import secrets
import time
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm

from dianoia_auth.store import data_dir, sha

ACCESS_TTL = 15 * 60


def issuer() -> str:
    return os.environ.get("AUTH_PUBLIC_URL", "http://127.0.0.1:8002").rstrip("/")


def _key_path(name: str = "signing-key.pem") -> Path:
    return data_dir() / name


@lru_cache(maxsize=4)
def _load(path: Path, mtime: float) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _key(name: str = "signing-key.pem", make: bool = True) -> Ed25519PrivateKey | None:
    path = _key_path(name)
    if not path.exists():
        if not make:
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_bytes(pem)
        tmp.chmod(0o600)
        tmp.replace(path)
    return _load(path, path.stat().st_mtime)


def _kid(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha(raw.hex())[:16]


def jwks() -> dict:
    keys = [k for k in (_key(), _key("signing-key.old.pem", make=False)) if k is not None]
    out = []
    for key in keys:
        jwk = OKPAlgorithm.to_jwk(key.public_key(), as_dict=True)
        out.append({**jwk, "kid": _kid(key), "use": "sig", "alg": "EdDSA"})
    return {"keys": out}


def issue(sub: str, client_id: str, scopes: list[str], resource: str | None = None,
          name: str | None = None) -> tuple[str, int]:
    """A signed access token and its lifetime in seconds; a person's carries their name."""
    key = _key()
    now = int(time.time())
    claims = {
        "iss": issuer(), "sub": sub, "aud": resource or issuer(), "client_id": client_id,
        "scope": " ".join(scopes), "iat": now, "exp": now + ACCESS_TTL, "jti": secrets.token_urlsafe(12),
        **({"name": name} if name else {}),
    }
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": _kid(key)}), ACCESS_TTL


def verify(token: str) -> dict | None:
    """Its claims, if this server signed it and it has not expired; any audience."""
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        return None
    for key in (_key(), _key("signing-key.old.pem", make=False)):
        if key is not None and _kid(key) == kid:
            try:
                return jwt.decode(token, key.public_key(), algorithms=["EdDSA"], issuer=issuer(),
                                  options={"verify_aud": False})
            except jwt.PyJWTError:
                return None
    return None
