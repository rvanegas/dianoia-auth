"""A software passkey, for tests: what a browser and its authenticator hand the server.

A P-256 key, `none` attestation, and the byte layouts WebAuthn defines:
authenticator data (RP ID hash, flags, counter, and on creation the
credential), the client data the browser signs over, and the ECDSA signature
an assertion carries.
"""

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Authenticator:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.counter = 0
        self.user_handle = b""

    def _cose(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})

    def _client_data(self, kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()

    def create(self, options: dict, origin: str) -> dict:
        """navigator.credentials.create, from the server's options."""
        self.user_handle = unb64(options["user"]["id"])
        rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
        auth_data = (rp_hash + bytes([0x45]) + struct.pack(">I", self.counter) + bytes(16)
                     + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose())
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client_data), "attestationObject": b64(attestation),
                             "transports": ["internal"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def get(self, options: dict, origin: str) -> dict:
        """navigator.credentials.get, from the server's options."""
        self.counter += 1
        rp_hash = hashlib.sha256(options["rpId"].encode()).digest()
        auth_data = rp_hash + bytes([0x05]) + struct.pack(">I", self.counter)
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client_data), "authenticatorData": b64(auth_data),
                             "signature": b64(signature), "userHandle": b64(self.user_handle)},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}
