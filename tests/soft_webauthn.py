# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Software WebAuthn authenticator for tests.

Produces REAL ES256 assertions that Fido2Server.authenticate_complete
verifies cryptographically -- no mocking of the fido2 layer. This is what
catches fido2 API drift (the 2.2.0 signature change was invisible to the
mocked tests for months).
"""

import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from fido2.cose import ES256
from fido2.utils import sha256, websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)


class SoftAuthenticator:
    """A minimal resident-key ES256 authenticator."""

    def __init__(self, rp_id: str = "localhost"):
        self.rp_id = rp_id
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.credential_data = AttestedCredentialData.create(
            b"\x00" * 16,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()),
        )
        self.counter = 0

    def assertion(
        self,
        challenge: bytes,
        origin: str | None = None,
        counter: int | None = None,
        tamper_signature: bool = False,
    ) -> dict:
        """Sign `challenge` and return a browser-shaped credential dict."""
        origin = origin or f"https://{self.rp_id}"
        client_data = CollectedClientData.create("webauthn.get", challenge, origin)
        self.counter = self.counter + 1 if counter is None else counter
        auth_data = AuthenticatorData.create(
            sha256(self.rp_id.encode()), AuthenticatorData.FLAG.UP, self.counter
        )
        signature = self.private_key.sign(
            bytes(auth_data) + client_data.hash, ec.ECDSA(SHA256())
        )
        if tamper_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "response": {
                "clientDataJSON": websafe_encode(bytes(client_data)),
                "authenticatorData": websafe_encode(bytes(auth_data)),
                "signature": websafe_encode(signature),
            },
            "type": "public-key",
        }
