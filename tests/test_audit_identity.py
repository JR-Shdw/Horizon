# SPDX-License-Identifier: AGPL-3.0-or-later
"""S3 -- audit Ed25519 identity custody (provision + at-rest + load + seal-drop).

Exercises the master-side custody mechanism: provision a per-node identity
(seed wrapped under dek_key in vault_config, public key registered), load it
into the mlock'd Rust signer at unseal, sign + publicly verify, and confirm
seal() drops the signer. Follower RPC delegation + log_action/verify wiring land
in S4/S5.
"""

import hashlib

import pytest
from api.app.audit_identity import (
    ensure_audit_identity,
    fingerprint,
    load_audit_identity_into_ram,
)
from api.app.crypto import verify_audit_ed25519
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text


async def _cleanup(db):
    await db.execute(
        text(
            "DELETE FROM vault_config WHERE key IN "
            "('audit_identity_seed_enc', 'audit_identity_pub')"
        )
    )
    await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
    await db.execute(text("DELETE FROM vault_audit_signer_certs"))
    await db.commit()


@pytest.mark.asyncio
async def test_provision_load_sign_verify(client, master_password):
    """Provision an identity, sign with it, verify with the public key."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            pub = await ensure_audit_identity(db)
        assert pub is not None and len(pub) == 32
        assert vault.has_audit_identity is True
        assert vault.audit_identity_pub == pub
        assert vault.audit_identity_fpr == hashlib.sha256(pub).hexdigest()

        # Master-local Ed25519 sign, then public-key verify (the verify path
        # that will run sealed in S5). prev_signature chains the entry.
        payload = "root|create_token|mcp-bot|{}"
        prev = "a" * 128
        sig = vault._audit_sign_identity_local(payload, prev)
        assert verify_audit_ed25519(pub, payload, prev, sig) is True
        # Wrong chain link must not verify.
        assert verify_audit_ed25519(pub, payload, "b" * 128, sig) is False

        # The public key is registered for verifiers, keyed by fingerprint.
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT public_key, cert_pem FROM vault_audit_signer_certs "
                        "WHERE fingerprint = :f"
                    ),
                    {"f": fingerprint(pub)},
                )
            ).fetchone()
        assert row is not None
        assert bytes(row.public_key) == pub
        # cert_pem may be NULL (bare, this S3 path) or filled (if the unseal
        # S6 bootstrap already certified it) -- cert issuance is asserted in
        # test_audit_s6_bootstrap.py, not here. The S3 invariant is that the
        # public key is registered for verifiers.
    finally:
        async with async_session() as db:
            await _cleanup(db)


@pytest.mark.asyncio
async def test_idempotent_and_reload(client, master_password):
    """ensure_audit_identity twice -> same identity; explicit reload restores it."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            pub1 = await ensure_audit_identity(db)
        async with async_session() as db:
            pub2 = await ensure_audit_identity(db)
        assert pub1 == pub2  # did not regenerate

        # Simulate a fresh unseal: drop the in-RAM signer, then reload from DB.
        vault._audit_signer = None
        assert vault.has_audit_identity is False
        async with async_session() as db:
            loaded = await load_audit_identity_into_ram(db)
        assert loaded is True
        assert vault.audit_identity_pub == pub1
    finally:
        async with async_session() as db:
            await _cleanup(db)


def test_assemble_ed25519_cert_matches_cryptography():
    """A1: ``_assemble_ed25519_cert`` reproduces cryptography's own X.509 DER for
    the same (tbs, sig). Proves the manual reassembly used by the Rust self-sign
    path is byte-correct -- no need to trust hand-rolled DER blindly.

    Built once with a real key (random serial + now() validity make two builds
    differ), then the SAME tbs+sig are fed back through the manual assembler; the
    PEM must match the library's verbatim.
    """
    from api.app.audit_identity import _assemble_ed25519_cert, _cert_builder
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node-assemble")])
    full = _cert_builder(pub, "node-assemble", issuer=subject).sign(
        private_key=sk, algorithm=None
    )

    assembled = _assemble_ed25519_cert(full.tbs_certificate_bytes, full.signature)
    assert assembled == full.public_bytes(serialization.Encoding.PEM)


@pytest.mark.asyncio
async def test_seal_drops_identity(client, master_password):
    """seal() zeroizes + drops the audit signer (no key material in a sealed vault)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await ensure_audit_identity(db)
    assert vault.has_audit_identity is True

    vault.seal()
    assert vault.has_audit_identity is False
    assert vault.audit_identity_pub is None

    # Restore for subsequent tests (fixtures also re-unseal, but be explicit).
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await _cleanup(db)


# --- cert issuance: standalone self-sign + HA CA-signed ---------------------


async def _cert_for(fpr):
    async with async_session() as db:
        return (
            await db.execute(
                text(
                    "SELECT cert_pem FROM vault_audit_signer_certs "
                    "WHERE fingerprint = :f"
                ),
                {"f": fpr},
            )
        ).fetchone()


@pytest.mark.asyncio
async def test_ensure_chain_identity_self_signed_standalone(
    client, master_password, monkeypatch
):
    """Standalone (no cluster CA): the audit cert is self-signed in Rust (the
    seed never enters Python) -- issuer == subject, CN == node_uuid."""
    from api.app import audit_identity, cluster_ca
    from cryptography import x509

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await _cleanup(db)

        async def _no_ca(_db):
            return None

        monkeypatch.setattr(cluster_ca, "load_cluster_ca", _no_ca)
        async with async_session() as db:
            fpr = await audit_identity.ensure_audit_chain_identity(
                db, node_uuid="node-x"
            )
        assert fpr is not None
        row = await _cert_for(fpr)
        assert row is not None and row.cert_pem
        cert = x509.load_pem_x509_certificate(row.cert_pem.encode())
        assert cert.subject == cert.issuer  # self-signed
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == "node-x"
    finally:
        async with async_session() as db:
            await _cleanup(db)


@pytest.mark.asyncio
async def test_ensure_chain_identity_ca_signed(client, master_password, monkeypatch):
    """HA (cluster CA present): the audit cert is signed by the cluster CA --
    issuer is the CA subject, distinct from the leaf subject."""
    from api.app import audit_identity, cluster_ca
    from cryptography import x509

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await _cleanup(db)
        ca_cert, ca_key, _fpr = cluster_ca.mint_cluster_ca()

        async def _ca(_db):
            return ca_cert, bytearray(ca_key)

        monkeypatch.setattr(cluster_ca, "load_cluster_ca", _ca)
        async with async_session() as db:
            fpr = await audit_identity.ensure_audit_chain_identity(
                db, node_uuid="node-y"
            )
        assert fpr is not None
        row = await _cert_for(fpr)
        assert row is not None and row.cert_pem
        cert = x509.load_pem_x509_certificate(row.cert_pem.encode())
        ca_subject = x509.load_pem_x509_certificate(ca_cert).subject
        assert cert.issuer == ca_subject and cert.subject != cert.issuer
    finally:
        async with async_session() as db:
            await _cleanup(db)
