# SPDX-License-Identifier: AGPL-3.0-or-later
"""S6 -- unseal bootstraps + certifies the per-node Ed25519 audit identity.

Before S6 the identity had to be provisioned by hand; prod kept writing hmac.
S6 wires ``ensure_audit_chain_identity`` into the master unseal path, so the act
of unsealing flips the chain to ed25519 (identity loaded -> ``has_audit_identity``
-> log_action signs asymmetrically) AND certifies the public key in the signer
registry. Standalone (no cluster CA, as in the test bench) issues a self-signed
cert; the cert certifies exactly the audit pubkey.
"""

import pytest
from api.app.audit_identity import ensure_audit_chain_identity, fingerprint
from api.app.database import async_session
from api.app.vault_state import vault
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text


async def _teardown():
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('audit_identity_seed_enc', 'audit_identity_pub')"
            )
        )
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await db.execute(text("DELETE FROM vault_audit_signer_certs"))
        await db.execute(text("TRUNCATE vault_audit"))
        await db.commit()
    vault._audit_signer = None


@pytest.mark.asyncio
async def test_unseal_bootstraps_and_certifies_identity(client, master_password):
    """Password unseal loads the identity, the unseal entry is ed25519, and the
    registry holds a self-signed cert over the audit pubkey."""
    # Force a sealed->unsealed transition so the unseal handler runs its full
    # master path (the global vault singleton may be left unsealed by a prior
    # test in the same file -- a no-op unseal would skip the bootstrap).
    vault.seal()
    resp = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert resp.status_code == 200
    try:
        # The unseal itself provisioned + loaded the identity (no manual call).
        assert vault.has_audit_identity
        pub = vault.audit_identity_pub
        assert pub is not None
        fpr = fingerprint(pub)

        async with async_session() as db:
            cert_row = (
                await db.execute(
                    text(
                        "SELECT public_key, cert_pem, node_uuid "
                        "FROM vault_audit_signer_certs WHERE fingerprint = :f"
                    ),
                    {"f": fpr},
                )
            ).fetchone()
            unseal_row = (
                await db.execute(
                    text(
                        "SELECT sig_alg, signer_fpr FROM vault_audit "
                        "WHERE action = 'unseal' ORDER BY timestamp DESC LIMIT 1"
                    )
                )
            ).fetchone()

        # Registry: pubkey stored raw + a cert was filled (standalone self-sign).
        assert cert_row is not None
        assert bytes(cert_row.public_key) == pub
        assert cert_row.cert_pem is not None
        assert "BEGIN CERTIFICATE" in cert_row.cert_pem

        # The cert certifies exactly the audit pubkey (verify reads the raw key,
        # but the cert must agree or provenance is a lie).
        cert = x509.load_pem_x509_certificate(cert_row.cert_pem.encode())
        cert_pub = cert.public_key()
        assert isinstance(cert_pub, Ed25519PublicKey)
        assert cert_pub.public_bytes(Encoding.Raw, PublicFormat.Raw) == pub

        # A1: the standalone cert is self-signed in Rust (the seed never enters
        # Python). It is self-signed, so its signature must verify under the
        # audit pubkey itself -- proves the Rust sign_raw + DER reassembly is
        # sound, not just structurally loadable. .verify() raises on a bad sig.
        cert_pub.verify(cert.signature, cert.tbs_certificate_bytes)

        # The unseal audit entry is the first ed25519-signed row (cutover).
        assert unseal_row is not None
        assert unseal_row.sig_alg == "ed25519"
        assert unseal_row.signer_fpr == fpr
    finally:
        await _teardown()


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent(client, master_password):
    """A second bootstrap reuses the same identity + cert -- no churn.

    Driven directly (not via a second unseal) so it is independent of the
    global vault singleton's seal state across tests.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            fpr1 = await ensure_audit_chain_identity(db)
            before = (
                await db.execute(
                    text(
                        "SELECT cert_pem FROM vault_audit_signer_certs "
                        "WHERE fingerprint = :f"
                    ),
                    {"f": fpr1},
                )
            ).fetchone()
            fpr2 = await ensure_audit_chain_identity(db)
            after = (
                await db.execute(
                    text(
                        "SELECT cert_pem FROM vault_audit_signer_certs "
                        "WHERE fingerprint = :f"
                    ),
                    {"f": fpr1},
                )
            ).fetchone()

        assert fpr1 is not None
        assert fpr2 == fpr1
        # Same identity, same cert: re-running did not re-issue.
        assert before is not None and after is not None
        assert before.cert_pem == after.cert_pem
        # Exactly one signer row (no duplicate registration).
        async with async_session() as db:
            n = (
                await db.execute(
                    text("SELECT COUNT(*) AS n FROM vault_audit_signer_certs")
                )
            ).fetchone()
        assert int(n.n) == 1
    finally:
        await _teardown()
