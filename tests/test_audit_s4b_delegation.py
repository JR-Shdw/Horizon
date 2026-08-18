# SPDX-License-Identifier: AGPL-3.0-or-later
"""S4b -- followers delegate Ed25519 audit signing instead of writing hmac.

Before S4b, log_action gated ed25519 on the LOCAL vault.has_audit_identity, so
only the master (which holds the signer) wrote ed25519 ; every follower wrote
hmac, reintroducing the per-epoch cross-host fragility ed25519 exists to kill
(the lab S8 finding: ed25519:3 / hmac:10 after a clean truncate). S4b routes a
follower's signature to the master over RPC and tags the row with the shared
cluster fingerprint (read from the shared vault_config), so the whole cluster
writes one ed25519 chain.
"""

import pytest
from api.app.audit import log_action
from api.app.audit_identity import (
    ensure_audit_chain_identity,
    fingerprint,
    resolve_signer_fpr,
)
from api.app.audit_payload import audit_row_payload
from api.app.crypto import verify_audit_ed25519
from api.app.database import async_session
from api.app.metrics import audit_sign_path
from api.app.vault_state import vault
from sqlalchemy import text


class _FakeMasterRpc:
    """Stand-in master RPC client: signs ed25519 with the cluster seed exactly
    as the real MasterRpcServer audit_sign_identity op does."""

    def __init__(self, signer):
        self._signer = signer
        self.calls = 0

    async def call(self, op, args):
        assert op == "audit_sign_identity"
        self.calls += 1
        return self._signer.sign(args["payload"], args.get("prev_signature", ""))


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
    vault._rpc_client = None
    vault._cluster_audit_fpr = None


@pytest.mark.asyncio
async def test_follower_delegates_ed25519_with_cluster_fpr(client, master_password):
    vault.seal()
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await ensure_audit_chain_identity(db)
        assert vault.has_audit_identity
        pub = vault.audit_identity_pub
        fpr = fingerprint(pub)

        # Build the signer through the same Rust-only path as the master RPC server.
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT value FROM vault_config "
                        "WHERE key = 'audit_identity_seed_enc'"
                    )
                )
            ).fetchone()
            signer = vault.aesgcm.load_audit_signer(bytes.fromhex(row.value))

        # Become a follower: no local signer, an RPC client to the master.
        vault._audit_signer = None
        vault._cluster_audit_fpr = None
        fake = _FakeMasterRpc(signer)
        vault._rpc_client = fake

        # The follower derives the shared cluster fpr from vault_config (no signer).
        async with async_session() as db:
            assert await resolve_signer_fpr(db) == fpr
        assert not vault.has_audit_identity

        before = audit_sign_path.labels(path="ed25519_delegated")._value.get()
        async with async_session() as db:
            prev_row = (
                await db.execute(
                    text(
                        "SELECT signature FROM vault_audit "
                        "WHERE signature != 'unsigned' "
                        "ORDER BY timestamp DESC, id DESC LIMIT 1"
                    )
                )
            ).fetchone()
            prev = prev_row.signature if prev_row else ""
            await log_action(
                db, actor="follower", action="s4b_probe", target="x", detail={"k": 1}
            )
            await db.commit()
        after = audit_sign_path.labels(path="ed25519_delegated")._value.get()

        # Delegated exactly once, tagged ed25519 + the shared cluster fpr.
        assert fake.calls == 1
        assert after == before + 1
        async with async_session() as db:
            r = (
                await db.execute(
                    text(
                        "SELECT id, timestamp, actor, action, target, detail, "
                        "ip_address, signature, key_epoch, sig_alg, signer_fpr, "
                        "payload_version FROM vault_audit "
                        "WHERE action = 's4b_probe' ORDER BY timestamp DESC LIMIT 1"
                    )
                )
            ).fetchone()
        assert r.sig_alg == "ed25519"
        assert r.signer_fpr == fpr
        # The delegated signature verifies under the cluster public key.
        payload = audit_row_payload(r)
        assert verify_audit_ed25519(pub, payload, prev, r.signature) is True
    finally:
        await _teardown()


@pytest.mark.asyncio
async def test_no_identity_still_hmac(client, master_password):
    """Backward compat: with no audit identity provisioned, the chain stays hmac
    (resolve_signer_fpr returns None -> legacy path, no fallback warning)."""
    vault.seal()
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        # Wipe any S6-provisioned identity to model a pre-S6 / standalone-hmac vault.
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('audit_identity_seed_enc', 'audit_identity_pub')"
                )
            )
            await db.commit()
        vault._audit_signer = None
        vault._cluster_audit_fpr = None

        async with async_session() as db:
            assert await resolve_signer_fpr(db) is None
            await log_action(db, actor="t", action="hmac_only", target=None, detail={})
            await db.commit()
        async with async_session() as db:
            r = (
                await db.execute(
                    text(
                        "SELECT sig_alg, signer_fpr FROM vault_audit "
                        "WHERE action = 'hmac_only' ORDER BY timestamp DESC LIMIT 1"
                    )
                )
            ).fetchone()
        assert r.sig_alg == "hmac"
        assert r.signer_fpr is None
    finally:
        await _teardown()
