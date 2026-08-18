# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""wrap_server_key_for_joiner.

Mirror of test_ha_node_key_wrap.py for the server-key wrap
domain. The key questions :
- Recipe reproducibility (HKDF info + AAD prefixes specified in the
  docstring match what an independent client-side derivation
  computes).
- Cross-domain isolation : a server-key wrap is NOT unwrappable with
  the node-key derivation, and vice versa.
- All the standard wrap properties (random nonce, AAD binding,
  ha_password sensitivity, sealed / not-loaded refusal).
- The Python unwrap helper roundtrips the Rust wrap.
"""

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app.database import async_session
from api.app.vault_state import VaultSealedError, vault
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import text

_SAMPLE_KEY_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MC4CAQAwBQYDK2VwBCIEIPlYL5lZTPHzU2gWuFMrAfu+ofZw9MeBfqQuiOmAUjAa\n"
    b"-----END PRIVATE KEY-----\n"
)


def _derive_server_key(ha_password: bytes, node_uuid: str) -> bytes:
    info = b"cluster-server-key-wrap:" + node_uuid.encode()
    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=info,
    ).derive(ha_password)


def _unwrap_server_clientside(
    wrapped: bytes, ha_password: bytes, node_uuid: str
) -> bytes:
    derived = _derive_server_key(ha_password, node_uuid)
    aad = b"vault-cluster:server-key:" + node_uuid.encode()
    nonce, ct = wrapped[:12], wrapped[12:]
    return AESGCM(derived).decrypt(nonce, ct, aad)


def _derive_node_key(ha_password: bytes, node_uuid: str) -> bytes:
    info = b"cluster-node-key-wrap:" + node_uuid.encode()
    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=info,
    ).derive(ha_password)


@pytest_asyncio.fixture(autouse=True)
async def _wipe_ha_password_row():
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": hp._CONFIG_KEY},
        )
        await db.commit()
    hp.clear()
    yield
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": hp._CONFIG_KEY},
        )
        await db.commit()
    hp.clear()


@pytest.mark.asyncio
async def test_wrap_roundtrips_via_independent_derivation(admin_token):
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    wrapped = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "node-abc-uuid")
    recovered = _unwrap_server_clientside(wrapped, ha_password, "node-abc-uuid")
    assert recovered == _SAMPLE_KEY_PEM


@pytest.mark.asyncio
async def test_unwrap_roundtrips_python_helper(admin_token):
    """The Python fallback unwrap helper used by the joiner roundtrips
    the Rust wrap."""
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    wrapped = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    recovered = hp.unwrap_server_key_for_joiner(wrapped, ha_password, "uuid")
    assert recovered == _SAMPLE_KEY_PEM


@pytest.mark.asyncio
async def test_wrap_output_shape_nonce_plus_ct(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()

    wrapped = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    assert len(wrapped) == 12 + len(_SAMPLE_KEY_PEM) + 16


@pytest.mark.asyncio
async def test_wrap_freshness_random_nonce(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()

    a = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    b = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    assert a != b


@pytest.mark.asyncio
async def test_cross_domain_isolation_server_vs_node(admin_token):
    """A server-key wrap cannot be unwrapped under the node-key
    derivation, even with the same ha_password and node_uuid.

    Concretely : an attacker who captures a JOIN response cannot
    re-cast the server-cert wrap blob as a node-cert wrap blob, and
    nginx cannot accidentally be handed a wrapped node-identity cert.
    """
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    server_wrap = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "node-A")
    node_wrap = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "node-A")

    assert server_wrap != node_wrap

    # Mis-domain unwraps must both fail (InvalidTag).
    node_derived = _derive_node_key(ha_password, "node-A")
    server_derived = _derive_server_key(ha_password, "node-A")
    nonce_s, ct_s = server_wrap[:12], server_wrap[12:]
    nonce_n, ct_n = node_wrap[:12], node_wrap[12:]

    with pytest.raises(Exception):
        AESGCM(node_derived).decrypt(nonce_s, ct_s, b"vault-cluster:node-key:node-A")
    with pytest.raises(Exception):
        AESGCM(server_derived).decrypt(
            nonce_n, ct_n, b"vault-cluster:server-key:node-A"
        )


@pytest.mark.asyncio
async def test_info_isolation_per_uuid(admin_token):
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    wrapped = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "node-A")
    with pytest.raises(Exception):
        _unwrap_server_clientside(wrapped, ha_password, "node-B")


@pytest.mark.asyncio
async def test_aad_binding(admin_token):
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    wrapped = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "node-A")
    derived = _derive_server_key(ha_password, "node-A")
    nonce, ct = wrapped[:12], wrapped[12:]
    with pytest.raises(Exception):
        AESGCM(derived).decrypt(nonce, ct, b"vault-cluster:server-key:node-A-WRONG")


@pytest.mark.asyncio
async def test_breaks_under_rotated_ha_password(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    wrapped = hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    with pytest.raises(Exception):
        _unwrap_server_clientside(wrapped, b"y" * 64, "uuid")


@pytest.mark.asyncio
async def test_unwrap_helper_rejects_short_payload():
    """The Python unwrap helper rejects payloads under 28 bytes."""
    with pytest.raises(hp.HaPasswordError):
        hp.unwrap_server_key_for_joiner(b"too-short", b"x" * 64, "uuid")


@pytest.mark.asyncio
async def test_wrap_rejects_when_sealed(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    vault.seal()
    try:
        with pytest.raises(VaultSealedError):
            hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    finally:
        from api.app.main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            await ac.post(
                "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
            )


@pytest.mark.asyncio
async def test_wrap_rejects_when_not_loaded(admin_token):
    assert vault._ha_password_enc is None
    with pytest.raises(hp.HaPasswordNotLoadedError):
        hp.wrap_server_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
