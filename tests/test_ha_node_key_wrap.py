"""wrap_node_key_for_joiner.

Covers :
- Roundtrip : encrypt server-side via the Rust HKDF-then-AES-GCM
  primitive, decrypt client-side via an independent Python derivation
  (``cryptography.hkdf`` + ``cryptography.AESGCM``) -- proves the
  recipe in the docstring is reproducible by anyone holding the same
  ``ha_password`` + ``node_uuid``.
- Per-uuid info isolation : a wrap for node-A cannot be unwrapped
  under a derivation keyed by node-B.
- AAD binding : tampering with the AAD breaks authentication.
- ha_password sensitivity : changing the ha_password breaks the
  derivation (rotation -> at-rest unwrap fails, as designed).
- State machine : sealed and not-loaded states refuse the op.
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

# Sample PEM-shaped payload (content is not parsed by the wrap, only
# encrypted as opaque bytes -- using a realistic PKCS8 PEM keeps test
# intent obvious without pulling in an Ed25519 generation step).
_SAMPLE_KEY_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MC4CAQAwBQYDK2VwBCIEIPlYL5lZTPHzU2gWuFMrAfu+ofZw9MeBfqQuiOmAUjAa\n"
    b"-----END PRIVATE KEY-----\n"
)


def _derive_key_clientside(ha_password: bytes, node_uuid: str) -> bytes:
    """Independent HKDF-SHA512 derivation -- mirrors the Rust primitive.

    Lives in the test file (not imported from the production code) so
    a regression in the production derivation surfaces as a roundtrip
    mismatch rather than co-failing alongside the bug.
    """
    info = b"cluster-node-key-wrap:" + node_uuid.encode()
    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=info,
    ).derive(ha_password)


def _unwrap_clientside(wrapped: bytes, ha_password: bytes, node_uuid: str) -> bytes:
    """Mirror of `wrap_node_key_for_joiner` -- joiner-side recipe."""
    derived = _derive_key_clientside(ha_password, node_uuid)
    aad = b"vault-cluster:node-key:" + node_uuid.encode()
    nonce, ct = wrapped[:12], wrapped[12:]
    return AESGCM(derived).decrypt(nonce, ct, aad)


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

    wrapped = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "node-abc-uuid")
    recovered = _unwrap_clientside(wrapped, ha_password, "node-abc-uuid")
    assert recovered == _SAMPLE_KEY_PEM


@pytest.mark.asyncio
async def test_wrap_output_shape_nonce_plus_ct(admin_token):
    """nonce(12) || ciphertext(plain + tag 16)."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()

    wrapped = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    assert len(wrapped) == 12 + len(_SAMPLE_KEY_PEM) + 16


@pytest.mark.asyncio
async def test_wrap_freshness_random_nonce(admin_token):
    """Two wraps of the same (plain, uuid) under the same ha_password
    must yield different ciphertexts -- nonce is random per call."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()

    a = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    b = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
    assert a != b


@pytest.mark.asyncio
async def test_wrap_info_isolation_per_node_uuid(admin_token):
    """A wrap minted for node-A cannot be unwrapped with node-B's
    derivation, even with the same ha_password."""
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    wrapped = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "node-A")
    with pytest.raises(Exception):  # InvalidTag from cryptography
        _unwrap_clientside(wrapped, ha_password, "node-B")


@pytest.mark.asyncio
async def test_wrap_aad_binding(admin_token):
    """Tampering with the AAD breaks decryption."""
    ha_password = b"x" * 64
    async with async_session() as db:
        await hp.set_ha_password(db, ha_password, actor="test")
        await db.commit()

    wrapped = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "node-A")
    derived = _derive_key_clientside(ha_password, "node-A")
    nonce, ct = wrapped[:12], wrapped[12:]
    wrong_aad = b"vault-cluster:node-key:node-A-WRONG"
    with pytest.raises(Exception):
        AESGCM(derived).decrypt(nonce, ct, wrong_aad)


@pytest.mark.asyncio
async def test_wrap_breaks_under_rotated_ha_password(admin_token):
    """If ha_password is rotated, a wrapped key minted under the old
    one cannot be unwrapped with the new one. Confirms the wrap is
    actually bound to ha_password (and not, e.g., a constant)."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    wrapped = hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")

    with pytest.raises(Exception):
        _unwrap_clientside(wrapped, b"y" * 64, "uuid")


@pytest.mark.asyncio
async def test_wrap_rejects_when_sealed(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    vault.seal()
    try:
        with pytest.raises(VaultSealedError):
            hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
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
    """Unsealed vault but no ha_password set -> HaPasswordNotLoadedError."""
    assert vault._ha_password_enc is None
    with pytest.raises(hp.HaPasswordNotLoadedError):
        hp.wrap_node_key_for_joiner(_SAMPLE_KEY_PEM, "uuid")
