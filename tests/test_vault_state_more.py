"""Extra tests for api/app/vault_state.py.

Targets the RPC-dispatch methods (95% -> 98%+).
"""

import asyncio
from typing import get_type_hints
from unittest.mock import AsyncMock, MagicMock

import pytest
from api.app import vault_state as vault_state_module
from api.app.cluster_rpc import CustodianRpcClient
from api.app.vault_state import VaultSealedError, VaultState
from rhorizon_crypto import DekCipher, secure_zero

# ---------------------------------------------------------------------------
# attach_rpc_client / detach_rpc_client / is_master
# ---------------------------------------------------------------------------


def test_attach_detach_rpc_client():
    vault = VaultState()
    fake_client = MagicMock()
    vault.attach_rpc_client(fake_client)
    assert vault._rpc_client is fake_client
    vault.detach_rpc_client()
    assert vault._rpc_client is None


def test_is_master_logic():
    vault = VaultState()
    # sealed + no rpc -> not master (sealed)
    assert vault.is_master is False
    # rpc attached -> not master (delegating)
    vault.attach_rpc_client(MagicMock())
    assert vault.is_master is False


def test_aesgcm_property_exposes_concrete_cipher_type():
    """Callers must retain DekCipher's interface instead of receiving object."""
    hints = get_type_hints(VaultState.aesgcm.fget)
    assert hints["return"] == DekCipher | None


def test_unseal_retains_wrapped_subkeys_not_plaintext():
    vault = VaultState()
    keys = {
        "hmac_key": b"h" * 32,
        "dek_key": b"d" * 32,
        "audit_key": b"a" * 32,
        "ha_wrap_key": b"w" * 32,
        "pki_wrap_key": b"p" * 32,
    }

    vault.unseal(keys)
    try:
        for attribute, key_name in (
            ("_hmac_enc", "hmac_key"),
            ("_dek_enc", "dek_key"),
            ("_audit_enc", "audit_key"),
            ("_ha_wrap_enc", "ha_wrap_key"),
            ("_pki_wrap_enc", "pki_wrap_key"),
        ):
            wrapped = getattr(vault, attribute)
            assert isinstance(wrapped, bytes)
            assert wrapped != keys[key_name]
    finally:
        vault.seal()


def test_unseal_failure_preserves_current_key_generation(monkeypatch):
    from api.app import vault_state

    vault = VaultState()
    old_keys = {
        "hmac_key": b"h" * 32,
        "dek_key": b"d" * 32,
        "audit_key": b"a" * 32,
        "ha_wrap_key": b"w" * 32,
        "pki_wrap_key": b"p" * 32,
    }
    new_keys = {name: b"n" * 32 for name in old_keys}
    vault.unseal(old_keys)
    old_generation = (
        vault._hmac_enc,
        vault._dek_enc,
        vault._audit_enc,
        vault._ha_wrap_enc,
        vault._pki_wrap_enc,
        vault._aesgcm,
    )
    monkeypatch.setattr(
        vault_state, "DekCipher", MagicMock(side_effect=RuntimeError("failed"))
    )

    try:
        with pytest.raises(RuntimeError, match="failed"):
            vault.unseal(new_keys)

        assert (
            vault._hmac_enc,
            vault._dek_enc,
            vault._audit_enc,
            vault._ha_wrap_enc,
            vault._pki_wrap_enc,
            vault._aesgcm,
        ) == old_generation
        assert vault.sealed is False
    finally:
        vault.seal()


def test_unseal_skips_legacy_rpc_refresh():
    class _LegacyServer:
        pass

    vault = VaultState()
    vault._master_rpc_server = _LegacyServer()
    keys = {
        "hmac_key": b"h" * 32,
        "dek_key": b"d" * 32,
        "audit_key": b"a" * 32,
        "ha_wrap_key": b"w" * 32,
        "pki_wrap_key": b"p" * 32,
    }

    vault.unseal(keys)
    vault._master_rpc_server = None
    vault.seal()


def test_unseal_logs_rust_rpc_refresh_failure(monkeypatch, caplog):
    from api.app import vault_state

    class _FailingRustServer:
        def set_subkeys(self, *_args):
            raise RuntimeError("refresh failed")

    vault = VaultState()
    vault._master_rpc_server = _FailingRustServer()
    monkeypatch.setattr(vault_state, "RustMasterRpcServer", _FailingRustServer)
    keys = {
        "hmac_key": b"h" * 32,
        "dek_key": b"d" * 32,
        "audit_key": b"a" * 32,
        "ha_wrap_key": b"w" * 32,
        "pki_wrap_key": b"p" * 32,
    }

    with caplog.at_level("CRITICAL", logger="rhorizon"):
        vault.unseal(keys)

    assert "failed to refresh master RPC key generation" in caplog.text
    vault._master_rpc_server = None
    vault.seal()


def test_seal_stops_rust_rpc_server_when_latch_fails(monkeypatch, caplog):
    from api.app import vault_state

    class _FailingRustServer:
        def __init__(self):
            self.stopped = False

        def seal(self):
            raise RuntimeError("seal failed")

        def stop(self):
            self.stopped = True

    server = _FailingRustServer()
    vault = VaultState()
    vault._master_rpc_server = server
    vault._hmac_enc = b"wrapped"
    monkeypatch.setattr(vault_state, "RustMasterRpcServer", _FailingRustServer)

    with caplog.at_level("CRITICAL", logger="rhorizon"):
        vault.seal()

    assert server.stopped is True
    assert vault._hmac_enc is None
    assert vault.sealed is True
    assert "failed to seal master RPC listener" in caplog.text


def test_seal_drops_shamir_server_when_close_fails(caplog):
    class _FailingShareServer:
        def close(self):
            raise RuntimeError("close failed")

    vault = VaultState()
    vault._cluster_share_server = _FailingShareServer()

    with caplog.at_level("ERROR", logger="rhorizon"):
        vault.seal()

    assert vault._cluster_share_server is None
    assert "failed to close Shamir share server" in caplog.text


def test_current_subkey_bundle_wipes_temporary_copies():
    vault = VaultState()
    plaintexts = [bytes([value]) * 32 for value in range(1, 6)]
    temporary_copies: list[bytearray] = []

    class _FakeSecureBuffer:
        def __init__(self, value):
            self._value = value

        def to_bytearray(self):
            copy = bytearray(self._value)
            temporary_copies.append(copy)
            return copy

    class _FakeWrap:
        def decrypt(self, wrapped):
            return _FakeSecureBuffer(wrapped)

    vault._wrap = _FakeWrap()
    vault._sealed = False
    (
        vault._hmac_enc,
        vault._dek_enc,
        vault._audit_enc,
        vault._ha_wrap_enc,
        vault._pki_wrap_enc,
    ) = plaintexts

    bundle = vault.current_subkey_bundle()
    try:
        assert bundle == b"".join(plaintexts)
        assert all(copy == bytearray(32) for copy in temporary_copies)
    finally:
        secure_zero(bundle)


def test_aesgcm_decrypt_local_rejects_invalid_nonce_length():
    vault = VaultState()
    vault._dek_enc = b"wrapped"

    with pytest.raises(ValueError, match="nonce must be 12 bytes"):
        vault._aesgcm_decrypt_local(b"ciphertext", b"short", b"aad")


def test_has_prev_hmac_with_rpc_client_returns_true():
    """When an RPC client is attached, has_prev_hmac returns True (conservative)."""
    vault = VaultState()
    vault.attach_rpc_client(MagicMock())
    assert vault.has_prev_hmac is True


def test_has_prev_hmac_without_rpc_no_prev():
    vault = VaultState()
    assert vault.has_prev_hmac is False


# ---------------------------------------------------------------------------
# Async wrappers : RPC dispatch path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hmac_sha512_hex_via_rpc():
    vault = VaultState()
    fake_client = MagicMock()
    fake_client.call = AsyncMock(return_value="ab" * 32)
    vault.attach_rpc_client(fake_client)

    result = await vault.hmac_sha512_hex("payload")
    assert result == "ab" * 32
    fake_client.call.assert_awaited_once()


@pytest.mark.asyncio
async def test_hmac_sha512_hex_prev_via_rpc_returns_none_on_empty():
    vault = VaultState()
    fake_client = MagicMock()
    fake_client.call = AsyncMock(return_value="")  # master returned empty
    vault.attach_rpc_client(fake_client)

    result = await vault.hmac_sha512_hex_prev("payload")
    assert result is None


@pytest.mark.asyncio
async def test_audit_sign_via_rpc():
    vault = VaultState()
    fake_client = MagicMock()
    fake_client.call = AsyncMock(return_value="sig-hex")
    vault.attach_rpc_client(fake_client)

    result = await vault.audit_sign("payload", "prev")
    assert result == "sig-hex"


@pytest.mark.asyncio
async def test_aesgcm_encrypt_via_rpc():
    vault = VaultState()
    fake_client = MagicMock()
    # 24 hex chars nonce + ct hex
    fake_client.call = AsyncMock(return_value="00" * 12 + "01" * 4)
    vault.attach_rpc_client(fake_client)

    ct, nonce = await vault.aesgcm_encrypt(b"x", b"")
    assert nonce == b"\x00" * 12
    assert ct == b"\x01" * 4


@pytest.mark.asyncio
async def test_aesgcm_decrypt_via_rpc():
    vault = VaultState()
    fake_client = MagicMock()
    fake_client.call = AsyncMock(return_value=b"plaintext".hex())
    vault.attach_rpc_client(fake_client)

    result = await vault.aesgcm_decrypt(b"\x01" * 4, b"\x00" * 12, b"")
    assert result == b"plaintext"


# ---------------------------------------------------------------------------
# Local ops sur vault sealed -> VaultSealedError
# ---------------------------------------------------------------------------


def test_hmac_local_sealed_raises():
    vault = VaultState()
    with pytest.raises(VaultSealedError):
        vault._hmac_sha512_hex_local("x")


def test_audit_sign_local_sealed_raises():
    vault = VaultState()
    with pytest.raises(VaultSealedError):
        vault._audit_sign_local("x")


def test_aesgcm_encrypt_local_sealed_raises():
    vault = VaultState()
    with pytest.raises(VaultSealedError):
        vault._aesgcm_encrypt_local(b"x", b"")


def test_aesgcm_decrypt_local_sealed_raises():
    vault = VaultState()
    with pytest.raises(VaultSealedError):
        vault._aesgcm_decrypt_local(b"x", b"\x00" * 12, b"")


def test_export_subkeys_for_shamir_sealed_raises():
    vault = VaultState()
    with pytest.raises(VaultSealedError):
        vault.export_subkeys_for_shamir()


def test_hmac_sha512_hex_prev_local_returns_none_when_unset():
    vault = VaultState()
    # No prev_hmac configured -> returns None
    assert vault._hmac_sha512_hex_prev_local("x") is None


def test_uptime_returns_none_when_sealed():
    vault = VaultState()
    assert vault.uptime is None


def test_memory_protection_reports_rust_lock_status(monkeypatch):
    vault = VaultState()
    monkeypatch.setattr(
        vault_state_module.rhorizon_crypto,
        "memory_lock_status",
        lambda: "mlock",
        raising=False,
    )
    assert vault.memory_protection == "mlock"

    monkeypatch.setattr(
        vault_state_module.rhorizon_crypto,
        "memory_lock_status",
        lambda: "zeroize-only",
    )
    assert vault.memory_protection == "zeroize-only"


def test_swap_protection_reports_host_state(monkeypatch):
    from api.app import mem_hardening

    vault = VaultState()
    monkeypatch.setattr(mem_hardening, "swap_protection", lambda: "protected")
    assert vault.swap_protection == "protected"


def test_process_memory_protection_reports_worker_state(monkeypatch):
    from api.app import mem_hardening

    vault = VaultState()
    monkeypatch.setattr(mem_hardening, "process_memory_protection", lambda: "swappable")
    assert vault.process_memory_protection == "swappable"


def test_clear_prev_hmac_idempotent():
    vault = VaultState()
    vault.clear_prev_hmac()
    vault.clear_prev_hmac()  # idempotent
    assert vault._prev_hmac_enc is None


def test_conditional_prev_hmac_clear_preserves_new_generation():
    vault = VaultState()
    vault.set_prev_hmac(b"a" * 32)
    observed = vault.prev_hmac_generation

    vault.set_prev_hmac(b"b" * 32)

    assert vault.clear_prev_hmac_if_generation(observed) is False
    assert vault._prev_hmac_enc is not None
    assert vault.clear_prev_hmac_if_generation(vault.prev_hmac_generation) is True
    assert vault._prev_hmac_enc is None


# --- Coverage gaps : master_rpc_server propagation on set/clear_prev_hmac ---


def test_set_prev_hmac_propagates_to_master_rpc_server():
    """set_prev_hmac on a vault with an attached master RPC server pushes
    the new encrypted prev-hmac to it so followers' ``hmac_sha512_prev``
    calls keep working through the rotation. Covers vault_state.py L144-150
    (the master_rpc_server-attached propagation branch)."""
    vault = VaultState()
    calls = []

    class _FakeRpcServer:
        def set_prev_hmac(self, enc):
            calls.append(enc)

    vault._master_rpc_server = _FakeRpcServer()
    try:
        vault.set_prev_hmac(b"k" * 32)
        assert vault._prev_hmac_enc is not None
        assert len(calls) == 1
        assert calls[0] is not None
    finally:
        vault._master_rpc_server = None
        vault._prev_hmac_enc = None


def test_set_prev_hmac_swallows_master_rpc_server_exception():
    """Defensive : a raising master_rpc_server.set_prev_hmac must NOT
    fail the rotation (the legacy Python MasterRpcServer reads
    ``_prev_hmac_enc`` directly so the explicit push is best-effort).
    Covers the silent ``except Exception: pass`` arm of L146-150."""
    vault = VaultState()

    class _RaisingRpcServer:
        def set_prev_hmac(self, enc):
            raise RuntimeError("rpc server transient")

    vault._master_rpc_server = _RaisingRpcServer()
    try:
        vault.set_prev_hmac(b"x" * 32)
        assert vault._prev_hmac_enc is not None
    finally:
        vault._master_rpc_server = None
        vault._prev_hmac_enc = None


def test_clear_prev_hmac_propagates_to_master_rpc_server():
    """clear_prev_hmac on a vault with attached master RPC server pushes
    None to the server. Covers vault_state.py L156-159 master_rpc_server
    branch."""
    vault = VaultState()
    calls = []

    class _FakeRpcServer:
        def set_prev_hmac(self, enc):
            calls.append(enc)

    vault._master_rpc_server = _FakeRpcServer()
    try:
        vault.clear_prev_hmac()
        assert vault._prev_hmac_enc is None
        assert calls == [None]
    finally:
        vault._master_rpc_server = None


def test_clear_prev_hmac_swallows_master_rpc_server_exception():
    """Same defensive guarantee for clear_prev_hmac : a raising server
    push does not propagate."""
    vault = VaultState()

    class _RaisingRpcServer:
        def set_prev_hmac(self, enc):
            raise RuntimeError("rpc server transient")

    vault._master_rpc_server = _RaisingRpcServer()
    try:
        vault.clear_prev_hmac()
        assert vault._prev_hmac_enc is None
    finally:
        vault._master_rpc_server = None


def test_ha_wrap_encrypt_local_raises_when_sealed():
    """primitive: ``_ha_wrap_encrypt_local`` refuses
    when the vault is sealed (no ha_wrap subkey in RAM). Covers
    vault_state.py L312."""
    vault = VaultState()
    assert vault._ha_wrap_enc is None
    with pytest.raises(VaultSealedError):
        vault._ha_wrap_encrypt_local(b"plaintext", b"aad")


def test_ha_wrap_decrypt_local_raises_when_sealed():
    """Mirror of the encrypt path : sealed vault refuses to unwrap.
    Covers vault_state.py L320."""
    vault = VaultState()
    assert vault._ha_wrap_enc is None
    with pytest.raises(VaultSealedError):
        vault._ha_wrap_decrypt_local(b"\x00" * 28, b"aad")


@pytest.mark.asyncio
async def test_master_transition_lock_serializes_local_role_changes():
    vault = VaultState()
    entered = asyncio.Event()

    async def contender():
        async with vault.master_transition_lock():
            entered.set()

    async with vault.master_transition_lock():
        task = asyncio.create_task(contender())
        await asyncio.sleep(0)
        assert entered.is_set() is False

    await task
    assert entered.is_set() is True


@pytest.mark.asyncio
async def test_external_custodian_raw_audit_signing_dispatches():
    vault = VaultState()
    vault._rpc_client = CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token")
    vault._cluster_audit_fpr = "f" * 64
    vault._call_rpc = AsyncMock(return_value=(b"s" * 64).hex())

    assert vault.can_audit_sign_raw is True
    assert await vault.audit_sign_raw(b"certificate-tbs") == b"s" * 64
    vault._call_rpc.assert_awaited_once_with(
        "audit_sign_raw", {"message": b"certificate-tbs".hex()}
    )
