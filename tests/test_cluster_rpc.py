"""Tests for cluster_rpc - master/worker IPC for crypto-ops."""

import os

import pytest
import rhorizon_crypto as rc
from api.app.cluster_rpc import (
    MasterRpcClient,
    MasterRpcServer,
    MasterUnreachable,
    RpcError,
    crypto_socket_name,
)
from api.app.vault_state import VaultSealedError, VaultState


def _gen_keys():
    return {
        "hmac_key": os.urandom(32),
        "dek_key": os.urandom(32),
        "audit_key": os.urandom(32),
        "ha_wrap_key": os.urandom(32),
        "pki_wrap_key": os.urandom(32),
    }


_SOCKET_CACHE: dict[str, str] = {}
_SOCKET_TMPDIR: str | None = None


def _socket(slot: str = "default") -> str:
    """A stable filesystem-path socket per test process and slot.

    The same `slot` returns the same path across calls (so server-side
    `start()` and client-side `connect()` agree). Each pytest run uses
    its own tempdir, so reruns don't collide."""
    import tempfile

    global _SOCKET_TMPDIR
    if _SOCKET_TMPDIR is None:
        _SOCKET_TMPDIR = tempfile.mkdtemp(prefix="rhorizon-rpc-test-")
    if slot not in _SOCKET_CACHE:
        _SOCKET_CACHE[slot] = f"{_SOCKET_TMPDIR}/sock-{os.getpid()}-{slot}.sock"
    return _SOCKET_CACHE[slot]


# -- Local fallback (no RPC client attached) --


@pytest.mark.asyncio
async def test_vault_local_dispatch_when_no_rpc():
    """Without an RPC client, methods execute locally in Rust."""
    v = VaultState()
    v.unseal(_gen_keys())
    sig = await v.hmac_sha512_hex("payload")
    assert len(sig) == 128  # SHA-512 hex


# -- RPC roundtrip with running server --


@pytest.mark.asyncio
async def test_rpc_hmac_sha512_roundtrip():
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("hmac"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("hmac")))

        sig_via_rpc = await worker.hmac_sha512_hex("the same payload")
        sig_local = master._hmac_sha512_hex_local("the same payload")
        assert sig_via_rpc == sig_local
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_aesgcm_roundtrip():
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("aesgcm"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("aesgcm")))

        plaintext = b"my secret value"
        aad = b"row:42"
        ct, nonce = await worker.aesgcm_encrypt(plaintext, aad)
        recovered = await worker.aesgcm_decrypt(ct, nonce, aad)
        assert recovered == plaintext
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_chained_secret_roundtrip_and_reencrypt():
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("chained-secret"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("chained-secret")))

        plaintext = b"secret that must not expose its DEK"
        old_dek_aad = b"dek:old"
        old_secret_aad = b"secret:legacy:binding"
        (
            encrypted_dek,
            dek_nonce,
            ciphertext,
            secret_nonce,
        ) = await worker.secret_encrypt(
            plaintext,
            old_dek_aad,
            old_secret_aad,
        )
        opened = await worker.secret_decrypt(
            encrypted_dek,
            dek_nonce,
            old_dek_aad,
            ciphertext,
            secret_nonce,
            old_secret_aad,
        )
        assert opened == plaintext
        rc.secure_zero(opened)

        new_dek_aad = b"dek:new"
        new_secret_aad = b"secret:v2:new-binding"
        (
            new_encrypted_dek,
            new_dek_nonce,
            new_ciphertext,
            new_secret_nonce,
        ) = await worker.secret_reencrypt(
            encrypted_dek,
            dek_nonce,
            old_dek_aad,
            ciphertext,
            secret_nonce,
            old_secret_aad,
            new_dek_aad,
            new_secret_aad,
        )
        reopened = await worker.secret_decrypt(
            new_encrypted_dek,
            new_dek_nonce,
            new_dek_aad,
            new_ciphertext,
            new_secret_nonce,
            new_secret_aad,
        )
        assert reopened == plaintext
        rc.secure_zero(reopened)
        assert new_encrypted_dek != encrypted_dek
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_ha_wrap_roundtrip():
    """ha_wrap_encrypt + ha_wrap_decrypt via the
    master RPC server. The wire format is the combined nonce || ct blob
    (no nonce / ct split, unlike aesgcm_*), and the AAD binding survives
    the roundtrip.
    """
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("ha_wrap"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("ha_wrap")))

        plain = b"row-payload"
        aad = b"vault-cluster:ha_password"
        wrapped = await worker.ha_wrap_encrypt(plain, aad)
        # 12B nonce + ciphertext + 16B GCM tag = >= 12 + 16 + len(plain)
        assert len(wrapped) >= 12 + 16 + len(plain)
        recovered = await worker.ha_wrap_decrypt(wrapped, aad)
        try:
            assert isinstance(recovered, bytearray)
            assert recovered == plain
        finally:
            rc.secure_zero(recovered)

        # Wrong AAD must fail authentication
        with pytest.raises(RpcError):
            await worker.ha_wrap_decrypt(wrapped, b"vault-cluster:wrong")

        # Master-local must produce a binary-compatible blob
        wrapped_local = master._ha_wrap_encrypt_local(plain, aad)
        recovered_local = master._ha_wrap_decrypt_local(wrapped_local, aad)
        try:
            assert isinstance(recovered_local, bytearray)
            assert recovered_local == plain
        finally:
            rc.secure_zero(recovered_local)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_audit_sign_roundtrip():
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("audit"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("audit")))

        sig_via_rpc = await worker.audit_sign("payload here", "prev_sig_value")
        sig_local = master._audit_sign_local("payload here", "prev_sig_value")
        assert sig_via_rpc == sig_local
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_audit_sign_identity_roundtrip_python_server():
    """A follower delegates Ed25519 audit signing to the master (Python server).

    The delegated signature is byte-identical to the master's local signature
    and verifies under the master's public key -- the seed never leaves master.
    """
    from api.app.crypto import verify_audit_ed25519

    master = VaultState()
    master.unseal(_gen_keys())
    master.install_audit_signer(rc.AuditSigner.from_seed(os.urandom(32)))

    server = MasterRpcServer(_socket("audit_id"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("audit_id")))
        sig_rpc = await worker.audit_sign_identity("row|payload", "prevsig")
        assert sig_rpc == master._audit_sign_identity_local("row|payload", "prevsig")
        assert verify_audit_ed25519(
            master.audit_identity_pub, "row|payload", "prevsig", sig_rpc
        )
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_audit_sign_identity_roundtrip_rust_server():
    """Same delegation against the production Rust listener (snapshots subkeys).

    The master pushes its wrapped audit seed via set_audit_seed_enc; the Rust
    audit_sign_identity op decrypts it under the master key, Ed25519-signs, and
    returns a signature identical to the master's local AuditSigner.
    """
    from api.app.crypto import verify_audit_ed25519

    master = VaultState()
    master.unseal(_gen_keys())
    master.install_audit_signer(rc.AuditSigner.from_seed(os.urandom(32)))

    server = master._wrap.create_master_rpc_server(
        _socket("audit_id_rust"),
        master._hmac_enc,
        master._dek_enc,
        master._audit_enc,
        os.getuid(),
    )
    server.set_audit_seed_enc(master._audit_seed_enc)
    server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("audit_id_rust")))
        sig_rpc = await worker.audit_sign_identity("row|payload", "prevsig")
        assert sig_rpc == master._audit_sign_identity_local("row|payload", "prevsig")
        assert verify_audit_ed25519(
            master.audit_identity_pub, "row|payload", "prevsig", sig_rpc
        )
    finally:
        server.stop()


@pytest.mark.asyncio
async def test_rpc_chained_secret_roundtrip_rust_server():
    """Production Rust listener keeps both DEK operations inside Rust."""
    master = VaultState()
    master.unseal(_gen_keys())
    server = master._wrap.create_master_rpc_server(
        _socket("chained_secret_rust"),
        master._hmac_enc,
        master._dek_enc,
        master._audit_enc,
        os.getuid(),
    )
    server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("chained_secret_rust")))
        plaintext = b"native RPC chained secret"
        (
            encrypted_dek,
            dek_nonce,
            ciphertext,
            secret_nonce,
        ) = await worker.secret_encrypt(
            plaintext,
            b"dek:native",
            b"secret:v2:native",
        )
        opened = await worker.secret_decrypt(
            encrypted_dek,
            dek_nonce,
            b"dek:native",
            ciphertext,
            secret_nonce,
            b"secret:v2:native",
        )
        assert opened == plaintext
        rc.secure_zero(opened)
    finally:
        server.stop()


@pytest.mark.asyncio
async def test_rpc_rust_server_seal_latch_refuses_ops():
    """Fail-closed seal latch end-to-end (Python double of the Rust unit test
    dispatch_refuses_when_sealed): a sealed Rust master refuses every op over
    the socket, and a subsequent set_subkeys (re-unseal refresh) re-arms it."""
    master = VaultState()
    master.unseal(_gen_keys())

    server = master._wrap.create_master_rpc_server(
        _socket("seal_latch"),
        master._hmac_enc,
        master._dek_enc,
        master._audit_enc,
        os.getuid(),
    )
    server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("seal_latch")))

        # Operational: op succeeds and matches the master-local result.
        sig = await worker.hmac_sha512_hex("payload")
        assert sig == master._hmac_sha512_hex_local("payload")

        # seal() (what vault.seal() calls): every op now refused, fail-closed.
        server.seal()
        with pytest.raises(RpcError):
            await worker.hmac_sha512_hex("payload")

        # A re-unseal refresh (set_subkeys) re-arms the listener.
        server.set_subkeys(master._hmac_enc, master._dek_enc, master._audit_enc)
        assert await worker.hmac_sha512_hex("payload") == sig
    finally:
        server.stop()


# -- Master-password rotation refreshes the live listener (regression) --


@pytest.mark.asyncio
async def test_rpc_rotation_refreshes_subkey_generation():
    """A master that rotates its own password must roll its running RPC
    listener forward to the new generation, or followers delegating via
    RPC keep validating against the pre-rotation sub-keys -- 401 on every
    token minted under the new hmac_key, tag-fail on every DEK re-wrapped
    under the new dek_key.

    This drives the *Rust* MasterRpcServer (the one that snapshots its
    sub-keys at construction -- the Python cluster_rpc.MasterRpcServer
    reads the vault live and never had the bug) through a real socket +
    RPC client, then rotates in place via ``vault.unseal(new_keys)`` --
    exactly what /rotate-password does. Asserts the listener now serves
    the new generation for all three sub-keys (hmac, dek, audit).
    """
    gen1 = _gen_keys()
    gen2 = _gen_keys()
    ref1 = VaultState()
    ref1.unseal(gen1)
    ref2 = VaultState()
    ref2.unseal(gen2)

    master = VaultState()
    master.unseal(gen1)

    # Wire a Rust master RPC server onto the master, like
    # cluster_setup.start_master_services does. The WrapKey factory hands
    # its internal master key to the server ; the encrypted sub-keys cross
    # as public ciphertext.
    server = master._wrap.create_master_rpc_server(
        _socket("rotate"),
        master._hmac_enc,
        master._dek_enc,
        master._audit_enc,
        os.getuid(),
    )
    server.start()
    master._master_rpc_server = server
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("rotate")))

        msg = "token-to-validate"
        # Baseline: the follower's delegated HMAC matches gen1.
        assert await worker.hmac_sha512_hex(msg) == ref1._hmac_sha512_hex_local(msg)

        # Rotate in place: same process WrapKey, freshly derived sub-keys.
        # unseal() must push the new snapshot to the running listener.
        master.unseal(gen2)

        # hmac rolled forward to gen2 (and is no longer gen1).
        sig_after = await worker.hmac_sha512_hex(msg)
        assert sig_after == ref2._hmac_sha512_hex_local(msg)
        assert sig_after != ref1._hmac_sha512_hex_local(msg)

        # audit rolled forward to gen2.
        assert await worker.audit_sign("row", "prev") == ref2._audit_sign_local(
            "row", "prev"
        )

        # dek rolled forward: a follower encrypt/decrypt round-trips under
        # the new dek_key (the op delegates to the refreshed listener).
        ct, nonce = await worker.aesgcm_encrypt(b"secret value", b"row:7")
        assert await worker.aesgcm_decrypt(ct, nonce, b"row:7") == b"secret value"
    finally:
        server.stop()


# -- Failure modes --


@pytest.mark.asyncio
async def test_rpc_master_unreachable():
    worker = VaultState()
    worker.attach_rpc_client(MasterRpcClient(_socket("nonexistent")))
    with pytest.raises(MasterUnreachable):
        await worker.hmac_sha512_hex("anything")


@pytest.mark.asyncio
async def test_rpc_master_returns_error_when_sealed():
    """If the master is sealed, ops raise - wrapped in RpcError on the wire."""
    master = VaultState()  # sealed (default)
    server = MasterRpcServer(_socket("sealed"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("sealed")))
        with pytest.raises(RpcError) as exc:
            await worker.hmac_sha512_hex("test")
        assert "VaultSealedError" in str(exc.value)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_invalid_socket_name_rejected():
    """Empty socket path is rejected. (The pre-2026-05 abstract-namespace
    \\0 prefix check was dropped - sockets are now plain filesystem paths.)"""
    with pytest.raises(ValueError):
        MasterRpcClient("")
    with pytest.raises(ValueError):
        master = VaultState()
        MasterRpcServer("", master)


@pytest.mark.asyncio
async def test_rpc_client_missing_peer_socket_fails_closed(monkeypatch):
    """If the transport exposes no socket object (get_extra_info -> None),
    the peer-UID check can't run, so the client fails closed with
    MasterUnreachable instead of leaking an AttributeError past its
    documented contract (mirrors the ucred-is-None guard)."""
    import asyncio as _asyncio

    class _FakeWriter:
        def __init__(self):
            self.wrote = False

        def get_extra_info(self, _name):
            return None

        def write(self, _data):
            self.wrote = True

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    fw = _FakeWriter()

    async def _fake_open(_path):
        return (object(), fw)

    monkeypatch.setattr(_asyncio, "open_unix_connection", _fake_open)
    client = MasterRpcClient(_socket("nosock"))
    with pytest.raises(MasterUnreachable):
        await client.call("hmac_sha512", {"message": "00"})
    assert fw.wrote is False  # rejected before sending the request


@pytest.mark.asyncio
async def test_rpc_server_missing_peer_socket_rejected():
    """Server side: a transport with no socket object is rejected (writer
    closed, no dispatch) instead of escaping _handle_client as an unhandled
    AttributeError that would leak the connection."""
    master = VaultState()
    server = MasterRpcServer(_socket("srvnosock"), master)
    closed = {"v": False}

    class _FakeWriter:
        def get_extra_info(self, _name):
            return None

        def close(self):
            closed["v"] = True

        async def wait_closed(self):
            pass

    class _FakeReader:
        async def readexactly(self, _n):
            raise AssertionError("must not read after a rejected peer")

    await server._handle_client(_FakeReader(), _FakeWriter())
    assert closed["v"] is True


@pytest.mark.asyncio
async def test_rpc_unknown_op_returns_error():
    """The master should reply with an error for an unknown op."""
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("unknown"), master)
    await server.start()
    try:
        client = MasterRpcClient(_socket("unknown"))
        with pytest.raises(RpcError) as exc:
            await client.call("totally_made_up_op", {})
        assert "unknown op" in str(exc.value).lower()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_aesgcm_wrong_aad_fails():
    """AAD mismatch on decrypt is propagated as an RpcError."""
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)

    server = MasterRpcServer(_socket("aad"), master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("aad")))

        ct, nonce = await worker.aesgcm_encrypt(b"data", b"aad-A")
        with pytest.raises(RpcError):
            await worker.aesgcm_decrypt(ct, nonce, b"aad-B")
    finally:
        await server.stop()


# -- wrap_node_key_for_joiner / wrap_server_key_for_joiner RPC ops --


@pytest.mark.asyncio
async def test_rpc_wrap_node_key_for_joiner_roundtrip():
    """a follower delegates the node-key wrap to
    master via the RPC dispatch op. The wrap key is the per-uuid HKDF
    derivation of ``vault._ha_password_enc``, which only master holds.
    The op returns the combined ``nonce || ct`` blob (hex). The joiner
    side replays the HKDF locally to unwrap.

    Test design : single-process tests cannot model two distinct
    singletons (master + follower share the same ``ha_password.vault``
    import). We patch the module-level ``vault`` to be the master for
    the duration of the call ; the RPC server handler reads the patched
    singleton and the test verifies the wire op produces an unwrappable
    blob.
    """
    from unittest.mock import patch

    from api.app import ha_password as _hap

    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)
    # Simulate /cluster/init's effect on master : ha_password loaded
    # into the wrapped RAM buffer. The module-level setter would do a
    # DB INSERT ; for this unit test we set the RAM directly.
    master._ha_password_enc = master._encrypt(b"x" * 32)

    server = MasterRpcServer(_socket("wrap_node_key"), master)
    await server.start()
    try:
        node_key_pem = (
            b"-----BEGIN PRIVATE KEY-----\nfakefakefake\n-----END PRIVATE KEY-----\n"
        )
        node_uuid = "deadbeef" * 4

        client = MasterRpcClient(_socket("wrap_node_key"))
        with patch.object(_hap, "vault", master):
            wrapped_local = _hap.wrap_node_key_for_joiner(node_key_pem, node_uuid)
            result_hex = await client.call(
                "wrap_node_key_for_joiner",
                {"node_key_pem": node_key_pem.hex(), "node_uuid": node_uuid},
            )
        wrapped_via_rpc = bytes.fromhex(result_hex)

        # Per-call nonce differs so the cipher bytes themselves diverge.
        # Round-trip via the joiner-side unwrap.
        recovered_local = _hap.unwrap_node_key_for_joiner(
            wrapped_local, b"x" * 32, node_uuid
        )
        recovered_via_rpc = _hap.unwrap_node_key_for_joiner(
            wrapped_via_rpc, b"x" * 32, node_uuid
        )
        assert recovered_local == node_key_pem
        assert recovered_via_rpc == node_key_pem
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_wrap_server_key_for_joiner_roundtrip():
    """same dispatch shape for the server-cert
    private key. Distinct HKDF info / AAD domain : a
    server-key blob cannot unwrap as a node-key blob, even with the
    same ha_password + node_uuid.
    """
    from unittest.mock import patch

    from api.app import ha_password as _hap

    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)
    master._ha_password_enc = master._encrypt(b"y" * 32)

    server = MasterRpcServer(_socket("wrap_server_key"), master)
    await server.start()
    try:
        server_key_pem = (
            b"-----BEGIN PRIVATE KEY-----\nserverkeypem\n-----END PRIVATE KEY-----\n"
        )
        node_uuid = "cafebabe" * 4

        client = MasterRpcClient(_socket("wrap_server_key"))
        with patch.object(_hap, "vault", master):
            result_hex = await client.call(
                "wrap_server_key_for_joiner",
                {"server_key_pem": server_key_pem.hex(), "node_uuid": node_uuid},
            )
        wrapped_via_rpc = bytes.fromhex(result_hex)

        recovered = _hap.unwrap_server_key_for_joiner(
            wrapped_via_rpc, b"y" * 32, node_uuid
        )
        assert recovered == server_key_pem

        # Cross-domain isolation : the server-key blob does NOT decrypt
        # as a node-key blob (different HKDF info).
        with pytest.raises(_hap.HaPasswordError):
            _hap.unwrap_node_key_for_joiner(wrapped_via_rpc, b"y" * 32, node_uuid)
    finally:
        await server.stop()


# -- is_master property --


def test_is_master_true_for_unsealed_local():
    v = VaultState()
    v.unseal(_gen_keys())
    assert v.is_master is True


def test_is_master_false_when_sealed():
    v = VaultState()
    assert v.is_master is False


def test_is_master_false_when_rpc_client_attached():
    v = VaultState()
    v.unseal(_gen_keys())
    v.attach_rpc_client(MasterRpcClient(_socket("ismaster")))
    assert v.is_master is False
    v.detach_rpc_client()
    assert v.is_master is True


# -- crypto_socket_name helper --


def test_crypto_socket_name_uses_hostname():
    name = crypto_socket_name("test-host")
    # Filesystem path now (not abstract namespace)
    assert name.endswith("crypto-ops-test-host.sock")
    assert "test-host" in name


def test_crypto_socket_name_default_from_env(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "container-xyz")
    name = crypto_socket_name()
    assert "container-xyz" in name


# -- VaultSealedError still raises locally without RPC --


@pytest.mark.asyncio
async def test_local_sealed_raises_vault_sealed_error():
    """When no RPC client is attached and vault is sealed,
    VaultSealedError surfaces directly (no RPC layer)."""
    v = VaultState()  # sealed
    with pytest.raises(VaultSealedError):
        await v.hmac_sha512_hex("test")
    with pytest.raises(VaultSealedError):
        await v.aesgcm_encrypt(b"x", b"aad")
    with pytest.raises(VaultSealedError):
        await v.audit_sign("test")


# -- Regression: uvloop abstract-socket compatibility --
#
# uvloop's high-level `asyncio.open_unix_connection(path)` does not handle
# abstract-namespace addresses (str or bytes with a leading '\0') and
# raises EINVAL. The bind side (`start_unix_server`) works fine, only
# the connect path is broken. Production runs uvicorn[standard], which
# enables uvloop, so this test catches the regression that broke every
# follower->master crypto-ops RPC call (every authenticated request).


def test_rpc_roundtrip_under_uvloop():
    """Run the full master+client roundtrip on an uvloop event loop.

    Skipped silently if uvloop isn't installed in the test env (it ships
    with uvicorn[standard], so it should be available in CI).
    """
    uvloop = pytest.importorskip("uvloop")

    async def _run():
        keys = _gen_keys()
        master = VaultState()
        master.unseal(keys)
        server = MasterRpcServer(_socket("uvloop"), master)
        await server.start()
        try:
            worker = VaultState()
            worker.attach_rpc_client(MasterRpcClient(_socket("uvloop")))
            sig = await worker.hmac_sha512_hex("uvloop-payload")
            assert len(sig) == 128
        finally:
            await server.stop()

    # uvloop.run() spins up a fresh uvloop event loop for this call only,
    # leaving the rest of the test suite on stock asyncio.
    uvloop.run(_run())


# -- proactive RPC recovery on MasterUnreachable --


@pytest.mark.asyncio
async def test_slice14e_recovery_success_swaps_client_and_retries():
    """When a stale client trips MasterUnreachable, the recovery hook
    swaps the worker over to a live master socket and the op succeeds
    on the retry. The recovery counter records `outcome=success`.
    """
    import asyncio

    from api.app.metrics import cluster_rpc_recovery

    # Live master + its socket
    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)
    live_sock = _socket("recover-live")
    server = MasterRpcServer(live_sock, master)
    await server.start()
    try:
        worker = VaultState()
        # Attach a client pointing at a NON-existent socket -- first call
        # will raise MasterUnreachable.
        worker.attach_rpc_client(MasterRpcClient(_socket("recover-dead")))

        async def _recover():
            # Simulate the cluster_setup helper : detach, re-attach to the
            # live master.
            await asyncio.sleep(0.05)
            worker.detach_rpc_client()
            worker.attach_rpc_client(MasterRpcClient(live_sock))
            return True

        worker.set_rpc_recovery_hook(_recover)

        before = cluster_rpc_recovery.labels(outcome="success")._value.get()
        sig = await worker.hmac_sha512_hex("after-recovery")
        after = cluster_rpc_recovery.labels(outcome="success")._value.get()

        # Same payload through the live master must match the local op.
        assert sig == master._hmac_sha512_hex_local("after-recovery")
        assert after - before == 1
        assert worker.rpc_fenced is False
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_slice14e_recovery_timeout_reraises_master_unreachable():
    """When the recovery hook does not converge within the vault's budget,
    `_call_rpc` re-raises `MasterUnreachable` (FastAPI then maps it to
    503 + Retry-After). The counter records `outcome=timeout`.
    """
    import asyncio

    from api.app.metrics import cluster_rpc_recovery

    worker = VaultState()
    worker.attach_rpc_client(MasterRpcClient(_socket("recover-stuck")))
    # Tight budget so the test stays fast.
    worker._rpc_recovery_budget_secs = 0.2

    async def _recover_hang():
        await asyncio.sleep(5)  # well over budget
        return True

    worker.set_rpc_recovery_hook(_recover_hang)

    before = cluster_rpc_recovery.labels(outcome="timeout")._value.get()
    with pytest.raises(MasterUnreachable):
        await worker.hmac_sha512_hex("never-arrives")
    after = cluster_rpc_recovery.labels(outcome="timeout")._value.get()
    assert after - before == 1
    assert worker.rpc_fenced is True


@pytest.mark.asyncio
async def test_rpc_recovery_promotion_does_not_fence_new_master():
    """Promotion during RPC recovery leaves the new master ready."""
    from api.app.metrics import cluster_rpc_recovery

    keys = _gen_keys()
    worker = VaultState()
    worker.attach_rpc_client(MasterRpcClient(_socket("recover-promoted")))

    async def _recover():
        worker.detach_rpc_client()
        worker.unseal(keys)
        return True

    worker.set_rpc_recovery_hook(_recover)

    before = cluster_rpc_recovery.labels(outcome="promoted")._value.get()
    with pytest.raises(MasterUnreachable):
        await worker.hmac_sha512_hex("promotion-race")
    after = cluster_rpc_recovery.labels(outcome="promoted")._value.get()

    assert after - before == 1
    assert worker.is_master is True
    assert worker.rpc_fenced is False
    assert await worker.hmac_sha512_hex(
        "promotion-race"
    ) == worker._hmac_sha512_hex_local("promotion-race")


@pytest.mark.asyncio
async def test_rpc_readiness_fence_clears_only_after_real_probe_success():
    """A failed recovery fences only this worker; a live RPC probe heals it."""
    from unittest.mock import AsyncMock

    from api.app.cluster_rpc import MasterUnreachable

    worker = VaultState()
    client = AsyncMock()
    client.call.side_effect = MasterUnreachable("master unavailable")
    worker.attach_rpc_client(client)
    worker._mark_rpc_unreachable()

    assert worker.rpc_fenced is True
    assert await worker.probe_fenced_rpc() is False
    assert worker.rpc_fenced is True

    client.call.side_effect = None
    client.call.return_value = "ab" * 64
    assert await worker.probe_fenced_rpc() is True
    assert worker.rpc_fenced is False


@pytest.mark.asyncio
async def test_slice14e_concurrent_recoveries_share_single_task():
    """Two concurrent failing crypto ops must share a single recovery
    cycle -- the hook is called once, not once per failed request.
    """
    import asyncio

    keys = _gen_keys()
    master = VaultState()
    master.unseal(keys)
    live_sock = _socket("recover-concurrent")
    server = MasterRpcServer(live_sock, master)
    await server.start()
    try:
        worker = VaultState()
        worker.attach_rpc_client(MasterRpcClient(_socket("recover-concurrent-dead")))

        call_count = 0

        async def _recover():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.1)
            worker.detach_rpc_client()
            worker.attach_rpc_client(MasterRpcClient(live_sock))
            return True

        worker.set_rpc_recovery_hook(_recover)

        # Fire two ops concurrently while the worker still points at the
        # dead socket. Both should converge through one recovery cycle.
        sig_a, sig_b = await asyncio.gather(
            worker.hmac_sha512_hex("alpha"),
            worker.hmac_sha512_hex("beta"),
        )
        assert sig_a == master._hmac_sha512_hex_local("alpha")
        assert sig_b == master._hmac_sha512_hex_local("beta")
        # Recovery hook fired once, not twice.
        assert call_count == 1
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_slice14e_recovery_hook_crash_does_not_propagate():
    """If the recovery callable itself raises (e.g. DB unreachable mid-
    attach), `_trigger_recovery` swallows the exception and returns False
    so that `_call_rpc` re-raises the original `MasterUnreachable` for
    the 503 path. The hook crash must not leak as 500.
    """
    worker = VaultState()
    worker.attach_rpc_client(MasterRpcClient(_socket("recover-crash")))
    worker._rpc_recovery_budget_secs = 0.5

    async def _recover_crashes():
        raise RuntimeError("DB went away during recovery")

    worker.set_rpc_recovery_hook(_recover_crashes)

    with pytest.raises(MasterUnreachable):
        await worker.hmac_sha512_hex("anything")


@pytest.mark.asyncio
async def test_slice14e_no_hook_falls_back_to_legacy_raise():
    """Without a recovery hook installed, `MasterUnreachable` surfaces
    unchanged -- the legacy behaviour that the FastAPI 503 handler relies
    on. Counter records `outcome=unwired`.
    """
    from api.app.metrics import cluster_rpc_recovery

    worker = VaultState()
    worker.attach_rpc_client(MasterRpcClient(_socket("recover-unwired")))

    before = cluster_rpc_recovery.labels(outcome="unwired")._value.get()
    with pytest.raises(MasterUnreachable):
        await worker.hmac_sha512_hex("no-hook")
    after = cluster_rpc_recovery.labels(outcome="unwired")._value.get()
    assert after - before == 1
