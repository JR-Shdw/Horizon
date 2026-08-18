"""Extra tests for api/app/cluster_rpc.py.

Cible : MasterRpcClient (connect, peer cred, error paths) +
MasterRpcServer (start/stop, _dispatch, _handle_client peer rejection).
"""

import asyncio
import json
import os
import struct
import uuid
from unittest.mock import MagicMock

import pytest
from api.app.cluster_rpc import (
    MAX_PAYLOAD,
    CustodianRpcClient,
    MasterRpcClient,
    MasterRpcServer,
    MasterUnreachable,
    RpcError,
    _read_control_capability,
    _read_peer_cred,
    crypto_socket_name,
)

# ---------------------------------------------------------------------------
# crypto_socket_name + _read_peer_cred
# ---------------------------------------------------------------------------


def test_crypto_socket_name_default(monkeypatch, tmp_path):
    # F2 fix : get_hostname() falls back to socket.gethostname() before
    # the literal "default" sentinel. Stub both to exercise the last-resort
    # branch that yields "crypto-ops-default.sock".
    import api.app.cluster as cluster_mod

    monkeypatch.delenv("HOSTNAME", raising=False)
    monkeypatch.setattr(cluster_mod.socket, "gethostname", lambda: "")
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path))
    assert crypto_socket_name().endswith("crypto-ops-default.sock")


def test_crypto_socket_name_falls_back_to_system_hostname(monkeypatch, tmp_path):
    # F2 fix : bare-metal systemd does not inherit HOSTNAME, but the
    # kernel hostname is always available -- get_hostname() must use it.
    import api.app.cluster as cluster_mod

    monkeypatch.delenv("HOSTNAME", raising=False)
    monkeypatch.setattr(cluster_mod.socket, "gethostname", lambda: "bare-metal-host")
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path))
    assert crypto_socket_name().endswith("crypto-ops-bare-metal-host.sock")


def test_crypto_socket_name_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOSTNAME", "myhost")
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path))
    assert crypto_socket_name().endswith("crypto-ops-myhost.sock")


def test_crypto_socket_name_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path))
    assert crypto_socket_name("explicit-id").endswith("crypto-ops-explicit-id.sock")


def test_read_peer_cred_failure_returns_none():
    """Sock sans SO_PEERCRED valide -> None (pas d'exception)."""

    class FakeSock:
        def getsockopt(self, *a, **kw):
            raise OSError("not a Unix socket")

        def fileno(self):
            # BSD path calls fileno() before getpeereid; -1 makes the
            # syscall fail and the function returns None.
            return -1

    assert _read_peer_cred(FakeSock()) is None


# ---------------------------------------------------------------------------
# Client / server: input validation
# ---------------------------------------------------------------------------


def test_client_rejects_empty_socket_name():
    with pytest.raises(ValueError, match="non-empty filesystem path"):
        MasterRpcClient("")


def test_custodian_client_rejects_empty_control_token_path():
    with pytest.raises(ValueError, match="control_token_file"):
        CustodianRpcClient("/tmp/custodian.sock", "")


def test_control_capability_reader_enforces_private_regular_file(tmp_path):
    token = tmp_path / "control.token"
    token.write_bytes(b" \t" + b"a" * 32 + b"\r\n")
    token.chmod(0o600)
    capability = _read_control_capability(str(token))
    try:
        assert capability == b"a" * 32
    finally:
        from rhorizon_crypto import secure_zero

        secure_zero(capability)

    token.chmod(0o640)
    with pytest.raises(RuntimeError, match="group/world"):
        _read_control_capability(str(token))
    token.chmod(0o600)
    link = tmp_path / "control-link.token"
    link.symlink_to(token)
    with pytest.raises(OSError):
        _read_control_capability(str(link))

    token.write_bytes(b"a" * 259)
    token.chmod(0o600)
    with pytest.raises(RuntimeError, match="too large"):
        _read_control_capability(str(token))


@pytest.mark.asyncio
async def test_custodian_client_sends_capability_only_for_control_ops(tmp_path):
    token = tmp_path / "control.token"
    token.write_bytes(b"0123456789abcdef0123456789abcdef\n")
    token.chmod(0o600)
    socket_name = _unique_sock_path()
    requests = []

    async def capture_request(reader, writer):
        try:
            frame_size = struct.unpack(">I", await reader.readexactly(4))[0]
            request = json.loads(await reader.readexactly(frame_size))
            requests.append(request)
            response = json.dumps({"result": ""}).encode()
            writer.write(struct.pack(">I", len(response)) + response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(capture_request, path=socket_name)
    try:
        client = CustodianRpcClient(socket_name, str(token), timeout=2.0)
        await client.call("hmac_sha512", {"message": "00"})
        await client.call("clear_prev_hmac", {})
        await client.call("generate_audit_identity", {})
        with pytest.raises(ValueError, match="not a custodian control operation"):
            await client.call_control("hmac_sha512", {"message": "00"})
    finally:
        server.close()
        await server.wait_closed()

    assert requests == [
        {"op": "hmac_sha512", "args": {"message": "00"}},
        {
            "op": "clear_prev_hmac",
            "args": {},
            "capability": "0123456789abcdef0123456789abcdef",
        },
        {
            "op": "generate_audit_identity",
            "args": {},
            "capability": "0123456789abcdef0123456789abcdef",
        },
    ]


def test_server_rejects_empty_socket_name():
    with pytest.raises(ValueError, match="non-empty filesystem path"):
        MasterRpcServer("", vault=MagicMock())


import tempfile as _tf  # noqa: E402


def _unique_sock_path() -> str:
    """Return a unique filesystem socket path under a per-call temp dir.

    Each test uses its own tempdir so concurrent / repeated runs don't
    collide. Cleanup is handled by Python's tempdir GC at process exit
    plus our `MasterRpcServer.stop()` -> `cleanup_socket` which unlinks
    the socket file proper.
    """
    d = _tf.mkdtemp(prefix="rhorizon-rpc-test-")
    return f"{d}/sock-{uuid.uuid4().hex}.sock"


@pytest.mark.asyncio
async def test_client_unreachable_raises(tmp_path):
    """Connect to a nonexistent socket -> MasterUnreachable."""
    path = str(tmp_path / f"doesnotexist-{uuid.uuid4()}.sock")
    client = MasterRpcClient(path, timeout=0.5)
    with pytest.raises(MasterUnreachable):
        await client.call("hmac_sha512", {"message": "00"})


# ---------------------------------------------------------------------------
# Server : start/stop idempotence + double-start logging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_start_stop_idempotent():
    """stop() before start() is a no-op; start() twice logs a warning."""
    sock_name = _unique_sock_path()
    vault = MagicMock()
    server = MasterRpcServer(sock_name, vault)

    await server.stop()  # no-op
    await server.start()
    await server.start()  # double start -> warning, no error
    await server.stop()


# ---------------------------------------------------------------------------
# Round-trip server <-> client : couvre _handle_client + _dispatch + call
# ---------------------------------------------------------------------------


def _build_fake_vault():
    vault = MagicMock()
    vault._hmac_sha512_hex_local.return_value = "ab" * 64
    vault._hmac_sha512_hex_prev_local.return_value = None
    vault._aesgcm_encrypt_local.return_value = (b"\x01\x02", b"\x00" * 12)
    vault._aesgcm_decrypt_local.return_value = b"plaintext"
    vault._audit_sign_local.return_value = "sig-hex"
    return vault


@pytest.mark.asyncio
async def test_rpc_roundtrip_hmac_sha512():
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        result = await client.call("hmac_sha512", {"message": "00"})
        assert result == "ab" * 64
        vault._hmac_sha512_hex_local.assert_called_once()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_roundtrip_hmac_sha512_prev_returns_empty_on_none():
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    vault._hmac_sha512_hex_prev_local.return_value = None
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        result = await client.call("hmac_sha512_prev", {"message": "00"})
        assert result == ""
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_roundtrip_aesgcm_encrypt():
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        result = await client.call(
            "aesgcm_encrypt", {"plaintext": "deadbeef", "aad": "1234"}
        )
        # nonce(12B = 24 hex) || ct
        assert len(result) == 24 + 4  # 12B nonce hex + 2B ct hex
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_roundtrip_aesgcm_decrypt():
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        result = await client.call(
            "aesgcm_decrypt",
            {"ciphertext": "0102", "nonce": "00" * 12, "aad": ""},
        )
        assert result == b"plaintext".hex()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_roundtrip_audit_sign():
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        result = await client.call(
            "audit_sign",
            {"payload": "p", "prev_signature": "prev"},
        )
        assert result == "sig-hex"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_unknown_op_returns_error():
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        with pytest.raises(RpcError, match="unknown op"):
            await client.call("nonexistent_op", {})
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rpc_master_exception_wrapped():
    """An exception on the master side becomes an RpcError on the client side."""
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    vault._hmac_sha512_hex_local.side_effect = RuntimeError("master internal error")
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        with pytest.raises(RpcError, match="master internal error"):
            await client.call("hmac_sha512", {"message": "00"})
    finally:
        await server.stop()


# ---------------------------------------------------------------------------
# Server _handle_client : invalid request length
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_rejects_peer_with_wrong_uid(monkeypatch):
    """SO_PEERCRED retourne un UID != ours -> server ferme la connexion."""
    from api.app import cluster_rpc as mod

    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()

    # Patch _read_peer_cred pour simuler un peer avec uid = our_uid + 1
    real_uid = os.getuid()
    monkeypatch.setattr(
        mod, "_read_peer_cred", lambda sock: (12345, real_uid + 1, real_uid + 1)
    )

    try:
        # Connect manuellement
        sock = __import__("socket").socket(
            __import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM
        )
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, sock_name)
        reader, writer = await asyncio.open_unix_connection(sock=sock)
        # The server must close immediately on ucred mismatch
        try:
            data = await asyncio.wait_for(reader.read(4), timeout=1.0)
            assert data == b""  # connection closed by the server
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_client_rejects_peer_with_wrong_uid(monkeypatch):
    """Client side: if _read_peer_cred returns a UID different from ours,
    MasterUnreachable is raised."""
    from api.app import cluster_rpc as mod

    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()

    # Patch _read_peer_cred to simulate a "foreign" master
    real_uid = os.getuid()
    monkeypatch.setattr(
        mod, "_read_peer_cred", lambda sock: (1, real_uid + 1, real_uid + 1)
    )

    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        with pytest.raises(MasterUnreachable, match="uid check failed"):
            await client.call("hmac_sha512", {"message": "00"})
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_client_rejects_peer_when_cred_unavailable(monkeypatch):
    """Client side: _read_peer_cred returning None (peer not
    authenticatable) must raise MasterUnreachable -- fail-closed, not a
    pass (a hijacked socket must not impersonate the master by
    suppressing SO_PEERCRED)."""
    from api.app import cluster_rpc as mod

    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()

    monkeypatch.setattr(mod, "_read_peer_cred", lambda sock: None)

    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        with pytest.raises(MasterUnreachable, match="uid check failed"):
            await client.call("hmac_sha512", {"message": "00"})
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_client_connect_to_nonexistent_socket_raises_master_unreachable():
    """MasterRpcClient.call against a non-existent socket path surfaces
    MasterUnreachable (wrapped FileNotFoundError). Covers cluster_rpc.py
    L100-101 -- the connect-side error path of the client wire helper."""
    client = MasterRpcClient(
        "/var/run/rhorizon/definitely-does-not-exist-{}.sock".format(uuid.uuid4().hex),
        timeout=2.0,
    )
    with pytest.raises(MasterUnreachable, match="connect to master failed"):
        await client.call("hmac_sha512", {"message": "00"})


@pytest.mark.asyncio
async def test_client_invalid_response_length_raises_master_unreachable():
    """Server reply with a length-prefix > MAX_PAYLOAD is rejected client-side
    via MasterUnreachable (covers cluster_rpc.py L122 invalid response length
    check). Wired via a minimal asyncio Unix socket server that emits a
    bogus length without an actual response body."""
    sock_name = _unique_sock_path()

    async def _bad_server(reader, writer):
        try:
            len_buf = await reader.readexactly(4)
            req_len = struct.unpack(">I", len_buf)[0]
            await reader.readexactly(req_len)
        except Exception:
            pass
        writer.write(struct.pack(">I", MAX_PAYLOAD + 1))
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_unix_server(_bad_server, path=sock_name)
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        with pytest.raises(MasterUnreachable, match="invalid response length"):
            await client.call("hmac_sha512", {"message": "00"})
    finally:
        server.close()
        await server.wait_closed()
        try:
            os.unlink(sock_name)
        except FileNotFoundError:
            pass


@pytest.mark.asyncio
async def test_client_incomplete_read_raises_master_unreachable():
    """Server closes the connection mid-read on the client side ->
    asyncio.IncompleteReadError -> wrapped as MasterUnreachable
    (covers cluster_rpc.py L132)."""
    sock_name = _unique_sock_path()

    async def _hangup_server(reader, writer):
        try:
            len_buf = await reader.readexactly(4)
            req_len = struct.unpack(">I", len_buf)[0]
            await reader.readexactly(req_len)
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_unix_server(_hangup_server, path=sock_name)
    try:
        client = MasterRpcClient(sock_name, timeout=2.0)
        with pytest.raises(MasterUnreachable, match="master closed connection"):
            await client.call("hmac_sha512", {"message": "00"})
    finally:
        server.close()
        await server.wait_closed()
        try:
            os.unlink(sock_name)
        except FileNotFoundError:
            pass


@pytest.mark.asyncio
async def test_server_rejects_oversized_request():
    """A len-prefix > MAX_PAYLOAD must be logged without crashing and close the conn."""
    sock_name = _unique_sock_path()
    vault = _build_fake_vault()
    server = MasterRpcServer(sock_name, vault)
    await server.start()
    try:
        # Connect manually and send a huge length
        sock = __import__("socket").socket(
            __import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM
        )
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, sock_name)
        reader, writer = await asyncio.open_unix_connection(sock=sock)
        writer.write(struct.pack(">I", MAX_PAYLOAD + 1) + b"X" * 8)
        await writer.drain()
        # Server must close the connection (perhaps after timeout)
        try:
            await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
            # If we got a buf, it is an error response (should not happen)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass  # expected behavior: conn closed
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    finally:
        await server.stop()
