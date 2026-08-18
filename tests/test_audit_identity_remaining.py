# SPDX-License-Identifier: AGPL-3.0-or-later
"""Failure-path coverage for audit signer custody and certification."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from api.app import audit_identity
from api.app.cluster_rpc import CustodianRpcClient
from api.app.vault_state import VaultSealedError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class _Result:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class _Db:
    def __init__(self, rows=()):
        self.rows = iter(rows)

    async def execute(self, *_args, **_kwargs):
        return _Result(next(self.rows, None))


class _ProvisionDb:
    def __init__(self, events, *, fail_commit=False):
        self.events = events
        self.fail_commit = fail_commit

    async def execute(self, statement, *_args, **_kwargs):
        sql = str(statement)
        if "pg_advisory_xact_lock" in sql:
            self.events.append("lock")
        elif "SELECT value FROM vault_config" in sql:
            self.events.append("check")
        elif "INSERT INTO vault_config" in sql:
            self.events.append("persist")
        return _Result(None)

    async def commit(self):
        self.events.append("commit")
        if self.fail_commit:
            raise RuntimeError("commit failed")


@pytest.mark.asyncio
async def test_rewrap_absent_seed_is_noop():
    assert not await audit_identity.rewrap_seed_for_rotation(_Db(), object(), object())


@pytest.mark.asyncio
async def test_load_identity_sealed_follower_missing_and_bad_cipher(monkeypatch):
    monkeypatch.setattr(audit_identity, "vault", SimpleNamespace(sealed=True))
    with pytest.raises(VaultSealedError):
        await audit_identity.load_audit_identity_into_ram(_Db())

    monkeypatch.setattr(
        audit_identity,
        "vault",
        SimpleNamespace(sealed=False, aesgcm=None),
    )
    assert not await audit_identity.load_audit_identity_into_ram(_Db())

    aes = SimpleNamespace(
        load_audit_signer=lambda _blob: (_ for _ in ()).throw(ValueError("bad"))
    )
    fake_vault = SimpleNamespace(sealed=False, aesgcm=aes)
    monkeypatch.setattr(audit_identity, "vault", fake_vault)
    assert not await audit_identity.load_audit_identity_into_ram(_Db())
    assert not await audit_identity.load_audit_identity_into_ram(
        _Db([SimpleNamespace(value="00")])
    )


@pytest.mark.asyncio
async def test_load_identity_sends_envelope_and_expected_public_to_custodian(
    monkeypatch,
):
    expected_public_key = b"p" * 32
    rpc = AsyncMock(
        return_value={"public_key": expected_public_key.hex(), "state": "installed"}
    )
    fake_vault = SimpleNamespace(
        sealed=False,
        aesgcm=None,
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
        _call_rpc=rpc,
        _cluster_audit_fpr=None,
    )
    monkeypatch.setattr(audit_identity, "vault", fake_vault)

    assert await audit_identity.load_audit_identity_into_ram(
        _Db(
            [
                SimpleNamespace(value="ab" * 60),
                SimpleNamespace(value=expected_public_key.hex()),
            ]
        )
    )
    rpc.assert_awaited_once_with(
        "install_audit_identity",
        {
            "wrapped_seed": "ab" * 60,
            "expected_public_key": expected_public_key.hex(),
        },
    )
    assert fake_vault._cluster_audit_fpr == audit_identity.fingerprint(
        expected_public_key
    )


@pytest.mark.asyncio
async def test_load_identity_rejects_custodian_public_key_mismatch(monkeypatch):
    expected_public_key = b"p" * 32
    rpc = AsyncMock(
        return_value={"public_key": (b"q" * 32).hex(), "state": "installed"}
    )
    fake_vault = SimpleNamespace(
        sealed=False,
        aesgcm=None,
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
        _call_rpc=rpc,
        _cluster_audit_fpr=None,
    )
    monkeypatch.setattr(audit_identity, "vault", fake_vault)

    assert not await audit_identity.load_audit_identity_into_ram(
        _Db(
            [
                SimpleNamespace(value="ab" * 60),
                SimpleNamespace(value=expected_public_key.hex()),
            ]
        )
    )
    assert fake_vault._cluster_audit_fpr is None


@pytest.mark.asyncio
async def test_ensure_identity_returns_none_without_local_key(monkeypatch):
    monkeypatch.setattr(
        audit_identity,
        "vault",
        SimpleNamespace(sealed=False, aesgcm=None),
    )
    assert await audit_identity.ensure_audit_identity(_Db()) is None


@pytest.mark.asyncio
async def test_external_identity_generation_commits_before_install(monkeypatch):
    events = []
    public_key = b"p" * 32
    wrapped_seed = b"w" * 60

    async def generate(op, args):
        assert (op, args) == ("generate_audit_identity", {})
        events.append("generate")
        return {
            "public_key": public_key.hex(),
            "wrapped_seed": wrapped_seed.hex(),
        }

    async def register(_db, pub):
        assert pub == public_key
        events.append("register")

    async def load(_db):
        events.append("install")
        return True

    fake_vault = SimpleNamespace(
        sealed=False,
        aesgcm=None,
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
        _call_rpc=AsyncMock(side_effect=generate),
    )
    monkeypatch.setattr(audit_identity, "vault", fake_vault)
    monkeypatch.setattr(audit_identity, "register_signer", register)
    monkeypatch.setattr(audit_identity, "load_audit_identity_into_ram", load)

    assert (
        await audit_identity.ensure_audit_identity(_ProvisionDb(events)) == public_key
    )
    assert events == [
        "lock",
        "check",
        "generate",
        "persist",
        "persist",
        "register",
        "commit",
        "install",
    ]


@pytest.mark.asyncio
async def test_external_identity_commit_failure_never_installs(monkeypatch):
    events = []
    generated = {
        "public_key": (b"p" * 32).hex(),
        "wrapped_seed": (b"w" * 60).hex(),
    }
    fake_vault = SimpleNamespace(
        sealed=False,
        aesgcm=None,
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
        _call_rpc=AsyncMock(return_value=generated),
    )
    install = AsyncMock(return_value=True)
    monkeypatch.setattr(audit_identity, "vault", fake_vault)
    monkeypatch.setattr(audit_identity, "register_signer", AsyncMock())
    monkeypatch.setattr(audit_identity, "load_audit_identity_into_ram", install)

    with pytest.raises(RuntimeError, match="commit failed"):
        await audit_identity.ensure_audit_identity(
            _ProvisionDb(events, fail_commit=True)
        )
    install.assert_not_awaited()


@pytest.mark.asyncio
async def test_external_existing_identity_must_install(monkeypatch):
    public_key = b"p" * 32
    fake_vault = SimpleNamespace(
        sealed=False,
        aesgcm=None,
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
    )
    monkeypatch.setattr(audit_identity, "vault", fake_vault)
    monkeypatch.setattr(
        audit_identity, "load_audit_identity_into_ram", AsyncMock(return_value=False)
    )

    with pytest.raises(RuntimeError, match="was not installed"):
        await audit_identity.ensure_audit_identity(
            _Db([None, SimpleNamespace(value=public_key.hex())])
        )


def test_assemble_rejects_wrong_signature_length():
    with pytest.raises(ValueError, match="64 bytes"):
        audit_identity._assemble_ed25519_cert(b"tbs", b"short")


@pytest.mark.asyncio
async def test_self_sign_handles_signing_and_verification_failures(monkeypatch):
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    monkeypatch.setattr(
        audit_identity,
        "vault",
        SimpleNamespace(
            has_audit_identity=True,
            can_audit_sign_raw=True,
            audit_sign_raw=AsyncMock(side_effect=RuntimeError("sign")),
        ),
    )
    assert await audit_identity._self_sign_audit_cert(pub, "node") is None

    monkeypatch.setattr(
        audit_identity,
        "vault",
        SimpleNamespace(
            has_audit_identity=True,
            can_audit_sign_raw=True,
            audit_sign_raw=AsyncMock(return_value=b"x" * 64),
        ),
    )
    assert await audit_identity._self_sign_audit_cert(pub, "node") is None


@pytest.mark.asyncio
async def test_self_sign_accepts_async_external_raw_signer(monkeypatch):
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    signer = AsyncMock(side_effect=lambda message: key.sign(message))
    monkeypatch.setattr(
        audit_identity,
        "vault",
        SimpleNamespace(
            has_audit_identity=False,
            can_audit_sign_raw=True,
            audit_sign_raw=signer,
        ),
    )

    cert_pem = await audit_identity._self_sign_audit_cert(pub, "node")
    assert cert_pem is not None
    cert = x509.load_pem_x509_certificate(cert_pem)
    key.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
    signer.assert_awaited_once()


@pytest.mark.asyncio
async def test_issue_cert_falls_back_when_ca_read_fails(monkeypatch):
    from api.app import cluster_ca

    async def failed(_db):
        raise RuntimeError("database")

    async def standalone(pub, node_uuid):
        assert pub == b"p" * 32
        assert node_uuid == "node"
        return b"cert"

    monkeypatch.setattr(cluster_ca, "load_cluster_ca", failed)
    monkeypatch.setattr(audit_identity, "_self_sign_audit_cert", standalone)
    assert (
        await audit_identity._issue_audit_cert(
            object(), pub=b"p" * 32, node_uuid="node"
        )
        == b"cert"
    )


@pytest.mark.asyncio
async def test_chain_identity_noop_when_identity_unavailable(monkeypatch):
    async def unavailable(_db):
        return None

    monkeypatch.setattr(audit_identity, "ensure_audit_identity", unavailable)
    assert await audit_identity.ensure_audit_chain_identity(object()) is None
