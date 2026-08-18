# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""per-node cert on-disk persistence + auto-JOIN.

Coverage map :

Persistence (api/app/cluster_cert.py)
- save_cluster_cert roundtrips with load_cluster_cert
- file modes are 0o400, parent dir 0o700
- has_cluster_cert returns True only when BOTH files present
- half-pair on disk is treated as missing (load returns None)
- validate_perms rejects loose modes, no-ops when files absent
- cert_not_after parses a PEM and returns a tz-aware datetime

Unwrap (api/app/ha_password.unwrap_node_key_for_joiner)
- roundtrip with wrap_node_key_for_joiner (Rust primitive)
- wrong ha_password -> HaPasswordError
- wrong node_uuid -> HaPasswordError
- tampered ciphertext -> HaPasswordError

/cluster/init integration
- primary cert + key persisted to disk after a successful init
- /cluster/challenge response carries observed_source_ip

Boot check (api/app/ha_boot_check.enforce_cluster_cert_perms_invariant)
- raises HaBootInvariantError when on-disk pair has loose mode
- no-op when files absent (auto-JOIN will create them)

Auto-JOIN gating (api/app/cluster_auto_join._should_attempt)
- no-op when cluster_ha_enabled is False
- no-op when ha_auto_join is False
- no-op when ha_primary_url is empty
- no-op when ha_password_file is missing
- no-op when cluster-cert is already on disk

Auto-JOIN happy path (mocked httpx)
- challenge + join + unwrap + persist sequence
- permanent error short-circuits retries
"""

import base64
import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import pytest_asyncio
from api.app import cluster_auto_join, cluster_ca, cluster_cert, ha_password
from api.app import ha_password as hp
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from api.app.ha_boot_check import (
    HaBootInvariantError,
    enforce_cluster_cert_perms_invariant,
)
from sqlalchemy import text

_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


# --- fixtures ---------------------------------------------------------------


@pytest_asyncio.fixture
async def _clean_cluster_state(tmp_path, monkeypatch):
    """Per-test isolation : redirect cert paths to tmp_path + wipe DB rows.

    We never write to the real /var/lib/rhorizon volume during tests.
    Every test that touches cluster_cert.* must use this fixture so the
    overrides land before any code reads ``settings.cluster_cert_path``.
    """
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp.clear()
    yield cert_p, key_p
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp.clear()


# --- persistence layer ------------------------------------------------------


def test_persistence_roundtrip_save_then_load(tmp_path):
    cert_p = tmp_path / "x" / "cluster-cert.pem"
    key_p = tmp_path / "x" / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"CERTDATA", b"KEYDATA", str(cert_p), str(key_p))

    loaded = cluster_cert.load_cluster_cert(str(cert_p), str(key_p))
    assert loaded == (b"CERTDATA", b"KEYDATA")


def test_persistence_file_mode_is_0400(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))

    assert cert_p.stat().st_mode & 0o777 == 0o400
    assert key_p.stat().st_mode & 0o777 == 0o400


def test_persistence_parent_dir_mode_0700(tmp_path):
    cert_p = tmp_path / "newdir" / "cluster-cert.pem"
    key_p = tmp_path / "newdir" / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))

    parent = tmp_path / "newdir"
    assert parent.stat().st_mode & 0o777 == 0o700


def test_persistence_overwrite_existing(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"OLD-CERT", b"OLD-KEY", str(cert_p), str(key_p))
    cluster_cert.save_cluster_cert(b"NEW-CERT", b"NEW-KEY", str(cert_p), str(key_p))

    assert cert_p.read_bytes() == b"NEW-CERT"
    assert key_p.read_bytes() == b"NEW-KEY"


def test_persistence_survives_stale_temp(tmp_path):
    """A leftover temp from a crashed write must not wedge future writes
    (the old fixed-name O_EXCL tmp raised FileExistsError forever, which
    would permanently block cert renewal -> cert expiry -> eviction)."""
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    (tmp_path / ".cluster-cert.pem.deadbeef.tmp").write_text("stale")
    cluster_cert.save_cluster_cert(b"FRESH", b"KEY", str(cert_p), str(key_p))
    # the write succeeds despite the orphan (which is none of its business)
    assert cert_p.read_bytes() == b"FRESH"
    assert (cert_p.stat().st_mode & 0o777) == 0o400


def test_persistence_concurrent_writers(tmp_path):
    """N threads writing the same paths converge on one valid 0400 pair
    with no leftover temps -- mkstemp per writer, last rename wins."""
    import threading

    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def writer(n: int):
        try:
            barrier.wait()
            cluster_cert.save_cluster_cert(
                f"cert-{n}".encode(), f"key-{n}".encode(), str(cert_p), str(key_p)
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"writers crashed: {errors}"
    assert cert_p.read_bytes().startswith(b"cert-")
    assert (cert_p.stat().st_mode & 0o777) == 0o400
    assert not list(tmp_path.glob(".cluster-cert.*.tmp"))


def test_persistence_save_rejects_empty(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    with pytest.raises(cluster_cert.ClusterCertError):
        cluster_cert.save_cluster_cert(b"", b"k", str(cert_p), str(key_p))
    with pytest.raises(cluster_cert.ClusterCertError):
        cluster_cert.save_cluster_cert(b"c", b"", str(cert_p), str(key_p))


def test_has_cluster_cert_false_when_both_absent(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    assert not cluster_cert.has_cluster_cert(str(cert_p), str(key_p))


def test_has_cluster_cert_true_only_when_both_present(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cert_p.write_bytes(b"c")
    assert not cluster_cert.has_cluster_cert(str(cert_p), str(key_p))
    key_p.write_bytes(b"k")
    assert cluster_cert.has_cluster_cert(str(cert_p), str(key_p))


def test_load_cluster_cert_half_pair_returns_none(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cert_p.write_bytes(b"c")
    assert cluster_cert.load_cluster_cert(str(cert_p), str(key_p)) is None


def test_validate_perms_rejects_loose_mode(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))
    os.chmod(cert_p, 0o644)
    with pytest.raises(cluster_cert.ClusterCertPermError):
        cluster_cert.validate_perms(str(cert_p), str(key_p))


def test_validate_perms_passes_when_files_absent(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    # No files on disk -- the auto-JOIN flow will create them. Boot-time
    # check must not raise.
    cluster_cert.validate_perms(str(cert_p), str(key_p))


def test_cert_not_after_returns_tz_aware_datetime():
    cert_pem, _key_pem, _fpr = cluster_ca.mint_cluster_ca(common_name="test-ca")
    not_after = cluster_cert.cert_not_after(cert_pem)
    assert isinstance(not_after, datetime)
    assert not_after.tzinfo is not None
    assert not_after > datetime.now(timezone.utc)


def test_remove_cluster_cert_idempotent(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    # No files -- must not raise.
    cluster_cert.remove_cluster_cert(str(cert_p), str(key_p))
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))
    cluster_cert.remove_cluster_cert(str(cert_p), str(key_p))
    assert not cert_p.exists()
    assert not key_p.exists()


# --- unwrap_node_key_for_joiner ---------------------------------------------

# 32-byte zeroed key for deterministic test crypto -- vault buffers are
# wrapped by the Rust WrapKey ; we need a real unsealed vault for the wrap
# side. Reuse the cluster init flow which mints + caches an ha_password,
# then call wrap_node_key_for_joiner against it.


@pytest.mark.asyncio
async def test_unwrap_roundtrip_matches_wrap(admin_token, client, _clean_cluster_state):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "unwrap-roundtrip"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    ha_pw = base64.b64decode(r.json()["ha_password"])

    secret_key = b"-----BEGIN PRIVATE KEY-----\nMC4CAQA...\n-----END PRIVATE KEY-----\n"
    node_uuid = "abcdef0123456789" * 2  # 32 hex chars
    wrapped = ha_password.wrap_node_key_for_joiner(secret_key, node_uuid)
    recovered = ha_password.unwrap_node_key_for_joiner(wrapped, ha_pw, node_uuid)
    assert recovered == secret_key


@pytest.mark.asyncio
async def test_unwrap_wrong_password_raises(admin_token, client, _clean_cluster_state):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    secret_key = b"PRIVKEY-MATERIAL"
    node_uuid = "deadbeef" * 4
    wrapped = ha_password.wrap_node_key_for_joiner(secret_key, node_uuid)

    wrong = b"X" * 32
    with pytest.raises(ha_password.HaPasswordError):
        ha_password.unwrap_node_key_for_joiner(wrapped, wrong, node_uuid)


@pytest.mark.asyncio
async def test_unwrap_wrong_uuid_raises(admin_token, client, _clean_cluster_state):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    ha_pw = base64.b64decode(r.json()["ha_password"])
    secret_key = b"PRIVKEY"
    wrapped = ha_password.wrap_node_key_for_joiner(secret_key, "uuid-A" * 5)
    with pytest.raises(ha_password.HaPasswordError):
        ha_password.unwrap_node_key_for_joiner(wrapped, ha_pw, "uuid-B" * 5)


@pytest.mark.asyncio
async def test_unwrap_tampered_payload_raises(
    admin_token, client, _clean_cluster_state
):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    ha_pw = base64.b64decode(r.json()["ha_password"])
    wrapped = bytearray(ha_password.wrap_node_key_for_joiner(b"key", "uuid-x" * 5))
    # Flip a bit deep in the ciphertext (past the nonce).
    wrapped[20] ^= 0xFF
    with pytest.raises(ha_password.HaPasswordError):
        ha_password.unwrap_node_key_for_joiner(bytes(wrapped), ha_pw, "uuid-x" * 5)


def test_unwrap_too_short_raises():
    with pytest.raises(ha_password.HaPasswordError):
        ha_password.unwrap_node_key_for_joiner(b"\x00" * 10, b"pw" * 16, "uuid")


# --- /cluster/init persists primary cert+key -------------------------------


@pytest.mark.asyncio
async def test_cluster_init_persists_primary_cert_pair(
    admin_token, client, _clean_cluster_state
):
    cert_p, key_p = _clean_cluster_state
    assert not cert_p.exists() and not key_p.exists()
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "persist-primary"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    assert cert_p.is_file()
    assert key_p.is_file()
    assert cert_p.stat().st_mode & 0o777 == 0o400
    assert key_p.stat().st_mode & 0o777 == 0o400
    assert cert_p.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert key_p.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")


# --- /cluster/challenge echoes observed_source_ip --------------------------


@pytest.mark.asyncio
async def test_challenge_response_includes_observed_source_ip(
    admin_token, client, _clean_cluster_state
):
    # Bootstrap a cluster first so /cluster/challenge has a valid CA + ha_password.
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "ab" * 16, "rhorizon_version": settings.version},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "observed_source_ip" in body
    # ASGITransport client sends from 127.0.0.1 by default ; the value
    # must be a non-empty IP literal.
    assert body["observed_source_ip"]


# --- boot check : cluster cert perm invariant ------------------------------


def test_boot_check_raises_on_loose_mode(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))
    os.chmod(key_p, 0o644)
    with pytest.raises(HaBootInvariantError):
        enforce_cluster_cert_perms_invariant(str(cert_p), str(key_p))


def test_boot_check_passes_when_files_absent(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    enforce_cluster_cert_perms_invariant(str(cert_p), str(key_p))


def test_boot_check_passes_with_0400(tmp_path):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))
    enforce_cluster_cert_perms_invariant(str(cert_p), str(key_p))


# --- auto-JOIN gating (no HTTP) --------------------------------------------


def test_auto_join_no_op_when_ha_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cluster_ha_enabled", False)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://example.invalid")
    monkeypatch.setattr(settings, "ha_password_file", str(tmp_path / "pw"))
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "c.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "c.key"))
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "cluster_ha_enabled" in reason


def test_auto_join_no_op_when_disabled_via_flag(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", False)
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_auto_join" in reason


def test_auto_join_no_op_when_primary_url_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "")
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_primary_url" in reason


def test_auto_join_no_op_when_password_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://x.invalid")
    monkeypatch.setattr(settings, "ha_password_file", str(tmp_path / "nope"))
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_password_file" in reason


def test_auto_join_no_op_when_cert_already_on_disk(monkeypatch, tmp_path):
    pw = tmp_path / "pw"
    pw.write_bytes(b"x" * 32)
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cluster_cert.save_cluster_cert(b"c", b"k", str(cert_p), str(key_p))
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://x.invalid")
    monkeypatch.setattr(settings, "ha_password_file", str(pw))
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "cluster-cert" in reason


# --- auto-JOIN happy path (mocked httpx) -----------------------------------


@pytest.mark.asyncio
async def test_auto_join_happy_path_persists_cert(
    admin_token, client, monkeypatch, tmp_path, _clean_cluster_state
):
    """End-to-end: simulate a primary that returns a valid JOIN payload.

    We boot a primary (init), mint a wrapped cert against its in-process
    state, then patch httpx so the auto-JOIN task receives that payload
    as if it had called a remote primary. The point is to exercise the
    full unwrap + persist pipeline end-to-end without setting up a
    second ASGI process.
    """
    # Step 1 : init primary, capture ha_password + cluster_id.
    cert_p, key_p = _clean_cluster_state
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    cluster_id = r.json()["cluster_id"]
    ha_pw = base64.b64decode(r.json()["ha_password"])

    # Step 2 : reset cert paths to a fresh location (init persisted the
    # primary's cert at the same paths -- we want auto-JOIN to write to
    # a clean target representing a new node).
    new_cert = tmp_path / "joiner-cert.pem"
    new_key = tmp_path / "joiner-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(new_cert))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(new_key))

    # Step 3 : write the ha_password to a tmpfs-like file and wire env.
    pw_file = tmp_path / "ha-password"
    pw_file.write_bytes(ha_pw)
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    monkeypatch.setattr(settings, "ha_password_file", str(pw_file))
    monkeypatch.setattr(settings, "ha_cluster_id", cluster_id)

    # Step 4 : build a synthetic JOIN response. The CA is the one /init
    # just minted ; we re-mint a node cert + wrap the key in-process and
    # feed the result back to the auto-JOIN task as if it came from the
    # primary.
    async with async_session() as db:
        ca = await cluster_ca.load_cluster_ca(db)
    assert ca is not None
    ca_cert_pem, ca_key_pem = ca
    joiner_uuid = nu.get_node_uuid()
    node_cert_pem, node_key_pem = cluster_ca.sign_node_cert(
        ca_cert_pem, ca_key_pem, joiner_uuid, "192.0.2.42"
    )
    wrapped = ha_password.wrap_node_key_for_joiner(node_key_pem, joiner_uuid)

    challenge_payload = {
        "nonce": "deadbeef" * 4,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.now(timezone.utc).isoformat(),
        "cluster_version": settings.version,
        "cluster_min_compatible_version": settings.cluster_min_compatible_version,
        "observed_source_ip": "192.0.2.42",
    }
    join_payload = {
        "accepted": True,
        "ha_state": "joining",
        "quarantine_until": datetime.now(timezone.utc).isoformat(),
        "primary_uuid": "primary-uuid",
        "cluster_version": settings.version,
        "node_cert_pem": node_cert_pem.decode(),
        "node_cert_key_wrapped_hex": wrapped.hex(),
        "ca_cert_pem": ca_cert_pem.decode(),
    }

    class _FakeResponse:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload
            self.text = ""

        def json(self):
            return self._payload

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _FakeResponse(challenge_payload)
        return _FakeResponse(join_payload)

    with patch("httpx.AsyncClient.post", _fake_post):
        ok = await cluster_auto_join._attempt_join_once(joiner_uuid)
    assert ok is True
    assert new_cert.is_file()
    assert new_key.is_file()
    assert new_cert.read_bytes() == node_cert_pem
    assert new_key.read_bytes() == node_key_pem


@pytest.mark.asyncio
async def test_auto_join_permanent_failure_short_circuits(
    monkeypatch, tmp_path, _clean_cluster_state
):
    pw = tmp_path / "pw"
    pw.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://x.invalid")
    monkeypatch.setattr(settings, "ha_password_file", str(pw))
    monkeypatch.setattr(settings, "ha_cluster_id", "any")

    class _FakeResponse:
        status_code = 401
        text = "ha_password proof mismatch"

        def json(self):
            return {}

    async def _fake_post(self, url, json=None):
        return _FakeResponse()

    with patch("httpx.AsyncClient.post", _fake_post):
        with pytest.raises(cluster_auto_join.AutoJoinPermanentError):
            await cluster_auto_join._attempt_join_once("uuid" * 8)
