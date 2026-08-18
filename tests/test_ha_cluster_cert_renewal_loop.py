# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""per-node cert renewal loop tests.

Coverage map :

renew_once early exits
- sealed vault -> "skipped_sealed"
- no cert on disk -> "skipped_no_cert"
- fresh cert + no force flag -> "skipped_not_needed"

renew_once triggers
- cert near expiry (under threshold) -> calls _post_refresh
- force_renew_at set in the past -> calls _post_refresh
- success path persists the new pair on disk via save_cluster_cert
- failure path bumps the fail counter and returns "fail"

Threshold check (cluster_cert_renewal._needs_threshold_renew)
- fresh cert (NotAfter far away) -> False
- cert under threshold -> True
- already-expired cert -> True (over-due is still renewal)
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import pytest_asyncio
from api.app import (
    cluster_ca,
    cluster_cert,
    cluster_cert_renewal,
    nginx_reload,
    node_uuid,
)
from api.app.config import settings
from api.app.database import async_session
from api.app.ha_password import clear as hp_clear
from sqlalchemy import text


@pytest.mark.asyncio
async def test_renewal_loop_checks_once_before_first_long_sleep(monkeypatch):
    checked = False

    async def _checked_then_stop():
        nonlocal checked
        checked = True
        raise asyncio.CancelledError

    monkeypatch.setattr(cluster_cert_renewal, "renew_once", _checked_then_stop)
    with pytest.raises(asyncio.CancelledError):
        await cluster_cert_renewal.cluster_cert_renewal_loop()
    assert checked is True


@pytest.mark.asyncio
async def test_renewal_loop_retries_quickly_while_sealed(monkeypatch):
    renew = AsyncMock(return_value="skipped_sealed")
    retry_sleep = AsyncMock(side_effect=asyncio.CancelledError)
    monkeypatch.setattr(cluster_cert_renewal, "renew_once", renew)
    monkeypatch.setattr(cluster_cert_renewal.asyncio, "sleep", retry_sleep)

    with pytest.raises(asyncio.CancelledError):
        await cluster_cert_renewal.cluster_cert_renewal_loop()

    renew.assert_awaited_once_with()
    retry_sleep.assert_awaited_once_with(5)


_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    monkeypatch.setattr(settings, "ha_primary_url", "http://test.invalid")
    node_uuid.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "renewal-loop-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    yield cert_p, key_p
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()


async def _sign_local_node_cert(
    node_uuid_str: str | None = None,
    validity_days: int | None = None,
):
    if node_uuid_str is None:
        node_uuid_str = node_uuid.get_node_uuid()
    async with async_session() as db:
        pair = await cluster_ca.load_cluster_ca(db)
    assert pair is not None
    ca_cert_pem, ca_key_pem = pair
    return cluster_ca.sign_node_cert(
        ca_cert_pem,
        ca_key_pem,
        node_uuid_str,
        "127.0.0.1",
        validity_days=validity_days,
    )


async def _insert_self_membership() -> None:
    """Insert a row for this container's node_uuid so renew_once can
    look up the force_renew_at column."""
    nu = node_uuid.get_node_uuid()
    cert_pem, _ = await _sign_local_node_cert(nu)
    fpr = cluster_ca.compute_fingerprint(cert_pem)
    nbf = cluster_ca.parse_cert(cert_pem).not_valid_after_utc
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes (node_uuid, source_ip, "
                "ha_state, cluster_version, cert_fingerprint, cert_not_after) "
                "VALUES (:u, CAST(:ip AS INET), 'secondary', :v, :f, :n) "
                "ON CONFLICT (node_uuid) DO UPDATE SET "
                "cert_fingerprint = :f, cert_not_after = :n"
            ),
            {
                "u": nu,
                "ip": "127.0.0.2",
                "v": "1.0.0-test",
                "f": fpr,
                "n": nbf,
            },
        )
        await db.commit()


# --- threshold check -------------------------------------------------------


@pytest.mark.asyncio
async def test_needs_threshold_renew_fresh_cert_false(_fresh_cluster):
    cert_pem, _ = await _sign_local_node_cert(validity_days=90)
    assert cluster_cert_renewal._needs_threshold_renew(cert_pem) is False


@pytest.mark.asyncio
async def test_needs_threshold_renew_short_cert_true(_fresh_cluster, monkeypatch):
    # Validity = 7 days (the floor) ; threshold default 30 days -> trigger.
    cert_pem, _ = await _sign_local_node_cert(validity_days=7)
    assert cluster_cert_renewal._needs_threshold_renew(cert_pem) is True


@pytest.mark.asyncio
async def test_needs_threshold_renew_expired_cert_true(_fresh_cluster, monkeypatch):
    # Simulate an already-expired cert by moving the clock forward.
    cert_pem, _ = await _sign_local_node_cert(validity_days=7)
    real_now = datetime.now(timezone.utc)
    fake_now = real_now + timedelta(days=8)  # 1 day past NotAfter

    class _FakeDatetime:
        @staticmethod
        def now(tz=None):
            return fake_now

    monkeypatch.setattr(cluster_cert_renewal, "datetime", _FakeDatetime)
    assert cluster_cert_renewal._needs_threshold_renew(cert_pem) is True


# --- renew_once early exits -------------------------------------------------


@pytest.mark.asyncio
async def test_renew_once_skipped_sealed(_fresh_cluster, master_password, client):
    from api.app.vault_state import vault

    vault.seal()
    try:
        outcome = await cluster_cert_renewal.renew_once()
        assert outcome == "skipped_sealed"
    finally:
        await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_renew_once_skipped_no_cert(_fresh_cluster):
    # /cluster/init wrote a cert to disk -- delete it to simulate
    # pre-JOIN state.
    cert_p, key_p = _fresh_cluster
    cluster_cert.remove_cluster_cert(str(cert_p), str(key_p))
    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "skipped_no_cert"


@pytest.mark.asyncio
async def test_renew_once_skipped_not_needed(_fresh_cluster):
    # Fresh /cluster/init cert + no force_renew_at flag = skip.
    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "skipped_not_needed"


@pytest.mark.asyncio
async def test_renew_once_skipped_when_sibling_holds_lock(_fresh_cluster):
    # N workers share the volume; only the flock holder renews. While a
    # sibling holds the host-local lock, this tick must skip rather than
    # fire a redundant refresh + write + reload.
    with cluster_cert_renewal._host_renewal_lock() as held:
        assert held is True
        outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "skipped_locked"


def test_host_renewal_lock_is_exclusive(_fresh_cluster):
    # Nested acquire (a second worker on the same host) must be denied,
    # then granted again once the first holder releases.
    with cluster_cert_renewal._host_renewal_lock() as first:
        assert first is True
        with cluster_cert_renewal._host_renewal_lock() as second:
            assert second is False
    with cluster_cert_renewal._host_renewal_lock() as third:
        assert third is True


# --- renew_once triggers ---------------------------------------------------


@pytest.mark.asyncio
async def test_renew_once_triggers_on_threshold(_fresh_cluster, monkeypatch, tmp_path):
    # Persist a short-validity cert (will trigger threshold).
    cert_p, key_p = _fresh_cluster
    cert_pem, key_pem = await _sign_local_node_cert(validity_days=7)
    cluster_cert.save_cluster_cert(cert_pem, key_pem, str(cert_p), str(key_p))

    # Mock _post_refresh to short-circuit the actual HTTP call. The refresh
    # extends the tuple to (node_cert, node_key, server_cert, server_key) ;
    # empty server pair is a valid "skip nginx persist" signal.
    new_cert_pem, new_key_pem = await _sign_local_node_cert(validity_days=90)
    mock = AsyncMock(return_value=(new_cert_pem, new_key_pem, b"", b""))
    monkeypatch.setattr(cluster_cert_renewal, "_post_refresh", mock)

    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "success"
    mock.assert_called_once()
    # On-disk pair is now the new cert.
    on_disk = cluster_cert.load_cluster_cert(str(cert_p), str(key_p))
    assert on_disk == (new_cert_pem, new_key_pem)


@pytest.mark.asyncio
async def test_renew_once_triggers_on_force_renew_at(_fresh_cluster, monkeypatch):
    cert_p, key_p = _fresh_cluster
    # Fresh /cluster/init cert (validity 90d, no threshold trigger) +
    # a self membership row with force_renew_at = NOW().
    await _insert_self_membership()
    nu = node_uuid.get_node_uuid()
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_cluster_nodes SET force_renew_at = NOW() "
                "WHERE node_uuid = :u"
            ),
            {"u": nu},
        )
        await db.commit()

    new_cert_pem, new_key_pem = await _sign_local_node_cert(validity_days=90)
    mock = AsyncMock(return_value=(new_cert_pem, new_key_pem, b"", b""))
    monkeypatch.setattr(cluster_cert_renewal, "_post_refresh", mock)

    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "success"
    mock.assert_called_once()


@pytest.mark.asyncio
async def test_renew_once_post_refresh_failure_bumps_fail_counter(
    _fresh_cluster, monkeypatch
):
    cert_p, key_p = _fresh_cluster
    # Persist a short-validity cert so the renewal triggers.
    cert_pem, key_pem = await _sign_local_node_cert(validity_days=7)
    cluster_cert.save_cluster_cert(cert_pem, key_pem, str(cert_p), str(key_p))

    async def _boom(*args, **kwargs):
        raise RuntimeError("simulated transport error")

    monkeypatch.setattr(cluster_cert_renewal, "_post_refresh", _boom)
    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "fail"
    # On-disk cert unchanged (failure does not corrupt the persistent pair).
    on_disk = cluster_cert.load_cluster_cert(str(cert_p), str(key_p))
    assert on_disk == (cert_pem, key_pem)


# --- _post_refresh direct paths --------------------------------------------


@pytest.mark.asyncio
async def test_post_refresh_raises_when_ha_primary_url_blank(
    _fresh_cluster, monkeypatch, tmp_path
):
    """Empty ``ha_primary_url`` fails loud before any network call."""
    monkeypatch.setattr(settings, "ha_primary_url", "")
    cert_p, key_p = _fresh_cluster
    with pytest.raises(RuntimeError, match="ha_primary_url is not configured"):
        await cluster_cert_renewal._post_refresh(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_post_refresh_wraps_transport_error(_fresh_cluster):
    """``httpx.HTTPError`` from POST is wrapped as RuntimeError with the
    canonical ``refresh-cert transport error:`` prefix."""
    cert_p, key_p = _fresh_cluster

    async def _boom(self, url, json=None):
        raise httpx.ConnectError("simulated dial failure")

    with patch("httpx.AsyncClient.post", _boom):
        with pytest.raises(RuntimeError, match="refresh-cert transport error"):
            await cluster_cert_renewal._post_refresh(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_post_refresh_non_200_raises_with_status_and_body(_fresh_cluster):
    """A non-200 response includes the status code and body text in the
    error message (operator-visible diagnostic)."""
    cert_p, key_p = _fresh_cluster

    class _Resp:
        status_code = 503
        text = "primary scheduling refresh, retry shortly"

        def json(self):
            return {}

    async def _fake_post(self, url, json=None):
        return _Resp()

    with patch("httpx.AsyncClient.post", _fake_post):
        with pytest.raises(RuntimeError, match=r"refresh-cert HTTP 503"):
            await cluster_cert_renewal._post_refresh(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_post_refresh_missing_fields_raises(_fresh_cluster):
    """200 with empty cert/key fields is still a server-side bug -- abort
    rather than persist garbage to disk."""
    cert_p, key_p = _fresh_cluster

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"node_cert_pem": "", "node_cert_key_pem": ""}

    async def _fake_post(self, url, json=None):
        return _Resp()

    with patch("httpx.AsyncClient.post", _fake_post):
        with pytest.raises(RuntimeError, match="missing cert/key fields"):
            await cluster_cert_renewal._post_refresh(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_post_refresh_returns_four_tuple_with_server_pair(
    _fresh_cluster,
):
    """Response: both node and server cert pairs flow back."""
    cert_p, key_p = _fresh_cluster
    new_node_cert, new_node_key = await _sign_local_node_cert(validity_days=90)
    new_server_cert, new_server_key = await _sign_local_node_cert(validity_days=90)

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {
                "node_cert_pem": new_node_cert.decode("ascii"),
                "node_cert_key_pem": new_node_key.decode("ascii"),
                "server_cert_pem": new_server_cert.decode("ascii"),
                "server_cert_key_pem": new_server_key.decode("ascii"),
            }

    async def _fake_post(self, url, json=None):
        return _Resp()

    with patch("httpx.AsyncClient.post", _fake_post):
        (
            node_cert,
            node_key,
            srv_cert,
            srv_key,
        ) = await cluster_cert_renewal._post_refresh(str(cert_p), str(key_p))
    assert node_cert == new_node_cert
    assert node_key == new_node_key
    assert srv_cert == new_server_cert
    assert srv_key == new_server_key


# --- renew_once force_renew except fallback --------------------------------


@pytest.mark.asyncio
async def test_renew_once_force_renew_db_error_falls_back_to_threshold(
    _fresh_cluster, monkeypatch
):
    """If the per-tick DB lookup for ``force_renew_at`` raises (e.g. PG
    hiccup), the loop logs + treats it as ``force=False`` and lets the
    threshold check drive the outcome. A short-validity cert still
    triggers renewal here -- the failure does not bypass the natural
    threshold path."""
    cert_p, key_p = _fresh_cluster
    cert_pem, key_pem = await _sign_local_node_cert(validity_days=7)
    cluster_cert.save_cluster_cert(cert_pem, key_pem, str(cert_p), str(key_p))

    async def _raise_force(*args, **kwargs):
        raise RuntimeError("simulated DB unavailable")

    monkeypatch.setattr(cluster_cert_renewal, "_needs_force_renew", _raise_force)
    new_cert_pem, new_key_pem = await _sign_local_node_cert(validity_days=90)
    mock = AsyncMock(return_value=(new_cert_pem, new_key_pem, b"", b""))
    monkeypatch.setattr(cluster_cert_renewal, "_post_refresh", mock)

    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "success"
    mock.assert_called_once()


# --- renew_once server cert persist + nginx reload -------------------------


@pytest.mark.asyncio
async def test_renew_once_persists_server_pair_and_reloads_nginx(
    _fresh_cluster, monkeypatch, tmp_path
):
    """When ``_post_refresh`` returns a non-empty server pair,
    ``renew_once`` writes both files atomically and triggers an nginx
    reload via the configured command."""
    cert_p, key_p = _fresh_cluster
    cert_pem, key_pem = await _sign_local_node_cert(validity_days=7)
    cluster_cert.save_cluster_cert(cert_pem, key_pem, str(cert_p), str(key_p))

    server_cert_p = tmp_path / "server.crt"
    server_key_p = tmp_path / "server.key"
    monkeypatch.setattr(settings, "cluster_server_cert_path", str(server_cert_p))
    monkeypatch.setattr(settings, "cluster_server_cert_key_path", str(server_key_p))
    monkeypatch.setattr(settings, "cluster_nginx_reload_cmd", "/bin/true")

    new_node_cert, new_node_key = await _sign_local_node_cert(validity_days=90)
    new_server_cert, new_server_key = await _sign_local_node_cert(validity_days=90)
    mock_refresh = AsyncMock(
        return_value=(new_node_cert, new_node_key, new_server_cert, new_server_key)
    )
    monkeypatch.setattr(cluster_cert_renewal, "_post_refresh", mock_refresh)

    save_calls: list[tuple] = []

    def _capture_save(cert, key, cpath, kpath):
        save_calls.append((cert, key, cpath, kpath))

    reload_calls: list[str] = []

    def _capture_reload(cmd):
        reload_calls.append(cmd)
        return True

    monkeypatch.setattr(nginx_reload, "save_server_cert", _capture_save)
    monkeypatch.setattr(nginx_reload, "reload_nginx", _capture_reload)

    outcome = await cluster_cert_renewal.renew_once()
    assert outcome == "success"
    assert save_calls == [
        (new_server_cert, new_server_key, str(server_cert_p), str(server_key_p))
    ]
    assert reload_calls == ["/bin/true"]


# --- _server_cert_needs_renew paths ----------------------------------------


def test_server_cert_needs_renew_absent_file_returns_false(tmp_path):
    """No file on disk -> nothing to renew yet (e.g. a legacy joiner)."""
    missing = tmp_path / "absent.pem"
    assert cluster_cert_renewal._server_cert_needs_renew(str(missing)) is False


def test_server_cert_needs_renew_unparseable_file_forces_renew(tmp_path):
    """A corrupt PEM forces renewal -- the cert is unusable and the renewal
    path will fetch a fresh pair from the primary on the next tick."""
    bogus = tmp_path / "bogus.pem"
    bogus.write_bytes(
        b"-----BEGIN CERTIFICATE-----\nnot valid PEM\n-----END CERTIFICATE-----\n"
    )
    assert cluster_cert_renewal._server_cert_needs_renew(str(bogus)) is True


@pytest.mark.asyncio
async def test_server_cert_needs_renew_fresh_cert_returns_false(
    _fresh_cluster, tmp_path
):
    """A freshly-signed cert (90-day validity) sits well above the default
    30-day threshold -- no renewal needed."""
    cert_pem, _ = await _sign_local_node_cert(validity_days=90)
    p = tmp_path / "fresh.pem"
    p.write_bytes(cert_pem)
    assert cluster_cert_renewal._server_cert_needs_renew(str(p)) is False


@pytest.mark.asyncio
async def test_server_cert_needs_renew_short_cert_returns_true(
    _fresh_cluster, tmp_path
):
    """A cert at the 7-day validity floor falls inside the 30-day renewal
    threshold -- renew."""
    cert_pem, _ = await _sign_local_node_cert(validity_days=7)
    p = tmp_path / "short.pem"
    p.write_bytes(cert_pem)
    assert cluster_cert_renewal._server_cert_needs_renew(str(p)) is True
