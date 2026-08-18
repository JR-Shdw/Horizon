# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""bug C -- /cluster/join 409 transient discrimination.

The original baseline classified any /cluster/join 409 as permanent
(``_PERMANENT_STATUSES = (401, 403, 409)``). The 2026-05-29 lab failure
exposed two cases of 409 that are recoverable :

- the previous attempt's response was lost in transit ; the cert is
  already persisted on disk, the next /cluster/join just observes the
  integrated row and 409s. Treat as success.
- the previous attempt landed the row in ``ha_state='joining'`` and the
  state-machine flipped it to ``'secondary'`` before our retry's
  refresh_joining_row could match. The membership row is still ours.
  Treat as transient.

The non-recoverable case is narrow : 409 with the row beyond 'joining'
AND no cert on disk -- the wrapped key is gone and the joiner must hit
the R1 recovery (operator evict + unrevoke + restart).

Coverage map :

Module invariant
- _PERMANENT_STATUSES no longer carries 409.

_post_join
- 409 raises AutoJoin409Error (subclass of AutoJoinError, so it stays
  recoverable by default for callers that do not opt in).

_get_membership
- 200 returns the parsed payload.
- 404 returns None (server hides unknown vs evicted).
- other status raises AutoJoinError.

_attempt_join_once
- 409 + cert-on-disk -> happy exit (return True).
- 409 + membership ha_state='joining' -> AutoJoinError (retry).
- 409 + membership ha_state='secondary' + no cert -> AutoJoinPermanentError.
- 409 + membership 404 (race with reaper) + no cert -> AutoJoinError (retry).
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import pytest_asyncio
from api.app import cluster_auto_join
from api.app import ha_password as hp
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from sqlalchemy import text

_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


# --- module invariant ----------------------------------------------------


def test_permanent_statuses_excludes_409():
    """409 is conditionally transient ; the discrimination
    lives in _attempt_join_once via _get_membership + cert-on-disk.
    """
    assert 409 not in cluster_auto_join._PERMANENT_STATUSES
    assert 401 in cluster_auto_join._PERMANENT_STATUSES
    assert 403 in cluster_auto_join._PERMANENT_STATUSES


# --- _post_join + _get_membership unit shape -----------------------------


class _Resp:
    """Minimal httpx-like response stub used by the auto-JOIN tests."""

    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_post_join_409_raises_autojoin_409_error(monkeypatch):
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_post(self, url, json=None):
        return _Resp(409, text="node_uuid already present -- use REJOIN flow")

    with patch("httpx.AsyncClient.post", _fake_post):
        import httpx

        async with httpx.AsyncClient() as client:
            with pytest.raises(cluster_auto_join.AutoJoin409Error) as exc_info:
                await cluster_auto_join._post_join(client, {"node_uuid": "x"})
    # The exception body carries the server-side detail for downstream
    # discrimination -- the membership-lookup helper does not need it
    # but logs in the joiner reference it.
    assert "REJOIN" in exc_info.value.body


@pytest.mark.asyncio
async def test_get_membership_returns_payload_on_200(monkeypatch):
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_get(self, url):
        assert "/cluster/ha/membership/" in url
        return _Resp(
            200,
            payload={
                "node_uuid": "abc",
                "ha_state": "secondary",
                "cert_fingerprint": "f" * 64,
                "cert_not_after": "2030-01-01T00:00:00+00:00",
            },
        )

    with patch("httpx.AsyncClient.get", _fake_get):
        import httpx

        async with httpx.AsyncClient() as client:
            body = await cluster_auto_join._get_membership(client, "abc")
    assert body["ha_state"] == "secondary"
    assert body["cert_fingerprint"] == "f" * 64


@pytest.mark.asyncio
async def test_get_membership_returns_none_on_404(monkeypatch):
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_get(self, url):
        return _Resp(404, text="node_uuid not found")

    with patch("httpx.AsyncClient.get", _fake_get):
        import httpx

        async with httpx.AsyncClient() as client:
            assert await cluster_auto_join._get_membership(client, "abc") is None


@pytest.mark.asyncio
async def test_get_membership_503_raises_autojoin_error(monkeypatch):
    """Sealed primary surfaces 503 + Retry-After ; the joiner treats
    this as a transient fault so the surrounding loop retries instead
    of escalating to PermanentError.
    """
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_get(self, url):
        return _Resp(503, text="vault is sealed")

    with patch("httpx.AsyncClient.get", _fake_get):
        import httpx

        async with httpx.AsyncClient() as client:
            with pytest.raises(cluster_auto_join.AutoJoinError):
                await cluster_auto_join._get_membership(client, "abc")


# --- _attempt_join_once 409 discrimination -------------------------------


@pytest_asyncio.fixture
async def _bug_c_cluster(tmp_path, monkeypatch):
    """Common scaffolding for the 409 discrimination tests.

    Bootstraps a primary via /cluster/init through the in-process route
    handler, captures ha_password + cluster_id, then rebinds the cert
    paths to a fresh joiner location. Yields a context dict with the
    bits each test needs to drive _attempt_join_once.
    """
    nu.init_node_uuid(settings.node_uuid_path)
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp.clear()
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    pw_file = tmp_path / "ha-password"
    pw_file.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "ha_password_file", str(pw_file))
    monkeypatch.setattr(settings, "ha_cluster_id", "test-cluster-id")
    yield {
        "tmp_path": tmp_path,
        "cert_path": cert_p,
        "key_path": key_p,
        "pw_file": pw_file,
    }
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp.clear()


def _challenge_payload() -> dict:
    """Shared challenge body for the 409 tests -- the bug C discrimination
    runs AFTER the challenge step, so this payload just needs to satisfy
    _post_challenge's contract.
    """
    return {
        "nonce": "deadbeef" * 4,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.now(timezone.utc).isoformat(),
        "cluster_version": settings.version,
        "cluster_min_compatible_version": settings.cluster_min_compatible_version,
        "observed_source_ip": "192.0.2.42",
        "cluster_id": "test-cluster-id",
    }


@pytest.mark.asyncio
async def test_attempt_join_409_with_cert_on_disk_returns_true(
    _bug_c_cluster, admin_token, client
):
    """Case (a) : cert already persisted -> exit happy on 409.

    Simulates the race observed in lab : a prior /cluster/join attempt
    succeeded and the joiner persisted the cert pair on disk, but the
    surrounding flow raised before _attempt_join_once returned True.
    The retry re-enters _attempt_join_once, the server 409s (row
    integrated, refresh_joining_row refused), the joiner sees the cert
    on disk and treats it as success.
    """
    # Seed the cert pair on disk so has_cluster_cert is True.
    _bug_c_cluster["cert_path"].write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n")
    _bug_c_cluster["key_path"].write_bytes(b"-----BEGIN PRIVATE KEY-----\nstub\n")
    _bug_c_cluster["cert_path"].chmod(0o400)
    _bug_c_cluster["key_path"].chmod(0o400)

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _Resp(200, payload=_challenge_payload())
        return _Resp(409, text="node_uuid already present -- use REJOIN flow")

    async def _fake_get(self, url):
        # The discriminator pairs the 409 with a membership lookup --
        # we return ha_state='secondary' so the cert-on-disk path is
        # the one that fires (without the cert check, this would
        # otherwise escalate to PermanentError).
        return _Resp(
            200,
            payload={
                "node_uuid": "uuid" * 8,
                "ha_state": "secondary",
                "cert_fingerprint": "a" * 64,
                "cert_not_after": "2030-01-01T00:00:00+00:00",
            },
        )

    with (
        patch("httpx.AsyncClient.post", _fake_post),
        patch("httpx.AsyncClient.get", _fake_get),
    ):
        ok = await cluster_auto_join._attempt_join_once("uuid" * 8)
    assert ok is True


@pytest.mark.asyncio
async def test_attempt_join_409_state_joining_raises_recoverable(_bug_c_cluster):
    """Case (b) : row still 'joining' -> raise AutoJoinError (retry)."""

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _Resp(200, payload=_challenge_payload())
        return _Resp(409, text="node_uuid already present")

    async def _fake_get(self, url):
        return _Resp(
            200,
            payload={
                "node_uuid": "uuid" * 8,
                "ha_state": "joining",
                "cert_fingerprint": "b" * 64,
                "cert_not_after": "2030-01-01T00:00:00+00:00",
            },
        )

    with (
        patch("httpx.AsyncClient.post", _fake_post),
        patch("httpx.AsyncClient.get", _fake_get),
    ):
        with pytest.raises(cluster_auto_join.AutoJoinError) as exc_info:
            await cluster_auto_join._attempt_join_once("uuid" * 8)
    # Must NOT be a PermanentError -- the retry path must fire.
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)
    assert "joining" in str(exc_info.value)


@pytest.mark.asyncio
async def test_attempt_join_409_state_secondary_no_cert_raises_permanent(
    _bug_c_cluster,
):
    """Case (c) : row integrated + no cert -> PermanentError with R1 hint."""

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _Resp(200, payload=_challenge_payload())
        return _Resp(409, text="node_uuid already present")

    async def _fake_get(self, url):
        return _Resp(
            200,
            payload={
                "node_uuid": "uuid" * 8,
                "ha_state": "secondary",
                "cert_fingerprint": "c" * 64,
                "cert_not_after": "2030-01-01T00:00:00+00:00",
            },
        )

    with (
        patch("httpx.AsyncClient.post", _fake_post),
        patch("httpx.AsyncClient.get", _fake_get),
    ):
        with pytest.raises(cluster_auto_join.AutoJoinPermanentError) as exc_info:
            await cluster_auto_join._attempt_join_once("uuid" * 8)
    # Operator-facing hint -- the runbook entry references the
    # recovery R1 procedure explicitly.
    assert "evict" in str(exc_info.value)
    assert "unrevoke" in str(exc_info.value)


@pytest.mark.asyncio
async def test_attempt_join_409_membership_404_raises_recoverable(_bug_c_cluster):
    """Case (d) : 409 + membership 404 -> AutoJoinError (transient drift)."""

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _Resp(200, payload=_challenge_payload())
        return _Resp(409, text="node_uuid already present")

    async def _fake_get(self, url):
        return _Resp(404, text="node_uuid not found")

    with (
        patch("httpx.AsyncClient.post", _fake_post),
        patch("httpx.AsyncClient.get", _fake_get),
    ):
        with pytest.raises(cluster_auto_join.AutoJoinError) as exc_info:
            await cluster_auto_join._attempt_join_once("uuid" * 8)
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)
    assert "404" in str(exc_info.value) or "transient" in str(exc_info.value)
