# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Peer-aware classification while PostgreSQL is unavailable.

The classifier consumes authenticated peer observations, never peer decisions.
It may keep an already-frozen node's key material for a bounded period or ask
the existing hard fence to seal sooner.  It can never return the node ACTIVE.
"""

import urllib.parse
from pathlib import Path
from types import SimpleNamespace

import pytest
from api.app import cluster_ca
from api.app import cluster_ha_loops as loops
from api.app import cluster_peer_frozen as peer_frozen
from api.app.cluster_peer_frozen import (
    PeerObservation,
    PeerVerdict,
    classify_frozen_peers,
)
from api.app.config import settings
from api.app.vault_state import vault


def _peer(**overrides) -> PeerObservation:
    values = {
        "node_id": "peer-a",
        "state": "frozen",
        "serving": False,
        "db_authority_confirmed": False,
        "primary_since": "2026-08-25T01:00:00+00:00",
        "key_epoch": 7,
    }
    values.update(overrides)
    return PeerObservation(**values)


def test_shared_database_outage_holds_frozen_without_granting_active():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[_peer()],
    )

    assert decision.verdict is PeerVerdict.SHARED_OUTAGE
    assert decision.peer_count == 1


def test_no_peer_falls_back_to_the_existing_local_fence():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[],
    )

    assert decision.verdict is PeerVerdict.LOCAL_FENCE


def test_peer_url_supports_ipv6_and_a_custom_internal_port(monkeypatch):
    monkeypatch.setattr(settings, "cluster_peer_https_port", 9443)
    assert (
        peer_frozen._peer_url("2001:db8::2")
        == "https://[2001:db8::2]:9443/internal/ha/peer-status"
    )


def test_tls_frontend_proxies_the_exact_authenticated_peer_route():
    source = (Path(__file__).parents[1] / "frontend/nginx-tls.conf").read_text()
    marker = "location = /internal/ha/peer-status {"
    assert source.count(marker) == 1
    block = source.split(marker, 1)[1].split("\n    }", 1)[0]
    assert "proxy_pass http://rhorizon_api;" in block
    assert "${CLIENT_CERT_HEADER}" in block


def test_active_peer_without_newer_referent_is_not_proof_enough_to_seal():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[
            _peer(
                state="active",
                serving=True,
                db_authority_confirmed=True,
            )
        ],
    )

    assert decision.verdict is PeerVerdict.LOCAL_FENCE


def test_newer_primary_term_is_positive_isolation_evidence():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[_peer(primary_since="2026-08-25T01:00:01+00:00")],
    )

    assert decision.verdict is PeerVerdict.SEAL_EARLY
    assert decision.reason == "newer_primary_since"


def test_newer_key_epoch_is_positive_stale_key_evidence():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[_peer(key_epoch=8)],
    )

    assert decision.verdict is PeerVerdict.SEAL_EARLY
    assert decision.reason == "newer_key_epoch"


def test_missing_local_primary_term_disables_term_acceleration():
    decision = classify_frozen_peers(
        local_primary_since=None,
        local_key_epoch=7,
        observations=[_peer(primary_since="2099-01-01T00:00:00+00:00")],
    )

    assert decision.verdict is PeerVerdict.SHARED_OUTAGE


def test_malformed_peer_facts_are_not_evidence():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[
            _peer(
                primary_since="not-a-date",
                key_epoch=True,
                state="mystery",
            )
        ],
    )

    assert decision.verdict is PeerVerdict.LOCAL_FENCE


def test_one_newer_referent_wins_over_shared_outage_observations():
    decision = classify_frozen_peers(
        local_primary_since="2026-08-25T01:00:00+00:00",
        local_key_epoch=7,
        observations=[
            _peer(node_id="peer-a"),
            _peer(
                node_id="peer-b",
                state="active",
                serving=True,
                db_authority_confirmed=True,
                primary_since="2026-08-25T01:01:00+00:00",
            ),
        ],
    )

    assert decision.verdict is PeerVerdict.SEAL_EARLY
    assert decision.reason == "newer_primary_since"


class _FrozenVault:
    sealed = False
    frozen = True
    last_primary_since = "2026-08-25T01:00:00+00:00"
    key_epoch = 7

    def __init__(self):
        self.prolonged_by = None

    def prolong_frozen(self, seconds):
        self.prolonged_by = seconds
        return True


@pytest.mark.asyncio
async def test_shared_outage_only_extends_the_non_serving_deadline(monkeypatch):
    vault = _FrozenVault()

    async def _observations():
        return [_peer()]

    async def _must_not_seal(_vault):
        raise AssertionError("shared outage must not accelerate the seal")

    monkeypatch.setattr(loops, "poll_peer_observations", _observations)
    monkeypatch.setattr(loops, "_lease_fence_seal", _must_not_seal)

    verdict = await loops._peer_frozen_body(vault)

    assert verdict is PeerVerdict.SHARED_OUTAGE
    assert vault.prolonged_by == loops.settings.cluster_frozen_max_secs
    assert vault.frozen is True


@pytest.mark.asyncio
async def test_newer_term_uses_the_existing_hard_seal_path(monkeypatch):
    vault = _FrozenVault()
    sealed = []

    async def _observations():
        return [_peer(primary_since="2026-08-25T01:00:01+00:00")]

    async def _seal(target):
        sealed.append(target)

    monkeypatch.setattr(loops, "poll_peer_observations", _observations)
    monkeypatch.setattr(loops, "_lease_fence_seal", _seal)

    verdict = await loops._peer_frozen_body(vault)

    assert verdict is PeerVerdict.SEAL_EARLY
    assert sealed == [vault]
    assert vault.prolonged_by is None


class _Request:
    class _Client:
        host = "127.0.0.1"

    client = _Client()

    def __init__(self, cert_pem):
        self.headers = {"X-Client-Cert": urllib.parse.quote(cert_pem.decode("ascii"))}


def test_cached_mtls_auth_accepts_only_the_last_confirmed_member(monkeypatch):
    ca_cert, ca_key, _ = cluster_ca.mint_cluster_ca()
    peer_cert, _ = cluster_ca.sign_node_cert(
        ca_cert,
        ca_key,
        "peer-a",
        "192.0.2.20",
    )
    monkeypatch.setattr(vault, "_sealed", False)
    monkeypatch.setattr(settings, "proxy_trusted_ips", "127.0.0.1/32")
    monkeypatch.setattr(
        peer_frozen,
        "_snapshot",
        peer_frozen.PeerSnapshot(
            peers=(
                peer_frozen.PeerRosterEntry(
                    "peer-a",
                    "192.0.2.20",
                    cluster_ca.compute_fingerprint(peer_cert),
                ),
            ),
            ca_cert_pem=ca_cert,
            refreshed_at=1.0,
        ),
    )

    assert peer_frozen.authenticate_cached_peer(_Request(peer_cert)) == "peer-a"


def test_cached_mtls_auth_rejects_a_valid_but_absent_member(monkeypatch):
    ca_cert, ca_key, _ = cluster_ca.mint_cluster_ca()
    peer_cert, _ = cluster_ca.sign_node_cert(
        ca_cert,
        ca_key,
        "peer-a",
        "192.0.2.20",
    )
    monkeypatch.setattr(vault, "_sealed", False)
    monkeypatch.setattr(settings, "proxy_trusted_ips", "127.0.0.1/32")
    monkeypatch.setattr(
        peer_frozen,
        "_snapshot",
        peer_frozen.PeerSnapshot(
            peers=(),
            ca_cert_pem=ca_cert,
            refreshed_at=1.0,
        ),
    )

    with pytest.raises(peer_frozen.HTTPException) as exc:
        peer_frozen.authenticate_cached_peer(_Request(peer_cert))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_authenticated_peer_status_remains_db_free(
    client,
    admin_token,
    monkeypatch,
):
    ca_cert, ca_key, _ = cluster_ca.mint_cluster_ca()
    peer_cert, _ = cluster_ca.sign_node_cert(
        ca_cert,
        ca_key,
        "peer-a",
        "192.0.2.20",
    )
    monkeypatch.setattr(settings, "proxy_trusted_ips", "127.0.0.1/32")
    monkeypatch.setattr(
        peer_frozen,
        "_snapshot",
        peer_frozen.PeerSnapshot(
            peers=(
                peer_frozen.PeerRosterEntry(
                    "peer-a",
                    "192.0.2.20",
                    cluster_ca.compute_fingerprint(peer_cert),
                ),
            ),
            ca_cert_pem=ca_cert,
            refreshed_at=1.0,
        ),
    )

    def _database_must_not_be_touched():
        raise AssertionError("peer status must not consult PostgreSQL")

    monkeypatch.setattr(
        "api.app.database.async_session",
        _database_must_not_be_touched,
    )
    response = await client.get(
        "/internal/ha/peer-status",
        headers={
            "X-Client-Cert": urllib.parse.quote(peer_cert.decode("ascii")),
        },
    )

    assert response.status_code == 200
    assert "primary_since" in response.json()
    assert "key_epoch" in response.json()


@pytest.mark.asyncio
async def test_snapshot_keeps_only_serving_members_and_public_trust(monkeypatch):
    rows = [
        SimpleNamespace(
            node_uuid="self",
            source_ip="192.0.2.10",
            ha_state="primary",
            cert_fingerprint="self-fingerprint",
        ),
        SimpleNamespace(
            node_uuid="peer-a",
            source_ip="192.0.2.20",
            ha_state="secondary",
            cert_fingerprint="AABB",
        ),
        SimpleNamespace(
            node_uuid="peer-joining",
            source_ip="192.0.2.30",
            ha_state="joining",
            cert_fingerprint="CCDD",
        ),
    ]

    async def _nodes(_db):
        return rows

    async def _ca(_db):
        return b"current-ca"

    async def _prev_ca(_db):
        return b"previous-ca"

    monkeypatch.setattr(peer_frozen.cluster_nodes, "list_nodes", _nodes)
    monkeypatch.setattr(peer_frozen.cluster_ca, "load_cluster_ca_cert", _ca)
    monkeypatch.setattr(peer_frozen.cluster_ca, "load_cluster_ca_prev_cert", _prev_ca)

    await peer_frozen.refresh_peer_snapshot(object(), "self")

    assert peer_frozen._snapshot.peers == (
        peer_frozen.PeerRosterEntry("peer-a", "192.0.2.20", "aabb"),
    )
    assert peer_frozen._snapshot.ca_cert_pem == b"current-ca"
    assert peer_frozen._snapshot.prev_ca_cert_pem == b"previous-ca"
