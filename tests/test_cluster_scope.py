# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster scope RBAC.

`cluster` splits observing the cluster from operating it, so an unprivileged
user can check HA status without holding `admin`. Three tiers:

  cluster:r  observe   /cluster, /cluster/health, /cluster/ha, ca-bundle
  cluster:w  operate   init, repair, promote, demote, drain, evict, unrevoke
  admin:w    trust root  CA issue/rotate, ha-password rotation

The CA stays on `admin` on purpose: whoever can issue a node cert can
impersonate a node in the cluster mTLS, which is not a cluster-operator task.

Allow-assertions check `!= 403` rather than `== 200`: most of these endpoints
answer 409 when no cluster is initialised, and it is the authorization
decision under test here, not the cluster state.
"""

import pytest

HEALTH = "/api/v1/vault/cluster/health"
TOPOLOGY = "/api/v1/vault/cluster"
DRAIN = "/api/v1/vault/cluster/drain/00000000-0000-0000-0000-000000000000"
ROTATE_CA = "/api/v1/vault/cluster/rotate-ca"


async def _mint(client, admin_token, name, permissions):
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": name, "permissions": permissions},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201, r.text
    return r.json()["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_cluster_ro_reads_status(client, admin_token):
    """The point of the scope: status without admin."""
    tok = await _mint(client, admin_token, "cl-ro", {"cluster": "r"})
    for path in (HEALTH, TOPOLOGY):
        r = await client.get(path, headers=_h(tok))
        assert r.status_code != 403, f"{path} denied to cluster:r -> {r.text}"


@pytest.mark.asyncio
async def test_cluster_ro_cannot_operate(client, admin_token):
    tok = await _mint(client, admin_token, "cl-ro-nw", {"cluster": "r"})
    r = await client.post(DRAIN, headers=_h(tok))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_cluster_ro_cannot_read_secrets(client, admin_token):
    """Scope isolation: cluster grants nothing outside the cluster surface."""
    tok = await _mint(client, admin_token, "cl-ro-iso", {"cluster": "r"})
    r = await client.get("/api/v1/vault/secrets/", headers=_h(tok))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_cluster_rw_operates_but_not_the_ca(client, admin_token):
    """cluster:w runs node lifecycle; the CA trust root stays admin-only."""
    tok = await _mint(client, admin_token, "cl-rw", {"cluster": "rw"})

    r = await client.post(DRAIN, headers=_h(tok))
    assert r.status_code != 403, f"drain denied to cluster:w -> {r.text}"

    r = await client.post(ROTATE_CA, headers=_h(tok))
    assert r.status_code == 403, "cluster:w must not reach the CA"


@pytest.mark.asyncio
async def test_admin_still_reads_cluster(client, admin_token):
    """Backward compat: admin applies to every scope, so pre-existing admin
    tokens keep working after the re-gate (auth.py `effective_modes`)."""
    tok = await _mint(client, admin_token, "cl-admin-ro", {"admin": "r"})
    r = await client.get(HEALTH, headers=_h(tok))
    assert r.status_code != 403


@pytest.mark.asyncio
async def test_health_summary_drops_topology_detail(client, admin_token):
    """The MCP projection: states and reasons survive, the cluster map does not."""
    tok = await _mint(client, admin_token, "cl-sum", {"cluster": "r"})

    full = await client.get(HEALTH, headers=_h(tok))
    lean = await client.get(HEALTH, params={"summary": "true"}, headers=_h(tok))
    assert full.status_code == 200 and lean.status_code == 200

    fb, lb = full.json(), lean.json()
    assert set(lb) == {"overall", "ready", "components"}
    assert lb["overall"] == fb["overall"]
    assert set(lb["components"]) == set(fb["components"])

    for name, comp in lb["components"].items():
        assert set(comp) == {"state", "reason"}, f"{name} leaked {set(comp)}"
        assert comp["state"] == fb["components"][name]["state"]

    # Detail keys must not survive anywhere in the summary payload.
    blob = str(lb)
    for leaked in ("replica_lags", "leader_timeline", "lag_threshold_bytes"):
        assert leaked not in blob


@pytest.mark.asyncio
async def test_cannot_grant_cluster_without_holding_it(client, admin_token):
    """POLA: a secrets-only token cannot mint itself cluster access."""
    weak = await _mint(client, admin_token, "cl-weak", {"secrets": "r"})
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "cl-escalate", "permissions": {"cluster": "r"}},
        headers=_h(weak),
    )
    assert r.status_code == 403
