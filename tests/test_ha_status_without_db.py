# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""The status surface must survive losing PostgreSQL.

Found by fault injection, not by unit tests. Blacking out a live node's route
to the database VIP produced this for the whole outage:

    t+6s   /api/v1/vault/status: no answer   /cluster/ha: 000
    t+12s  /api/v1/vault/status: no answer   /cluster/ha: 500

Two failures. Requests answered 500 -- a raw database exception, which a client
reads as an application bug rather than "retry another node". And the status
endpoint did not answer at all, because describing the vault required the
database. An endpoint that needs the authority in order to report on losing the
authority is unusable in exactly the situation it exists for.

/internal/ha/status is the answer: process-local only, no I/O, always 200. The
HTTP status means "this process answered"; the body carries the state, because
a peer must be able to tell "frozen" from "unreachable" and folding the state
into the status code destroys that distinction.

Cf api/app/main.py::internal_ha_status and ::readiness.
"""

import time

import pytest


@pytest.mark.asyncio
async def test_ha_status_answers_and_reports_active(client, admin_token):
    r = await client.get("/internal/ha/status")
    assert r.status_code == 200
    body = r.json()
    for field in (
        "node_id",
        "role",
        "state",
        "serving",
        "holds_primary_lease",
        "db_authority_confirmed",
        "confirmation_age_seconds",
    ):
        assert field in body, f"missing {field}"


@pytest.mark.asyncio
async def test_ha_status_reports_frozen_without_touching_the_database(
    client, admin_token, monkeypatch
):
    """The load-bearing case: frozen, and the answer needs no database.

    async_session is replaced with something that raises on use, so if the
    handler performs ANY query the test fails rather than silently passing on
    a database that happens to be up.
    """
    from api.app.vault_state import vault

    def _explode():
        raise AssertionError("/internal/ha/status must not touch PostgreSQL")

    monkeypatch.setattr("api.app.database.async_session", _explode)

    vault.renew_db_confirmation(0.05, 3600)
    vault.note_role("secondary")
    vault.release_primary_lease()
    time.sleep(0.15)
    try:
        assert vault.frozen is True
        r = await client.get("/internal/ha/status")
        assert r.status_code == 200, "must answer even while frozen"
        body = r.json()
        assert body["state"] == "frozen"
        assert body["serving"] is False
        assert body["db_authority_confirmed"] is False
        assert body["role"] == "secondary", "last known role, reported as stale"
        assert body["confirmation_age_seconds"] >= 0.05
    finally:
        vault.release_db_confirmation()


@pytest.mark.asyncio
async def test_readiness_reports_frozen_before_probing_the_database(
    client, admin_token, monkeypatch
):
    """503 frozen, and it must not hang on the database to say so.

    The frozen check sits ahead of _database_ready() deliberately: a frozen
    node is precisely when that probe hangs, and a load balancer cannot act on
    a probe that never returns.
    """
    from api.app.vault_state import vault

    async def _never_returns():
        raise AssertionError("readiness must short-circuit before the DB probe")

    monkeypatch.setattr("api.app.main._database_ready", _never_returns)

    vault.renew_db_confirmation(0.05, 3600)
    time.sleep(0.15)
    try:
        r = await client.get("/readiness")
        assert r.status_code == 503
        assert r.json()["status"] == "frozen"
        assert r.json()["serving"] is False
    finally:
        vault.release_db_confirmation()


@pytest.mark.asyncio
async def test_liveness_is_unconditional(client, admin_token):
    """/health answers regardless of state -- it means "the process is up"."""
    from api.app.vault_state import vault

    vault.renew_db_confirmation(0.05, 3600)
    time.sleep(0.15)
    try:
        assert vault.frozen is True
        r = await client.get("/health")
        assert r.status_code == 200
    finally:
        vault.release_db_confirmation()
