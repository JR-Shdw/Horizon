# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Replica-lag debounce.

A write burst pushes WAL past the lag threshold for a few seconds and then
catches up. Reporting each blip as critical trains the operator to ignore the
check, which is worse than not having it.

Motivating evidence: a 14 h chaos run logged 6 `database_ha` criticals. All 6
were isolated single samples (observation indices 16, 142, 216, 285, 657,
2536 out of 2500+, never two in a row), both replicas reported byte-identical
lag each time -- a leader-side write burst, not a replica falling behind --
and Patroni reported one leader with every member streaming throughout.

So the breach must persist for `database_ha_lag_grace_secs` before it is
reported. The window is measured in seconds rather than consecutive samples
because callers poll at very different rates.
"""

import pytest
from api.app import cluster_health as ch
from api.app.cluster_health import Health


@pytest.fixture(autouse=True)
def _clear_streaks():
    """Module-level streak state must not leak between tests."""
    ch._lag_breach_since.clear()
    yield
    ch._lag_breach_since.clear()


def _patch_httpx(monkeypatch, data):
    class _Resp:
        def json(self):
            return data

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, _url):
            return _Resp()

    monkeypatch.setattr(ch.httpx, "AsyncClient", lambda *a, **k: _Client())


def _lagging_cluster(lag):
    return {
        "members": [
            {"name": "p1", "role": "leader", "state": "running", "timeline": 9},
            {
                "name": "p2",
                "role": "replica",
                "state": "streaming",
                "timeline": 9,
                "lag": lag,
            },
        ]
    }


# --------------------------------------------------------------------------
# The streak helper in isolation
# --------------------------------------------------------------------------


def test_clean_sample_reports_no_breach():
    assert ch._lag_breach_secs("patroni", []) == 0.0


def test_first_breach_starts_the_clock_at_zero(monkeypatch):
    monkeypatch.setattr(ch.time, "monotonic", lambda: 100.0)
    assert ch._lag_breach_secs("patroni", [{"name": "p2"}]) == 0.0


def test_breach_duration_accumulates(monkeypatch):
    monkeypatch.setattr(ch.time, "monotonic", lambda: 100.0)
    ch._lag_breach_secs("patroni", [{"name": "p2"}])
    monkeypatch.setattr(ch.time, "monotonic", lambda: 145.0)
    assert ch._lag_breach_secs("patroni", [{"name": "p2"}]) == 45.0


def test_clean_sample_resets_the_streak(monkeypatch):
    monkeypatch.setattr(ch.time, "monotonic", lambda: 100.0)
    ch._lag_breach_secs("patroni", [{"name": "p2"}])
    monkeypatch.setattr(ch.time, "monotonic", lambda: 150.0)
    assert ch._lag_breach_secs("patroni", []) == 0.0
    # A later breach starts a fresh streak rather than resuming the old one.
    monkeypatch.setattr(ch.time, "monotonic", lambda: 200.0)
    assert ch._lag_breach_secs("patroni", [{"name": "p2"}]) == 0.0


def test_providers_do_not_clear_each_other(monkeypatch):
    """`database_ha_provider` may be "auto", so both probes can run."""
    monkeypatch.setattr(ch.time, "monotonic", lambda: 100.0)
    ch._lag_breach_secs("patroni", [{"name": "p2"}])
    monkeypatch.setattr(ch.time, "monotonic", lambda: 160.0)
    ch._lag_breach_secs("pgha", [])  # pgha clean must not reset patroni
    assert ch._lag_breach_secs("patroni", [{"name": "p2"}]) == 60.0


# --------------------------------------------------------------------------
# End to end through probe_patroni
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transient_breach_is_not_reported(monkeypatch):
    """The exact shape of the 6 chaos-run false criticals."""
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    monkeypatch.setattr(ch.settings, "database_ha_lag_grace_secs", 60)
    monkeypatch.setattr(ch.time, "monotonic", lambda: 500.0)

    _patch_httpx(monkeypatch, _lagging_cluster(4096))
    health, reason, detail = await ch.probe_patroni()
    assert health is Health.GREEN, reason
    assert detail["max_replica_lag_bytes"] == 4096  # still measured...
    assert detail["lag_breach_secs"] == 0  # ...just not yet reported

    # Recovered before the window elapsed -> never reported at all.
    _patch_httpx(monkeypatch, _lagging_cluster(0))
    monkeypatch.setattr(ch.time, "monotonic", lambda: 530.0)
    assert (await ch.probe_patroni())[0] is Health.GREEN


@pytest.mark.asyncio
async def test_sustained_breach_is_reported(monkeypatch):
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    monkeypatch.setattr(ch.settings, "database_ha_lag_grace_secs", 60)
    _patch_httpx(monkeypatch, _lagging_cluster(4096))

    monkeypatch.setattr(ch.time, "monotonic", lambda: 500.0)
    assert (await ch.probe_patroni())[0] is Health.GREEN

    monkeypatch.setattr(ch.time, "monotonic", lambda: 561.0)
    health, reason, detail = await ch.probe_patroni()
    assert health is Health.ORANGE
    assert "lag exceeds" in reason and "61s" in reason
    assert detail["lag_breach_secs"] == 61


@pytest.mark.asyncio
async def test_zero_grace_restores_fire_on_first_sample(monkeypatch):
    """Escape hatch for anyone who wants the old behaviour."""
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    monkeypatch.setattr(ch.settings, "database_ha_lag_grace_secs", 0)
    _patch_httpx(monkeypatch, _lagging_cluster(4096))
    assert (await ch.probe_patroni())[0] is Health.ORANGE


@pytest.mark.asyncio
async def test_grace_does_not_delay_real_failures(monkeypatch):
    """The debounce covers lag only. A lost leader is still immediate."""
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    monkeypatch.setattr(ch.settings, "database_ha_lag_grace_secs", 3600)
    _patch_httpx(
        monkeypatch,
        {
            "members": [
                {"name": "p1", "role": "replica", "state": "running", "lag": 0},
                {"name": "p2", "role": "replica", "state": "running", "lag": 0},
            ]
        },
    )
    assert (await ch.probe_patroni())[0] is Health.RED
