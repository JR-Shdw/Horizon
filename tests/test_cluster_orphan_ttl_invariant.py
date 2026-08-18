# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""The joining-orphan reaper TTL must exceed the join quarantine.

Regression: with cluster_joining_orphan_ttl_secs == cluster_join_quarantine_secs
a healthy joiner becomes flip-eligible (joining -> secondary) and reap-eligible
at the SAME instant (joined_at + quarantine), so the reaper can purge a perfectly
healthy node instead of letting it promote. Observed evicting a fresh 3rd-domain
joiner at ~60s. The settings model now guarantees a margin.
"""

from api.app.config import Settings


def test_default_orphan_ttl_exceeds_quarantine():
    s = Settings()
    assert s.cluster_joining_orphan_ttl_secs > s.cluster_join_quarantine_secs
    assert s.cluster_joining_orphan_ttl_secs == 90


def test_override_cannot_recreate_equality():
    # Operator bumps quarantine but leaves orphan at the old default.
    s = Settings(cluster_join_quarantine_secs=120, cluster_joining_orphan_ttl_secs=60)
    # Bumped to quarantine + one reaper interval of margin.
    assert s.cluster_joining_orphan_ttl_secs == 150
    assert s.cluster_joining_orphan_ttl_secs > s.cluster_join_quarantine_secs


def test_generous_orphan_ttl_is_respected():
    s = Settings(cluster_join_quarantine_secs=30, cluster_joining_orphan_ttl_secs=300)
    assert s.cluster_joining_orphan_ttl_secs == 300


def test_margin_is_at_least_one_reaper_interval():
    s = Settings(
        cluster_join_quarantine_secs=45,
        cluster_reaper_interval_secs=20,
        cluster_joining_orphan_ttl_secs=10,
    )
    assert (
        s.cluster_joining_orphan_ttl_secs
        >= s.cluster_join_quarantine_secs + s.cluster_reaper_interval_secs
    )


def test_state_machine_interval_controls_margin_when_slower():
    s = Settings(
        cluster_join_quarantine_secs=0,
        cluster_state_machine_interval_secs=60,
        cluster_reaper_interval_secs=5,
        cluster_joining_orphan_ttl_secs=10,
    )
    assert s.cluster_joining_orphan_ttl_secs == 60


def test_orphan_ttl_ceiling_covers_maximum_safe_margin():
    s = Settings(
        cluster_join_quarantine_secs=3600,
        cluster_state_machine_interval_secs=60,
        cluster_reaper_interval_secs=600,
        cluster_joining_orphan_ttl_secs=9999,
    )
    assert s.cluster_joining_orphan_ttl_secs == 4200
