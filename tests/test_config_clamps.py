# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Config validators that guard against silently-broken security controls."""

import pytest
from api.app.config import Settings
from pydantic import ValidationError


def test_cluster_advertise_ip_is_canonical_and_env_tunable(monkeypatch):
    monkeypatch.setenv("RH_CLUSTER_ADVERTISE_IP", " 2001:0db8::1 ")
    assert Settings().cluster_advertise_ip == "2001:db8::1"


def test_cluster_advertise_ip_rejects_hostnames():
    with pytest.raises(ValidationError, match="IPv4 or IPv6 address"):
        Settings(cluster_advertise_ip="vault-node.example.test")


@pytest.mark.parametrize(
    "raw,expected",
    [
        (90, 90),  # default, untouched
        (0, 7),  # would mint a cert born expired -> clamped to the floor
        (-30, 7),
        (5000, 366),  # capped like the node cert
    ],
)
def test_server_cert_validity_clamped(raw, expected):
    assert (
        Settings(
            cluster_server_cert_validity_days=raw
        ).cluster_server_cert_validity_days
        == expected
    )


def test_server_cert_validity_matches_node_bounds():
    # The two certs are minted by the same CA; their bounds must agree.
    for v in (0, 3, 7, 90, 366, 9999):
        s = Settings(
            cluster_node_cert_validity_days=v,
            cluster_server_cert_validity_days=v,
        )
        assert s.cluster_server_cert_validity_days == s.cluster_node_cert_validity_days


@pytest.mark.parametrize(
    ("node_days", "server_days", "expected_threshold"),
    [(90, 7, 6), (7, 90, 6), (90, 90, 30)],
)
def test_cert_renewal_threshold_follows_shorter_validity(
    node_days, server_days, expected_threshold
):
    settings = Settings(
        cluster_node_cert_validity_days=node_days,
        cluster_server_cert_validity_days=server_days,
        cluster_cert_renewal_threshold_days=30,
    )
    assert settings.cluster_cert_renewal_threshold_days == expected_threshold


def test_database_ha_legacy_lag_setting_is_preserved():
    s = Settings(patroni_max_replica_lag_bytes=1234)
    assert s.database_ha_max_replica_lag_bytes == 1234
    explicit = Settings(
        database_ha_max_replica_lag_bytes=5678,
        patroni_max_replica_lag_bytes=1234,
    )
    assert explicit.database_ha_max_replica_lag_bytes == 5678


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("auto", "auto"),
        ("Patroni", "patroni"),
        ("rhorizon-pgha", "pgha"),
        ("disabled", "none"),
    ],
)
def test_database_ha_provider_normalized(raw, expected):
    assert Settings(database_ha_provider=raw).database_ha_provider == expected


def test_database_ha_provider_rejects_unknown():
    with pytest.raises(ValueError, match="auto, patroni, pgha, or none"):
        Settings(database_ha_provider="carp-magic")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(0, 1), (1, 1), (2, 5), (4, 5), (5, 5), (8, 8), (10, 10), (255, 255)],
)
def test_worker_count_normalized(raw, expected):
    assert Settings(workers=raw).workers == expected


def test_worker_count_rejects_more_than_shamir_supports():
    with pytest.raises(ValueError, match="Shamir limit of 255"):
        Settings(workers=256)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("best-effort", "best-effort"),
        ("BEST_EFFORT", "best-effort"),
        ("required", "required"),
    ],
)
def test_memory_lock_mode_normalization(raw, expected):
    assert Settings(memory_lock_mode=raw).memory_lock_mode == expected


def test_memory_lock_mode_rejects_unknown_value():
    with pytest.raises(ValueError, match="best-effort or required"):
        Settings(memory_lock_mode="silent")


def test_cluster_failover_defaults_are_multi_zone_safe():
    settings = Settings()
    assert settings.cluster_heartbeat_interval_secs == 3
    assert settings.cluster_state_machine_interval_secs == 2
    assert settings.cluster_primary_lease_ttl_secs == 20
    assert settings.cluster_auto_promote_cooldown_secs == 20


def test_primary_lease_allows_two_missed_heartbeats():
    with pytest.raises(ValueError, match="at least three times"):
        Settings(
            cluster_heartbeat_interval_secs=5,
            cluster_primary_lease_ttl_secs=14,
        )

    settings = Settings(
        cluster_heartbeat_interval_secs=5,
        cluster_primary_lease_ttl_secs=15,
    )
    assert settings.cluster_primary_lease_ttl_secs == 15


def test_auto_promote_cooldown_is_at_least_one_lease_or_disabled():
    settings = Settings(
        cluster_primary_lease_ttl_secs=30,
        cluster_auto_promote_cooldown_secs=10,
    )
    assert settings.cluster_auto_promote_cooldown_secs == 30

    disabled = Settings(
        cluster_primary_lease_ttl_secs=30,
        cluster_auto_promote_cooldown_secs=0,
    )
    assert disabled.cluster_auto_promote_cooldown_secs == 0


def test_identity_proxy_trust_defaults_fail_closed():
    assert "172.16.0.0/12" in Settings.model_fields["xff_trusted_ips"].default
    assert Settings.model_fields["proxy_trusted_ips"].default == ""


def test_proxy_auth_requires_explicit_trusted_proxy():
    with pytest.raises(ValueError, match="proxy_trusted_ips is required"):
        Settings(proxy_auth_enabled=True, proxy_trusted_ips="")

    settings = Settings(
        proxy_auth_enabled=True,
        proxy_trusted_ips="10.0.0.1/32",
    )
    assert settings.proxy_trusted_ips == "10.0.0.1/32"


def test_cluster_ha_requires_explicit_trusted_proxy():
    with pytest.raises(ValueError, match="proxy_trusted_ips is required"):
        Settings(cluster_ha_enabled=True, proxy_trusted_ips="")


def test_invalid_trusted_proxy_fails_startup_validation():
    with pytest.raises(ValueError, match="invalid trusted proxy"):
        Settings(proxy_trusted_ips="10.0.0.1/32,not-a-network")


def test_canonical_worker_env_wins_over_legacy(monkeypatch):
    monkeypatch.setenv("RH_WORKERS", "8")
    monkeypatch.setenv("RHORIZON_WORKERS", "10")
    assert Settings().workers == 8


def test_legacy_worker_env_remains_supported(monkeypatch):
    monkeypatch.delenv("RH_WORKERS", raising=False)
    monkeypatch.setenv("RHORIZON_WORKERS", "10")
    assert Settings().workers == 10


def test_failover_timeouts_are_operator_tunable(monkeypatch):
    monkeypatch.setenv("RH_CLUSTER_MASTER_TIMEOUT_SECS", "300")
    monkeypatch.setenv("RH_CLUSTER_MASTER_WATCH_INTERVAL_SECS", "150")
    monkeypatch.setenv("RH_CLUSTER_RPC_TIMEOUT_SECS", "400")
    settings = Settings()
    assert settings.cluster_master_timeout_secs == 300.0
    assert settings.cluster_master_watch_interval_secs == 150.0
    assert settings.cluster_rpc_timeout_secs == 400.0


def test_failover_default_waits_out_an_io_stall():
    """5s treats a worker starved on iowait as dead and triggers a full
    Shamir reconstruction on a box that is already collapsing -- which is the
    failure separated custody exists to survive."""
    settings = Settings()
    assert settings.cluster_master_timeout_secs == 120.0
    assert settings.cluster_master_watch_interval_secs == 60.0
    assert settings.cluster_rpc_timeout_secs == 180.0


def test_an_rpc_deadline_below_the_master_timeout_refuses_to_start(monkeypatch):
    """Otherwise every in-flight request fails before the cluster has even
    decided whether the master is gone -- and the operator who raised the
    master timeout to survive a stall never finds out why it did not help."""
    monkeypatch.setenv("RH_CLUSTER_MASTER_TIMEOUT_SECS", "120")
    monkeypatch.setenv("RH_CLUSTER_RPC_TIMEOUT_SECS", "60")
    with pytest.raises(ValueError, match="must exceed cluster_master_timeout_secs"):
        Settings()


def test_a_watch_interval_above_the_timeout_refuses_to_start(monkeypatch):
    """Master loss would be detected a full poll after the deadline it is
    supposed to enforce."""
    monkeypatch.setenv("RH_CLUSTER_MASTER_TIMEOUT_SECS", "60")
    monkeypatch.setenv("RH_CLUSTER_MASTER_WATCH_INTERVAL_SECS", "120")
    monkeypatch.setenv("RH_CLUSTER_RPC_TIMEOUT_SECS", "200")
    with pytest.raises(ValueError, match="must not exceed"):
        Settings()


def test_db_audit_window_can_never_outlive_the_archive(monkeypatch):
    """Pruning a row whose archive file is already deleted would put a hole in
    the record that nothing detects. Same technique as clamp_audit_compress."""
    monkeypatch.setenv("RH_AUDIT_RETENTION_DAYS", "400")
    monkeypatch.setenv("RH_AUDIT_DB_RETENTION_DAYS", "9999")
    settings = Settings()
    assert settings.audit_db_retention_days == 400
    assert settings.audit_db_retention_days <= settings.audit_retention_days


def test_audit_retention_knobs_are_env_tunable(monkeypatch):
    monkeypatch.setenv("RH_AUDIT_RETENTION_DAYS", "900")
    monkeypatch.setenv("RH_AUDIT_COMPRESS_DAYS", "7")
    monkeypatch.setenv("RH_AUDIT_DB_RETENTION_DAYS", "45")
    settings = Settings()
    assert settings.audit_retention_days == 900
    assert settings.audit_compress_days == 7
    assert settings.audit_db_retention_days == 45


def test_db_audit_window_defaults_to_a_walkable_working_set():
    """audit_retention_days is floored at 365 because it is a compliance knob
    for the archive. A year of chain in the database is neither walkable by
    /audit/verify nor cheap, so the database window is its own setting."""
    settings = Settings()
    assert settings.audit_db_retention_days == 30
    assert settings.audit_retention_days == 365


def test_audit_pruning_is_on_by_default():
    """Nothing is lost by it: a day is pruned only once the archive provably
    holds it -- sealed against the database rows while both copies existed,
    and that seal still verifying against the file."""
    assert Settings().audit_db_prune_enabled is True


def test_audit_pruning_can_be_disabled(monkeypatch):
    """An operator who wants the whole chain in the database can keep it."""
    monkeypatch.setenv("RH_AUDIT_DB_PRUNE_ENABLED", "false")
    assert Settings().audit_db_prune_enabled is False
