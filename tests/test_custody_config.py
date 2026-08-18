"""Configuration contracts for separated crypto custody."""

from pathlib import Path

import pytest
from api.app.config import Settings


def test_embedded_custody_remains_the_compatibility_default():
    cfg = Settings(_env_file=None)
    assert cfg.custody_mode == "embedded"
    assert cfg.custody_backend == "python"
    assert cfg.process_role == "api"
    assert cfg.custodian_workers == 5


@pytest.mark.parametrize("workers", [3, 5, 7, 9])
def test_custodian_quorum_accepts_only_small_odd_pools(workers):
    cfg = Settings(
        custody_mode="separated",
        process_role="custodian",
        custodian_workers=workers,
        _env_file=None,
    )
    assert cfg.custodian_workers == workers


@pytest.mark.parametrize("workers", [1, 2, 4, 6, 10])
def test_custodian_quorum_rejects_non_quorum_sizes(workers):
    with pytest.raises(ValueError, match="3, 5, 7, or 9"):
        Settings(custodian_workers=workers, _env_file=None)


def test_custodian_role_requires_separated_mode():
    with pytest.raises(ValueError, match="requires custody_mode=separated"):
        Settings(process_role="custodian", _env_file=None)


def test_disposable_api_pool_is_not_forced_to_shamir_floor():
    api = Settings(
        custody_mode="separated",
        process_role="api",
        workers=2,
        _env_file=None,
    )
    custodian = Settings(
        custody_mode="separated",
        process_role="custodian",
        workers=2,
        custodian_workers=3,
        _env_file=None,
    )
    embedded = Settings(custody_mode="embedded", workers=2, _env_file=None)
    assert api.workers == 2
    assert custodian.workers == 3
    assert embedded.workers == 5


def test_custodian_runtime_paths_must_be_absolute():
    with pytest.raises(ValueError, match="absolute path"):
        Settings(custodian_uds_path="relative.sock", _env_file=None)
    cfg = Settings(
        custody_mode="separated",
        custodian_uds_path="/tmp/rhorizon-custodian.sock",
        custodian_token_file="/tmp/rhorizon-custodian.token",
        _env_file=None,
    )
    assert Path(cfg.custodian_uds_path).is_absolute()


def test_three_custodians_use_two_share_majority(monkeypatch):
    from api.app import cluster_setup

    monkeypatch.setattr(cluster_setup.settings, "custody_mode", "separated")
    monkeypatch.setattr(cluster_setup.settings, "process_role", "custodian")
    monkeypatch.setattr(cluster_setup.settings, "custodian_workers", 3)
    monkeypatch.setattr(cluster_setup.settings, "workers", 3)
    monkeypatch.setattr(cluster_setup.settings, "cluster_shamir_total", 0)
    monkeypatch.setattr(cluster_setup.settings, "cluster_shamir_threshold", 0)
    monkeypatch.setattr(cluster_setup.settings, "cluster_shamir_spare_shares", 8)

    assert cluster_setup._shamir_total_threshold() == (11, 2)


def test_rust_backend_is_explicit_separated_api_only():
    cfg = Settings(
        custody_mode="separated",
        custody_backend="rust",
        rust_custodian_slots=3,
        rust_custodian_threshold=0,
        _env_file=None,
    )
    assert cfg.rust_custodian_threshold == 2
    with pytest.raises(ValueError, match="requires custody_mode=separated"):
        Settings(custody_backend="rust", _env_file=None)
    with pytest.raises(ValueError, match="standalone"):
        Settings(
            custody_mode="separated",
            custody_backend="rust",
            process_role="custodian",
            _env_file=None,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("custody_backend", "unknown", "python or rust"),
        ("rust_custodian_slots", 4, "3, 5, 7, or 9"),
        ("rust_custodian_threshold", 4, "between 2"),
        ("rust_custody_maintenance_interval_secs", 0.5, "between 1 and 300"),
    ],
)
def test_rust_backend_rejects_invalid_configuration(field, value, message):
    values = {field: value}
    if field == "rust_custodian_threshold":
        values.update(custody_mode="separated", custody_backend="rust")
    with pytest.raises(ValueError, match=message):
        Settings(**values, _env_file=None)
