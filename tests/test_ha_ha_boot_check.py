"""enforce_ha_tls_invariant -- pure unit tests.

Exercises the four (cluster_ha_enabled, tls_enabled)
combinations + verifies the error message carries the operator-
actionable hint (env var names + remediation steps). The settings
singleton is intentionally not touched -- the function takes plain
booleans so the test grid stays trivial.
"""

import pytest
from api.app.ha_boot_check import (
    HaBootInvariantError,
    enforce_ha_tls_invariant,
)


def test_ha_off_tls_off_boots():
    # Single-node, no TLS, no HA -- the default rhorizon shape.
    enforce_ha_tls_invariant(cluster_ha_enabled=False, tls_enabled=False)


def test_ha_off_tls_on_boots():
    # Single-node with TLS termination on the API -- still no HA, OK.
    enforce_ha_tls_invariant(cluster_ha_enabled=False, tls_enabled=True)


def test_ha_on_tls_on_boots():
    # HA cluster with TLS termination -- the supported HA deployment.
    enforce_ha_tls_invariant(cluster_ha_enabled=True, tls_enabled=True)


def test_ha_on_tls_off_refuses():
    """The forbidden combo : HA enabled but no TLS. Must refuse boot."""
    with pytest.raises(HaBootInvariantError) as excinfo:
        enforce_ha_tls_invariant(cluster_ha_enabled=True, tls_enabled=False)
    msg = str(excinfo.value)
    # Operator-actionable : the error names the offending env vars
    # and the remediation paths (TLS on, OR HA off).
    assert "RHORIZON_CLUSTER_HA_ENABLED" in msg
    assert "RHORIZON_TLS_ENABLED" in msg
    assert "HA-CLUSTER.md" in msg


def test_error_is_runtime_subclass():
    """HaBootInvariantError must be catchable as RuntimeError too --
    keeps the lifespan-side handling generic if we ever want to
    fall back on a broader catch."""
    assert issubclass(HaBootInvariantError, RuntimeError)
