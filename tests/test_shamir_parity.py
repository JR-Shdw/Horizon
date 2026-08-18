# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Shamir parity: the Rust constant-time GF (rhorizon_crypto) must agree
byte-for-byte with the Python reference (api.app.crypto) on every case.

The Python implementation is the trusted, readable reference; this test is the
gate that the constant-time Rust rewrite never silently derives from it. Runs
in CI via pytest (validate.yml). Cf. test_audit_ed25519_parity.py (same pattern
for the Ed25519 path).
"""

import os

import pytest
import rhorizon_crypto as rc
from api.app import crypto as py

# (threshold, total) grids covering the operator defaults + edges.
_CONFIGS = [(2, 2), (2, 3), (3, 5), (5, 9), (2, 255), (10, 16)]
# Secret sizes incl. the 128-byte operator sub-key bundle + a 1-byte edge.
_SIZES = [1, 16, 32, 96, 128, 200]


def _secret(n):
    return os.urandom(n)


@pytest.mark.parametrize("threshold,total", _CONFIGS)
@pytest.mark.parametrize("size", _SIZES)
def test_rust_split_python_combine_roundtrip(threshold, total, size):
    # Rust split (randomized) -> Python combine must recover the secret with
    # ANY threshold-sized subset of shares.
    secret = _secret(size)
    shares = [bytes(s) for s in rc.shamir_split_bytes(secret, threshold, total)]
    assert [s[0] for s in shares] == list(range(1, total + 1))  # 1-indexed x prefix
    assert py.shamir_combine(shares[:threshold]) == secret
    assert py.shamir_combine(shares[-threshold:]) == secret


@pytest.mark.parametrize("threshold,total", _CONFIGS)
@pytest.mark.parametrize("size", _SIZES)
def test_python_split_rust_combine_roundtrip(threshold, total, size):
    secret = _secret(size)
    shares = py.shamir_split(secret, threshold, total)
    assert bytes(rc.shamir_combine_bytes(shares[:threshold])) == secret


def test_combine_is_byte_identical():
    # combine is deterministic given shares -> Python and Rust must produce the
    # EXACT same bytes, not just both-correct.
    secret = os.urandom(128)
    shares = py.shamir_split(secret, 3, 7)
    import itertools

    for combo in itertools.combinations(shares, 3):
        assert bytes(rc.shamir_combine_bytes(list(combo))) == py.shamir_combine(
            list(combo)
        )


@pytest.mark.parametrize(
    "threshold,total",
    [(1, 5), (3, 2)],  # threshold<2, total<threshold
)
def test_split_error_parity(threshold, total):
    secret = os.urandom(32)
    with pytest.raises(ValueError):
        py.shamir_split(secret, threshold, total)
    with pytest.raises(ValueError):
        rc.shamir_split_bytes(secret, threshold, total)


def test_combine_error_parity_duplicate_indices():
    secret = os.urandom(32)
    shares = py.shamir_split(secret, 3, 5)
    dup = [shares[0], shares[0], shares[1]]
    with pytest.raises(ValueError):
        py.shamir_combine(dup)
    with pytest.raises(ValueError):
        rc.shamir_combine_bytes(dup)


def test_combine_error_parity_short():
    secret = os.urandom(32)
    shares = py.shamir_split(secret, 3, 5)
    one = [shares[0]]
    with pytest.raises(ValueError):
        py.shamir_combine(one)
    with pytest.raises(ValueError):
        rc.shamir_combine_bytes(one)
