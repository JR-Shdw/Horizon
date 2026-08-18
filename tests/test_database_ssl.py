# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Postgres TLS mode: honest 3-state flag + pinned verify-full context."""

import ssl
import subprocess

import pytest
from api.app import database
from api.app.config import Settings


@pytest.mark.parametrize(
    "raw,expected",
    [
        (True, "require"),
        (False, "disable"),
        ("true", "require"),
        ("false", "disable"),
        ("1", "require"),
        ("0", "disable"),
        ("", "require"),
        ("disable", "disable"),
        ("require", "require"),
        ("verify-full", "verify-full"),
        ("VERIFY-FULL", "verify-full"),
    ],
)
def test_database_ssl_normalization(raw, expected):
    assert Settings(database_ssl=raw).database_ssl == expected


def test_database_ssl_rejects_garbage():
    with pytest.raises(ValueError, match="disable|require|verify-full"):
        Settings(database_ssl="sslmode=allow")


def test_require_encrypts_without_verifying(monkeypatch):
    monkeypatch.setattr(database, "settings", Settings(database_ssl="require"))
    ctx = database._pg_ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_verify_full_keeps_secure_baseline(monkeypatch):
    monkeypatch.setattr(
        database, "settings", Settings(database_ssl="verify-full", database_ca_cert="")
    )
    ctx = database._pg_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_verify_full_pins_ca_cert(tmp_path, monkeypatch):
    # A self-signed cert acts as its own CA; load_verify_locations must accept it.
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=postgres",
            "-addext",
            "subjectAltName=DNS:postgres",
            # Mark it a CA explicitly: get_ca_certs() only lists CA-flagged
            # certs, and `openssl req -x509` only defaults to CA:TRUE on
            # OpenSSL 3.x -- LibreSSL (OpenBSD base `openssl`) does not.
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr(
        database,
        "settings",
        Settings(database_ssl="verify-full", database_ca_cert=str(cert)),
    )
    ctx = database._pg_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    # The pinned cert is now a trusted anchor.
    assert any(c for c in ctx.get_ca_certs() if "postgres" in str(c.get("subject")))


def test_verify_full_missing_ca_fails_closed(monkeypatch):
    monkeypatch.setattr(
        database,
        "settings",
        Settings(database_ssl="verify-full", database_ca_cert="/nope/missing.pem"),
    )
    with pytest.raises(FileNotFoundError):
        database._pg_ssl_context()
