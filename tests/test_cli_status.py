# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
from unittest.mock import MagicMock

from cli.rhorizon.main import app as cli_app
from typer.testing import CliRunner


def test_status_reports_degraded_memory_protection(monkeypatch):
    client = MagicMock()
    client.status.return_value = {
        "sealed": False,
        "version": "test",
        "second_factor": "none",
        "memory_protection": "zeroize-only",
        "process_memory_protection": "swappable",
        "swap_protection": "unencrypted",
        "shamir_enabled": False,
    }
    monkeypatch.setattr("cli.rhorizon.main.VaultClient", lambda *a, **kw: client)
    monkeypatch.setattr("cli.rhorizon.main.get_url", lambda: "http://test")
    monkeypatch.setattr("cli.rhorizon.main.load_token", lambda: None)

    result = CliRunner().invoke(cli_app, ["status"])

    assert result.exit_code == 0
    assert "Buffers:  zeroize-only" in result.output
    assert "not locked against unencrypted or unknown swap" in result.output
    assert "RH_MEMORY_LOCK_MODE=required" in result.output


def test_status_does_not_warn_when_swap_is_protected(monkeypatch):
    client = MagicMock()
    client.status.return_value = {
        "sealed": False,
        "version": "test",
        "second_factor": "none",
        "memory_protection": "zeroize-only",
        "process_memory_protection": "swappable",
        "swap_protection": "protected",
        "shamir_enabled": False,
    }
    monkeypatch.setattr("cli.rhorizon.main.VaultClient", lambda *a, **kw: client)
    monkeypatch.setattr("cli.rhorizon.main.get_url", lambda: "http://test")
    monkeypatch.setattr("cli.rhorizon.main.load_token", lambda: None)

    result = CliRunner().invoke(cli_app, ["status"])

    assert result.exit_code == 0
    assert "Buffers:  zeroize-only" in result.output
    assert "Swap:     protected" in result.output
    assert "Warning:" not in result.output


def test_status_warns_when_process_pages_are_swappable(monkeypatch):
    client = MagicMock()
    client.status.return_value = {
        "sealed": False,
        "version": "test",
        "second_factor": "none",
        "memory_protection": "mlock",
        "process_memory_protection": "swappable",
        "swap_protection": "unencrypted",
        "shamir_enabled": False,
    }
    monkeypatch.setattr("cli.rhorizon.main.VaultClient", lambda *a, **kw: client)
    monkeypatch.setattr("cli.rhorizon.main.get_url", lambda: "http://test")
    monkeypatch.setattr("cli.rhorizon.main.load_token", lambda: None)

    result = CliRunner().invoke(cli_app, ["status"])

    assert result.exit_code == 0
    assert "Buffers:  mlock" in result.output
    assert "Process:  swappable" in result.output
    assert "Warning:" in result.output
