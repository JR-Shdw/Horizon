# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""CLI config: URL/token env resolution order (RH_* canonical, HKV_* legacy)."""

import pytest
from cli.rhorizon import config

_URL_ENVS = ("RH_ADDR", "RH_URL", "HKV_ADDR")
_TOKEN_ENVS = ("RH_TOKEN", "HKV_TOKEN", "RH_TOKEN_STDIN")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in _URL_ENVS + _TOKEN_ENVS:
        monkeypatch.delenv(k, raising=False)


def test_get_url_prefers_rh_addr(monkeypatch):
    monkeypatch.setenv("RH_ADDR", "https://rh")
    monkeypatch.setenv("HKV_ADDR", "https://legacy")
    assert config.get_url() == "https://rh"


def test_get_url_rh_url_over_legacy(monkeypatch):
    monkeypatch.setenv("RH_URL", "https://rh-url")
    monkeypatch.setenv("HKV_ADDR", "https://legacy")
    assert config.get_url() == "https://rh-url"


def test_get_url_legacy_hkv_still_works(monkeypatch):
    monkeypatch.setenv("HKV_ADDR", "https://legacy")
    assert config.get_url() == "https://legacy"


def test_get_url_falls_back_to_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("RH_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.toml")
    config.set_profile("default", "https://from-file")
    assert config.get_url() == "https://from-file"


def test_get_url_none_when_unset():
    assert config.get_url("nonexistent-profile") is None


def test_load_token_prefers_rh_token(monkeypatch):
    monkeypatch.setenv("RH_TOKEN", "rh_new")
    monkeypatch.setenv("HKV_TOKEN", "rh_legacy")
    assert config.load_token() == "rh_new"


def test_load_token_legacy_hkv(monkeypatch):
    monkeypatch.setenv("HKV_TOKEN", "rh_legacy")
    assert config.load_token() == "rh_legacy"
