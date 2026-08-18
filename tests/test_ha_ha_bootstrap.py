# SPDX-License-Identifier: AGPL-3.0-or-later
"""(bug 7) -- portable ha_password delivery via
age-encrypted file + vault-fetched key.

Coverage :
- :mod:`api.app.ha_bootstrap` unit surface (read token, decrypt age,
  fetch key, cleanup, end-to-end)
- :mod:`api.app.cluster_auto_join` gating dispatcher (file vs
  age_vault storage mode)
"""

from unittest.mock import patch

import httpx
import pytest
from api.app import cluster_auto_join, ha_bootstrap
from api.app.config import settings
from pyrage import passphrase as age_passphrase

# --- helpers ---------------------------------------------------------------


def _age_encrypt(plaintext: bytes, key: str) -> bytes:
    return age_passphrase.encrypt(plaintext, key)


def _setup_age_vault_settings(monkeypatch, tmp_path, **overrides):
    """Place a coherent age_vault config + on-disk artifacts under
    tmp_path. Returns the paths so the test can inspect / mutate them.
    """
    age_path = tmp_path / "ha-password.age"
    token_path = tmp_path / "ha-bootstrap-token"

    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "age_vault")
    monkeypatch.setattr(settings, "ha_password_age_path", str(age_path))
    monkeypatch.setattr(settings, "ha_bootstrap_token_file", str(token_path))
    monkeypatch.setattr(settings, "ha_bootstrap_secret_name", "ha-bootstrap")
    monkeypatch.setattr(settings, "ha_bootstrap_namespace", "cluster-ha")
    monkeypatch.setattr(settings, "ha_bootstrap_vault_url", "")
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "c.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "c.key"))
    monkeypatch.setattr(settings, "ha_password_min_length", 32)

    for k, v in overrides.items():
        monkeypatch.setattr(settings, k, v)

    return age_path, token_path


# --- gating dispatcher (cluster_auto_join._should_attempt) -----------------


def test_should_attempt_file_storage_uses_legacy_path(monkeypatch, tmp_path):
    """Storage='file' keeps the file-storage behavior (ha_password_file gate)."""
    pw = tmp_path / "ha-password"
    pw.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://x.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_password_file", str(pw))
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "c.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "c.key"))
    attempt, _ = cluster_auto_join._should_attempt()
    assert attempt is True


def test_should_attempt_age_vault_happy_path(monkeypatch, tmp_path):
    age_path, token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    age_path.write_bytes(b"any-ciphertext")
    token_path.write_text("rh_" + "a" * 30)
    attempt, _ = cluster_auto_join._should_attempt()
    assert attempt is True


def test_should_attempt_age_vault_missing_age_path_setting(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path, ha_password_age_path="")
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_password_age_path" in reason


def test_should_attempt_age_vault_missing_token_setting(monkeypatch, tmp_path):
    age_path, _ = _setup_age_vault_settings(
        monkeypatch, tmp_path, ha_bootstrap_token_file=""
    )
    age_path.write_bytes(b"x")
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_bootstrap_token_file" in reason


def test_should_attempt_age_vault_age_file_not_on_disk(monkeypatch, tmp_path):
    _age_path, token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    token_path.write_text("rh_" + "a" * 30)
    # age_path not written to disk
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_password_age_path" in reason and "not present" in reason


def test_should_attempt_age_vault_token_file_not_on_disk(monkeypatch, tmp_path):
    age_path, _token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    age_path.write_bytes(b"x")
    # token_path not written to disk
    attempt, reason = cluster_auto_join._should_attempt()
    assert not attempt
    assert "ha_bootstrap_token_file" in reason and "not present" in reason


# --- ha_bootstrap.decrypt_ha_password --------------------------------------


def test_decrypt_happy_roundtrip():
    key = "passphrase-32-bytes-random-ok-yes"
    plaintext = b"y" * 48
    ciphertext = _age_encrypt(plaintext, key)
    out = ha_bootstrap.decrypt_ha_password(ciphertext, key.encode())
    assert out == plaintext


def test_decrypt_wrong_key_permanent_error():
    ciphertext = _age_encrypt(b"y" * 48, "correct-passphrase-here")
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
        ha_bootstrap.decrypt_ha_password(ciphertext, b"wrong-passphrase-here")
    assert "age decrypt failed" in str(ei.value)


def test_decrypt_corrupted_ciphertext_permanent_error():
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError):
        ha_bootstrap.decrypt_ha_password(b"\x00garbage\xff", b"any-key")


def test_decrypt_strips_trailing_newline_then_validates_length(monkeypatch):
    monkeypatch.setattr(settings, "ha_password_min_length", 32)
    key = "passphrase-32-bytes-random-ok-yes"
    plaintext_with_nl = (b"y" * 32) + b"\n"
    ciphertext = _age_encrypt(plaintext_with_nl, key)
    out = ha_bootstrap.decrypt_ha_password(ciphertext, key.encode())
    assert out == b"y" * 32


def test_decrypt_too_short_plaintext_permanent_error(monkeypatch):
    monkeypatch.setattr(settings, "ha_password_min_length", 32)
    key = "passphrase-32-bytes-random-ok-yes"
    ciphertext = _age_encrypt(b"short", key)
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
        ha_bootstrap.decrypt_ha_password(ciphertext, key.encode())
    assert "too short" in str(ei.value)


# --- ha_bootstrap.fetch_age_key (mocked httpx) -----------------------------


@pytest.mark.asyncio
async def test_fetch_age_key_happy_path(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    captured = {}

    async def _fake_get(self, url, headers=None):
        captured["url"] = url
        captured["auth"] = headers.get("Authorization") if headers else None
        return httpx.Response(200, json={"name": "ha-bootstrap", "value": "deadbeef"})

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            key = await ha_bootstrap.fetch_age_key(client)

    assert key == b"deadbeef"
    assert "/secrets/ha-bootstrap?namespace=cluster-ha" in captured["url"]
    assert captured["auth"] == "Bearer rh_" + "t" * 30


@pytest.mark.asyncio
async def test_fetch_age_key_non_ascii_value_permanent(monkeypatch, tmp_path):
    """A non-ASCII stored value yields a clean permanent error, not an
    uncaught UnicodeEncodeError that would escape the typed contract and
    kill the auto-join task."""
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(200, json={"name": "ha-bootstrap", "value": "clé-é"})

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
                await ha_bootstrap.fetch_age_key(client)
    assert "ASCII" in str(ei.value)


@pytest.mark.asyncio
async def test_fetch_age_key_401_permanent(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(401, text="token revoked")

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
                await ha_bootstrap.fetch_age_key(client)
    assert "401" in str(ei.value)


@pytest.mark.asyncio
async def test_fetch_age_key_403_permanent_ip_mismatch(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(403, text="ip not allowed")

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            with pytest.raises(ha_bootstrap.HaBootstrapPermanentError):
                await ha_bootstrap.fetch_age_key(client)


@pytest.mark.asyncio
async def test_fetch_age_key_404_permanent_secret_missing(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(404, text="secret not found")

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            with pytest.raises(ha_bootstrap.HaBootstrapPermanentError):
                await ha_bootstrap.fetch_age_key(client)


@pytest.mark.asyncio
async def test_fetch_age_key_500_transient(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(500, text="ops vault overloaded")

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            with pytest.raises(ha_bootstrap.HaBootstrapError) as ei:
                await ha_bootstrap.fetch_age_key(client)
    # Not permanent : caller will retry per ha_auto_join_max_attempts.
    assert not isinstance(ei.value, ha_bootstrap.HaBootstrapPermanentError)


@pytest.mark.asyncio
async def test_fetch_age_key_missing_value_field(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(200, json={"name": "ha-bootstrap"})

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
                await ha_bootstrap.fetch_age_key(client)
    assert "value" in str(ei.value)


@pytest.mark.asyncio
async def test_fetch_age_key_uses_primary_url_when_bootstrap_url_unset(
    monkeypatch, tmp_path
):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "ha_bootstrap_vault_url", "")
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary-only.example")
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    captured = {}

    async def _fake_get(self, url, headers=None):
        captured["url"] = url
        return httpx.Response(200, json={"value": "deadbeef"})

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            await ha_bootstrap.fetch_age_key(client)

    assert captured["url"].startswith("https://primary-only.example/")


@pytest.mark.asyncio
async def test_fetch_age_key_dedicated_bootstrap_url_overrides(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "ha_bootstrap_vault_url", "https://ops-vault.example")
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.example")
    (tmp_path / "ha-bootstrap-token").write_text("rh_" + "t" * 30)

    captured = {}

    async def _fake_get(self, url, headers=None):
        captured["url"] = url
        return httpx.Response(200, json={"value": "deadbeef"})

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            await ha_bootstrap.fetch_age_key(client)

    assert captured["url"].startswith("https://ops-vault.example/")


# --- ha_bootstrap.cleanup_on_join_success ----------------------------------


def test_cleanup_unlinks_both_files(monkeypatch, tmp_path):
    age_path, token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    age_path.write_bytes(b"ciphertext")
    token_path.write_text("rh_foo")
    assert age_path.exists() and token_path.exists()
    ha_bootstrap.cleanup_on_join_success()
    assert not age_path.exists()
    assert not token_path.exists()


def test_cleanup_idempotent_when_files_already_gone(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    # No files written -- cleanup must not raise.
    ha_bootstrap.cleanup_on_join_success()
    # Idempotent : running twice still does nothing controversial.
    ha_bootstrap.cleanup_on_join_success()


def test_cleanup_skips_empty_path_settings(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "ha_password_age_path", "")
    monkeypatch.setattr(settings, "ha_bootstrap_token_file", "")
    # No-op (no path = nothing to unlink) ; must not raise.
    ha_bootstrap.cleanup_on_join_success()


# --- ha_bootstrap.read_ha_password_from_vault (end-to-end mocked) ----------


@pytest.mark.asyncio
async def test_read_ha_password_from_vault_end_to_end(monkeypatch, tmp_path):
    age_path, token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    age_key = "ha-bootstrap-32B-random-key-test1"
    ha_password_plain = b"P" * 48
    age_path.write_bytes(_age_encrypt(ha_password_plain, age_key))
    token_path.write_text("rh_" + "t" * 30)

    async def _fake_get(self, url, headers=None):
        return httpx.Response(200, json={"value": age_key})

    async with httpx.AsyncClient() as client:
        with patch("httpx.AsyncClient.get", _fake_get):
            out = await ha_bootstrap.read_ha_password_from_vault(client)

    assert out == ha_password_plain


# --- token / age path reading edge cases -----------------------------------


def test_read_token_file_missing_permanent_error(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    # Token file not written : should surface permanent error.
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
        ha_bootstrap._read_token_file()
    assert "not present" in str(ei.value)


def test_read_token_file_too_short_permanent_error(monkeypatch, tmp_path):
    _, token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    token_path.write_text("rh_short")  # only 8 chars
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
        ha_bootstrap._read_token_file()
    assert "too short" in str(ei.value)


def test_read_token_file_strips_trailing_whitespace(monkeypatch, tmp_path):
    _, token_path = _setup_age_vault_settings(monkeypatch, tmp_path)
    token_path.write_text("rh_" + "x" * 30 + "\n")
    out = ha_bootstrap._read_token_file()
    assert out == "rh_" + "x" * 30


def test_read_age_ciphertext_empty_file_permanent_error(monkeypatch, tmp_path):
    age_path, _ = _setup_age_vault_settings(monkeypatch, tmp_path)
    age_path.write_bytes(b"")
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
        ha_bootstrap._read_age_ciphertext()
    assert "empty" in str(ei.value)


# --- vault URL resolution --------------------------------------------------


def test_vault_url_raises_when_both_unset(monkeypatch, tmp_path):
    _setup_age_vault_settings(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "ha_bootstrap_vault_url", "")
    monkeypatch.setattr(settings, "ha_primary_url", "")
    with pytest.raises(ha_bootstrap.HaBootstrapPermanentError) as ei:
        ha_bootstrap._vault_url()
    msg = str(ei.value)
    assert "neither" in msg.lower() or "ha_bootstrap_vault_url" in msg
