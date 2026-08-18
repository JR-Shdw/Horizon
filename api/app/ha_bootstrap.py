# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Portable ha_password delivery.

Replaces the systemd-tmpfs-only ``RHORIZON_HA_PASSWORD_FILE`` flow
with a cross-platform path :

- ``ha_password.age``  : age-encrypted ha_password on persistent disk
  (mode 0400 owner rhorizon, useless without the key)
- ``ha-bootstrap-token``: bearer token on persistent disk (mode 0400),
  IP-scoped + scoped to ``secrets:r`` + namespace ``cluster-ha``,
  revocable + auditable + short TTL

At joiner boot, the bootstrap token fetches the 32 B random key from
the cluster vault (any cluster member that can serve the
``ha-bootstrap`` secret), the key decrypts the local ciphertext, the
joiner runs the normal JOIN flow with the plaintext briefly in a
SecureBuffer-backed bytearray. After JOIN succeeds both on-disk
artifacts are unlinked.

Cross-platform : zero init-system dependency. No tmpfs. Works
identically Linux / macOS / FreeBSD / OpenBSD because the only
runtime dependencies are :

- a regular filesystem (for the two on-disk artifacts)
- HTTPS reachability of the cluster vault URL
- ``pyrage`` for age decryption (already in api/requirements.txt)

Threat model :
- disk-only exfil : ciphertext + token. Token IP-locked at mint by
  operator -- fetch from a different IP is rejected by the vault.
- token compromise via separate vector : useless without on-disk
  ciphertext to decrypt.
- vault unreachable at JOIN : retry per
  ``ha_auto_join_max_attempts``. REJOIN-by-cert (steady state for
  already-joined nodes) is unaffected.
- post-JOIN : both artifacts unlinked ; cluster cert becomes the
  long-lived credential.

Backward compat : when ``settings.ha_password_storage == "file"``
(default), :mod:`cluster_auto_join` skips this module entirely and
keeps the tmpfs path.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
from pyrage import passphrase as age_passphrase

from .config import settings

log = logging.getLogger("rhorizon.ha_bootstrap")

# Same shape as cluster_auto_join : two short round-trips, 10s connect
# + 30s read total. The fetch is a single GET ; we keep the read
# budget generous to absorb a slow primary.
_HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Permanent : retrying does not help. 401 = token revoked or expired,
# 403 = IP allowlist mismatch or scope insufficient, 404 = secret
# missing in the configured namespace.
_PERMANENT_STATUSES = (401, 403, 404)


class HaBootstrapError(RuntimeError):
    """Recoverable bootstrap failure -- caller decides whether to retry."""


class HaBootstrapPermanentError(HaBootstrapError):
    """Non-recoverable bootstrap failure -- exit the JOIN attempt."""


def _read_token_file() -> str:
    """Read the bootstrap bearer token from disk.

    Strips a trailing newline an operator might have added with
    ``echo``. Length floor (16 chars) catches obvious operator
    mistakes (empty file, truncated copy).
    """
    p = Path(settings.ha_bootstrap_token_file)
    if not p.is_file():
        raise HaBootstrapPermanentError(f"ha_bootstrap_token_file {p} not present")
    raw = p.read_text(encoding="ascii").strip()
    if len(raw) < 16:
        raise HaBootstrapPermanentError(
            f"ha_bootstrap_token_file {p} content too short "
            f"({len(raw)} chars, need at least 16)"
        )
    return raw


def _read_age_ciphertext() -> bytes:
    """Read the age-encrypted ha_password blob from disk."""
    p = Path(settings.ha_password_age_path)
    if not p.is_file():
        raise HaBootstrapPermanentError(f"ha_password_age_path {p} not present")
    data = p.read_bytes()
    if not data:
        raise HaBootstrapPermanentError(f"ha_password_age_path {p} is empty")
    return data


def _vault_url() -> str:
    """Resolve which rhorizon serves ha-bootstrap.

    Empty ``ha_bootstrap_vault_url`` defaults to ``ha_primary_url`` --
    the typical case where the cluster being bootstrapped is itself
    the ops vault.
    """
    url = settings.ha_bootstrap_vault_url or settings.ha_primary_url
    if not url:
        raise HaBootstrapPermanentError(
            "neither ha_bootstrap_vault_url nor ha_primary_url is set"
        )
    return url.rstrip("/")


async def fetch_age_key(client: httpx.AsyncClient) -> bytes:
    """GET ha-bootstrap secret from the cluster vault.

    Returns the raw key bytes (base64-decoded if the vault stored
    them base64-encoded, otherwise as-is). The caller treats the
    return value as the age scrypt passphrase.
    """
    token = _read_token_file()
    url = (
        f"{_vault_url()}/api/v1/vault/secrets/"
        f"{settings.ha_bootstrap_secret_name}"
        f"?namespace={settings.ha_bootstrap_namespace}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise HaBootstrapError(f"ha-bootstrap fetch transport error: {exc}") from exc
    if r.status_code in _PERMANENT_STATUSES:
        raise HaBootstrapPermanentError(
            f"ha-bootstrap fetch rejected ({r.status_code}): {r.text[:200]}"
        )
    if r.status_code != 200:
        raise HaBootstrapError(
            f"ha-bootstrap fetch unexpected {r.status_code}: {r.text[:200]}"
        )
    try:
        value = r.json()["value"]
    except (ValueError, KeyError) as exc:
        raise HaBootstrapPermanentError(
            f"ha-bootstrap response missing 'value' field: {exc}"
        ) from exc
    if not value:
        raise HaBootstrapPermanentError("ha-bootstrap secret value is empty")
    # Used verbatim as the age passphrase (operator's encrypt step uses
    # the same string). A non-ASCII value can never be the passphrase, so
    # fail closed here rather than let UnicodeEncodeError escape the typed
    # contract and kill the auto-join task.
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise HaBootstrapPermanentError(
                "ha-bootstrap secret value is not ASCII -- the age "
                "passphrase must round-trip as ASCII text"
            ) from exc
    return bytes(value)


def decrypt_ha_password(ciphertext: bytes, passphrase: bytes) -> bytes:
    """age-decrypt ciphertext with the fetched key as passphrase.

    Strips a trailing newline that an operator's encrypt step might
    have introduced (matches :mod:`cluster_auto_join._read_ha_password`
    semantics).
    """
    try:
        plaintext = age_passphrase.decrypt(ciphertext, passphrase.decode("ascii"))
    except Exception as exc:
        # pyrage raises a variety of subclasses depending on failure
        # mode (HeaderFailure, NoIdentities, DecryptError, ...). All
        # map to "permanent : operator must re-mint the file with the
        # right key" -- retry will not help.
        raise HaBootstrapPermanentError(
            f"age decrypt failed: {type(exc).__name__}: {exc}"
        ) from exc
    if plaintext.endswith(b"\n"):
        plaintext = plaintext[:-1]
    if len(plaintext) < settings.ha_password_min_length:
        raise HaBootstrapPermanentError(
            f"decrypted ha_password too short: {len(plaintext)} bytes "
            f"(min {settings.ha_password_min_length})"
        )
    return plaintext


async def read_ha_password_from_vault(client: httpx.AsyncClient) -> bytes:
    """End-to-end : fetch age key + decrypt ciphertext -> ha_password.

    The caller is responsible for zeroizing the returned bytes after
    use (see :func:`cluster_auto_join._zero_bytes`).
    """
    ciphertext = _read_age_ciphertext()
    age_key = bytearray(await fetch_age_key(client))
    try:
        return decrypt_ha_password(ciphertext, bytes(age_key))
    finally:
        # age_key is a bytearray we own, so wipe it in place through the native
        # zeroize implementation. The bytes() copy passed to decrypt is
        # short-lived. (The HKDF output inside decrypt cannot be zeroed in
        # Python -- see ha_password unwrap.)
        from rhorizon_crypto import secure_zero

        secure_zero(age_key)


def cleanup_on_join_success() -> None:
    """Unlink the two on-disk artifacts after a successful JOIN.

    Best-effort : a failure to unlink is logged but does not abort the
    JOIN (the cert is already persisted ; the operator can clean up
    manually). Both files exist by construction at JOIN time -- the
    gating in :mod:`cluster_auto_join._should_attempt` verifies their
    presence.
    """
    for label, path_str in (
        ("ha_password_age_path", settings.ha_password_age_path),
        ("ha_bootstrap_token_file", settings.ha_bootstrap_token_file),
    ):
        if not path_str:
            continue
        try:
            Path(path_str).unlink(missing_ok=True)
        except OSError as exc:
            log.warning(
                "ha_bootstrap cleanup: failed to unlink %s=%s: %s",
                label,
                path_str,
                exc,
            )
