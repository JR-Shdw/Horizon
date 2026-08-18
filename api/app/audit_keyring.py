# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Audit-key archive -- keeps the audit chain verifiable across key rotations.

``audit_key = HKDF(master_key, "audit-sign")`` changes whenever the master
password rotates, so ``/audit/verify`` -- which recomputes every entry's HMAC
with the *current* audit_key -- would false-break the entire chain after any
rotation.

The fix epochs the chain (see api/app/key_epoch.py): every audit row is tagged
with the key generation that SIGNED it, and each retired audit_key is archived
here, encrypted at rest under the current dek_key. ``/audit/verify`` then picks
the right key per entry -- the in-RAM key for the current epoch, an archived key
for retired epochs -- so every generation stays verifiable and tamper-evident.

Invariant: archive rows are ALWAYS encrypted under the CURRENT dek_key. Because
both rotations change the dek_key, every rotation re-wraps the whole archive
(decrypt old / encrypt new) in the same transaction, exactly like the DEKs.
``load_audit_keyring`` therefore decrypts with the current dek_key. HTTP callers
must use the async ``decrypt_blob`` hook wired to ``vault.aesgcm_decrypt`` so
followers delegate to the host master instead of touching the master-only
``vault.aesgcm`` property.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_log = logging.getLogger("rhorizon.audit_keyring")


def _enc(aesgcm, plaintext: bytes | bytearray) -> bytes:
    """AES-256-GCM wrap -> nonce(12) || ciphertext.

    No AAD: the audit chain is already tamper-evident, so a DB-write attacker
    who swaps a key between epoch rows only makes /audit/verify false-BREAK
    (detected), never forge. Binding the epoch as AAD would harden that, but
    re-wrapping every existing archive row is a migration not worth the gain.
    """
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def _dec(aesgcm, blob: bytes) -> bytes:
    blob = bytes(blob)
    return aesgcm.decrypt(blob[:12], blob[12:], None)


async def rotate_audit_keyring(
    db: AsyncSession,
    *,
    retiring_epoch: int,
    retiring_audit_key: bytes | bytearray,
    old_aesgcm,
    new_aesgcm,
) -> None:
    """Re-wrap the existing archive and append the retiring epoch's audit_key.

    Must run inside the rotation transaction, BEFORE ``bump_key_epoch`` and the
    commit, with ``old_aesgcm`` = the current dek_key cipher and ``new_aesgcm``
    = the post-rotation dek_key cipher.

    1. Re-wrap every existing archive row from the old dek_key to the new one,
       so the whole archive stays readable after the dek_key flips.
    2. Archive ``retiring_audit_key`` under ``retiring_epoch`` (the generation
       being superseded), encrypted under the NEW dek_key.

    Idempotent on ``retiring_epoch`` (ON CONFLICT upsert): a retried rotation
    overwrites the same row rather than duplicating it.
    """
    existing = await db.execute(
        text(
            "SELECT key_epoch, audit_key_enc FROM vault_audit_key_archive "
            "WHERE quarantined_at IS NULL"
        )
    )
    for row in existing.fetchall():
        try:
            if hasattr(old_aesgcm, "rewrap_to"):
                # Production rotations use Rust DekCipher: no archive key
                # plaintext crosses into Python.
                rewrapped = bytes(
                    old_aesgcm.rewrap_to(new_aesgcm, bytes(row.audit_key_enc))
                )
            else:
                # Compatibility path for direct library callers/tests.
                plaintext = _dec(old_aesgcm, row.audit_key_enc)
                rewrapped = _enc(new_aesgcm, plaintext)
        except Exception:
            # A row that does not decrypt under the current dek_key is already
            # dead: load_audit_keyring skips it too, so its epoch is already
            # unverifiable and re-wrapping is impossible. A stale/foreign row
            # (e.g. left by a DB restore) must NOT brick every future rotation,
            # including an emergency master-password rotation. QUARANTINE it once
            # (A4) instead of aborting the rotation OR re-alarming every cycle:
            # stamp quarantined_at so future rotations skip it and stop logging,
            # and so load_audit_keyring's wrong-cipher tripwire ignores it.
            await db.execute(
                text(
                    "UPDATE vault_audit_key_archive SET quarantined_at = NOW() "
                    "WHERE key_epoch = :ep"
                ),
                {"ep": row.key_epoch},
            )
            _log.critical(
                "audit key archive row for epoch %s does not decrypt under the "
                "current dek_key; quarantined (its audit epoch is now "
                "unverifiable). Likely a stale/foreign row from a DB restore -- "
                "inspect and remove it.",
                row.key_epoch,
            )
            continue
        await db.execute(
            text(
                "UPDATE vault_audit_key_archive SET audit_key_enc = :e "
                "WHERE key_epoch = :ep"
            ),
            {"e": rewrapped, "ep": row.key_epoch},
        )

    await db.execute(
        text(
            "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
            "VALUES (:ep, :e) "
            "ON CONFLICT (key_epoch) DO UPDATE SET audit_key_enc = :e"
        ),
        {"ep": retiring_epoch, "e": _enc(new_aesgcm, retiring_audit_key)},
    )


async def load_audit_keyring(
    db: AsyncSession,
    aesgcm=None,
    *,
    decrypt_blob=None,
) -> dict[int, bytes]:
    """Return ``{epoch: audit_key}`` for all archived (retired) epochs.

    Decrypts with the current dek_key cipher. ``aesgcm`` is the legacy direct
    master-side path used by rotation tests and code that already holds the
    cipher. ``decrypt_blob`` is an async hook for follower-safe callers; pass a
    function that accepts ``nonce || ciphertext`` and returns plaintext.

    A SINGLE row that fails to decrypt is skipped -- ``/audit/verify`` falls
    back to the in-RAM key for that epoch and surfaces a break if it genuinely
    cannot verify. But if EVERY non-quarantined row fails (A4), that is not one
    dead row: it is a systemic wrong-dek_key/wrong-cipher bug (e.g. the wrong
    decryptor was passed) that would otherwise silently return ``{}`` and
    false-break the whole chain. Raise in that case so the bug surfaces loudly.
    Quarantined rows are excluded -- they are known-dead, not wrong-cipher
    evidence -- so they never trip the all-fail guard.
    """
    if aesgcm is None and decrypt_blob is None:
        raise TypeError("load_audit_keyring requires aesgcm or decrypt_blob")

    result = await db.execute(
        text(
            "SELECT key_epoch, audit_key_enc FROM vault_audit_key_archive "
            "WHERE quarantined_at IS NULL"
        )
    )
    rows = result.fetchall()
    keyring: dict[int, bytes] = {}
    for row in rows:
        try:
            blob = bytes(row.audit_key_enc)
            if decrypt_blob is not None:
                keyring[row.key_epoch] = await decrypt_blob(blob)
            else:
                keyring[row.key_epoch] = _dec(aesgcm, blob)
        except Exception:
            continue
    if rows and not keyring:
        raise RuntimeError(
            f"audit key archive: all {len(rows)} non-quarantined row(s) failed to "
            "decrypt under the current dek_key -- wrong cipher / dek_key, not a "
            "single dead row. Refusing to return an empty keyring (would "
            "false-break /audit/verify)."
        )
    return keyring
