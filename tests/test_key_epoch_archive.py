# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""key_epoch atomic bump + corrupt-value visibility, and audit_keyring rotation
resilience to an undecryptable (stale/foreign) archive row."""

import logging
import os

import pytest
from api.app import audit_keyring, key_epoch
from api.app.database import async_session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text


async def _set_epoch(db, value: str):
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
            "ON CONFLICT (key) DO UPDATE SET value = :v"
        ),
        {"v": value},
    )


async def _clear_epoch(db):
    await db.execute(text("DELETE FROM vault_config WHERE key = 'key_epoch'"))


# ---- key_epoch (#3 atomic bump, #4 corrupt visibility) ----


async def test_get_epoch_absent_is_zero(setup_db):
    async with async_session() as db:
        await _clear_epoch(db)
        await db.commit()
        assert await key_epoch.get_key_epoch(db) == 0


async def test_bump_from_absent_starts_at_one(setup_db):
    async with async_session() as db:
        await _clear_epoch(db)
        await db.commit()
        assert await key_epoch.bump_key_epoch(db) == 1
        await db.commit()
        assert await key_epoch.get_key_epoch(db) == 1


async def test_bump_is_monotonic(setup_db):
    async with async_session() as db:
        await _set_epoch(db, "5")
        await db.commit()
        assert await key_epoch.bump_key_epoch(db) == 6
        await db.commit()
        assert await key_epoch.get_key_epoch(db) == 6


async def test_bump_empty_value_starts_at_one(setup_db):
    async with async_session() as db:
        await _set_epoch(db, "")
        await db.commit()
        assert await key_epoch.bump_key_epoch(db) == 1
        await db.commit()


async def test_corrupt_epoch_logs_and_returns_zero(setup_db, caplog):
    async with async_session() as db:
        await _set_epoch(db, "not-a-number")
        await db.commit()
        with caplog.at_level(logging.CRITICAL, logger="rhorizon.key_epoch"):
            assert await key_epoch.get_key_epoch(db) == 0
        assert any("unparseable" in r.getMessage() for r in caplog.records)
        await _clear_epoch(db)
        await db.commit()


async def test_bump_raises_on_corrupt(setup_db):
    async with async_session() as db:
        await _set_epoch(db, "garbage")
        await db.commit()
    async with async_session() as db:
        with pytest.raises(Exception):
            await key_epoch.bump_key_epoch(db)
        await db.rollback()
    async with async_session() as db:
        await _clear_epoch(db)
        await db.commit()


# ---- audit_keyring (#2 rotation skips an undecryptable row) ----


async def test_rotate_skips_undecryptable_row(setup_db, caplog):
    old, new, foreign = (
        AESGCM(os.urandom(32)),
        AESGCM(os.urandom(32)),
        AESGCM(os.urandom(32)),
    )
    good_key, foreign_key, retiring = b"A" * 32, b"B" * 32, b"C" * 32
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.execute(
            text(
                "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
                "VALUES (1, :e)"
            ),
            {"e": audit_keyring._enc(old, good_key)},
        )
        await db.execute(
            text(
                "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
                "VALUES (2, :e)"
            ),
            {"e": audit_keyring._enc(foreign, foreign_key)},
        )
        await db.commit()

        with caplog.at_level(logging.CRITICAL, logger="rhorizon.audit_keyring"):
            await audit_keyring.rotate_audit_keyring(
                db,
                retiring_epoch=3,
                retiring_audit_key=retiring,
                old_aesgcm=old,
                new_aesgcm=new,
            )
        await db.commit()

        # No raise; loadable under the NEW dek_key.
        ring = await audit_keyring.load_audit_keyring(db, new)
        assert ring.get(1) == good_key  # good row re-wrapped old->new
        assert ring.get(3) == retiring  # retiring key archived under new
        assert 2 not in ring  # foreign row left as-is, undecryptable -> skipped
        assert any(r.args and 2 in r.args for r in caplog.records)  # alarmed by epoch

        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.commit()


async def test_rotate_quarantines_dead_row_then_stops_alarming(setup_db, caplog):
    """A4: a dead row is quarantined on first rotation (stamped + alarmed once),
    and a SECOND rotation neither re-wraps nor re-alarms it."""
    old, new, new2, foreign = (
        AESGCM(os.urandom(32)),
        AESGCM(os.urandom(32)),
        AESGCM(os.urandom(32)),
        AESGCM(os.urandom(32)),
    )
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.execute(
            text(
                "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
                "VALUES (1, :e)"
            ),
            {"e": audit_keyring._enc(old, b"A" * 32)},
        )
        await db.execute(
            text(
                "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
                "VALUES (2, :e)"
            ),
            {"e": audit_keyring._enc(foreign, b"B" * 32)},
        )
        await db.commit()

        # First rotation old->new quarantines epoch 2 (alarms once).
        with caplog.at_level(logging.CRITICAL, logger="rhorizon.audit_keyring"):
            await audit_keyring.rotate_audit_keyring(
                db,
                retiring_epoch=3,
                retiring_audit_key=b"C" * 32,
                old_aesgcm=old,
                new_aesgcm=new,
            )
        await db.commit()
        assert any(r.args and 2 in r.args for r in caplog.records)
        q = (
            await db.execute(
                text(
                    "SELECT quarantined_at FROM vault_audit_key_archive "
                    "WHERE key_epoch = 2"
                )
            )
        ).fetchone()
        assert q.quarantined_at is not None  # stamped, not deleted (evidence kept)

        # Second rotation new->new2 must skip the quarantined row: no re-alarm.
        caplog.clear()
        with caplog.at_level(logging.CRITICAL, logger="rhorizon.audit_keyring"):
            await audit_keyring.rotate_audit_keyring(
                db,
                retiring_epoch=4,
                retiring_audit_key=b"D" * 32,
                old_aesgcm=new,
                new_aesgcm=new2,
            )
        await db.commit()
        assert not any(r.args and 2 in r.args for r in caplog.records)

        ring = await audit_keyring.load_audit_keyring(db, new2)
        assert ring.get(1) == b"A" * 32  # live rows followed the dek_key forward
        assert 2 not in ring  # quarantined: excluded
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.commit()


async def test_load_raises_when_all_nonquarantined_rows_fail(setup_db):
    """A4: if EVERY non-quarantined row fails to decrypt, that is a wrong-cipher
    bug (e.g. wrong aesgcm), not one dead row -- raise instead of a silent {}
    that would false-break /audit/verify."""
    real, wrong = AESGCM(os.urandom(32)), AESGCM(os.urandom(32))
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        for ep, k in ((1, b"A" * 32), (2, b"B" * 32)):
            await db.execute(
                text(
                    "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
                    "VALUES (:ep, :e)"
                ),
                {"ep": ep, "e": audit_keyring._enc(real, k)},
            )
        await db.commit()

        # Correct cipher: loads cleanly.
        assert set(await audit_keyring.load_audit_keyring(db, real)) == {1, 2}
        # Wrong cipher: every row fails -> raise (not silent empty).
        with pytest.raises(RuntimeError):
            await audit_keyring.load_audit_keyring(db, wrong)

        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.commit()


async def test_load_supports_async_decrypt_blob_hook(setup_db):
    """Followers call /audit/verify through vault.aesgcm_decrypt RPC, not the
    master-only vault.aesgcm object. The loader must accept that async decrypt
    shape without weakening the all-fail guard."""
    real = AESGCM(os.urandom(32))

    async def decrypt_blob(blob: bytes) -> bytes:
        return real.decrypt(blob[:12], blob[12:], None)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.execute(
            text(
                "INSERT INTO vault_audit_key_archive (key_epoch, audit_key_enc) "
                "VALUES (7, :e)"
            ),
            {"e": audit_keyring._enc(real, b"G" * 32)},
        )
        await db.commit()

        assert await audit_keyring.load_audit_keyring(
            db, decrypt_blob=decrypt_blob
        ) == {7: b"G" * 32}

        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.commit()


async def test_load_empty_archive_returns_empty(setup_db):
    """An empty archive is fresh, not wrong-cipher -- returns {}, never raises."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.commit()
        assert await audit_keyring.load_audit_keyring(db, AESGCM(os.urandom(32))) == {}
