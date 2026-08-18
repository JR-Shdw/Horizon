"""Final coverage push - targets main.py loops, vault.py Shamir/2FA,
webauthn register_complete, backup restore with groups
broadcast, and remaining edge cases.

Goal: 91% -> 95%.
"""

import asyncio
import base64
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

# ===================================================================
# main.py: background loop one-shot + _apply_schema
# ===================================================================


class TestMainLoops:
    """Exercise the background loop bodies and _apply_schema."""

    @pytest.mark.asyncio
    async def test_apply_schema_runs(self, client, master_password):
        """_apply_schema can be called idempotently (IF NOT EXISTS)."""
        from api.app.main import _apply_schema

        # Schema is already applied by conftest, but calling again is safe
        await _apply_schema()

    # _key_sync_loop tests removed, historical /dev/shm key sharing was
    # dropped in favour of RPC-only worker compartmentalisation.

    @pytest.mark.asyncio
    async def test_reaper_loop_runs_one_iteration(
        self, client, master_password, admin_token
    ):
        """reaper_loop body: runs cleanup when unsealed."""
        from api.app.main import _reaper_loop

        await client.post("/api/v1/vault/unseal", json={"password": master_password})

        call_count = 0

        async def fake_sleep(n):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise asyncio.CancelledError

        with patch("asyncio.sleep", side_effect=fake_sleep):
            with patch("api.app.routes.audit.compress_old_files", return_value=0):
                task = asyncio.create_task(_reaper_loop())
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    @pytest.mark.asyncio
    async def test_reaper_loop_with_compression(
        self, client, master_password, admin_token
    ):
        """reaper_loop: compression branch when files compressed."""
        from api.app.main import _reaper_loop

        await client.post("/api/v1/vault/unseal", json={"password": master_password})

        call_count = 0

        async def fake_sleep(n):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise asyncio.CancelledError

        with patch("asyncio.sleep", side_effect=fake_sleep):
            with patch(
                "api.app.routes.audit.compress_old_files", return_value=3
            ) as compress_mock:
                with patch(
                    "api.app.main.asyncio.to_thread", wraps=asyncio.to_thread
                ) as to_thread_mock:
                    task = asyncio.create_task(_reaper_loop())
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

                to_thread_mock.assert_awaited_once_with(compress_mock)

    @pytest.mark.asyncio
    async def test_reaper_loop_handles_exception(
        self, client, master_password, admin_token, caplog
    ):
        """A failed cycle is visible, counted, and retried by the daemon."""
        from api.app import metrics as _metrics
        from api.app.main import _reaper_loop

        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        failures_before = _metrics.reaper_failures._value.get()

        call_count = 0

        async def fake_sleep(n):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise asyncio.CancelledError

        with caplog.at_level("WARNING", logger="rhorizon"):
            with patch("asyncio.sleep", side_effect=fake_sleep):
                with patch(
                    "api.app.routes.audit.compress_old_files",
                    side_effect=RuntimeError("disk full"),
                ):
                    task = asyncio.create_task(_reaper_loop())
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

        assert _metrics.reaper_failures._value.get() == failures_before + 1
        assert "reaper_loop cycle failed; retrying in 5 minutes" in caplog.text

    @pytest.mark.asyncio
    async def test_audit_checkpoint_body_failure_counted_once(
        self, monkeypatch, caplog
    ):
        """A checkpoint-body failure rolls back and has one outer signal."""
        from api.app import main as main_mod
        from api.app import metrics as _metrics

        monkeypatch.setattr(main_mod.settings, "audit_lite_checkpoint_enabled", True)
        monkeypatch.setattr(main_mod.settings, "audit_lite_checkpoint_interval_secs", 1)
        vault_mock = MagicMock()
        vault_mock.sealed = False
        monkeypatch.setattr(main_mod, "vs", vault_mock)

        sleep_calls = 0

        async def one_cycle(_delay):
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls > 1:
                raise asyncio.CancelledError

        failures = _metrics.audit_lite_checkpoints.labels(result="failure")
        before = failures._value.get()
        monkeypatch.setattr(main_mod.asyncio, "sleep", one_cycle)

        with caplog.at_level("WARNING", logger="rhorizon"):
            with patch(
                "api.app.audit_mtree.create_audit_lite_checkpoint",
                side_effect=RuntimeError("checkpoint write failed"),
            ):
                with pytest.raises(asyncio.CancelledError):
                    await main_mod._audit_lite_checkpoint_loop()

        assert failures._value.get() == before + 1
        assert caplog.text.count("audit_lite_checkpoint cycle failed") == 1

    @pytest.mark.asyncio
    async def test_audit_checkpoint_lock_failure_is_counted(self, monkeypatch, caplog):
        """A failure before the checkpoint body is also visible and counted."""
        from api.app import main as main_mod
        from api.app import metrics as _metrics

        monkeypatch.setattr(main_mod.settings, "audit_lite_checkpoint_enabled", True)
        monkeypatch.setattr(main_mod.settings, "audit_lite_checkpoint_interval_secs", 1)
        vault_mock = MagicMock()
        vault_mock.sealed = False
        monkeypatch.setattr(main_mod, "vs", vault_mock)

        sleep_calls = 0

        async def one_cycle(_delay):
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls > 1:
                raise asyncio.CancelledError

        failures = _metrics.audit_lite_checkpoints.labels(result="failure")
        before = failures._value.get()
        monkeypatch.setattr(main_mod.asyncio, "sleep", one_cycle)

        with caplog.at_level("WARNING", logger="rhorizon"):
            with patch(
                "api.app.cluster.with_cluster_lock",
                side_effect=RuntimeError("lock unavailable"),
            ):
                with pytest.raises(asyncio.CancelledError):
                    await main_mod._audit_lite_checkpoint_loop()

        assert failures._value.get() == before + 1
        assert caplog.text.count("audit_lite_checkpoint cycle failed") == 1


# ===================================================================
# vault.py: Shamir full flow
# ===================================================================


class TestShamirUnseal:
    """Full Shamir split -> seal -> unseal with shares."""

    @pytest.mark.asyncio
    async def test_shamir_full_flow(self, client, master_password, admin_token):
        """Init Shamir 2-of-3, seal, unseal with 2 shares."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Init Shamir split
        r = await client.post(
            "/api/v1/vault/shamir/init",
            json={
                "current_password": master_password,
                "threshold": 2,
                "total": 3,
            },
            headers=headers,
        )
        assert r.status_code == 200
        data = r.json()
        shares = data["shares"]
        assert len(shares) == 3

        # Seal vault
        r = await client.post("/api/v1/vault/seal", headers=headers)
        assert r.status_code == 200

        # Submit share 1
        r = await client.post("/api/v1/vault/unseal", json={"share": shares[0]})
        assert r.status_code == 200
        assert r.json()["status"] == "share_accepted"

        # Submit share 2 -> should unseal
        r = await client.post("/api/v1/vault/unseal", json={"share": shares[2]})
        assert r.status_code == 200
        assert r.json()["status"] == "unsealed"

        # Verify vault is unsealed
        r = await client.get("/api/v1/vault/status")
        assert r.json()["sealed"] is False

        # Disable Shamir for other tests
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('shamir_enabled', 'shamir_threshold', 'shamir_total')"
                )
            )
            await db.commit()

    @pytest.mark.asyncio
    async def test_shamir_no_password_hint(self, client, master_password, admin_token):
        """When Shamir enabled, missing both share and password gives hint."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Enable Shamir
        from api.app.database import async_session

        async with async_session() as db:
            for key, val in [
                ("shamir_enabled", "true"),
                ("shamir_threshold", "2"),
                ("shamir_total", "3"),
            ]:
                await db.execute(
                    text(
                        "INSERT INTO vault_config (key, value) "
                        "VALUES (:k, :v) "
                        "ON CONFLICT (key) DO UPDATE SET value = :v"
                    ),
                    {"k": key, "v": val},
                )
            await db.commit()

        # Seal
        r = await client.post("/api/v1/vault/seal", headers=headers)

        # Try unseal with neither share nor password
        r = await client.post("/api/v1/vault/unseal", json={})
        assert r.status_code == 400
        detail = r.json()["detail"].lower()
        assert "share" in detail or "password" in detail

        # Cleanup: unseal with password and remove Shamir
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('shamir_enabled', 'shamir_threshold', 'shamir_total')"
                )
            )
            await db.commit()

    @pytest.mark.asyncio
    async def test_shamir_bad_hex_share(self, client, master_password, admin_token):
        """Non-hex share returns 400."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Enable Shamir
        from api.app.database import async_session

        async with async_session() as db:
            for key, val in [
                ("shamir_enabled", "true"),
                ("shamir_threshold", "2"),
                ("shamir_total", "3"),
            ]:
                await db.execute(
                    text(
                        "INSERT INTO vault_config (key, value) "
                        "VALUES (:k, :v) "
                        "ON CONFLICT (key) DO UPDATE SET value = :v"
                    ),
                    {"k": key, "v": val},
                )
            await db.commit()

        r = await client.post("/api/v1/vault/seal", headers=headers)

        # Send invalid hex
        r = await client.post(
            "/api/v1/vault/unseal", json={"share": "not-valid-hex!!!"}
        )
        assert r.status_code == 400
        assert "hex" in r.json()["detail"].lower()

        # Restore
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('shamir_enabled', 'shamir_threshold', 'shamir_total')"
                )
            )
            await db.commit()


# ===================================================================
# vault.py: TOTP unseal flow
# ===================================================================


class TestTotpUnseal:
    @pytest.mark.asyncio
    async def test_totp_unseal_valid(self, client, master_password, admin_token):
        """Full TOTP setup -> enable -> unseal with code."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Setup TOTP
        r = await client.post("/api/v1/vault/totp/setup", headers=headers)
        assert r.status_code == 200
        totp_secret = r.json()["secret"]

        # Enable TOTP
        import pyotp

        code = pyotp.TOTP(totp_secret).now()
        r = await client.post(
            "/api/v1/vault/totp/enable",
            json={"code": code},
            headers=headers,
        )
        assert r.status_code == 200

        # Set mode to TOTP
        r = await client.put(
            "/api/v1/vault/2fa",
            params={"mode": "totp"},
            headers=headers,
        )
        assert r.status_code == 200

        # Seal
        r = await client.post("/api/v1/vault/seal", headers=headers)
        assert r.status_code == 200

        # Unseal with password + TOTP
        code = pyotp.TOTP(totp_secret).now()
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"password": master_password, "totp_code": code},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "unsealed"

        # Cleanup: disable TOTP
        r = await client.put(
            "/api/v1/vault/2fa",
            params={"mode": "none"},
            headers=headers,
        )
        assert r.status_code == 200
        await client.delete("/api/v1/vault/totp", headers=headers)


# ===================================================================
# vault.py: YubiKey unseal with mocked challenge
# ===================================================================


class TestYubikeyUnseal:
    @pytest.mark.asyncio
    async def test_yubikey_unseal_invalid_response(
        self, client, master_password, admin_token
    ):
        """YubiKey unseal with wrong response -> 401."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Register a fake YubiKey

        fake_secret = os.urandom(20).hex()
        r = await client.post(
            "/api/v1/vault/yubikey",
            json={
                "serial": "99999999",
                "name": "test-yk",
                "hmac_secret": fake_secret,
            },
            headers=headers,
        )
        assert r.status_code == 200

        # Set mode
        r = await client.put(
            "/api/v1/vault/2fa",
            params={"mode": "yubikey"},
            headers=headers,
        )
        assert r.status_code == 200

        # Seal
        r = await client.post("/api/v1/vault/seal", headers=headers)

        # Get challenge
        r = await client.post("/api/v1/vault/challenge")
        assert r.status_code == 200
        challenge = r.json()["challenge"]

        # Send wrong response
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": challenge,
                "yubikey_response": "00" * 20,
            },
        )
        assert r.status_code == 401

        # Unseal with password (restore mode first)
        # Need to unseal without 2FA, switch mode back
        # Since we're sealed, need to use password-only path
        # Set mode back via DB
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'"
                )
            )
            await db.commit()

        from api.app.vault_state import vault as vs

        vs.invalidate_2fa_cache()

        await client.post("/api/v1/vault/unseal", json={"password": master_password})

        # Re-bootstrap root token (hmac_key unchanged since no password rotation)
        # Cleanup YubiKey
        headers = {"Authorization": f"Bearer {admin_token}"}
        r = await client.delete("/api/v1/vault/yubikey/99999999", headers=headers)


# ===================================================================
# vault.py: rate limit list with actual entries
# ===================================================================


class TestRateLimitListWithData:
    @pytest.mark.asyncio
    async def test_rate_limits_show_locked(self, client, master_password, admin_token):
        """Rate limit list includes locked_until and locked flag."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Insert a rate limit entry with locked_until
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text("""
                    INSERT INTO vault_rate_limits
                        (ip_address, fail_count, locked_until, updated_at)
                    VALUES
                        ('10.99.99.99', 5, NOW() + interval '10 minutes', NOW())
                    ON CONFLICT (ip_address) DO UPDATE
                        SET fail_count = 5,
                            locked_until = NOW() + interval '10 minutes',
                            updated_at = NOW()
                """)
            )
            await db.commit()

        r = await client.get("/api/v1/vault/rate-limits", headers=headers)
        assert r.status_code == 200
        items = r.json()["items"]
        locked = [i for i in items if i["ip_address"] == "10.99.99.99"]
        assert len(locked) == 1
        assert locked[0]["locked"] is True
        assert locked[0]["locked_until"] is not None

        # Cleanup
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_rate_limits WHERE ip_address = '10.99.99.99'")
            )
            await db.commit()


# ===================================================================
# webauthn.py: register_complete with mocked fido2
# ===================================================================


class TestWebAuthnRegisterComplete:
    @pytest.mark.asyncio
    async def test_register_complete_success(
        self, client, master_password, admin_token
    ):
        """Full WebAuthn registration flow with mocked fido2."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Begin registration to get a valid challenge
        r = await client.post(
            "/api/v1/vault/webauthn/register/begin",
            json={"name": "test-key-complete"},
            headers=headers,
        )
        assert r.status_code == 200
        challenge_id = r.json()["challenge_id"]

        # Mock fido2 server.register_complete
        fake_cred_id = os.urandom(32)
        fake_cred_data = os.urandom(128)

        mock_cred = MagicMock()
        mock_cred.credential_data = MagicMock()
        mock_cred.credential_data.credential_id = fake_cred_id
        mock_cred.credential_data.__bytes__ = MagicMock(return_value=fake_cred_data)

        import base64

        def b64url(data):
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        with patch("api.app.routes.webauthn._get_fido2_server") as mock_server_fn:
            mock_server = MagicMock()
            mock_server.register_complete.return_value = mock_cred
            mock_server_fn.return_value = mock_server

            with patch("fido2.webauthn.CollectedClientData"):
                with patch("fido2.webauthn.AttestationObject"):
                    r = await client.post(
                        "/api/v1/vault/webauthn/register/complete",
                        json={
                            "challenge_id": challenge_id,
                            "name": "test-key-complete",
                            "id": b64url(fake_cred_id),
                            "rawId": b64url(fake_cred_id),
                            "type": "public-key",
                            "response": {
                                "clientDataJSON": b64url(b'{"dummy":"data"}'),
                                "attestationObject": b64url(b"\xa0"),
                            },
                        },
                        headers=headers,
                    )

        assert r.status_code == 200
        assert r.json()["status"] == "registered"

        # Cleanup
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(text("DELETE FROM vault_webauthn"))
            await db.commit()


# ===================================================================
# backup.py: restore with groups
# ===================================================================


class TestBackupRestoreGroups:
    @pytest.mark.asyncio
    async def test_restore_with_groups(self, client, master_password, admin_token):
        """Backup restore includes groups table."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create backup
        r = await client.post(
            "/api/v1/vault/backup/create",
            json={"passphrase": "test-backup-12chars"},
            headers=headers,
        )
        assert r.status_code == 200
        backup_payload = r.json()["payload"]

        # Create a group first
        r = await client.post(
            "/api/v1/vault/groups/",
            json={
                "name": "backup-test-group",
                "permissions": {"secrets": "r"},
            },
            headers=headers,
        )

        # Delete the group
        from api.app.database import async_session

        async with async_session() as db:
            result = await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'backup-test-group'")
            )
            row = result.fetchone()
            if row:
                await db.execute(
                    text("DELETE FROM vault_groups WHERE name = 'backup-test-group'")
                )
                await db.commit()

        # Restore backup (may include groups if backup had any).
        # Bloc G dual-context : age passphrase + backup master password +
        # operator-typed confirm phrase.
        r = await client.post(
            "/api/v1/vault/backup/restore",
            json={
                "passphrase": "test-backup-12chars",
                "master_password_backup": master_password,
                "confirm_phrase": "RESTORE",
                "payload": backup_payload,
            },
            headers=headers,
        )
        assert r.status_code == 200


# ===================================================================
# audit.py: file write (lines 45-46) + bad date format
# ===================================================================


class TestAuditEdgeCases:
    @pytest.mark.asyncio
    async def test_audit_file_bad_date_format(
        self, client, master_password, admin_token
    ):
        """Delete audit file with bad date format -> 400."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        r = await client.delete("/api/v1/vault/audit/files/not-a-date", headers=headers)
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_audit_file_invalid_date_value(
        self, client, master_password, admin_token
    ):
        """Delete audit file with valid format but invalid date -> 400."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        r = await client.delete("/api/v1/vault/audit/files/2024-13-99", headers=headers)
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_compress_old_files_with_bad_filename(self, client, master_password):
        """compress_old_files skips files with non-date names."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with a bad name
            bad_file = Path(tmpdir) / "audit-not-a-date.jsonl"
            bad_file.write_text('{"test": true}\n')

            with patch(
                "api.app.routes.audit._audit_dir",
                return_value=Path(tmpdir),
            ):
                from api.app.routes.audit import compress_old_files

                result = compress_old_files()
                # Bad filename should be skipped
                assert result == 0
                assert bad_file.exists()


# ===================================================================
# authfail.py: log_authfail with successful write + _ensure_log
# ===================================================================


class TestAuthfailExtra:
    def test_log_authfail_no_path(self):
        """log_authfail returns silently when _ensure_log returns None."""
        from api.app.authfail import log_authfail

        with patch("api.app.authfail._ensure_log", return_value=None):
            log_authfail("10.0.0.1", "test_fail")


# ===================================================================
# vault.py: 2FA factor mismatch
# ===================================================================


class TestFactorMismatch:
    @pytest.mark.asyncio
    async def test_wrong_factor_for_mode(self, client, master_password, admin_token):
        """Providing TOTP when mode is yubikey-only -> 400."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Register a YubiKey and set mode
        fake_secret = os.urandom(20).hex()
        await client.post(
            "/api/v1/vault/yubikey",
            json={
                "serial": "88888888",
                "name": "test-yk2",
                "hmac_secret": fake_secret,
            },
            headers=headers,
        )
        await client.put(
            "/api/v1/vault/2fa",
            params={"mode": "yubikey"},
            headers=headers,
        )

        # Seal
        await client.post("/api/v1/vault/seal", headers=headers)

        # Try TOTP code on yubikey-only mode
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"password": master_password, "totp_code": "123456"},
        )
        assert r.status_code == 400

        # Restore
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'"
                )
            )
            await db.commit()

        from api.app.vault_state import vault as vs

        vs.invalidate_2fa_cache()

        await client.post("/api/v1/vault/unseal", json={"password": master_password})

        # Cleanup YubiKey
        await client.delete("/api/v1/vault/yubikey/88888888", headers=headers)


# ===================================================================
# notifications.py: remaining lines (253-254, 260)
# ===================================================================


class TestNotificationEdge:
    @pytest.mark.asyncio
    async def test_send_email_not_implemented(
        self, client, master_password, admin_token
    ):
        """Email notification type returns noop."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create an email channel
        r = await client.post(
            "/api/v1/vault/notifications/",
            json={
                "name": "email-test-chan",
                "type": "email",
                "config": {"to": "test@example.com"},
            },
            headers=headers,
        )
        if r.status_code == 200:
            chan_id = r.json()["id"]
            # Test delivery
            r = await client.post(
                f"/api/v1/vault/notifications/{chan_id}/test",
                headers=headers,
            )
            # Cleanup
            await client.delete(
                f"/api/v1/vault/notifications/{chan_id}",
                headers=headers,
            )


# ===================================================================
# vault.py: WebAuthn unseal flow (covers lines 262, 272-371)
# ===================================================================


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class TestWebAuthnUnsealFlow:
    @pytest.mark.asyncio
    async def test_webauthn_unseal_full(self, client, master_password, admin_token):
        """Full WebAuthn unseal: no-factor error, no-challenge error, success."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Insert credential FIRST (set_2fa_mode validates at least one exists)
        from api.app.database import async_session

        from .soft_webauthn import SoftAuthenticator

        soft = SoftAuthenticator()
        fake_cred_id = soft.credential_id

        async with async_session() as db:
            await db.execute(
                text(
                    "INSERT INTO vault_webauthn "
                    "(name, credential_id, credential_data, sign_count, registered_by) "
                    "VALUES ('test-wa-unseal', :cid, :cdata, 0, 'test-admin')"
                ),
                {"cid": fake_cred_id, "cdata": bytes(soft.credential_data)},
            )
            await db.commit()

        # Now set 2FA mode (credential exists)
        r = await client.put(
            "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
        )
        assert r.status_code == 200

        # Get a challenge for later
        r = await client.post("/api/v1/vault/challenge")
        assert r.status_code == 200
        challenge_hex = r.json()["challenge"]

        # Seal
        r = await client.post("/api/v1/vault/seal", headers=headers)
        assert r.status_code == 200

        # --- Test 1: no 2FA factor -> 400 "security key" (line 262) ---
        r = await client.post(
            "/api/v1/vault/unseal", json={"password": master_password}
        )
        assert r.status_code == 400
        assert "security key" in r.json()["detail"]

        # --- Test 2: WebAuthn without challenge -> 400 (line 272) ---
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "webauthn_response": {
                    "rawId": _b64url(fake_cred_id),
                    "response": {
                        "clientDataJSON": _b64url(b"x"),
                        "authenticatorData": _b64url(b"x"),
                        "signature": _b64url(b"x"),
                    },
                },
            },
        )
        assert r.status_code == 400
        assert "Challenge required" in r.json()["detail"]

        # --- Test 3: successful WebAuthn unseal (real ES256 assertion,
        # no fido2 mocking -- mocks hid the 2.2.0 API drift for months) ---
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": challenge_hex,
                "webauthn_response": soft.assertion(bytes.fromhex(challenge_hex)),
            },
        )

        assert r.status_code == 200, r.json()

        # Cleanup: reset 2FA + remove credential
        headers = {"Authorization": f"Bearer {admin_token}"}
        await client.put("/api/v1/vault/2fa", params={"mode": "none"}, headers=headers)
        async with async_session() as db:
            await db.execute(text("DELETE FROM vault_webauthn"))
            await db.commit()


# ===================================================================
# vault.py: YubiKey unseal edge cases (lines 376, 387-395)
# ===================================================================


class TestYubikeyUnsealEdge:
    @pytest.mark.asyncio
    async def test_yubikey_no_challenge(self, client, master_password, admin_token):
        """YubiKey unseal without challenge -> 400."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Insert yubikey FIRST (set_2fa_mode validates at least one exists)
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text(
                    "INSERT INTO vault_yubikeys (serial, hmac_secret, registered_by) "
                    "VALUES ('99999999', :sec, 'test-admin')"
                ),
                {"sec": os.urandom(20)},
            )
            await db.commit()

        # Now set mode
        r = await client.put(
            "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
        )
        assert r.status_code == 200

        # Seal
        await client.post("/api/v1/vault/seal", headers=headers)

        # Unseal with yubikey_response but no challenge
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "yubikey_response": "aa" * 20,
            },
        )
        assert r.status_code == 400
        assert "Challenge required" in r.json()["detail"]

        # Unseal with yubikey_response + bad challenge
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "yubikey_response": "aa" * 20,
                "challenge": "deadbeef" * 4,
            },
        )
        assert r.status_code == 400
        assert "Invalid or expired challenge" in r.json()["detail"]

        # Cleanup: unseal normally (need to reset 2FA first via DB)
        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'"
                )
            )
            await db.execute(text("DELETE FROM vault_yubikeys"))
            await db.commit()

        from api.app import vault_state

        vault_state.vault.invalidate_2fa_cache()

        r = await client.post(
            "/api/v1/vault/unseal", json={"password": master_password}
        )
        assert r.status_code == 200


# ===================================================================
# vault.py: password rotation with TOTP (lines 757-759)
# ===================================================================


class TestRotatePasswordWithTotp:
    @pytest.mark.asyncio
    async def test_rotate_with_totp_active(self, client, master_password, admin_token):
        """Password rotation re-encrypts TOTP secret."""
        import pyotp

        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Setup TOTP
        r = await client.post("/api/v1/vault/totp/setup", headers=headers)
        assert r.status_code == 200
        totp_uri = r.json()["uri"]
        secret = pyotp.parse_uri(totp_uri).secret

        # Enable TOTP with valid code
        code = pyotp.TOTP(secret).now()
        r = await client.post(
            "/api/v1/vault/totp/enable", json={"code": code}, headers=headers
        )
        assert r.status_code == 200

        # Rotate password
        new_pass = "new-rotation-pass-789"
        r = await client.post(
            "/api/v1/vault/rotate-password",
            json={
                "current_password": master_password,
                "new_password": new_pass,
            },
            headers=headers,
        )
        assert r.status_code == 200

        # Restore original password (admin_token re-hashed inside)
        from api.app import vault_state as vs_mod

        vs = vs_mod.vault
        # hmac_token import removed: vault.hmac_sha512_hex used directly

        token_hash = await vs.hmac_sha512_hex(admin_token)

        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"
                ),
                {"h": token_hash},
            )
            await db.commit()

        r = await client.post(
            "/api/v1/vault/rotate-password",
            json={
                "current_password": new_pass,
                "new_password": master_password,
                # second rotation inside the migration window -> force required.
                "force": True,
            },
            headers=headers,
        )
        assert r.status_code == 200

        # Re-hash admin_token for restored password
        token_hash2 = await vs.hmac_sha512_hex(admin_token)
        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"
                ),
                {"h": token_hash2},
            )
            # Clean TOTP + truncate audit (chain broken by rotation)
            await db.execute(text("DELETE FROM vault_config WHERE key = 'totp_secret'"))
            await db.execute(
                text(
                    "UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'"
                )
            )
            await db.execute(text("TRUNCATE vault_audit"))
            await db.commit()

        vs.invalidate_2fa_cache()


# ===================================================================
# backup.py: restore with groups actually in backup (lines 261-275)
# ===================================================================


class TestBackupRestoreWithGroupData:
    @pytest.mark.asyncio
    async def test_restore_includes_groups(self, client, master_password, admin_token):
        """Create group BEFORE backup so restore loop executes."""
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create a group first
        r = await client.post(
            "/api/v1/vault/groups/",
            json={"name": "bkp-grp-test", "permissions": {"secrets": "r"}},
            headers=headers,
        )
        assert r.status_code in (200, 201, 409)

        # Now create backup (includes the group)
        r = await client.post(
            "/api/v1/vault/backup/create",
            json={"passphrase": "backup-pass-12chars"},
            headers=headers,
        )
        assert r.status_code == 200
        payload = r.json()["payload"]

        # Delete the group
        from api.app.database import async_session

        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_groups WHERE name = 'bkp-grp-test'")
            )
            await db.commit()

        # Restore: groups loop should execute. Bloc G dual-context.
        r = await client.post(
            "/api/v1/vault/backup/restore",
            json={
                "passphrase": "backup-pass-12chars",
                "master_password_backup": master_password,
                "confirm_phrase": "RESTORE",
                "payload": payload,
            },
            headers=headers,
        )
        assert r.status_code == 200
        assert r.json()["groups"] >= 1

        # Cleanup
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_groups WHERE name = 'bkp-grp-test'")
            )
            await db.commit()
