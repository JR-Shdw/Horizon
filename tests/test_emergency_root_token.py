# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Integration tests for tools/emergency_root_token.py (break-glass mint).

Runs the tool's main() in-process against the same test PG as the app
fixtures, with getpass monkeypatched to feed the master password and
factor inputs. The admin_token fixture bootstraps argon2_salt +
master_check and leaves an active admin row, so --force is required for
every mint.
"""

import hashlib
import hmac as _hmac
import importlib.util
import os
import secrets as _secrets
import sys
from pathlib import Path
from types import SimpleNamespace

import pyotp
import pytest
import pytest_asyncio
from api.app.crypto import derive_keys, derive_master_key, shamir_split
from api.app.database import async_session
from sqlalchemy import text

_TOOL_PATH = Path(__file__).parent.parent / "tools" / "emergency_root_token.py"

_spec = importlib.util.spec_from_file_location("emergency_root_token", _TOOL_PATH)
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


async def _set_config(key: str, value: str) -> None:
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES (:k, :v) "
                "ON CONFLICT (key) DO UPDATE SET value = :v"
            ),
            {"k": key, "v": value},
        )
        await db.commit()


async def _get_config(key: str) -> str | None:
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :k"), {"k": key}
            )
        ).first()
        return row[0] if row else None


async def _del_config(*keys: str) -> None:
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_config WHERE key = ANY(:ks)"), {"ks": list(keys)}
        )
        await db.commit()


async def _recovery_token_count() -> int:
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT COUNT(*) FROM vault_tokens "
                    "WHERE created_by = 'emergency-recovery'"
                )
            )
        ).first()
        return row[0]


@pytest_asyncio.fixture
async def break_glass():
    """Arm break_glass_2fa for one test, disarm + clean factor state after."""

    async def _arm(mode: str) -> None:
        await _set_config("break_glass_2fa", mode)

    yield _arm
    await _del_config("break_glass_2fa", "shamir_enabled", "shamir_threshold")
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_webauthn"))
        await db.commit()


def _feed(monkeypatch, inputs: list[str]) -> None:
    """Point the tool's DSN at the test PG and script its getpass prompts."""
    monkeypatch.setenv("RHORIZON_DB_URL", os.environ["RHORIZON_DATABASE_URL"])
    it = iter(inputs)
    monkeypatch.setattr(tool.getpass, "getpass", lambda prompt="": next(it))


async def test_refuses_when_active_admin_and_no_force(admin_token, monkeypatch):
    _feed(monkeypatch, [])  # refused before the password prompt
    assert await tool.main([]) == 3


async def test_force_mints_working_admin_token(
    client, master_password, admin_token, monkeypatch, capsys
):
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password])
    assert await tool.main(["--force"]) == 0
    assert await _recovery_token_count() == before + 1

    # the printed plaintext authenticates as admin against the live app
    minted = capsys.readouterr().out.strip()
    assert minted.startswith("rh_")
    r = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {minted}"},
    )
    assert r.status_code == 200
    assert r.json()["permissions"] == {"admin": "rw"}

    # critical breadcrumb lands in vault_audit, unsigned by design
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT actor, detail, signature FROM vault_audit "
                    "WHERE action = 'recovery-token-mint' ORDER BY id DESC LIMIT 1"
                )
            )
        ).first()
    assert row is not None
    assert row.actor == "emergency-recovery"
    assert row.signature == "unsigned"
    assert row.detail["_critical"] is True
    assert row.detail["second_factor"] == "none"


async def test_wrong_password_mints_nothing(admin_token, monkeypatch):
    before = await _recovery_token_count()
    _feed(monkeypatch, ["definitely-not-the-master-password"])
    assert await tool.main(["--force"]) == 4
    assert await _recovery_token_count() == before


async def test_unknown_factor_fails_closed(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("carrier-pigeon")
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password])
    assert await tool.main(["--force"]) == 5
    assert await _recovery_token_count() == before


async def test_totp_env_seed_accepts_valid_code(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("totp")
    seed = pyotp.random_base32()
    monkeypatch.setenv("RH_BREAK_GLASS_TOTP_SECRET", seed)
    _feed(monkeypatch, [master_password, pyotp.TOTP(seed).now()])
    assert await tool.main(["--force"]) == 0

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action = 'recovery-token-mint' ORDER BY id DESC LIMIT 1"
                )
            )
        ).first()
    assert row.detail["second_factor"] == "totp"


async def test_totp_rejects_bad_code(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("totp")
    seed = pyotp.random_base32()
    monkeypatch.setenv("RH_BREAK_GLASS_TOTP_SECRET", seed)
    good = pyotp.TOTP(seed).now()
    bad = "000000" if good != "000000" else "111111"
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password, bad])
    with pytest.raises(SystemExit) as exc:
        await tool.main(["--force"])
    assert exc.value.code == 6
    assert await _recovery_token_count() == before


async def test_yubikey_env_secret_accepts_valid_response(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("yubikey")
    secret = os.urandom(20)
    monkeypatch.setenv("RH_BREAK_GLASS_YUBIKEY_SECRET", secret.hex())
    # pin the challenge so the test can compute the operator-side response;
    # keep token_hex real (used for the recovery token name suffix)
    challenge = b"\x42" * 32
    monkeypatch.setattr(
        tool,
        "secrets",
        SimpleNamespace(
            token_bytes=lambda n: challenge[:n], token_hex=_secrets.token_hex
        ),
    )
    response = _hmac.new(secret, challenge, hashlib.sha1).hexdigest()
    _feed(monkeypatch, [master_password, response])
    assert await tool.main(["--force"]) == 0


async def test_yubikey_rejects_bad_response(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("yubikey")
    monkeypatch.setenv("RH_BREAK_GLASS_YUBIKEY_SECRET", os.urandom(20).hex())
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password, "00" * 20])
    with pytest.raises(SystemExit) as exc:
        await tool.main(["--force"])
    assert exc.value.code == 6
    assert await _recovery_token_count() == before


async def test_shamir_quorum_accepts_matching_shares(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("shamir")
    await _set_config("shamir_enabled", "true")
    await _set_config("shamir_threshold", "2")

    # rebuild the 160B bundle the vault Shamir protects; only [:32]
    # (hmac_key) is checked against the password-derived key
    salt = bytes.fromhex(await _get_config("argon2_salt"))
    keys = derive_keys(derive_master_key(master_password.encode(), salt))
    material = (
        keys["hmac_key"]
        + keys["dek_key"]
        + keys["audit_key"]
        + keys["ha_wrap_key"]
        + keys["pki_wrap_key"]
    )
    shares = shamir_split(material, threshold=2, total=3)
    _feed(monkeypatch, [master_password, shares[0].hex(), shares[2].hex()])
    assert await tool.main(["--force"]) == 0


async def test_shamir_rejects_foreign_shares(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("shamir")
    await _set_config("shamir_enabled", "true")
    await _set_config("shamir_threshold", "2")
    shares = shamir_split(os.urandom(160), threshold=2, total=3)
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password, shares[0].hex(), shares[1].hex()])
    with pytest.raises(SystemExit) as exc:
        await tool.main(["--force"])
    assert exc.value.code == 6
    assert await _recovery_token_count() == before


async def test_fido2_fails_closed_without_credential(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("fido2")
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password])
    with pytest.raises(SystemExit) as exc:
        await tool.main(["--force"])
    assert exc.value.code == 5
    assert await _recovery_token_count() == before


def _alias_app_modules(monkeypatch) -> None:
    """standalone the tool imports app.config / app.routes.webauthn itself;
    in-process those would re-execute as a duplicate of the already-loaded
    api.app tree and collide on the Prometheus registry. Alias them so the
    tool's imports resolve to the live modules without re-execution."""
    for name in ("config", "routes", "routes.webauthn"):
        monkeypatch.setitem(sys.modules, f"app.{name}", sys.modules[f"api.app.{name}"])


async def test_fido2_fails_closed_without_device(
    master_password, admin_token, break_glass, monkeypatch
):
    await break_glass("fido2")
    _alias_app_modules(monkeypatch)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_webauthn "
                "(credential_id, credential_data, sign_count, registered_by) "
                "VALUES (:cid, :cdata, 0, 'test')"
            ),
            {"cid": os.urandom(16), "cdata": os.urandom(64)},
        )
        await db.commit()
    monkeypatch.setattr(
        "fido2.hid.CtapHidDevice.list_devices", staticmethod(lambda: [])
    )
    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password])
    with pytest.raises(SystemExit) as exc:
        await tool.main(["--force"])
    assert exc.value.code == 6
    assert await _recovery_token_count() == before


async def test_fido2_accepts_soft_authenticator_assertion(
    master_password, admin_token, break_glass, monkeypatch
):
    """Full break-glass fido2 path minus the USB transport: a fake HID
    client returns a REAL ES256 assertion over the tool's challenge, and
    the app Fido2Server verifies it cryptographically (no verify mocking).
    """
    from fido2.webauthn import AuthenticationResponse

    from .soft_webauthn import SoftAuthenticator

    await break_glass("fido2")
    _alias_app_modules(monkeypatch)

    soft = SoftAuthenticator()
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_webauthn "
                "(credential_id, credential_data, sign_count, registered_by) "
                "VALUES (:cid, :cdata, 0, 'test')"
            ),
            {"cid": soft.credential_id, "cdata": bytes(soft.credential_data)},
        )
        await db.commit()

    class _FakeAssertions:
        def __init__(self, options):
            self._options = options

        def get_response(self, index):
            return AuthenticationResponse.from_dict(
                soft.assertion(bytes(self._options.challenge))
            )

    class _FakeFido2Client:
        def __init__(self, device, collector, user_interaction=None):
            pass

        def get_assertion(self, options):
            return _FakeAssertions(options)

    monkeypatch.setattr(
        "fido2.hid.CtapHidDevice.list_devices", staticmethod(lambda: [object()])
    )
    monkeypatch.setattr("fido2.client.Fido2Client", _FakeFido2Client)

    before = await _recovery_token_count()
    _feed(monkeypatch, [master_password])
    assert await tool.main(["--force"]) == 0
    assert await _recovery_token_count() == before + 1

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action = 'recovery-token-mint' ORDER BY id DESC LIMIT 1"
                )
            )
        ).first()
    assert row.detail["second_factor"] == "fido2"
